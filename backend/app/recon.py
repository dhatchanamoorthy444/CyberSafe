"""
CyberSafe — Safe Recon Engine
Performs limited, controlled public technical reconnaissance on a target hostname/URL.

SECURITY MODEL:
- SSRF protection: rejects private IPs, loopback, link-local, cloud metadata
- DNS resolved before HTTP — resolved IP re-checked
- Redirect chain re-checked for private IPs
- Strict timeout, redirect limit, response size limit
- Never executes page JavaScript
- Never stores response body
- Never logs cookies or auth headers
"""

import os
import re
import ssl
import socket
import hashlib
import logging
import ipaddress
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import dns.resolver
import dns.exception

logger = logging.getLogger("cybersafe.recon")

# ── Configuration (from env with sensible defaults) ─────────────────────────
RECON_TIMEOUT     = int(os.environ.get("RECON_TIMEOUT", "10"))
MAX_REDIRECTS     = int(os.environ.get("MAX_REDIRECTS", "5"))
MAX_RESPONSE_SIZE = int(os.environ.get("MAX_RESPONSE_SIZE", str(1 * 1024 * 1024)))  # 1 MB
USER_AGENT        = "CyberSafe-Recon/1.0 (Defensive Security Scanner)"

# ── SSRF block-list ──────────────────────────────────────────────────────────
_BLOCKED_HOSTS = {
    "localhost", "ip6-localhost", "ip6-loopback",
    "broadcasthost", "local",
}
_CLOUD_METADATA = {
    "169.254.169.254",  # AWS / GCP / Azure IMDS
    "metadata.google.internal",
    "100.100.100.200",  # Alibaba Cloud
}
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# ── Security headers to audit ────────────────────────────────────────────────
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "Forces browsers to use HTTPS for future visits, preventing protocol-downgrade attacks.",
    },
    "content-security-policy": {
        "name": "CSP",
        "description": "Restricts which resources the browser can load, reducing XSS and injection risks.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents browsers from MIME-sniffing responses away from the declared content type.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Controls whether the page can be embedded in iframes, protecting against clickjacking.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls how much referrer information is included in requests from this page.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls which browser features (camera, geolocation, etc.) the page can use.",
    },
    "cross-origin-opener-policy": {
        "name": "COOP",
        "description": "Isolates the browsing context from cross-origin documents.",
    },
    "cross-origin-resource-policy": {
        "name": "CORP",
        "description": "Restricts which origins can embed this resource.",
    },
}


# ── SSRF guard ────────────────────────────────────────────────────────────────

def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if the IP address is private, loopback, link-local, or cloud metadata."""
    if ip_str in _CLOUD_METADATA:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return True
        for net in _PRIVATE_NETWORKS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


def _is_blocked_host(hostname: str) -> bool:
    """Return True if the hostname itself is an obviously blocked name."""
    h = hostname.lower().rstrip(".")
    if h in _BLOCKED_HOSTS or h in _CLOUD_METADATA:
        return True
    # bare IP?
    try:
        return _is_blocked_ip(h)
    except Exception:
        pass
    return False


def _resolve_and_guard(hostname: str) -> list[str]:
    """
    Resolve hostname to IP addresses and check each one.
    Raises ValueError if any resolved IP is private/blocked.
    Returns the list of resolved IPs.
    """
    if _is_blocked_host(hostname):
        raise ValueError(f"Blocked hostname: {hostname}")

    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = list({info[4][0] for info in infos})
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc

    for ip in ips:
        if _is_blocked_ip(ip):
            raise ValueError(f"Resolved to blocked IP: {ip}")

    return ips


# ── DNS collection ────────────────────────────────────────────────────────────

def _collect_dns(hostname: str) -> dict:
    """Query common DNS record types for the target hostname."""
    records: dict = {}
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype, raise_on_no_answer=False)
            records[rtype] = []
            for rdata in answers:
                records[rtype].append({
                    "value": str(rdata),
                    "ttl": answers.ttl,
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            records[rtype] = []
        except Exception as exc:
            records[rtype] = [{"error": str(type(exc).__name__)}]

    return records


# ── TLS info ──────────────────────────────────────────────────────────────────

def _collect_tls(hostname: str, port: int = 443) -> dict:
    """Retrieve basic TLS certificate information without sending HTTP traffic."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=RECON_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        if not cert:
            return {"enabled": True, "error": "No certificate returned"}

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter",  "")

        not_after_dt = None
        expired = None
        days_remaining = None
        if not_after_str:
            try:
                not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                expired = now > not_after_dt
                days_remaining = (not_after_dt - now).days
            except ValueError:
                pass

        # SAN hostname match
        san_list = [v for _, v in cert.get("subjectAltName", [])]
        hostname_matches = any(
            hostname == san or (san.startswith("*.") and hostname.endswith(san[1:]))
            for san in san_list
        )

        return {
            "enabled": True,
            "version": tls_version,
            "subject": subject.get("commonName", ""),
            "issuer":  issuer.get("organizationName", issuer.get("commonName", "")),
            "valid_from": not_before_str,
            "valid_until": not_after_str,
            "expired": expired,
            "days_remaining": days_remaining,
            "hostname_matches": hostname_matches,
            "san": san_list[:10],
        }

    except ssl.SSLCertVerificationError as exc:
        return {"enabled": True, "error": "Certificate verification failed", "detail": str(exc)}
    except ssl.SSLError as exc:
        return {"enabled": True, "error": "TLS error", "detail": str(exc)}
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"enabled": False, "error": str(type(exc).__name__), "detail": str(exc)}


# ── HTTP collection ───────────────────────────────────────────────────────────

def _collect_http(url: str, resolved_ips: list[str]) -> dict:
    """
    Perform a controlled HTTP request, collecting headers and redirect chain.
    Re-checks every redirect target for SSRF.
    """
    redirects: list[dict] = []
    final_url = url
    status_code = None
    response_headers: dict = {}
    error: Optional[str] = None

    try:
        transport = httpx.HTTPTransport(retries=0)
        with httpx.Client(
            follow_redirects=False,
            timeout=RECON_TIMEOUT,
            transport=transport,
            headers={"User-Agent": USER_AGENT},
            max_redirects=0,
        ) as client:
            current_url = url
            seen_urls: set[str] = set()

            for hop in range(MAX_REDIRECTS + 1):
                if current_url in seen_urls:
                    error = "Redirect loop detected"
                    break
                seen_urls.add(current_url)

                parsed = urlparse(current_url)
                hop_host = parsed.hostname or ""

                # SSRF guard on each hop
                try:
                    _resolve_and_guard(hop_host)
                except ValueError as exc:
                    error = f"Redirect blocked (SSRF): {exc}"
                    break

                try:
                    resp = client.get(
                        current_url,
                        headers={"User-Agent": USER_AGENT},
                    )
                except httpx.RequestError as exc:
                    error = f"Request error: {type(exc).__name__}"
                    break

                # Limit response size
                content_length_hdr = resp.headers.get("content-length")
                if content_length_hdr:
                    try:
                        if int(content_length_hdr) > MAX_RESPONSE_SIZE:
                            error = "Response too large"
                            status_code = resp.status_code
                            response_headers = dict(resp.headers)
                            break
                    except ValueError:
                        pass

                status_code = resp.status_code
                response_headers = dict(resp.headers)
                final_url = str(resp.url)

                redirects.append({
                    "url": current_url,
                    "status": resp.status_code,
                    "location": resp.headers.get("location", ""),
                })

                if resp.status_code not in (301, 302, 303, 307, 308):
                    break

                location = resp.headers.get("location", "")
                if not location:
                    break

                # Resolve relative redirect
                if location.startswith("/"):
                    parsed_cur = urlparse(current_url)
                    current_url = f"{parsed_cur.scheme}://{parsed_cur.netloc}{location}"
                elif not location.startswith("http"):
                    current_url = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}/{location}"
                else:
                    current_url = location

                if hop == MAX_REDIRECTS:
                    error = f"Redirect limit reached ({MAX_REDIRECTS})"
                    break

    except Exception as exc:
        error = f"Unexpected error: {type(exc).__name__}: {exc}"

    return {
        "status_code": status_code,
        "final_url": final_url,
        "redirect_count": max(0, len(redirects) - 1),
        "redirects": redirects,
        "headers": response_headers,
        "error": error,
    }


# ── Security headers audit ───────────────────────────────────────────────────

def _audit_security_headers(headers: dict) -> dict:
    """Analyse HTTP response headers for security posture."""
    result = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_key, meta in SECURITY_HEADERS.items():
        present = header_key in headers_lower
        result[meta["name"]] = {
            "present": present,
            "value": headers_lower.get(header_key, ""),
            "description": meta["description"],
        }

    return result


# ── Cookie audit ─────────────────────────────────────────────────────────────

def _audit_cookies(headers: dict) -> list[dict]:
    """Parse Set-Cookie headers and flag missing security attributes."""
    cookies = []
    set_cookie_values = []

    for k, v in headers.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                set_cookie_values.extend(v)
            else:
                set_cookie_values.append(v)

    for raw in set_cookie_values:
        parts = [p.strip() for p in raw.split(";")]
        name_value = parts[0].split("=", 1)
        name = name_value[0].strip() if name_value else "?"

        attrs = {p.lower().split("=")[0].strip() for p in parts[1:]}

        warnings = []
        if "secure" not in attrs:
            warnings.append("Missing Secure flag — cookie may be sent over HTTP")
        if "httponly" not in attrs:
            warnings.append("Missing HttpOnly flag — cookie accessible via JavaScript")
        samesite = next((p for p in parts[1:] if "samesite" in p.lower()), None)
        if not samesite:
            warnings.append("Missing SameSite attribute — vulnerable to CSRF in some contexts")

        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "http_only": "httponly" in attrs,
            "same_site": samesite.split("=")[-1].strip() if samesite else None,
            "warnings": warnings,
        })

    return cookies


# ── Technology detection ──────────────────────────────────────────────────────

def _detect_technology(headers: dict) -> dict:
    """Detect server technology from public HTTP headers only."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    tech = {}

    server = headers_lower.get("server", "")
    if server:
        tech["server"] = server

    via = headers_lower.get("via", "")
    if via:
        tech["proxy"] = via

    powered = headers_lower.get("x-powered-by", "")
    if powered:
        tech["framework"] = powered

    # CDN detection from common headers
    cdn_signals = {
        "cf-ray":        "Cloudflare",
        "x-vercel-id":   "Vercel",
        "x-amz-cf-id":   "AWS CloudFront",
        "x-fastly-request-id": "Fastly",
        "x-cache":       "CDN cache layer",
    }
    for header, cdn_name in cdn_signals.items():
        if header in headers_lower:
            tech["cdn"] = cdn_name
            break

    return tech


# ── Optional resources ───────────────────────────────────────────────────────

def _check_optional_resource(base_url: str, path: str) -> dict:
    """Check for optional well-known resources (robots.txt, security.txt)."""
    parsed = urlparse(base_url)
    url = f"{parsed.scheme}://{parsed.netloc}{path}"
    try:
        with httpx.Client(
            timeout=5,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = client.get(url)
            return {
                "url": url,
                "exists": resp.status_code == 200,
                "status": resp.status_code,
            }
    except Exception:
        return {"url": url, "exists": False, "status": None}


# ── Risk scoring for recon ───────────────────────────────────────────────────

def _compute_recon_risk(http_data: dict, tls_data: dict, sec_headers: dict) -> dict:
    """
    Produce a lightweight risk score from recon observations.
    This does not replace the offline analysis score; it supplements it.
    """
    score = 0
    indicators = []

    # TLS
    if not tls_data.get("enabled"):
        score += 20
        indicators.append("No TLS/HTTPS detected")
    elif tls_data.get("expired"):
        score += 25
        indicators.append("TLS certificate is expired")
    elif not tls_data.get("hostname_matches"):
        score += 15
        indicators.append("TLS certificate hostname mismatch")
    elif (tls_data.get("days_remaining") or 999) < 14:
        score += 10
        indicators.append(f"Certificate expires soon ({tls_data.get('days_remaining')} days)")

    # Missing critical security headers
    critical_headers = ["HSTS", "CSP", "X-Content-Type-Options"]
    for h in critical_headers:
        if sec_headers.get(h, {}).get("present") is False:
            score += 5
            indicators.append(f"Missing security header: {h}")

    # Redirects
    redirect_count = http_data.get("redirect_count", 0)
    if redirect_count >= 3:
        score += 10
        indicators.append(f"Multiple redirects: {redirect_count}")

    # HTTP status
    status = http_data.get("status_code")
    if status and status >= 500:
        score += 5
        indicators.append(f"Server error: HTTP {status}")

    # Cross-scheme redirect (HTTPS → HTTP)
    for redir in http_data.get("redirects", []):
        loc = redir.get("location", "")
        if loc.startswith("http://"):
            score += 15
            indicators.append("Redirect from HTTPS to HTTP")
            break

    score = min(score, 100)

    if score < 20:
        level = "LOW"
    elif score < 40:
        level = "MEDIUM"
    elif score < 70:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {"score": score, "level": level, "indicators": indicators}


# ── Main entry point ─────────────────────────────────────────────────────────

async def run_recon(url: str) -> dict:
    """
    Full safe recon pipeline.
    Returns structured dict with all collected data.
    Raises ValueError for blocked/invalid targets.
    """
    parsed = urlparse(url)
    scheme   = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    port     = parsed.port or (443 if scheme == "https" else 80)

    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {scheme!r}. Only http/https allowed for recon.")

    if not hostname:
        raise ValueError("No hostname found in URL.")

    # SSRF guard — resolves DNS and checks IPs
    resolved_ips = _resolve_and_guard(hostname)

    timestamp = datetime.now(timezone.utc).isoformat()

    # 1. DNS
    dns_records = _collect_dns(hostname)

    # 2. TLS (HTTPS only)
    tls_data: dict = {}
    if scheme == "https":
        tls_data = _collect_tls(hostname, port)
    else:
        tls_data = {"enabled": False, "reason": "Target uses HTTP, not HTTPS"}

    # 3. HTTP
    http_data = _collect_http(url, resolved_ips)

    # 4. Security headers
    sec_headers = _audit_security_headers(http_data.get("headers", {}))

    # 5. Cookies
    cookies = _audit_cookies(http_data.get("headers", {}))

    # 6. Technology
    technology = _detect_technology(http_data.get("headers", {}))

    # 7. Optional resources
    robots = _check_optional_resource(url, "/robots.txt")
    security_txt = _check_optional_resource(url, "/.well-known/security.txt")

    # 8. Risk
    risk = _compute_recon_risk(http_data, tls_data, sec_headers)

    # 9. Domain info (from parsed URL + DNS)
    domain_info = {
        "hostname": hostname,
        "scheme": scheme,
        "port": port,
        "resolved_ips": resolved_ips[:10],
    }
    try:
        import tldextract
        ext = tldextract.extract(hostname)
        domain_info["registered_domain"] = f"{ext.domain}.{ext.suffix}" if ext.suffix else hostname
        domain_info["subdomain"] = ext.subdomain or ""
        domain_info["tld"] = ext.suffix or ""
    except ImportError:
        pass

    return {
        "target": domain_info,
        "dns": dns_records,
        "http": {
            "status_code": http_data.get("status_code"),
            "final_url": http_data.get("final_url"),
            "redirect_count": http_data.get("redirect_count", 0),
            "redirects": http_data.get("redirects", []),
            "content_type": http_data.get("headers", {}).get("content-type", ""),
            "content_length": http_data.get("headers", {}).get("content-length", ""),
            "server": http_data.get("headers", {}).get("server", ""),
            "error": http_data.get("error"),
        },
        "tls": tls_data,
        "headers": sec_headers,
        "cookies": cookies,
        "technology": technology,
        "resources": {
            "robots_txt": robots,
            "security_txt": security_txt,
        },
        "risk": risk,
        "warnings": [i for i in risk["indicators"]],
        "timestamp": timestamp,
    }

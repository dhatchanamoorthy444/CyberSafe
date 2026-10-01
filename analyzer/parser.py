"""
CyberSafe - Safe URL Parser Module
Extracts and normalizes URL components strictly offline without any network or DNS activity.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import urllib.parse
import re


@dataclass
class ParsedURL:
    """Structured representation of a safely parsed URL."""
    valid: bool
    original_url: str
    scheme: str
    netloc: str
    hostname: Optional[str]
    username: Optional[str]
    password: Optional[str]
    port: Optional[int]
    raw_port: Optional[str]
    path: str
    query: str
    fragment: str
    has_userinfo: bool
    is_punycode: bool
    unicode_hostname: Optional[str]
    has_trailing_dot: bool
    parse_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)


class SafeURLParser:
    """
    Robust, offline URL parser designed to withstand evasion, obfuscation,
    and malformed inputs while preventing SSRF / network resolution.
    """

    # Common non-web pseudo-schemes or schemes without netloc
    OPAQUE_SCHEMES = {"javascript", "data", "vbscript", "blob", "file", "about", "mailto", "tel"}

    @classmethod
    def parse(cls, raw_url: Optional[str]) -> ParsedURL:
        """
        Safely parse raw input URL into structured components.
        Guaranteed to never make DNS or HTTP requests.
        """
        if not raw_url or not isinstance(raw_url, str):
            return ParsedURL(
                valid=False,
                original_url=str(raw_url or ""),
                scheme="",
                netloc="",
                hostname=None,
                username=None,
                password=None,
                port=None,
                raw_port=None,
                path="",
                query="",
                fragment="",
                has_userinfo=False,
                is_punycode=False,
                unicode_hostname=None,
                has_trailing_dot=False,
                parse_error="Empty or non-string input URL"
            )

        original_url = raw_url.strip()

        # Check for scheme-relative or missing scheme
        scheme = ""
        rest = original_url

        # Check if URL starts with scheme: (e.g. https:, javascript:, data:)
        scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", original_url)
        if scheme_match:
            scheme = scheme_match.group(1).lower()
            rest = original_url[len(scheme) + 1:]
        else:
            scheme = ""
            rest = original_url

        # Handle dangerous/opaque schemes like javascript:, data:, vbscript:
        if scheme in cls.OPAQUE_SCHEMES:
            return ParsedURL(
                valid=True,
                original_url=original_url,
                scheme=scheme,
                netloc="",
                hostname=None,
                username=None,
                password=None,
                port=None,
                raw_port=None,
                path=rest,
                query="",
                fragment="",
                has_userinfo=False,
                is_punycode=False,
                unicode_hostname=None,
                has_trailing_dot=False,
                parse_error=None
            )

        # Standard hierarchical URL processing (http, https, ftp, or missing scheme)
        parse_target = original_url
        if not scheme:
            # If no scheme was found, check if it starts with //
            if not original_url.startswith("//"):
                parse_target = "//" + original_url

        try:
            parsed = urllib.parse.urlsplit(parse_target, scheme=scheme)
        except Exception as e:
            return ParsedURL(
                valid=False,
                original_url=original_url,
                scheme=scheme,
                netloc="",
                hostname=None,
                username=None,
                password=None,
                port=None,
                raw_port=None,
                path="",
                query="",
                fragment="",
                has_userinfo=False,
                is_punycode=False,
                unicode_hostname=None,
                has_trailing_dot=False,
                parse_error=f"Malformed URL structure: {str(e)}"
            )

        effective_scheme = (parsed.scheme or scheme or "").lower()
        netloc = parsed.netloc

        # Extract userinfo, host, and port accurately
        # Special handling for @ symbol: everything before the LAST @ in authority is userinfo
        username: Optional[str] = None
        password: Optional[str] = None
        hostname_str: Optional[str] = None
        raw_port: Optional[str] = None
        port: Optional[int] = None
        has_userinfo = False

        if "@" in netloc:
            has_userinfo = True
            userinfo_part, host_part = netloc.rsplit("@", 1)
            if ":" in userinfo_part:
                u, p = userinfo_part.split(":", 1)
                username = urllib.parse.unquote(u)
                password = urllib.parse.unquote(p)
            else:
                username = urllib.parse.unquote(userinfo_part)
                password = None
        else:
            host_part = netloc
            username = parsed.username
            password = parsed.password
            if username or password:
                has_userinfo = True

        # Extract hostname and port from host_part
        # Handle IPv6 in brackets [2001:db8::1]:8080
        if host_part.startswith("[") and "]" in host_part:
            bracket_end = host_part.find("]")
            hostname_str = host_part[1:bracket_end]
            port_part = host_part[bracket_end + 1:]
            if port_part.startswith(":"):
                raw_port = port_part[1:]
        elif ":" in host_part:
            h, p = host_part.rsplit(":", 1)
            hostname_str = h
            raw_port = p
        else:
            hostname_str = host_part

        # Parse port safely without raising exceptions
        if raw_port:
            try:
                p_int = int(raw_port)
                if 1 <= p_int <= 65535:
                    port = p_int
            except ValueError:
                port = None

        # Normalize hostname safely
        has_trailing_dot = False
        is_punycode = False
        unicode_hostname: Optional[str] = None

        if hostname_str:
            # Unquote percent-encoding in hostname (e.g. %67oogle.com)
            try:
                hostname_str = urllib.parse.unquote(hostname_str)
            except Exception:
                pass

            if hostname_str.endswith("."):
                has_trailing_dot = True
                hostname_str = hostname_str.rstrip(".")

            hostname_str = hostname_str.lower()

            # Punycode / IDN detection and decoding
            if "xn--" in hostname_str:
                is_punycode = True
                try:
                    unicode_hostname = hostname_str.encode("ascii").decode("idna")
                except Exception:
                    unicode_hostname = None
            else:
                # Check if hostname contains non-ASCII unicode
                try:
                    hostname_str.encode("ascii")
                except UnicodeEncodeError:
                    unicode_hostname = hostname_str

        # If hostname is empty string, normalize to None
        if hostname_str == "":
            hostname_str = None

        return ParsedURL(
            valid=True,
            original_url=original_url,
            scheme=effective_scheme,
            netloc=netloc,
            hostname=hostname_str,
            username=username,
            password=password,
            port=port,
            raw_port=raw_port,
            path=parsed.path or "",
            query=parsed.query or "",
            fragment=parsed.fragment or "",
            has_userinfo=has_userinfo,
            is_punycode=is_punycode,
            unicode_hostname=unicode_hostname,
            has_trailing_dot=has_trailing_dot,
            parse_error=None
        )

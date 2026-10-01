"""
CyberSafe - URL Shortening Detector Module
Identifies known URL shortening services strictly offline without resolution.
"""

from typing import List, Optional
import re
from .models import Finding
from .parser import ParsedURL


class URLShorteningDetector:
    """Detects known URL shortening services for risk assessment."""

    # Known URL shortening services (updated list of popular ones)
    KNOWN_SHORTENERS: List[str] = [
        'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly',
        'shorturl.at', 'ow.ly', 'buff.ly', 'ift.tt', 'lnkd.in',
        'adcraft.ly', 'cuttly.com', 'shorte.st', 'short.io',
        'clicky.me', 'cutey.io', 'tiny.cc', 'short.cm', 'shortear.com',
        'rb.gy', 'hyperurl.co', 'go2l.ink', 'url.shortener', 'glamorous.ly'
    ]

    # Additional suspicious patterns for shorteners
    SUSPICIOUS_SHORTENERS: List[str] = [
        'short.link', 'link.short', 'url.short', 'tiny.link',
        'short.site', 'urlcut.com', 'shortest.link', 'short.link'
    ]

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> List[Finding]:
        """Analyze hostname for URL shortening services."""
        findings: List[Finding] = []
        host = parsed.hostname

        if not host:
            return findings

        host_lower = host.lower()

        # Normalize hostname for comparison (strip a leading "www." label only).
        # str.lstrip('www.') strips a character *set*, which would also eat the
        # leading characters of hosts like "web.ly" or "w.something".
        normalized_host = host_lower[4:] if host_lower.startswith("www.") else host_lower

        # 1. Direct match with known shorteners
        if normalized_host in cls.KNOWN_SHORTENERS:
            findings.append(
                Finding(
                    rule_id="KNOWN_URL_SHORTENER",
                    severity="medium",
                    score=20,
                    title=f"Known URL shortening service: {host}",
                    message=(
                        f"The hostname '{host}' is a recognized URL shortening service. "
                        f"While legitimate use cases exist, these services are frequently abused in phishing campaigns "
                        f"to hide malicious destinations from security filters."
                    ),
                    evidence=f"Hostname matches known shortener: {normalized_host}"
                )
            )
            return findings

        # 2. Check suspicious shortener patterns
        for suspicious in cls.SUSPICIOUS_SHORTENERS:
            if suspicious in host_lower or host_lower.endswith(f".{suspicious}"):
                findings.append(
                    Finding(
                        rule_id="SUSPICIOUS_SHORTENER_PATTERN",
                        severity="medium",
                        score=15,
                        title=f"Suspicious shortener pattern: {host}",
                        message=(
                            f"The hostname '{host}' contains patterns similar to known URL shortening services. "
                            f"This could indicate an attempt to obfuscate the final destination."
                        ),
                        evidence=f"Suspicious pattern detected: {host_lower} matches {suspicious}"
                    )
                )
                break

        # 3. Check for excessive shortening patterns (e.g., multiple subdomains)
        if len(host_lower.split('.')) > 3:
            findings.append(
                Finding(
                    rule_id="EXCESSIVE_SUBDOMAINS",
                    severity="low",
                    score=10,
                    title="Excessive subdomain count suggests URL shortening",
                    message=(
                        f"The hostname '{host}' has {len(host_lower.split('.'))} subdomain levels. "
                        f"While legitimate services may use multiple subdomains, this pattern is often associated "
                        f"with URL shortening or proxy services."
                    ),
                    evidence=f"High subdomain count: {len(host_lower.split('.'))}"
                )
            )

        return findings
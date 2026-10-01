"""
CyberSafe - Lookalike Domain Detector
Identifies potential brand impersonation through character substitutions and suspicious patterns.

Fix: Official domains (google.com, paypal.com etc.) are no longer flagged as impersonators.
Only flag when the registered domain differs from the known official domain.
"""

from typing import List, Dict, Tuple, Optional, Set
import re
from .models import Finding
from .parser import ParsedURL

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


class LookalikeDetector:
    """
    Detects potential domain impersonation through character substitutions, added suspicious words,
    hyphenated brand impersonation, or brand name embedded in different domains.

    KEY RULE: Never flag a domain that IS the official domain for a brand.
    Only flag domains that LOOK LIKE the official domain but are NOT.
    """

    # Maps brand keyword → set of official registered domains for that brand.
    # A URL whose registered domain appears in this set is legitimate — never flag it.
    OFFICIAL_DOMAINS: Dict[str, Set[str]] = {
        'google':       {'google.com', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp',
                         'google.com.au', 'google.ca', 'google.co.in', 'googleapis.com', 'gstatic.com'},
        'microsoft':    {'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com',
                         'office.com', 'azure.com', 'bing.com', 'msn.com', 'xbox.com'},
        'paypal':       {'paypal.com', 'paypal.me', 'paypalobjects.com'},
        'amazon':       {'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp',
                         'amazon.com.au', 'amazon.ca', 'amazon.in', 'aws.amazon.com', 'amazonaws.com'},
        'apple':        {'apple.com', 'icloud.com', 'itunes.com', 'icloud.com'},
        'facebook':     {'facebook.com', 'fb.com', 'messenger.com', 'fbcdn.net'},
        'instagram':    {'instagram.com', 'cdninstagram.com'},
        'github':       {'github.com', 'github.io', 'githubusercontent.com', 'githubcopilot.com'},
        'linkedin':     {'linkedin.com', 'licdn.com'},
        'netflix':      {'netflix.com', 'nflximg.com', 'nflxvideo.net'},
        'twitter':      {'twitter.com', 'x.com', 'twimg.com', 't.co'},
        'youtube':      {'youtube.com', 'youtu.be', 'yt.be', 'ytimg.com'},
        'reddit':       {'reddit.com', 'redd.it', 'redditmedia.com', 'reddituploads.com'},
        'yahoo':        {'yahoo.com', 'yahoo.co.uk', 'yahoo.co.jp', 'yimg.com'},
        'cnn':          {'cnn.com'},
        'bbc':          {'bbc.com', 'bbc.co.uk'},
        'forbes':       {'forbes.com'},
        'nasa':         {'nasa.gov'},
        'wikipedia':    {'wikipedia.org', 'wikimedia.org', 'wikidata.org'},
        'stackoverflow': {'stackoverflow.com', 'stackexchange.com', 'superuser.com', 'serverfault.com'},
        'gmail':        {'gmail.com', 'google.com'},
        'outlook':      {'outlook.com', 'live.com', 'hotmail.com', 'microsoft.com'},
        'pinterest':    {'pinterest.com', 'pinimg.com'},
        'dropbox':      {'dropbox.com', 'dropboxstatic.com'},
        'zoom':         {'zoom.us', 'zoom.com'},
        'slack':        {'slack.com', 'slack-edge.com'},
        'spotify':      {'spotify.com', 'scdn.co'},
        'uber':         {'uber.com'},
        'lyft':         {'lyft.com'},
        'airbnb':       {'airbnb.com'},
    }

    # All known brand keywords (derived from OFFICIAL_DOMAINS keys)
    LEGITIMATE_BRANDS: Set[str] = set(OFFICIAL_DOMAINS.keys())

    # Character substitution patterns (visually similar characters)
    SUBSTITUTION_MAP: Dict[str, List[str]] = {
        'a': ['4', '@'],
        'b': ['8'],
        'e': ['3'],
        'g': ['6', '9'],
        'i': ['1', '!', 'l'],
        'l': ['1', '|', 'i'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['+', '7'],
        'w': ['vv'],
    }

    # Highly suspicious appended word suffixes (common in phishing)
    SUSPICIOUS_SUFFIXES: List[str] = [
        'login', 'signin', 'verify', 'verification', 'account', 'password',
        'reset', 'secure', 'authentication', 'confirm', 'update', 'billing',
        'payment', 'wallet', 'admin', 'support', 'service', 'online', 'portal',
        'web', 'webmail', 'email', 'auth', 'id', 'token', 'security',
    ]

    @classmethod
    def _get_registered_domain(cls, hostname: str) -> str:
        """
        Return the registered domain (eTLD+1) for a hostname.
        Falls back to the last two labels if tldextract is unavailable.
        """
        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            return hostname
        # Fallback: last two labels
        parts = hostname.lower().split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname

    @classmethod
    def _is_official_domain(cls, registered_domain: str) -> bool:
        """Return True if registered_domain is a known official domain for any brand."""
        rd = registered_domain.lower()
        for official_set in cls.OFFICIAL_DOMAINS.values():
            if rd in official_set:
                return True
        return False

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> Tuple[List[Finding], Optional[str]]:
        """
        Detect potential lookalike domain impersonation and brand impersonation attempts.
        Returns (findings, risk_level).

        Never flags an official domain as an impersonator.
        """
        findings: List[Finding] = []
        host = parsed.hostname

        if not host:
            return findings, None

        host_lower = host.lower()
        registered_domain = cls._get_registered_domain(host_lower)

        # ── GATE: if the registered domain IS an official domain, stop here ──
        # e.g. google.com, www.google.com, mail.google.com → all clean
        if cls._is_official_domain(registered_domain):
            return findings, None

        # Extract just the domain label (without TLD) for brand matching
        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(host_lower)
            domain_label = ext.domain or host_lower.split('.')[0]
        else:
            parts = host_lower.split('.')
            domain_label = parts[-2] if len(parts) >= 2 else parts[0]

        # 1. Direct brand name in domain label (e.g. "paypal" in "paypal-secure.com")
        for brand, official_set in cls.OFFICIAL_DOMAINS.items():
            if brand not in domain_label:
                continue
            # Registered domain is NOT official (checked above), but brand name appears
            findings.append(
                Finding(
                    rule_id="BRAND_IN_NON_OFFICIAL_DOMAIN",
                    severity="high",
                    score=55,
                    title=f"Brand name '{brand}' in non-official domain",
                    message=(
                        f"The hostname '{host}' contains the brand name '{brand}' but is not "
                        f"the official {brand.capitalize()} domain. "
                        f"Official domains: {', '.join(sorted(official_set)[:3])}."
                        f" This pattern is commonly used in phishing."
                    ),
                    evidence=f"Brand '{brand}' found in domain label '{domain_label}' of non-official host '{registered_domain}'"
                )
            )
            return findings, "suspicious"

        # 2. Character substitution lookalike (e.g. "g00gle.com", "paypa1.com")
        possible_subs = cls._detect_substitutions(domain_label)
        for description, brand in possible_subs.items():
            findings.append(
                Finding(
                    rule_id="LOOKALIKE_HOSTNAME",
                    severity="high",
                    score=50,
                    title=f"Possible lookalike domain: {domain_label}",
                    message=(
                        f"The hostname '{host}' uses '{domain_label}', which appears to be a "
                        f"character-substitution variation of '{brand}' "
                        f"(e.g. '0' for 'o', '1' for 'l'). "
                        f"This is a common phishing technique."
                    ),
                    evidence=f"Observed: {domain_label} | Impersonated brand: {brand} | Reason: {description}"
                )
            )

        # 3. Suspicious suffix appended to a brand name
        suffix_matches = cls._detect_suspicious_suffixes(domain_label)
        if suffix_matches and not findings:  # avoid double-firing with rule 1
            findings.append(
                Finding(
                    rule_id="SUSPICIOUS_SUFFIX_IMPERSONATION",
                    severity="medium",
                    score=30,
                    title=f"Suspicious suffix in domain: {domain_label}",
                    message=(
                        f"The domain label '{domain_label}' ends with a suspicious suffix "
                        f"'{suffix_matches[0]}', which is commonly appended to brand names "
                        f"in phishing domains."
                    ),
                    evidence=f"Suspicious suffix: {suffix_matches[0]} in {domain_label}"
                )
            )

        # 4. Hyphenated brand impersonation (e.g. "google-login.com")
        hyphen_brand = cls._detect_hyphen_impersonation(host_lower, registered_domain)
        if hyphen_brand and not findings:
            findings.append(
                Finding(
                    rule_id="HYPHEN_BRAND_IMPERSONATION",
                    severity="high",
                    score=50,
                    title=f"Hyphenated brand impersonation: {host}",
                    message=(
                        f"The hostname '{host}' uses a hyphenated pattern that combines "
                        f"the brand name '{hyphen_brand}' with other words. "
                        f"This is a classic phishing domain structure "
                        f"(e.g. 'paypal-secure.com', 'google-login.net')."
                    ),
                    evidence=f"Hyphenated impersonation: {host} → brand '{hyphen_brand}'"
                )
            )
            return findings, "suspicious"

        # Determine overall risk level
        is_suspicious = any(
            f.severity == "high" and f.score >= 40 for f in findings
        )
        return findings, "suspicious" if is_suspicious else None

    # ── Private helpers ──────────────────────────────────────────────────────

    @classmethod
    def _detect_substitutions(cls, domain_label: str) -> Dict[str, str]:
        """
        Detect if domain_label looks like a brand after reversing common
        character substitutions (0→o, 1→l, 3→e, …).
        """
        result: Dict[str, str] = {}
        for i, char in enumerate(domain_label):
            for orig, subs in cls.SUBSTITUTION_MAP.items():
                if char in subs:
                    candidate = domain_label[:i] + orig + domain_label[i + 1:]
                    if candidate in cls.LEGITIMATE_BRANDS:
                        reason = f"'{char}' substitutes for '{orig}' → '{candidate}'"
                        result[reason] = candidate
        return result

    @staticmethod
    def _detect_suspicious_suffixes(domain_label: str) -> List[str]:
        """Detect suspicious word suffixes in the domain label."""
        matches: List[str] = []
        for suffix in LookalikeDetector.SUSPICIOUS_SUFFIXES:
            if (domain_label.endswith(f"-{suffix}")
                    or domain_label.endswith(f"_{suffix}")
                    or domain_label.endswith(suffix)):
                matches.append(suffix)
        return matches

    @classmethod
    def _detect_hyphen_impersonation(cls, host: str, registered_domain: str) -> Optional[str]:
        """
        Detect patterns like 'paypal-secure.com', 'google-login.net' where a known brand
        appears as a hyphenated component of a non-official registered domain.
        """
        parts = registered_domain.split('-')
        if len(parts) < 2:
            return None
        for part in parts:
            part_clean = part.split('.')[0]  # strip TLD fragment
            if part_clean in cls.LEGITIMATE_BRANDS:
                return part_clean
        return None

"""
CyberSafe - Lookalike Domain Detector
Identifies potential brand impersonation through character substitutions and suspicious patterns.
"""

from typing import List, Dict, Tuple, Optional, Set
import re
from .models import Finding
from .parser import ParsedURL


class LookalikeDetector:
    """
    Detects potential domain impersonation through character substitutions, added suspicious words,
    hyphenated brand impersonation, or brand name embedded in different domains.
    """

    # Common legitimate brand names for comparison
    LEGITIMATE_BRANDS: Set[str] = {
        'google', 'microsoft', 'paypal', 'amazon', 'apple', 'facebook', 'instagram',
        'github', 'linkedin', 'netflix', 'twitter', 'youtube', 'reddit', 'outlook',
        'yahoo', 'cnn', 'bbc', 'forbes', 'nasa', 'wikipedia', 'stackoverflow',
        'gmail', 'office365', 'outlook', 'linkedin', 'instagram', 'pinterest'
    }

    # Character substitution patterns (from keyboard adjacency)
    SUBSITUTION_MAP: Dict[str, List[str]] = {
        'a': ['4', '@'],  # @ can also be userinfo, handled separately
        'b': ['8'],
        'c': ['(', '['],  # ( often used in phishing
        'd': [')'],
        'e': ['3'],
        'f': ['&'],
        'g': ['6', '9'],
        'h': ['#'],
        'i': ['1', '!', 'l'],
        'j': ['!', '7', 'l'],
        'k': ['!'],
        'l': ['1', '|', 'i'],
        'm': ['@'],
        'n': ['^'],
        'o': ['0'],
        'p': ['?'],
        'q': ['@'],
        'r': ['8'],
        's': ['$', '5'],
        't': ['+', '7'],
        'u': ['\$'],
        'v': ['\^'],
        'w': ['vv'],
        'x': ['%', '><'],
        'y': ['&', 'v'],
        'z': ['2', 'z', 'zza'],
    }

    # Highly suspicious appended word suffixes (common in phishing)
    SUSPICIOUS_SUFFIXES: List[str] = [
        'login', 'signin', 'verify', 'verification', 'account', 'password',
        'reset', 'secure', 'authentication', 'confirm', 'update', 'billing',
        'payment', 'wallet', 'admin', 'support', 'service', 'online', 'portal',
        'web', 'webmail', 'email', 'auth', 'id', 'token', 'security'
    ]

    # Hyphenated impersonation patterns: BRAND-brand.com
    # Where both BRAND and brand versions appear
    HYPHEN_IMPERSONATION_PATTERN: str = r'^(\w+)-(\w+)\.\w+$'

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> Tuple[List[Finding], Optional[str]]:
        """
        Detect potential lookalike domain impersonation and brand impersonation attempts.
        Returns (findings, risk_level) where risk_level is 'suspicious' if strong indicators found.
        """
        findings: List[Finding] = []
        host = parsed.hostname

        if not host:
            return findings, None

        host_lower = host.lower()
        labels = host_lower.split('.')
        domain_part = labels[0] if labels else ""

        # 1. Direct brand impersonation (exact brand name)
        if domain_part in cls.LEGITIMATE_BRANDS:
            findings.append(
                Finding(
                    rule_id="DIRECT_BRAND_IMPERSONATION",
                    severity="high",
                    score=50,
                    title=f"Direct brand impersonation: {domain_part}",
                    message=(
                        f"The hostname '{host}' uses '{domain_part}', which is a legitimate brand name. "
                        f"This is frequently seen in phishing campaigns impersonating this service."
                    ),
                    evidence=f"Exact brand match: {domain_part}"
                )
            )
            return findings, "suspicious"

        # 2. Character substitution detection
        possible_subs = cls._detect_substitutions(domain_part)
        for description, brand in possible_subs.items():
            findings.append(
                Finding(
                    rule_id="LOOKALIKE_HOSTNAME",
                    severity="high",
                    score=50,
                    title=f"Possible lookalike hostname: {domain_part}",
                    message=(
                        f"The hostname '{host}' contains '{domain_part}', which is a character-substitution variation "
                        f"of '{brand}'. Such substitutions (e.g., '1' for 'l', '0' for 'o') are common in phishing attacks."
                    ),
                    evidence=f"Observed hostname: {domain_part} | Possible impersonated brand: {brand} | Reason: {description}"
                )
            )

        # 3. Suspicious suffix detection
        suffix_matches = cls._detect_suspicious_suffixes(domain_part)
        if suffix_matches:
            findings.append(
                Finding(
                    rule_id="SUSPICIOUS_SUFFIX_IMPERSONATION",
                    severity="medium",
                    score=30,
                    title=f"Suspicious suffix detection: {domain_part}",
                    message=(
                        f"The hostname '{host}' includes '{domain_part}' which contains suspicious suffix '{suffix_matches[0]}'. "
                        f"Such appended words are frequently used in phishing domains attempting to impersonate services."
                    ),
                    evidence=f"Suspicious suffix detected: {domain_part} -> {suffix_matches[0]}"
                )
            )

        # 4. Hyphenated brand impersonation (brand-brand.com)
        hyphen_impersonation = cls._detect_hyphen_impersonation(host_lower)
        if hyphen_impersonation:
            findings.append(
                Finding(
                    rule_id="HYPHEN_IMPERSONATION",
                    severity="high",
                    score=45,
                    title=f"Hyphenated brand impersonation: {host}",
                    message=(
                        f"The hostname '{host}' appears to be a hyphenated version of '{hyphen_impersonation}', "
                        f"a pattern frequently used to impersonate legitimate services (e.g., 'google-login.com')."
                    ),
                    evidence=f"Hyphenated impersonation pattern detected: {host}"
                )
            )
            return findings, "suspicious"

        # 5. Brand name embedded in different domain (e.g., 'paypa' in 'paypa-store.com')
        embedded_brand = cls._detect_embedded_brands(domain_part)
        if embedded_brand:
            findings.append(
                Finding(
                    rule_id="EMBEDDED_BRAND_IMPERSONATION",
                    severity="medium",
                    score=35,
                    title=f"Brand name embedded in different domain: {domain_part}",
                    message=(
                        f"The hostname '{host}' contains brand-related term '{domain_part}' that appears to be "
                        f"embedded within a different domain structure, potentially attempting to impersonate '{embedded_brand}'."
                    ),
                    evidence=f"Brand '{domain_part}' embedded in different domain: {host}"
                )
            )

        # Determine if hostname should be marked as SUSPICIOUS based on findings
        is_suspicious = False
        for finding in findings:
            if finding.severity == "high" and finding.score >= 35:
                is_suspicious = True
                break

        return findings, "suspicious" if is_suspicious else None

    @staticmethod
    def _detect_substitutions(domain_part: str) -> Dict[str, str]:
        """Detect character substitutions that could impersonate legitimate brands."""
        result: Dict[str, str] = {}
        brand_candidates: List[Tuple[str, str]] = []

        # Check if any brand name directly appears within domain_part (embedded brand)
        for brand in LookalikeDetector.LEGITIMATE_BRANDS:
            if brand in domain_part:
                result[f"Embedded brand '{brand}'"] = brand
                continue

        # Check for potential substitution patterns by reversing character mapping
        for i, char in enumerate(domain_part):
            if char in LookalikeDetector.SUBSITUTION_MAP:
                for substitution in LookalikeDetector.SUBSITUTION_MAP[char]:
                    potential_brand = domain_part[:i] + substitution + domain_part[i + 1:]
                    if potential_brand in LookalikeDetector.LEGITIMATE_BRANDS:
                        # Create a descriptive reason string
                        reason = f"Character substitution: '{char}' -> '{substitution}' transforms into '{potential_brand}'"
                        brand_candidates.append((reason, potential_brand))

        # Convert to requested format: description -> brand
        for reason, brand in brand_candidates:
            result[reason] = brand

        return result

    @staticmethod
    def _detect_suspicious_suffixes(domain_part: str) -> List[str]:
        """Detect suspicious word suffixes appended to domain part."""
        matches: List[str] = []
        for suffix in LookalikeDetector.SUSPICIOUS_SUFFIXES:
            # Check if domain_part ends with or contains the suffix
            # Also handle cases where there's a separator like '-' or '_'
            if domain_part.endswith(f"-{suffix}") or domain_part.endswith(f"_{suffix}") or domain_part.endswith(suffix):
                matches.append(suffix)
        return matches

    @staticmethod
    def _detect_hyphen_impersonation(host: str) -> Optional[str]:
        """
        Detect hyphenated brand impersonation pattern like 'brand-brand.com'
        Returns the brand that might be impersonated, or None.
        """
        match = re.match(LookalikeDetector.HYPHEN_IMPERSONATION_PATTERN, host)
        if match:
            prefix = match.group(1).lower()
            suffix = match.group(2).lower()

            # Check if either part matches a known brand
            if prefix in LookalikeDetector.LEGITIMATE_BRANDS:
                return prefix
            elif suffix in LookalikeDetector.LEGITIMATE_BRANDS:
                return suffix

        # Check other hyphen patterns like 'brand-login.com' where login is suspicious suffix
        parts = host.split('-')
        if len(parts) >= 2:
            for part in parts:
                # Check if part ends with a suspicious suffix
                for suffix in LookalikeDetector.SUSPICIOUS_SUFFIXES:
                    if part.endswith(suffix):
                        # Check if any other part is a known brand
                        for other_part in parts:
                            if other_part.lower() in LookalikeDetector.LEGITIMATE_BRANDS:
                                return other_part

        return None

    @staticmethod
    def _detect_embedded_brands(domain_part: str) -> Optional[str]:
        """Detect brand names embedded in domain parts (e.g., 'paypa' in 'paypa-store.com')."""
        for brand in LookalikeDetector.LEGITIMATE_BRANDS:
            if brand in domain_part:
                # Check if domain_part is longer or different from brand
                if domain_part != brand and len(domain_part) > len(brand):
                    return brand

        return None
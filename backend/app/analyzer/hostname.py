"""
CyberSafe - Hostname Structure Analyzer
Validates hostname syntax and checks for suspicious patterns that indicate obfuscation or malicious intent.
"""

from typing import List, Optional, Tuple
import re
from .models import Finding
from .parser import ParsedURL


class HostnameAnalyzer:
    """Comprehensive hostname structure and content analysis."""

    # Basic hostname syntax rules per RFC 1123 (per label)
    LABEL_REGEX = re.compile(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$')

    # Suspicious characters that can be abused for obfuscation or evasion
    SUSPICIOUS_CHARS = {'_'}

    # Highly suspicious patterns that indicate active obfuscation attempts.
    # These must be *malformed* structures, not characters that appear in every
    # ordinary hostname — a bare dot matches all multi-label domains.
    HIGH_RISK_PATTERNS = {
        r'\.\.+',   # Runs of two or more consecutive dots (e.g. google..example)
        r'^\.',     # Leading dot
        r'[^\x20-\x7e]',  # Non-printable / non-ASCII control bytes
    }

    # Thresholds for risk assessment
    MAX_LABEL_LENGTH = 63
    MAX_TOTAL_LENGTH = 253
    DOMAIN_HYPHEN_PROXIMITY_THRESHOLD = 3  # Max hyphens per label before penalty

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> Tuple[List[Finding], Optional[str]]:
        """
        Analyze hostname syntax, length, and structure for suspicious patterns.
        Returns (findings, hostname_type) where hostname_type is 'suspicious' if flagged, otherwise None.
        """
        findings: List[Finding] = []
        host = parsed.hostname
        unicode_host = parsed.unicode_hostname

        if not host:
            findings.append(
                Finding(
                    rule_id="EMPTY_HOSTNAME",
                    severity="medium",
                    score=15,
                    title="Empty hostname",
                    message="The hostname component is empty, which can indicate a malformed or intentionally obfuscated URL.",
                    evidence="No hostname specified"
                )
            )
            return findings, "empty"

        # 1. Check for non-ASCII characters (IDN) - punycode is acceptable, but may indicate risk
        if unicode_host and unicode_host != host:
            findings.append(
                Finding(
                    rule_id="PUNYCODE_HOSTNAME",
                    severity="low",
                    score=15,
                    title="Hostname uses IDNs (Internationalized Domain Names)",
                    message=(
                        f"The hostname '{host}' contains IDN characters, shown as Punycode '{host}'. "
                        f"While legitimate for non-Latin scripts, IDNs can be used in phishing to impersonate legitimate domains."
                    ),
                    evidence=f"IDN: {unicode_host} (Punycode: {host})"
                )
            )
            # Do not consider this alone as SUSPICIOUS

        # 2. Structural analysis: Split into labels (separated by dots)
        labels = host.split('.')

        # 3. Check for trailing dot (RFC 1123 allows trailing dot, but suspicious in phishing)
        if parsed.has_trailing_dot:
            findings.append(
                Finding(
                    rule_id="TRAILING_DOT_HOSTNAME",
                    severity="low",
                    score=5,
                    title="Hostname ends with a trailing dot",
                    message="The hostname includes a trailing dot, which is uncommon in legitimate consumer URLs.",
                    evidence=f"Trailing dot: {host}."
                )
            )

        # 4. Check for excessive subdomains (more than 4 levels)
        if len(labels) > 4:
            findings.append(
                Finding(
                    rule_id="EXCESSIVE_SUBDOMAINS",
                    severity="medium",
                    score=20,
                    title=f"Excessive subdomain count: {len(labels)} levels",
                    message=(
                        f"The hostname '{host}' has {len(labels)} label levels, exceeding the typical 4-level threshold. "
                        f"While legitimate for some services, this is often used to hide malicious domains or bypass domain reputation filters."
                    ),
                    evidence=f"Labels: {'.'.join(labels)}"
                )
            )

        # 5. Label length violations
        long_labels = [label for label in labels if len(label) > cls.MAX_LABEL_LENGTH]
        if long_labels:
            findings.append(
                Finding(
                    rule_id="LONG_LABEL_HOSTNAME",
                    severity="high",
                    score=40,
                    title=f"Hostname labels exceed {cls.MAX_LABEL_LENGTH} characters",
                    message=(
                        f"The hostname '{host}' contains labels longer than {cls.MAX_LABEL_LENGTH} characters. "
                        f"While technically allowed, such overly long labels are unusual and often used in obfuscation."
                    ),
                    evidence=f"Long labels: {long_labels}"
                )
            )

        # 6. Total length violations
        if len(host) > cls.MAX_TOTAL_LENGTH:
            findings.append(
                Finding(
                    rule_id="LONG_HOSTNAME",
                    severity="high",
                    score=40,
                    title=f"Hostname exceeds {cls.MAX_TOTAL_LENGTH} characters",
                    message=(
                        f"The hostname '{host}' is longer than {cls.MAX_TOTAL_LENGTH} characters, exceeding DNS limits. "
                        f"This is often used to bypass security filters."
                    ),
                    evidence=f"Length: {len(host)}"
                )
            )

        # 7. Suspicious characters and patterns in labels
        for i, label in enumerate(labels):
            # 7a. Check for suspicious characters in label
            if any(char in label for char in cls.SUSPICIOUS_CHARS):
                findings.append(
                    Finding(
                        rule_id="SUSPICIOUS_CHARS_HOSTNAME",
                        severity="medium",
                        score=30,
                        title=f"Suspicious characters in label '{label}'",
                        message=(
                            f"The hostname label '{label}' contains characters ({''.join(cls.SUSPICIOUS_CHARS)}) "
                            f"that are disallowed by RFC hostname specifications but can be used for obfuscation."
                        ),
                        evidence=f"Label '{label}' contains unsupported character"
                    )
                )

            # 7b. Hyphen proximity: Check for patterns like 'a-b-c-d-e' where many hyphens
            hyphens_in_label = label.count('-')
            if hyphens_in_label >= cls.DOMAIN_HYPHEN_PROXIMITY_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="HYPHEN_PROXIMITY_HOSTNAME",
                        severity="medium",
                        score=20,
                        title=f"Excessive hyphens in label '{label}' ({hyphens_in_label} hyphens)",
                        message=(
                            f"The hostname label '{label}' contains {hyphens_in_label} hyphens, which is unusually high for a legitimate domain label. "
                            f"This pattern is common in phishing domains attempting to mimic legitimate services."
                        ),
                        evidence=f"Label '{label}' has {hyphens_in_label} hyphens"
                    )
                )

            # 7c. Numeric-heavy labels
            numeric_chars = sum(c.isdigit() for c in label)
            if numeric_chars >= 6:
                findings.append(
                    Finding(
                        rule_id="NUMERIC_HEAVY_HOSTNAME",
                        severity="high",
                        score=35,
                        title=f"Numeric-heavy label: '{label}'",
                        message=(
                            f"The hostname label '{label}' contains {numeric_chars} digits, which is unusual for legitimate domains. "
                            f"Such numeric-heavy labels are frequently used to impersonate or obfuscate domain names."
                        ),
                        evidence=f"Label '{label}' contains {numeric_chars} digits"
                    )
                )

        # 8. Check for suspicious label patterns in entire hostname
        for pattern in cls.HIGH_RISK_PATTERNS:
            if re.search(pattern, host):
                findings.append(
                    Finding(
                        rule_id="SUSPICIOUS_PATTERN_HOSTNAME",
                        severity="medium",
                        score=25,
                        title=f"Suspicious pattern in hostname",
                        message=(
                            f"The hostname '{host}' contains the suspicious pattern '{pattern}'. "
                            f"Such patterns can be used to obfuscate or deceive URL parsing filters."
                        ),
                        evidence=f"Pattern '{pattern}' found in '{host}'"
                    )
                )

        # 9. Check for suspicious domain suffixes
        suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.download',
            '.top', '.work', '.men', '.loan', '.win', '.cricket',
        ]
        for tld in suspicious_tlds:
            if host.endswith(tld):
                findings.append(
                    Finding(
                        rule_id="SUSPICIOUS_TLD_HOSTNAME",
                        severity="medium",
                        score=20,
                        title=f"Suspicious domain suffix: {tld}",
                        message=(
                            f"The hostname '{host}' ends with the suspicious TLD '{tld}'. "
                            f"These domains are frequently used in phishing and malicious campaigns."
                        ),
                        evidence=f"Ends with {tld}"
                    )
                )

        # Determine if hostname should be marked as SUSPICIOUS based on findings
        is_suspicious = False
        for finding in findings:
            if finding.severity == "high" and finding.score >= 35:
                is_suspicious = True
                break

        return findings, "suspicious" if is_suspicious else None

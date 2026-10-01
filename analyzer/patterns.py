"""
CyberSafe - URL Path/Query Pattern Analyzer
Detects suspicious patterns in URL paths and query parameters strictly offline.
"""

from typing import List, Optional, Dict, Any
import re
from .models import Finding
from .parser import ParsedURL


class PathPatternAnalyzer:
    """Analyzes URL paths and query parameters for suspicious patterns."""

    # Credential-related path patterns
    CREDENTIAL_PATHS = [
        r'\/login', r'\/signin', r'\/auth', r'\/authentication',
        r'\/verify', r'\/verification', r'\/account', r'\/dashboard',
        r'\/portal', r'\/webmail', r'\/secure', r'\/sign-in',
        r'\/login\.', r'\/signin\.', r'\/auth\.', r'\/secure\.'
    ]

    # Account verification patterns
    ACCOUNT_VERIFICATION_PATHS = [
        r'\/confirm', r'\/activate', r'\/verify-account', r'\/email-verify',
        r'\/email-confirmation', r'\/account-verify', r'\/user-verify'
    ]

    # Password/reset paths
    PASSWORD_RESET_PATHS = [
        r'\/reset-password', r'\/password-reset', r'\/forgot-password',
        r'\/reset\.', r'\/recover\.', r'\/recover-account'
    ]

    # Payment/billing paths
    PAYMENT_PATHS = [
        r'\/billing', r'\/payment', r'\/checkout', r'\/pay', r'\/wallet',
        r'\/invoice', r'\/subscription', r'\/upgrade', r'\/buy', r'\/purchase'
    ]

    # Suspicious query parameter patterns
    SUSPICIOUS_QUERY_PARAMS = [
        'redirect', 'url', 'uri', 'continue', 'next', 'return', 'return_url',
        'dest', 'destination', 'callback', 'redirect_uri', 'redirect_url',
        'return_to', 'forward', 'r', 'q', 'query', 'ref', 'referrer',
        'goto', 'out', 'out_url', 'outclick', 'redirect_back', 'safe_redirect'
    ]

    # Excessive encoding patterns
    ENCODING_PATTERNS = [
        r'%[0-9a-fA-F]{2}',  # Valid percent encoding
        r'%[0-9a-fA-F]{1}',   # Invalid incomplete percent encoding
        r'%[g-zG-Z]',         # Invalid percent characters
        r'%[0-9a-fA-F]{4,}',  # Multiple percent sequences in a row
        r'\?%25', r'\&%25', r'%2F', r'%2E', r'%2D', r'%5F', r'%7E',  # Common encodings
    ]

    # Deception patterns
    DECEPTION_PATTERNS = [
        r'@[a-zA-Z0-9.-]+\.',  # @ symbol deception (e.g., google.com@example.com)
        r'@[^:]*:',  # @ in userinfo
        r'%[0-9a-fA-F]{3}',  # Triple percent encoding
        r'[a-zA-Z0-9_-]+%2[Ff]',  # Trailing %2f
    ]

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> List[Finding]:
        """Analyze URL path and query parameters for suspicious patterns."""
        findings: List[Finding] = []

        # Check for @ symbol deception
        if parsed.has_userinfo:
            findings.append(
                Finding(
                    rule_id="AT_SYMBOL_DECEPTION",
                    severity="high",
                    score=60,
                    title="Deceptive @ pattern",
                    message=(
                        f"The URL contains user-information before the '@' symbol. "
                        f"Username '{parsed.username}' is not part of the destination hostname. "
                        f"Actual hostname is '{parsed.hostname}'."
                    ),
                    evidence=f"{parsed.username or 'username'}@{parsed.hostname}"
                )
            )

        # Analyze path for credential-related patterns
        if parsed.path:
            for pattern in cls.CREDENTIAL_PATHS:
                if re.search(pattern, parsed.path.lower()):
                    findings.append(
                        Finding(
                            rule_id="CREDENTIAL_PATH",
                            severity="medium",
                            score=15,
                            title=f"Credential-related path: {parsed.path}",
                            message=(
                                f"The URL path '{parsed.path}' contains credential-related terms "
                                f"(login, sign-in, authentication) which are frequently used in phishing URLs."
                            ),
                            evidence=f"Path pattern matched: {pattern}"
                        )
                    )
                    break

            # Check for account verification paths
            for pattern in cls.ACCOUNT_VERIFICATION_PATHS:
                if re.search(pattern, parsed.path.lower()):
                    findings.append(
                        Finding(
                            rule_id="ACCOUNT_VERIFICATION_PATH",
                            severity="medium",
                            score=15,
                            title=f"Account verification path: {parsed.path}",
                            message=(
                                f"The URL path '{parsed.path}' contains account verification terms "
                                f"which are frequently used in credential harvesting campaigns."
                            ),
                            evidence=f"Account verification pattern matched: {pattern}"
                        )
                    )
                    break

            # Check for password reset paths
            for pattern in cls.PASSWORD_RESET_PATHS:
                if re.search(pattern, parsed.path.lower()):
                    findings.append(
                        Finding(
                            rule_id="PASSWORD_RESET_PATH",
                            severity="medium",
                            score=15,
                            title=f"Password reset path: {parsed.path}",
                            message=(
                                f"The URL path '{parsed.path}' contains password reset terms "
                                f"which are frequently used in phishing attacks to capture reset tokens."
                            ),
                            evidence=f"Password reset pattern matched: {pattern}"
                        )
                    )
                    break

            # Check for payment/billing paths
            for pattern in cls.PAYMENT_PATHS:
                if re.search(pattern, parsed.path.lower()):
                    findings.append(
                        Finding(
                            rule_id="PAYMENT_PATH",
                            severity="medium",
                            score=15,
                            title=f"Payment/billing path: {parsed.path}",
                            message=(
                                f"The URL path '{parsed.path}' contains payment/billing terms "
                                f"which are frequently used in phishing campaigns targeting financial information."
                            ),
                            evidence=f"Payment path pattern matched: {pattern}"
                        )
                    )
                    break

        # Analyze query parameters
        if parsed.query:
            query_lower = parsed.query.lower()

            # Check for suspicious query parameters
            for param in cls.SUSPICIOUS_QUERY_PARAMS:
                # Look for param=value patterns
                if re.search(rf"\b{param}[ =]", query_lower) or f"{param}=" in query_lower:
                    findings.append(
                        Finding(
                            rule_id="SUSPICIOUS_QUERY_PARAMETER",
                            severity="low",
                            score=10,
                            title=f"Suspicious query parameter: {param}",
                            message=(
                                f"The URL contains query parameter '{param}' which is frequently used "
                                f"for URL redirection or parameter-based attacks."
                            ),
                            evidence=f"Query parameter '{param}' found in URL"
                        )
                    )
                    break

        # Check for excessive URL encoding
        encoding_count = len(re.findall(r'%[0-9a-fA-F]{2}', parsed.original_url))
        if encoding_count > 5:
            findings.append(
                Finding(
                    rule_id="EXCESSIVE_ENCODING",
                    severity="low",
                    score=10,
                    title="Excessive URL encoding",
                    message=(
                        f"The URL contains {encoding_count} percent-encoded sequences, which is unusually high. "
                        f"Excessive encoding can be used to obfuscate the true destination."
                    ),
                    evidence=f"Found {encoding_count} percent-encoded sequences"
                )
            )

        # Check for invalid percent encoding
        invalid_encodings = re.findall(r'%[0-9a-fA-F]{1}|%[g-zG-Z]', parsed.original_url)
        if invalid_encodings:
            findings.append(
                Finding(
                    rule_id="INVALID_PERCENT_ENCODING",
                    severity="medium",
                    score=10,
                    title="Invalid percent encoding",
                    message=(
                        f"The URL contains {len(invalid_encodings)} invalid percent-encoded sequences. "
                        f"This can indicate obfuscation attempts or malformed URLs."
                    ),
                    evidence=f"Invalid encodings: {', '.join(invalid_encodings[:3])}"
                )
            )

        # Check for unusual ports.
        # The parser only yields a port within 1-65535, so an out-of-range value
        # cannot reach here; a non-None raw_port with no port means the port text
        # was unparseable, which is itself worth surfacing.
        if parsed.raw_port and not parsed.port:
            findings.append(
                Finding(
                    rule_id="INVALID_PORT",
                    severity="medium",
                    score=15,
                    title=f"Unparseable port: {parsed.raw_port}",
                    message=(
                        f"The URL specifies port '{parsed.raw_port}', which is not a valid number in the range 1-65535. "
                        f"Browsers reject or reinterpret such ports, so the real destination is ambiguous."
                    ),
                    evidence=f"Raw port value: {parsed.raw_port}"
                )
            )
        elif parsed.port:
            if parsed.port in [8080, 8443, 9443, 2080, 8000, 8888]:
                findings.append(
                    Finding(
                        rule_id="UNUSUAL_PORT",
                        severity="low",
                        score=5,
                        title=f"Unusual port: {parsed.port}",
                        message=(
                            f"The URL uses port {parsed.port}, which is less common for standard web services. "
                            f"While legitimate use cases exist, this pattern is sometimes used to evade detection."
                        ),
                        evidence=f"Port {parsed.port} is non-standard"
                    )
                )

        # Check for HTTP instead of HTTPS
        if parsed.scheme == "http":
            findings.append(
                Finding(
                    rule_id="HTTP_UNENCRYPTED",
                    severity="low",
                    score=5,
                    title="Unencrypted HTTP scheme",
                    message=(
                        f"The URL uses unencrypted HTTP instead of HTTPS. "
                        f"Communication over this link can be intercepted or altered."
                    ),
                    evidence="HTTP scheme detected"
                )
            )

        # Check for extremely long URLs
        if len(parsed.original_url) > 500:
            findings.append(
                Finding(
                    rule_id="EXTREMELY_LONG_URL",
                    severity="medium",
                    score=10,
                    title="Extremely long URL",
                    message=(
                        f"The URL length of {len(parsed.original_url)} characters exceeds the typical 500-character threshold. "
                        f"Long URLs are frequently used in phishing to hide malicious destinations."
                    ),
                    evidence=f"URL length: {len(parsed.original_url)} characters"
                )
            )

        # Check for repeated separators
        if re.search(r'/[/]+', parsed.path) or re.search(r'\?\?+', parsed.query) or re.search(r'#[#]+', parsed.fragment):
            findings.append(
                Finding(
                    rule_id="REPEATED_SEPARATORS",
                    severity="low",
                    score=5,
                    title="Repeated URL separators",
                    message=(
                        "The URL contains repeated separators (e.g., // or ??) which is unusual "
                        "for legitimate URLs and may indicate obfuscation attempts."
                    ),
                    evidence="Repeated separators found in URL"
                )
            )

        return findings
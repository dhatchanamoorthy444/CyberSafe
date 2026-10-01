"""
CyberSafe - URL Scheme Analyzer
Detects dangerous, unusual, and normal web schemes strictly without execution.
"""

from typing import List, Optional
from .models import Finding
from .parser import ParsedURL


class SchemeDetector:
    """Evaluates the risk profile of the URL scheme."""

    NORMAL_WEB_SCHEMES = {"http", "https"}

    # Schemes that can execute code, load local files, or inject data directly
    DANGEROUS_SCHEMES = {
        "javascript": ("JavaScript Execution Scheme", "Executes inline script code in the browser context rather than navigating to a remote web server."),
        "data": ("Data URI Scheme", "Embeds inline raw payloads or HTML directly inside the URL, often used to bypass web content filters."),
        "file": ("Local File Access Scheme", "Attempts to access files on the local device filesystem rather than a web host."),
        "vbscript": ("VBScript Execution Scheme", "Executes Windows VBScript payloads in legacy browser engines."),
        "blob": ("Blob URI Scheme", "References an in-memory binary object which may deliver dynamic uninspected payloads."),
        "about": ("Browser Internal Scheme", "Navigates to browser internal pages or about:blank."),
        "filesystem": ("Local Filesystem Scheme", "References sandboxed local filesystem objects."),
        "jar": ("Java Archive Scheme", "Directly targets Java archive internal files."),
    }

    # Protocol handlers that are not standard HTTP/HTTPS web links
    UNUSUAL_SCHEMES = {
        "ftp": "File Transfer Protocol (FTP) link.",
        "sftp": "Secure File Transfer Protocol link.",
        "ssh": "Secure Shell link.",
        "telnet": "Telnet protocol connection link.",
        "ldap": "Lightweight Directory Access Protocol link.",
        "gopher": "Legacy Gopher protocol link.",
        "ws": "Unencrypted WebSocket connection link.",
        "wss": "Encrypted WebSocket connection link.",
        "mailto": "Email composition link.",
        "tel": "Telephony dialing link.",
        "sms": "SMS messaging link.",
        "market": "Application store deep link.",
        "intent": "Android intent deep link.",
        "android-app": "Android application deep link.",
        "ios-app": "iOS application deep link.",
    }

    @classmethod
    def analyze(cls, parsed: ParsedURL) -> List[Finding]:
        """Analyze scheme of the parsed URL and return any security findings."""
        findings: List[Finding] = []
        scheme = parsed.scheme.lower() if parsed.scheme else ""

        if not scheme:
            findings.append(
                Finding(
                    rule_id="MISSING_SCHEME",
                    severity="low",
                    score=5,
                    title="Missing URL scheme",
                    message="No explicit protocol scheme (e.g. https://) was provided. Browsers may default to unencrypted HTTP or search query resolution.",
                    evidence="No scheme in URL"
                )
            )
            return findings

        # Check dangerous schemes
        if scheme in cls.DANGEROUS_SCHEMES:
            title, desc = cls.DANGEROUS_SCHEMES[scheme]
            findings.append(
                Finding(
                    rule_id="DANGEROUS_SCHEME",
                    severity="high",
                    score=70,
                    title=f"Dangerous URL scheme: {scheme}",
                    message=f"The URL uses a non-web scheme that can execute or reference local content. {desc}",
                    evidence=f"{scheme}:"
                )
            )
            return findings

        # Check unusual non-web protocol schemes
        if scheme in cls.UNUSUAL_SCHEMES:
            desc = cls.UNUSUAL_SCHEMES[scheme]
            findings.append(
                Finding(
                    rule_id="UNUSUAL_SCHEME",
                    severity="medium",
                    score=25,
                    title=f"Unusual URL scheme: {scheme}",
                    message=f"The URL uses a specialized protocol ({scheme}) instead of standard web HTTPS. {desc}",
                    evidence=f"{scheme}://"
                )
            )
            return findings

        # Check unknown / custom schemes
        if scheme not in cls.NORMAL_WEB_SCHEMES:
            findings.append(
                Finding(
                    rule_id="CUSTOM_SCHEME",
                    severity="medium",
                    score=25,
                    title=f"Custom or unrecognized URL scheme: {scheme}",
                    message=f"The URL uses an unrecognized application or custom scheme '{scheme}'. Verify the destination application before launching.",
                    evidence=f"{scheme}://"
                )
            )
            return findings

        # Normal web schemes: flag plain HTTP
        if scheme == "http":
            findings.append(
                Finding(
                    rule_id="HTTP_UNENCRYPTED",
                    severity="low",
                    score=5,
                    title="Unencrypted HTTP connection",
                    message="The URL uses unencrypted HTTP instead of HTTPS. Communication over this link can be intercepted or altered on the local network.",
                    evidence="http://"
                )
            )

        return findings

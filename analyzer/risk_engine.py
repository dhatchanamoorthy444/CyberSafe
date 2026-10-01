"""
CyberSafe - Risk Engine
Aggregates findings into explainable risk assessments with configurable scoring.
"""

from typing import Dict, Any, List, Optional, Tuple
from .parser import SafeURLParser, ParsedURL
from .schemes import SchemeDetector
from .hostname import HostnameAnalyzer
from .ip_detection import IPDetector
from .lookalike import LookalikeDetector
from .shortening import URLShorteningDetector
from .patterns import PathPatternAnalyzer
from .models import Finding, AnalysisResult


class RiskEngine:
    """
    Central risk assessment engine for CyberSafe.
    Aggregates findings with configurable weights and produces transparent verdicts.
    """

    # Configurable scoring weights
    WEIGHTS = {
        "DANGEROUS_SCHEME": 70,
        "AT_SYMBOL_DECEPTION": 60,
        "LOOKALIKE_HOSTNAME": 50,
        "IP_ADDRESS_HOST": 25,
        "SHORTENED_URL": 20,
        "CREDENTIAL_PATH": 15,
        "EXCESSIVE_ENCODING": 10,
        "UNUSUAL_PORT": 10,
        "HTTP_SCHEME": 5,
        "LONG_URL": 5,
        "PUNYCODE_HOSTNAME": 15,
        "OBFUSCATED_IP_HOST": 55,
    }

    # Verdict thresholds
    SAFE_MAX = 19
    REVIEW_MAX = 49

    @classmethod
    def analyze(cls, url_string: str) -> AnalysisResult:
        """
        Perform complete offline security analysis on a URL.
        Never makes network requests.
        """
        # 1. Parse URL safely (offline only)
        parsed = SafeURLParser.parse(url_string)

        findings: List[Finding] = []
        scores: List[int] = []

        # Gather findings from all modules
        # Scheme analysis
        scheme_findings = SchemeDetector.analyze(parsed)
        findings.extend(scheme_findings)

        # Hostname structure
        hostname_findings, hostname_risk = HostnameAnalyzer.analyze(parsed)
        findings.extend(hostname_findings)

        # IP Detection
        ip_findings, ip_type = IPDetector.analyze(parsed)
        findings.extend(ip_findings)

        # Lookalike / Brand Impersonation
        lookalike_findings, lookalike_risk = LookalikeDetector.analyze(parsed)
        findings.extend(lookalike_findings)

        # URL Shortening
        shortening_findings = URLShorteningDetector.analyze(parsed)
        findings.extend(shortening_findings)

        # Pattern Analysis (paths, queries, deception)
        pattern_findings = PathPatternAnalyzer.analyze(parsed)
        findings.extend(pattern_findings)

        # Compute score from findings
        total_score = sum(f.score for f in findings)

        # Cap score at 100
        total_score = min(total_score, 100)

        # Determine verdict with rules
        verdict = cls._compute_verdict(findings, total_score)

        # Compute confidence based on score spread and high-severity findings
        confidence = cls._compute_confidence(findings, total_score, verdict)

        # Recommendation text
        recommendation = cls._recommendation(verdict, findings)

        # Determine actual hostname
        actual_hostname = parsed.hostname
        if parsed.has_userinfo and parsed.hostname:
            # If there's a deceptive @, the actual hostname is clearly stated
            pass

        # Build parsed output for API
        parsed_output = parsed.to_dict()

        return AnalysisResult(
            verdict=verdict,
            score=total_score,
            confidence=confidence,
            input_url=url_string,
            parsed=parsed_output,
            actual_hostname=actual_hostname,
            findings=findings,
            recommendation=recommendation
        )

    @classmethod
    def _compute_verdict(cls, findings: List[Finding], total_score: int) -> str:
        """Compute final verdict considering score and high-confidence rules."""
        # Force SUSPICIOUS if dangerous scheme found
        for f in findings:
            if f.rule_id == "DANGEROUS_SCHEME" and f.severity == "high":
                return "SUSPICIOUS"

        # Force SUSPICIOUS if deceptive @ symbol detected
        for f in findings:
            if f.rule_id == "AT_SYMBOL_DECEPTION" and f.severity == "high":
                return "SUSPICIOUS"

        # Force SUSPICIOUS if lookalike + credential path combination exists
        has_lookalike = any(f.rule_id == "LOOKALIKE_HOSTNAME" and f.score >= 40 for f in findings)
        has_cred_path = any(f.rule_id == "CREDENTIAL_PATH" for f in findings)
        if has_lookalike and has_cred_path:
            return "SUSPICIOUS"

        if total_score >= 50:
            return "SUSPICIOUS"
        elif total_score >= 20:
            return "REVIEW"
        else:
            return "SAFE"

    @classmethod
    def _compute_confidence(cls, findings: List[Finding], total_score: int, verdict: str) -> str:
        """Compute confidence level based on findings consistency."""
        high_severity = sum(1 for f in findings if f.severity in ("high", "critical"))

        if verdict == "SAFE":
            return "high" if total_score < 5 else "medium"

        if verdict == "SUSPICIOUS":
            if high_severity >= 2:
                return "high"
            elif high_severity == 1 or total_score >= 60:
                return "high"
            else:
                return "medium"

        # REVIEW
        if high_severity >= 1:
            return "medium"
        return "low" if total_score < 30 else "medium"

    @classmethod
    def _recommendation(cls, verdict: str, findings: List[Finding]) -> str:
        if verdict == "SAFE":
            return "This URL appears safe for opening based on offline structural analysis."
        elif verdict == "REVIEW":
            return "Exercise caution. Some indicators suggest this URL should be independently verified before opening."
        else:
            return "Do not open this URL until the destination is independently verified. Multiple high-risk indicators detected."

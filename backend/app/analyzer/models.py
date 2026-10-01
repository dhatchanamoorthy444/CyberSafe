"""
CyberSafe - Data Models
Defines structured dataclasses for findings, scores, and risk analysis results.
"""

from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, List


@dataclass
class Finding:
    """Represents an individual explainable security finding."""
    rule_id: str
    severity: str  # "info", "low", "medium", "high", "critical"
    score: int     # 0 to 100 contribution
    title: str
    message: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Final aggregated explainable risk assessment response."""
    verdict: str  # "SAFE", "REVIEW", "SUSPICIOUS"
    score: int    # 0 to 100
    confidence: str  # "low", "medium", "high"
    input_url: str
    parsed: Dict[str, Any]
    actual_hostname: Optional[str]
    findings: List[Finding] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        return data

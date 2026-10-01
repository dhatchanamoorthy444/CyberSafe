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
    category: str = "general"  # "identity", "destination", "structure", "protocol", "context"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceLink:
    """A single step in the evidence chain."""
    step: int
    description: str
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceChain:
    """Logical chain of evidence leading to findings."""
    finding_rule_id: str
    links: List[EvidenceLink]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityXRay:
    """Structured parsed URL components for Security X-Ray display."""
    scheme: str
    user_information: Optional[str]
    actual_hostname: Optional[str]
    port: Optional[str]
    path: str
    query: str
    fragment: str
    has_trailing_dot: bool = False
    is_punycode: bool = False
    unicode_hostname: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeceptionMapItem:
    """Single item in the Deception Map."""
    category: str  # "identity", "destination", "structure", "protocol", "context"
    status: str    # "warning", "caution", "safe", "unknown"
    icon: str
    label: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GroqExplanation:
    """AI-generated explanation of the analysis."""
    summary: str
    technical_details: str
    recommendation: str

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
    security_xray: Optional[SecurityXRay] = None
    deception_map: List[DeceptionMapItem] = field(default_factory=list)
    evidence_chains: List[EvidenceChain] = field(default_factory=list)
    groq_explanation: Optional[GroqExplanation] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() if isinstance(f, Finding) else f for f in self.findings]
        data["security_xray"] = self.security_xray.to_dict() if self.security_xray else None
        data["deception_map"] = [d.to_dict() for d in self.deception_map]
        data["evidence_chains"] = [e.to_dict() for e in self.evidence_chains]
        data["groq_explanation"] = self.groq_explanation.to_dict() if self.groq_explanation else None
        return data

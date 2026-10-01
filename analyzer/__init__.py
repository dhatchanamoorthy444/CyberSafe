"""
CyberSafe - Explainable URL & QR Risk Screening Engine
Package initialization and unified analyzer API.
"""

from typing import Dict, Any, List
from .parser import SafeURLParser, ParsedURL
from .risk_engine import RiskEngine, AnalysisResult

__version__ = "1.0.0"
__all__ = ["SafeURLParser", "ParsedURL", "RiskEngine", "AnalysisResult", "analyze_url"]


def analyze_url(url_string: str) -> Dict[str, Any]:
    """
    Main entry point to perform complete offline risk screening on a URL string.

    Security Guarantee:
    - NEVER performs network requests, DNS lookups, or URL fetching.
    - Operates purely on lexical and structural analysis.
    """
    engine = RiskEngine()
    result = engine.analyze(url_string)
    return result.to_dict()

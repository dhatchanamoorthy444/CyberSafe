#!/usr/bin/env python3
"""
Comprehensive detailed test runner for CyberSafe analyzer.
Tests all cases from the specification and shows detailed results.
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from analyzer import analyze_url


def safe_print(text):
    """Print text safely handling Unicode."""
    if isinstance(text, str):
        text = text.encode('ascii', 'replace').decode('ascii')
    print(text)


def run_test(name, url, expected_verdict=None, expected_rules=None):
    """Run a single test and return detailed results."""
    safe_print(f"\n{'='*70}")
    safe_print(f"TEST: {name}")
    safe_print(f"URL:  {url}")
    safe_print(f"{'='*70}")
    
    try:
        result = analyze_url(url)
    except Exception as e:
        safe_print(f"ERROR: {e}")
        return {"name": name, "url": url, "error": str(e)}
    
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("score", 0)
    confidence = result.get("confidence", "unknown")
    actual_hostname = result.get("actual_hostname", "N/A")
    findings = result.get("findings", [])
    parsed = result.get("parsed", {})
    recommendation = result.get("recommendation", "")
    
    safe_print(f"VERDICT:       {verdict}")
    safe_print(f"RISK SCORE:    {score} / 100")
    safe_print(f"CONFIDENCE:    {confidence.upper()}")
    safe_print(f"ACTUAL HOST:   {actual_hostname}")
    safe_print(f"RECOMMENDATION: {recommendation}")
    
    safe_print(f"\nURL ANATOMY:")
    safe_print(f"  Scheme:        {parsed.get('scheme', 'N/A')}")
    safe_print(f"  Hostname:      {parsed.get('hostname', 'N/A')}")
    safe_print(f"  Username:      {parsed.get('username', 'N/A')}")
    safe_print(f"  Password:      {'***' if parsed.get('password') else 'N/A'}")
    safe_print(f"  Port:          {parsed.get('port', 'default')}")
    safe_print(f"  Path:          {parsed.get('path', '/')}")
    safe_print(f"  Query:         {parsed.get('query', 'N/A')}")
    safe_print(f"  Fragment:      {parsed.get('fragment', 'N/A')}")
    safe_print(f"  Has UserInfo:  {parsed.get('has_userinfo', False)}")
    safe_print(f"  Is Punycode:   {parsed.get('is_punycode', False)}")
    unicode_host = parsed.get('unicode_hostname', 'N/A')
    safe_print(f"  Unicode Host:  {unicode_host}")
    safe_print(f"  Valid:         {parsed.get('valid', False)}")
    
    safe_print(f"\nDETECTED RULES ({len(findings)}):")
    if not findings:
        safe_print("  (none)")
    else:
        for i, f in enumerate(findings, 1):
            safe_print(f"  {i}. {f.get('rule_id', 'UNKNOWN')}")
            safe_print(f"     Severity: {f.get('severity', 'unknown').upper()}")
            safe_print(f"     Score:    {f.get('score', 0)}")
            safe_print(f"     Title:    {f.get('title', 'N/A')}")
            safe_print(f"     Message:  {f.get('message', 'N/A')}")
            evidence = f.get('evidence', 'N/A')
            if isinstance(evidence, str):
                evidence = evidence.encode('ascii', 'replace').decode('ascii')
            safe_print(f"     Evidence: {evidence}")
            safe_print(f"     Category: {f.get('category', 'general')}")
    
    # Security X-Ray if available
    if result.get("security_xray"):
        xray = result["security_xray"]
        safe_print(f"\nSECURITY X-RAY:")
        for k, v in xray.items():
            safe_print(f"  {k}: {v}")
    
    # Deception Map if available
    if result.get("deception_map"):
        safe_print(f"\nDECEPTION MAP:")
        for d in result["deception_map"]:
            safe_print(f"  [{d['category'].upper()}] {d['status'].upper()} - {d['label']}: {d['detail']}")
    
    # Evidence Chains if available
    if result.get("evidence_chains"):
        safe_print(f"\nEVIDENCE CHAINS:")
        for ec in result["evidence_chains"]:
            safe_print(f"  Rule: {ec['finding_rule_id']}")
            for link in ec["links"]:
                safe_print(f"    Step {link['step']}: {link['description']}")
                safe_print(f"      {link['details']}")
    
    # Groq Explanation if available
    if result.get("groq_explanation"):
        ge = result["groq_explanation"]
        safe_print(f"\nAI EXPLANATION:")
        safe_print(f"  Summary: {ge.get('summary', 'N/A')}")
        safe_print(f"  Technical: {ge.get('technical_details', 'N/A')}")
        safe_print(f"  Recommendation: {ge.get('recommendation', 'N/A')}")
    
    # Validation
    status = "PASS"
    if expected_verdict and verdict != expected_verdict:
        status = f"FAIL (expected {expected_verdict}, got {verdict})"
    
    safe_print(f"\nSTATUS: {status}")
    
    return {
        "name": name,
        "url": url,
        "verdict": verdict,
        "score": score,
        "confidence": confidence,
        "actual_hostname": actual_hostname,
        "findings_count": len(findings),
        "findings": findings,
        "parsed": parsed,
        "recommendation": recommendation,
        "status": status,
        "expected_verdict": expected_verdict
    }


def main():
    safe_print("="*70)
    safe_print("CYBERSAFE ANALYZER - COMPREHENSIVE DETAILED TEST SUITE")
    safe_print("="*70)
    
    test_cases = [
        # SAFE cases
        ("SAFE - Example.com", "https://example.com", "SAFE"),
        ("SAFE - GitHub", "https://github.com", "SAFE"),
        ("SAFE - Google", "https://www.google.com", "SAFE"),
        ("SAFE - Example with login path", "https://example.com/login", "SAFE"),
        
        # REVIEW cases
        ("REVIEW - HTTP IP Address", "http://192.168.1.10/login", "REVIEW"),
        ("REVIEW - Bit.ly Shortener", "https://bit.ly/example", "REVIEW"),
        ("REVIEW - Unusual Port", "https://example.com:8443/login", "REVIEW"),
        ("REVIEW - HTTP Scheme", "http://example.com", "REVIEW"),
        
        # SUSPICIOUS cases
        ("SUSPICIOUS - Deceptive @ Pattern", "https://google.com@evil.example/login", "SUSPICIOUS"),
        ("SUSPICIOUS - JavaScript Scheme", "javascript:alert(1)", "SUSPICIOUS"),
        ("SUSPICIOUS - Lookalike Domain", "https://paypa1.example/login", "SUSPICIOUS"),
        ("SUSPICIOUS - Data URI", "data:text/html,test", "SUSPICIOUS"),
        
        # Additional edge cases
        ("EDGE - Empty String", "", "SAFE"),  # Should be invalid
        ("EDGE - Malformed", "not_a_url_at_all", "SAFE"),  # Should be invalid
        ("EDGE - Multiple @ Symbols", "https://a@b@c.example/login", "SUSPICIOUS"),
        ("EDGE - Punycode", "https://xn--pple-43d.com", "REVIEW"),
        ("EDGE - IPv6", "https://[2001:db8::1]/login", "REVIEW"),
        ("EDGE - Long URL", "https://example.com/" + "a"*500, "REVIEW"),
        ("EDGE - Encoded URL", "https://example.com/%61%64%6d%69%6e", "REVIEW"),
        ("EDGE - File Scheme", "file:///etc/passwd", "SUSPICIOUS"),
        ("EDGE - Nested URL", "https://example.com?url=https://evil.com", "REVIEW"),
        ("EDGE - Suspicious Query", "https://example.com?redirect=https://evil.com", "REVIEW"),
        ("EDGE - Private IP", "http://10.0.0.1/admin", "REVIEW"),
        ("EDGE - Loopback IP", "http://127.0.0.1:8080", "REVIEW"),
    ]
    
    results = []
    for name, url, expected in test_cases:
        result = run_test(name, url, expected)
        results.append(result)
    
    # Summary
    safe_print("\n" + "="*70)
    safe_print("SUMMARY")
    safe_print("="*70)
    
    passed = sum(1 for r in results if r.get("status") == "PASS")
    failed = sum(1 for r in results if r.get("status", "").startswith("FAIL"))
    errors = sum(1 for r in results if "error" in r)
    
    safe_print(f"Total:  {len(results)}")
    safe_print(f"Passed: {passed}")
    safe_print(f"Failed: {failed}")
    safe_print(f"Errors: {errors}")
    
    safe_print("\nDETAILED RESULTS:")
    safe_print("-"*70)
    for r in results:
        if "error" in r:
            safe_print(f"  ERROR  | {r['name']}: {r['error']}")
        elif r["status"] == "PASS":
            safe_print(f"  PASS   | {r['name']}: {r['verdict']} (score={r['score']})")
        else:
            safe_print(f"  FAIL   | {r['name']}: {r['status']}")
    
    # Save detailed JSON results
    with open("test_results_detailed.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    safe_print(f"\nDetailed results saved to test_results_detailed.json")
    
    return results


if __name__ == "__main__":
    main()
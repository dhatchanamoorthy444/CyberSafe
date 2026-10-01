"""
CyberSafe - Unit Tests
Comprehensive test suite for the security analysis engine.
"""

import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer import analyze_url


class TestCyberSafeEngine(unittest.TestCase):
    """Test the CyberSafe URL Risk Screening Engine."""

    def test_safe_google(self):
        """SAFE case: https://www.google.com"""
        result = analyze_url("https://www.google.com")
        self.assertEqual(result["verdict"], "SAFE")
        self.assertEqual(result["parsed"]["hostname"], "www.google.com")
        self.assertTrue(result["parsed"]["valid"])

    def test_safe_github(self):
        """SAFE case: https://github.com"""
        result = analyze_url("https://github.com")
        self.assertEqual(result["verdict"], "SAFE")
        self.assertIn("github", result["actual_hostname"] or "")

    def test_safe_example_login_path(self):
        """SAFE case: https://example.com/login (login alone is not malicious)"""
        result = analyze_url("https://example.com/login")
        # Should be SAFE or REVIEW, not SUSPICIOUS
        self.assertNotEqual(result["verdict"], "SUSPICIOUS")
        self.assertTrue(result["parsed"]["valid"])

    def test_review_http_ip_address(self):
        """REVIEW case: http://192.168.1.10/login"""
        result = analyze_url("http://192.168.1.10/login")
        self.assertEqual(result["parsed"]["hostname"], "192.168.1.10")
        self.assertEqual(result["verdict"], "REVIEW")
        # Should have IP address finding
        has_ip_finding = any(f.get("rule_id") == "IP_ADDRESS_HOST" for f in result.get("findings", []))
        self.assertTrue(has_ip_finding, "Should detect IP_ADDRESS_HOST finding")

    def test_review_bitly_url_shortener(self):
        """REVIEW case: https://bit.ly/example"""
        result = analyze_url("https://bit.ly/example")
        self.assertEqual(result["verdict"], "REVIEW")
        # Should detect URL shortener
        has_shortener_finding = any(
            "SHORTENER" in (f.get("rule_id") or "") for f in result.get("findings", [])
        )
        self.assertTrue(has_shortener_finding, "Should detect URL shortener")

    def test_review_unusual_port(self):
        """REVIEW case: https://example.com:8443/login"""
        result = analyze_url("https://example.com:8443/login")
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertEqual(result["parsed"]["port"], 8443)

    def test_suspicious_deceptive_at_pattern(self):
        """SUSPICIOUS case: https://google.com@evil.example/login"""
        result = analyze_url("https://google.com@evil.example/login")
        # Critical test: hostname must be evil.example
        self.assertEqual(
            result["actual_hostname"], "evil.example",
            f"Hostname should be evil.example, got: {result.get('actual_hostname')}"
        )
        # Must have AT_SYMBOL_DECEPTION finding
        at_findings = [
            f for f in result.get("findings", [])
            if f.get("rule_id") == "AT_SYMBOL_DECEPTION"
        ]
        self.assertTrue(at_findings, "Should have AT_SYMBOL_DECEPTION finding")
        # Verdict should be SUSPICIOUS
        self.assertEqual(result["verdict"], "SUSPICIOUS", f"Expected SUSPICIOUS, got: {result['verdict']}")

    def test_suspicious_javascript_scheme(self):
        """SUSPICIOUS case: javascript:alert(1)"""
        result = analyze_url("javascript:alert(1)")
        # Should detect dangerous scheme
        self.assertIn(result.get("verdict"), ["SUSPICIOUS", "REVIEW"])
        has_dangerous = any(
            f.get("rule_id") == "DANGEROUS_SCHEME" for f in result.get("findings", [])
        )
        self.assertTrue(has_dangerous, "Should detect DANGEROUS_SCHEME")

    def test_suspicious_lookalike_domain(self):
        """SUSPICIOUS case: https://paypa1.example/login"""
        result = analyze_url("https://paypa1.example/login")
        self.assertIn(result.get("verdict"), ["SUSPICIOUS", "REVIEW"])
        has_lookalike = any(
            f.get("rule_id") == "LOOKALIKE_HOSTNAME" for f in result.get("findings", [])
        )
        self.assertTrue(has_lookalike, "Should detect LOOKALIKE_HOSTNAME finding")

    def test_malformed_url_empty_string(self):
        """Malformed URL: empty string"""
        result = analyze_url("")
        self.assertFalse(result.get("parsed", {}).get("valid"), "Should be invalid for empty URL")

    def test_malformed_url_invalid_scheme(self):
        """Malformed URL with strange input"""
        result = analyze_url("not_a_url_at_all")
        # Should handle gracefully without errors
        self.assertIn("parsed", result)

    def test_critical_at_behavior_hostname_is_evil_example(self):
        """Critical test: hostname extraction for deceptive @"""
        result = analyze_url("https://google.com@evil.example/login")
        self.assertEqual(
            result["actual_hostname"], "evil.example",
            "Actual hostname must be evil.example, not google.com"
        )
        # Verify parsed username is google.com
        parsed = result.get("parsed", {})
        self.assertEqual(parsed.get("username"), "google.com", "Username should be google.com")
        # Verify parsed hostname is evil.example
        self.assertEqual(parsed.get("hostname"), "evil.example", "Hostname should be evil.example")

    def test_deceptive_evidence_string(self):
        """Test evidence string for deceptive @ pattern"""
        result = analyze_url("https://google.com@evil.example/login")
        at_findings = [
            f for f in result.get("findings", [])
            if f.get("rule_id") == "AT_SYMBOL_DECEPTION"
        ]
        # Should contain evidence referencing the user info
        if at_findings:
            evidence = at_findings[0].get("evidence", "")
            self.assertIn("google.com", evidence, "Evidence should reference google.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)

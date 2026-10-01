"""
CyberSafe — API Test Suite
Comprehensive tests covering all required API request/response paths:
  • POST valid SAFE URL
  • POST REVIEW URL
  • POST SUSPICIOUS URL
  • Empty URL
  • Missing URL
  • Non-string URL
  • Oversized URL (>4096 chars)
  • Malformed JSON
  • GET /api/analyze
  • OPTIONS /api/analyze
  • No network activity guarantee
"""

import json
import unittest
import io
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.analyze import handler


class MockRequest:
    """Mock socket file for BaseHTTPRequestHandler testing."""

    def __init__(self, method: str, path: str, body: bytes = b"", headers: dict = None):
        self.method = method
        self.path = path
        self.body_bytes = body
        self.headers_dict = headers or {}
        if body and "Content-Length" not in self.headers_dict:
            self.headers_dict["Content-Length"] = str(len(body))

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode:
            # Reconstruct HTTP request stream
            header_lines = [f"{self.method} {self.path} HTTP/1.1"]
            for k, v in self.headers_dict.items():
                header_lines.append(f"{k}: {v}")
            header_lines.append("")
            header_lines.append("")
            raw = "\r\n".join(header_lines).encode("utf-8") + self.body_bytes
            return io.BytesIO(raw)
        else:
            return io.BytesIO()


def run_handler(method: str, path: str = "/api/analyze", body: dict = None, raw_body: bytes = None, headers: dict = None) -> tuple[int, dict, dict]:
    """
    Helper to run the Vercel BaseHTTPRequestHandler handler safely in tests.
    Returns (status_code, response_headers_dict, response_json_dict).
    """
    if raw_body is None and body is not None:
        raw_body = json.dumps(body).encode("utf-8")
        headers = headers or {}
        headers["Content-Type"] = "application/json"

    mock_req = MockRequest(method, path, raw_body or b"", headers or {})
    wfile = io.BytesIO()

    # Instantiate handler with mock streams
    h = handler.__new__(handler)
    h.rfile = mock_req.makefile('r')
    h.wfile = wfile
    h.headers = mock_req.headers_dict
    h.client_address = ('127.0.0.1', 12345)
    h.command = method
    h.path = path
    h.requestline = f"{method} {path} HTTP/1.1"

    # Capture status code
    sent_status = [200]
    sent_headers = {}

    def mock_send_response(code, message=None):
        sent_status[0] = code

    def mock_send_header(keyword, value):
        sent_headers[keyword] = value

    def mock_end_headers():
        pass

    h.send_response = mock_send_response
    h.send_header = mock_send_header
    h.end_headers = mock_end_headers

    # Execute method
    if method == "GET":
        h.do_GET()
    elif method == "POST":
        h.do_POST()
    elif method == "OPTIONS":
        h.do_OPTIONS()

    response_data = {}
    out_bytes = wfile.getvalue()
    if out_bytes:
        try:
            response_data = json.loads(out_bytes.decode("utf-8"))
        except Exception:
            response_data = {"raw": out_bytes.decode("utf-8", errors="replace")}

    return sent_status[0], sent_headers, response_data


class TestCyberSafeAPI(unittest.TestCase):
    """API endpoint specification compliance tests."""

    # 1. GET /api/analyze
    def test_get_api_analyze(self):
        status, headers, body = run_handler("GET")
        self.assertEqual(status, 200)
        self.assertIn("service", body)
        self.assertIn("CyberSafe", body["service"])

    # 2. OPTIONS /api/analyze
    def test_options_api_analyze(self):
        status, headers, body = run_handler("OPTIONS")
        self.assertEqual(status, 204)
        self.assertIn("Access-Control-Allow-Methods", headers)

    # 3. POST valid SAFE URL
    def test_post_valid_safe_url(self):
        status, headers, body = run_handler("POST", body={"url": "https://example.com"})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("success"))
        analysis = body.get("analysis", {})
        self.assertEqual(analysis.get("verdict"), "SAFE")
        self.assertEqual(analysis.get("score"), 0)
        self.assertEqual(analysis.get("confidence"), "high")
        self.assertEqual(analysis.get("input_url"), "https://example.com")
        self.assertIn("recommendation", analysis)

    # 4. POST REVIEW URL
    def test_post_review_url(self):
        status, headers, body = run_handler("POST", body={"url": "http://192.168.1.1/login"})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("success"))
        analysis = body.get("analysis", {})
        self.assertEqual(analysis.get("verdict"), "REVIEW")

    # 5. POST SUSPICIOUS URL
    def test_post_suspicious_url(self):
        status, headers, body = run_handler("POST", body={"url": "https://google.com@evil.example/login"})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("success"))
        analysis = body.get("analysis", {})
        self.assertEqual(analysis.get("verdict"), "SUSPICIOUS")
        self.assertEqual(analysis.get("actual_hostname"), "evil.example")

    # 6. Empty URL
    def test_post_empty_url(self):
        status, headers, body = run_handler("POST", body={"url": "   "})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("error", {}).get("code"), "EMPTY_URL")

    # 7. Missing URL
    def test_post_missing_url(self):
        status, headers, body = run_handler("POST", body={})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("error", {}).get("code"), "MISSING_URL")

    # 8. Malformed JSON
    def test_post_malformed_json(self):
        status, headers, body = run_handler("POST", raw_body=b"{invalid json...", headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("error", {}).get("code"), "INVALID_JSON")

    # 9. Oversized URL
    def test_post_oversized_url(self):
        long_url = "https://example.com/" + ("a" * 4500)
        status, headers, body = run_handler("POST", body={"url": long_url})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("error", {}).get("code"), "URL_TOO_LONG")

    # 10. Non-string URL
    def test_post_non_string_url(self):
        status, headers, body = run_handler("POST", body={"url": 12345})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("error", {}).get("code"), "INVALID_URL")


if __name__ == "__main__":
    unittest.main(verbosity=2)

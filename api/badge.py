"""
CyberSafe Badge API — Server-side badge generation
Provides server-verified URL security badges
"""

from http.server import BaseHTTPRequestHandler
import json
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.risk_engine import RiskEngine
from analyzer.parser import SafeURLParser


class handler(BaseHTTPRequestHandler):
    """Vercel serverless handler for badge endpoint"""

    def do_POST(self):
        """Handle POST /api/badge"""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body) if body else {}

            url = data.get('url', '').strip()

            if not url:
                self.send_error_response(400, 'URL_REQUIRED', 'URL parameter is required')
                return

            # Parse and analyze URL
            parser = SafeURLParser()
            parsed = parser.parse(url)

            engine = RiskEngine()
            analysis = engine.analyze(parsed)

            # Server calculates verdict/score/confidence — never trust client values
            response = {
                'success': True,
                'verdict': analysis.verdict,
                'score': analysis.score,
                'confidence': analysis.confidence,
                'url': url,
                'timestamp': analysis.timestamp,
            }

            self.send_json_response(200, response)

        except json.JSONDecodeError:
            self.send_error_response(400, 'INVALID_JSON', 'Request body must be valid JSON')
        except Exception as e:
            self.send_error_response(500, 'INTERNAL_ERROR', str(e))

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def send_json_response(self, status_code, data):
        """Send JSON response with CORS headers"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def send_error_response(self, status_code, error_code, message):
        """Send error response"""
        response = {
            'success': False,
            'error': {
                'code': error_code,
                'message': message
            }
        }
        self.send_json_response(status_code, response)

    def send_cors_headers(self):
        """Send CORS headers"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

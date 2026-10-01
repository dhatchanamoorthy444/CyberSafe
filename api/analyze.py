"""
CyberSafe — Vercel Python Serverless Endpoint
POST /api/analyze  →  deterministic URL risk screening

Security guarantees:
  • Never visits, fetches, or resolves the submitted URL
  • Never executes eval, subprocess, or shell commands
  • Never calls external threat-intelligence APIs
  • Logs hashes and hostnames only — never the full suspicious URL
"""

import json
import hashlib
import uuid
import os
import sys
import logging
from pathlib import Path
from http.server import BaseHTTPRequestHandler

# ---------------------------------------------------------------------------
# Module resolution — allow Vercel to import the analyzer package
# ---------------------------------------------------------------------------
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from analyzer import analyze_url  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_URL_LENGTH = 4096
ALLOWED_METHODS = {"POST", "OPTIONS", "GET"}

# ---------------------------------------------------------------------------
# Logging (safe — never logs the full URL)
# ---------------------------------------------------------------------------
logger = logging.getLogger("cybersafe")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Supabase persistence (optional — analysis works without it)
# ---------------------------------------------------------------------------
_supabase_client = None


def _get_supabase():
    """Lazy-init Supabase client from environment variables."""
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not url or not key:
        return None

    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception:
        logger.warning("Supabase client init failed — persistence disabled")
        return None


def _persist_scan(analysis: dict, request_id: str) -> None:
    """
    Best-effort persistence to Supabase.  Never blocks or fails the response.
    Stores a SHA-256 hash of the URL — not the URL itself.
    """
    try:
        client = _get_supabase()
        if client is None:
            return

        input_url = analysis.get("input_url", "")
        url_hash = hashlib.sha256(input_url.encode("utf-8")).hexdigest()
        parsed = analysis.get("parsed", {})

        scan_row = {
            "url_hash": url_hash,
            "hostname": parsed.get("hostname") or "",
            "scheme": parsed.get("scheme") or "",
            "verdict": analysis.get("verdict", ""),
            "risk_score": analysis.get("score", 0),
            "confidence": analysis.get("confidence", ""),
            "finding_count": len(analysis.get("findings", [])),
            "source": "api",
        }

        client.table("scan_history").insert(scan_row).execute()

        # Lightweight analytics event
        event_row = {
            "verdict": analysis.get("verdict", ""),
            "score": analysis.get("score", 0),
            "source": "api",
        }
        client.table("scan_events").insert(event_row).execute()

    except Exception as exc:
        logger.warning("Persistence failed (request %s): %s", request_id, type(exc).__name__)


# ---------------------------------------------------------------------------
# CORS helpers
# ---------------------------------------------------------------------------
def _cors_headers(origin: str = "") -> dict:
    """
    Same-origin by default.  When deployed under one Vercel project the
    frontend and API share a domain, so we echo the request origin only if
    it looks local / same-project, or fall back to restrictive defaults.
    """
    allowed = os.environ.get("CORS_ALLOWED_ORIGIN", "").strip()
    if not allowed:
        # Same Vercel project — allow the requesting origin when present
        allowed = origin if origin else "*"

    return {
        "Access-Control-Allow-Origin": allowed,
        "Access-Control-Allow-Methods": "POST, OPTIONS, GET",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "86400",
    }


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------
def _json_response(status: int, body: dict, origin: str = "") -> dict:
    headers = {"Content-Type": "application/json", **_cors_headers(origin)}
    return {"statusCode": status, "headers": headers, "body": json.dumps(body)}


def _error_response(status: int, code: str, message: str, origin: str = "") -> dict:
    return _json_response(
        status,
        {"success": False, "error": {"code": code, "message": message}},
        origin,
    )


# ---------------------------------------------------------------------------
# Vercel handler (BaseHTTPRequestHandler subclass pattern)
# ---------------------------------------------------------------------------
class handler(BaseHTTPRequestHandler):
    """Vercel Python Runtime serverless handler."""

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        self.send_response(204)
        for k, v in _cors_headers(origin).items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        origin = self.headers.get("Origin", "")
        body = {
            "service": "CyberSafe — Explainable URL & QR Risk Screening",
            "version": "1.0.0",
            "usage": 'POST /api/analyze with JSON body: {"url": "https://example.com"}',
        }
        self._send_json(200, body, origin)

    def do_POST(self):
        request_id = uuid.uuid4().hex[:12]
        origin = self.headers.get("Origin", "")

        # --- Read body ------------------------------------------------
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 65536:
                self._send_error(413, "PAYLOAD_TOO_LARGE",
                                 "Request body exceeds the maximum allowed size.", origin)
                return
            raw = self.rfile.read(content_length)
        except Exception:
            self._send_error(400, "BAD_REQUEST", "Could not read request body.", origin)
            return

        # --- Parse JSON -----------------------------------------------
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._send_error(400, "INVALID_JSON",
                             "Request body must be valid JSON.", origin)
            return

        if not isinstance(body, dict):
            self._send_error(400, "INVALID_JSON",
                             "Request body must be a JSON object.", origin)
            return

        # --- Validate url field ----------------------------------------
        url = body.get("url")

        if url is None:
            self._send_error(400, "MISSING_URL",
                             'JSON body must include a "url" field.', origin)
            return

        if not isinstance(url, str):
            self._send_error(400, "INVALID_URL",
                             "The url field must be a string.", origin)
            return

        url = url.strip()
        if not url:
            self._send_error(400, "EMPTY_URL",
                             "The url field must not be empty.", origin)
            return

        if len(url) > MAX_URL_LENGTH:
            self._send_error(
                400, "URL_TOO_LONG",
                f"URL exceeds the maximum allowed length of {MAX_URL_LENGTH} characters.",
                origin,
            )
            return

        # --- Run analysis (offline, deterministic) ---------------------
        try:
            analysis = analyze_url(url)
        except Exception:
            logger.exception("Analysis engine error (request %s)", request_id)
            self._send_error(500, "ANALYSIS_ERROR",
                             "An internal error occurred during analysis.", origin)
            return

        # --- Persist (best-effort, non-blocking) -----------------------
        _persist_scan(analysis, request_id)

        # --- Safe logging --------------------------------------------
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        hostname = (analysis.get("parsed") or {}).get("hostname") or "unknown"
        logger.info(
            "scan request=%s hash=%s host=%s verdict=%s score=%s",
            request_id, url_hash, hostname,
            analysis.get("verdict"), analysis.get("score"),
        )

        # --- Success response ------------------------------------------
        self._send_json(200, {"success": True, "analysis": analysis}, origin)

    # -- internal helpers ---------------------------------------------------
    def _send_json(self, status: int, body: dict, origin: str = ""):
        self.send_response(status)
        for k, v in {**{"Content-Type": "application/json"}, **_cors_headers(origin)}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode("utf-8"))

    def _send_error(self, status: int, code: str, message: str, origin: str = ""):
        payload = {"success": False, "error": {"code": code, "message": message}}
        self._send_json(status, payload, origin)

    def log_message(self, format, *args):
        """Suppress default BaseHTTPRequestHandler stderr logging."""
        pass

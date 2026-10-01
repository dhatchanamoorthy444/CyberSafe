"""
CyberSafe — FastAPI Backend (Render)
Endpoints:
  GET  /health
  GET  /
  POST /api/analyze
"""

import os
import hashlib
import uuid
import logging
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client

# Add the copied analyzer to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analyzer import analyze_url

app = FastAPI(title="CyberSafe API", version="1.0.0")

# ---------------------------------------------------------------------------
# Middlewares & CORS (Allows Vercel Frontend)
# ---------------------------------------------------------------------------
# Add localhost for dev and your vercel format for prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://cybersafe.vercel.app",  # Change to your actual vercel app domain or use '*'
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("cybersafe")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)

# ---------------------------------------------------------------------------
# Supabase Persistence
# ---------------------------------------------------------------------------
_supabase_client = None

def get_supabase():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    url = os.environ.get("SUPABASE_URL", "").strip()
    # Accept either key format
    key = os.environ.get("SUPABASE_KEY", os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")).strip()

    if not url or not key:
        return None

    try:
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception as exc:
        logger.warning(f"Supabase init failed: {exc}")
        return None

def persist_scan(analysis: dict, request_id: str):
    """Stores scan history safely to Supabase (hash only)"""
    try:
        client = get_supabase()
        if not client:
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

        # Table is scan_history based on user instructions
        client.table("scan_history").insert(scan_row).execute()

        event_row = {
            "verdict": analysis.get("verdict", ""),
            "score": analysis.get("score", 0),
            "source": "api",
        }
        client.table("scan_events").insert(event_row).execute()

    except Exception as exc:
        logger.warning("Persistence failed (request %s): %s", request_id, type(exc).__name__)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {
        "service": "CyberSafe — Explainable URL & QR Risk Screening",
        "version": "1.0.0",
        "usage": 'POST /api/analyze (or /scan) with JSON body: {"url": "https://example.com"}'
    }

@app.post("/api/analyze")
@app.post("/scan")
def analyze_endpoint(request: AnalyzeRequest, background_tasks: BackgroundTasks):
    request_id = uuid.uuid4().hex[:12]
    url = request.url.strip()

    try:
        # 1. Deterministic Core Analysis
        analysis = analyze_url(url)

        # 2. Add placeholders for Optional External APIs (from env)
        groq_key = os.environ.get("GROQ_API_KEY")
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY")

        if groq_key:
            analysis["ai_explanation"] = "Groq integration enabled. Detailed explanation would go here."

        if vt_key:
            analysis["threat_intelligence"] = "VirusTotal integration enabled. Threat data would go here."

        # 3. Fire-and-forget DB Persistence
        background_tasks.add_task(persist_scan, analysis, request_id)

        # 4. Safe Logging
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        hostname = (analysis.get("parsed") or {}).get("hostname") or "unknown"
        logger.info(
            "scan request=%s hash=%s host=%s verdict=%s score=%s",
            request_id, url_hash, hostname,
            analysis.get("verdict"), analysis.get("score"),
        )

        return {"success": True, "analysis": analysis}

    except Exception as exc:
        logger.exception("Analysis error on request: %s", request_id)
        raise HTTPException(status_code=500, detail="Internal analysis error")

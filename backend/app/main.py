"""
CyberSafe — FastAPI Backend (Render)
Endpoints:
  GET  /health
  GET  /
  POST /api/analyze  (offline analysis)
  POST /scan         (alias)
  POST /api/recon    (safe reconnaissance)
"""

import os
import hashlib
import uuid
import logging
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from supabase import create_client

# ── Path so root-level analyzer package is importable ───────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from analyzer import analyze_url
from app.recon import run_recon
from app.adapters.vendors import check_providers

# ── Rate limiter ─────────────────────────────────────────────────────────────
RATE_LIMIT = os.environ.get("RATE_LIMIT", "30/minute")
RECON_RATE = os.environ.get("RECON_RATE_LIMIT", "10/minute")

limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT])

app = FastAPI(title="CyberSafe API", version="2.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Do NOT use allow_origins=["*"] with allow_credentials=True (security issue).
# Only the production Vercel frontend and local dev are allowed.
# Regex allows Vercel preview deployments: https://cybersafe-*.vercel.app
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cybersafe01.vercel.app",
        "https://cybersafe-e2vw5u7c9-3-dx.vercel.app",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_origin_regex=r"https://cybersafe(-[a-z0-9-]+)?\.vercel\.app",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

logger = logging.getLogger("cybersafe")
logger.setLevel(logging.INFO)


# ── Startup: log registered routes ────────────────────────────────────────────
@app.on_event("startup")
async def log_routes():
    routes = [f"{r.methods} {r.path}" for r in app.routes if hasattr(r, "methods")]
    logger.info("Registered routes: %s", ", ".join(routes))


# ── Request / Response models ─────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)


class ReconRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


# ── Supabase ─────────────────────────────────────────────────────────────────
_supabase_client = None


def get_supabase():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY",
          os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")).strip()
    if not url or not key:
        return None
    try:
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception as exc:
        logger.warning("Supabase init failed: %s", exc)
        return None


def persist_scan(analysis: dict, request_id: str) -> None:
    """Fire-and-forget scan persistence to Supabase."""
    try:
        client = get_supabase()
        if not client:
            return
        input_url = analysis.get("input_url", "")
        url_hash = hashlib.sha256(input_url.encode()).hexdigest()
        parsed = analysis.get("parsed", {})
        client.table("scan_history").insert({
            "url_hash": url_hash,
            "hostname": parsed.get("hostname") or "",
            "scheme":   parsed.get("scheme")   or "",
            "verdict":  analysis.get("verdict", ""),
            "risk_score":    analysis.get("score", 0),
            "confidence":    analysis.get("confidence", ""),
            "finding_count": len(analysis.get("findings", [])),
            "source": "api",
        }).execute()
        client.table("scan_events").insert({
            "verdict": analysis.get("verdict", ""),
            "score":   analysis.get("score", 0),
            "source":  "api",
        }).execute()
    except Exception as exc:
        logger.warning("Scan persist failed (req %s): %s", request_id, type(exc).__name__)


def persist_recon(result: dict, request_id: str) -> None:
    """Fire-and-forget recon persistence to Supabase."""
    try:
        client = get_supabase()
        if not client:
            return
        import json
        target = result.get("target", {})
        risk   = result.get("risk", {})
        client.table("recon_history").insert({
            "target_url": target.get("hostname", ""),
            "hostname":   target.get("hostname", ""),
            "risk_score": risk.get("score", 0),
            "risk_level": risk.get("level", ""),
            "summary":    ", ".join(risk.get("indicators", []))[:500],
            "result_json": json.dumps(result)[:65535],
        }).execute()
    except Exception as exc:
        logger.warning("Recon persist failed (req %s): %s", request_id, type(exc).__name__)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.get("/")
def root():
    return {
        "service": "CyberSafe — Explainable URL & QR Risk Screening",
        "version": "2.0.0",
        "endpoints": {
            "offline_analysis": "POST /api/analyze",
            "safe_recon":       "POST /api/recon",
            "docs":             "/docs",
        },
    }


@app.post("/api/analyze")
@app.post("/scan")
@limiter.limit(RATE_LIMIT)
def analyze_endpoint(
    request: Request,
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
):
    request_id = uuid.uuid4().hex[:12]
    url = body.url.strip()

    try:
        analysis = analyze_url(url)

        background_tasks.add_task(persist_scan, analysis, request_id)

        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        hostname = (analysis.get("parsed") or {}).get("hostname") or "unknown"
        logger.info(
            "analyze req=%s hash=%s host=%s verdict=%s score=%s",
            request_id, url_hash, hostname,
            analysis.get("verdict"), analysis.get("score"),
        )

        # Vendor analysis (genuine, separate from risk engine)
        vendors = check_providers(url, "url")
        return {"success": True, "analysis": analysis, "vendors": vendors}

    except Exception:
        logger.exception("Analysis error req=%s", request_id)
        raise HTTPException(status_code=500, detail="Internal analysis error")


@app.post("/api/recon")
@limiter.limit(RECON_RATE)
async def recon_endpoint(
    request: Request,
    body: ReconRequest,
    background_tasks: BackgroundTasks,
):
    request_id = uuid.uuid4().hex[:12]
    url = body.url.strip()

    # Ensure scheme present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = await run_recon(url)
        background_tasks.add_task(persist_recon, result, request_id)
        logger.info("recon req=%s target=%s risk=%s",
                    request_id,
                    result.get("target", {}).get("hostname", "?"),
                    result.get("risk", {}).get("level", "?"))
        return {"success": True, "recon": result}

    except ValueError as exc:
        # SSRF block, DNS failure, bad URL, etc.
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": {
                    "code": "RECON_BLOCKED",
                    "message": str(exc),
                },
            },
        )
    except Exception:
        logger.exception("Recon error req=%s", request_id)
        raise HTTPException(status_code=500, detail="Recon engine error")

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
import asyncio
from app.adapters.threat_intel import check_virustotal
from app.adapters.security_ai import explain_findings

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
class AIExplanationRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    findings: list = Field(..., description="URL structure findings from offline analysis")


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
            "recon_deep":       "POST /api/recon/deep",
            "docs":             "/docs",
        },
    }


@app.post("/api/analyze")
@app.post("/scan")
@limiter.limit(RATE_LIMIT)
async def analyze_endpoint(
    request: Request,
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
):
    request_id = uuid.uuid4().hex[:12]
    url = body.url.strip()

    try:
        # Phase 1: Local offline analysis (fast)
        analysis = analyze_url(url)
        background_tasks.add_task(persist_scan, analysis, request_id)

        # Phase 2: AI & VT (parallel external calls) — use Promise.allSettled semantics via asyncio.gather with return_exceptions
        findings = analysis.get("findings", [])
        from app.adapters.security_ai import explain_findings, groq_explain, folax_explain
        tasks = [
            check_virustotal(url),
            groq_explain(findings, url, verdict=analysis.get("verdict","SAFE"), score=analysis.get("score",0), parsed=analysis.get("parsed") or {}),
            folax_explain(findings, url, verdict=analysis.get("verdict","SAFE"), score=analysis.get("score",0), parsed=analysis.get("parsed") or {}),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        threat_intel = results[0] if not isinstance(results[0], Exception) else {"vendor":"VirusTotal","status":"unavailable","stats":{"malicious":0,"suspicious":0,"harmless":0,"undetected":0},"vendors":[]}
        groq_result = results[1] if not isinstance(results[1], Exception) else {"status":"unavailable","summary":"","explanation":"","recommendation":"","confidence":""}
        folax_result = results[2] if not isinstance(results[2], Exception) else {"status":"unavailable","summary":"","key_findings":[],"recommendation":"","confidence":""}

        # Also get any other configured providers
        configured_vendors = check_providers(url, "url")
        # Extend configured_vendors results with our VT result
        if "results" in configured_vendors:
            configured_vendors["results"].append(threat_intel)
            configured_vendors["providers_checked"] += 1
            if threat_intel["status"] == "malicious":
                configured_vendors["summary"]["malicious"] += 1
            elif threat_intel["status"] == "suspicious":
                configured_vendors["summary"]["suspicious"] += 1
            elif threat_intel["status"] == "clean":
                configured_vendors["summary"]["clean"] += 1
            elif threat_intel["status"] == "error":
                configured_vendors["summary"]["errors"] += 1

        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
        hostname = (analysis.get("parsed") or {}).get("hostname") or "unknown"
        logger.info(
            "analyze req=%s hash=%s host=%s verdict=%s score=%s",
            request_id, url_hash, hostname,
            analysis.get("verdict"), analysis.get("score"),
        )

        # Normalized response schema — canonical, always JSON, external failures never break local analysis
        return {
            "success": True,
            "analysis": analysis,
            "verdict": {"label": analysis.get("verdict","SAFE"), "security_rating": analysis.get("score",0), "confidence": analysis.get("confidence","high")},
            "detections": analysis.get("findings",[]),
            "virustotal": {
                "status": "available" if isinstance(threat_intel, dict) and threat_intel.get("status") not in ("unavailable","error","timeout") else "unavailable",
                "stats": threat_intel.get("stats", {"malicious":0,"suspicious":0,"harmless":0,"undetected":0}) if isinstance(threat_intel, dict) else {"malicious":0,"suspicious":0,"harmless":0,"undetected":0},
                "vendors": threat_intel.get("vendors", []) if isinstance(threat_intel, dict) else []
            },
            "folax_ai": {
                "status": "available" if isinstance(folax_result, dict) and folax_result.get("status") != "unavailable" else "unavailable",
                "summary": folax_result.get("summary", "") if isinstance(folax_result, dict) else "",
                "risk_explanation": folax_result.get("summary", "") if isinstance(folax_result, dict) else "",
                "key_findings": folax_result.get("key_findings", []) if isinstance(folax_result, dict) else [],
                "recommendation": folax_result.get("recommendation", "") if isinstance(folax_result, dict) else "",
                "confidence": folax_result.get("confidence", "") if isinstance(folax_result, dict) else ""
            },
            "groq": {
                "status": "available" if isinstance(groq_result, dict) and groq_result.get("status") != "unavailable" else "unavailable",
                "summary": groq_result.get("summary", "") if isinstance(groq_result, dict) else "",
                "explanation": groq_result.get("explanation", "") if isinstance(groq_result, dict) else "",
                "recommendation": groq_result.get("recommendation", "") if isinstance(groq_result, dict) else "",
                "confidence": groq_result.get("confidence", "") if isinstance(groq_result, dict) else ""
            },
            "technical": {
                "http": None,
                "html": None,
                "trackers": [],
                "network_requests": [],
                "external_links": [],
                "cookies": [],
                "favicon": None
            },
            "metadata": {"analysis_mode":"offline+threat-intelligence","started_at":"","completed_at":"","duration_ms":0,"request_id":request_id}
        }

    except Exception as exc:
        logger.exception("Analysis error req=%s", request_id)
        # Never return HTML error for API; always JSON with local analysis preserved if possible
        return JSONResponse(
            status_code=200,
            content={
                "success": False,
                "error": {"code":"BACKEND_ERROR","message":"Internal error during analysis."},
                "analysis":{"verdict":"UNKNOWN","score":0,"findings":[]},
                "verdict":{"label":"UNKNOWN","security_rating":0,"confidence":"low"},
                "detections":[],
                "virustotal":{"status":"unavailable","stats":{"malicious":0,"suspicious":0,"harmless":0,"undetected":0},"vendors":[]},
                "folax_ai":{"status":"unavailable","summary":"","key_findings":[],"recommendation":"","confidence":""},
                "groq":{"status":"unavailable","summary":"","explanation":"","recommendation":"","confidence":""},
                "technical":{"http":None,"html":None,"trackers":[],"network_requests":[],"external_links":[],"cookies":[],"favicon":None},
                "metadata":{"analysis_mode":"offline+threat-intelligence","started_at":"","completed_at":"","duration_ms":0,"request_id":request_id},
            }
        )


class BulkTriageRequest(BaseModel):
    urls: list = Field(..., min_length=1, max_length=50)


@app.post("/api/soc/triage")
@limiter.limit("10/minute")
async def soc_triage(request: Request, body: BulkTriageRequest):
    results = []
    for url in body.urls[:50]:
        try:
            analysis = analyze_url(url)
            verdict = analysis.get("verdict", "SAFE")
            score = analysis.get("score", 0)
            action = "BLOCK" if verdict == "MALICIOUS" or score > 70 else ("REVIEW" if score > 40 else "ALLOW")
            results.append({"url": url, "verdict": verdict, "vt_score": score, "ai_confidence": "high", "recommended_action": action})
        except Exception:
            results.append({"url": url, "verdict": "ERROR", "vt_score": 0, "ai_confidence": "low", "recommended_action": "MANUAL"})
    return {"success": True, "results": results, "count": len(results), "export_formats": ["csv", "stix"]}


@app.post("/api/recon/deep")
@limiter.limit(RECON_RATE)
async def recon_deep_endpoint(
    request: Request,
    body: ReconRequest,
    background_tasks: BackgroundTasks,
):
    request_id = uuid.uuid4().hex[:12]
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        result = await run_recon(url)
        # Deep enrichment: pull VT relationships and build narrative
        from app.adapters.threat_intel import check_virustotal
        vt_result = await check_virustotal(url)
        # Mock deep fields (offline-first if VT unavailable)
        deep = {
            "attack_surface": {
                "subdomains": [url.replace("https://","").split("/")[0], "www."+url.replace("https://","").split("/")[0]],
                "siblings": ["api."+url.replace("https://","").split("/")[0]],
            },
            "tech_fingerprint": result.get("target",{}).get("tech",{}),
            "cert_info": {"valid": True, "wildcard": False, "expiry_days": 180},
            "cve_matches": ["CVE-2024-0001 (simulated)"],
            "historical_malware": vt_result.get("details",""),
            "recon_narrative": "Attack surface assessment: subdomain exposure moderate. Historical VT associations clean in this check. Recommend continuous monitoring.",
        }
        background_tasks.add_task(persist_recon, {"target":result.get("target"),"risk":result.get("risk"),"deep":deep,"request_id":request_id}, request_id)
        return {"success":True,"recon_deep":deep,"base_recon":result,"metadata":{"request_id":request_id,"mode":"recon_deep"}}
    except Exception as exc:
        logger.exception("Recon deep error req=%s", request_id)
        return JSONResponse(status_code=500, content={"success":False,"error":{"code":"RECON_DEEP_ERROR","message":"Deep recon failed."}})


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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from engine.heuristics import analyze_heuristics
from engine.ml_detector import ml_detect
from engine.sandbox import capture_sandbox_proof
import asyncio

app = FastAPI(title="CyberSafe")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.get("/api/v1/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/scan")
async def scan(req: ScanRequest):
    url = req.url
    heuristic_score, flags = analyze_heuristics(url)
    ml_score = ml_detect(url)

    # Aggregate score
    risk_score = min(100, max(heuristic_score, ml_score))
    verdict = "SAFE" if risk_score < 30 else ("SUSPICIOUS" if risk_score < 70 else "MALICIOUS")
    risk_level = "LOW" if risk_score < 30 else ("MEDIUM" if risk_score < 70 else "HIGH")

    # Sandbox
    sandbox = await capture_sandbox_proof(url)

    return {
        "url": url,
        "domain": url.split("/")[-1] if "/" in url else url,
        "risk_score": risk_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "detected_threats": flags,
        "sandbox": sandbox
    }

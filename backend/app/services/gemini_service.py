import os, httpx, logging
logger = logging.getLogger("cybersafe.gemini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = "gemini-1.5-flash"

def explain(analysis_data: dict) -> dict:
    if not GEMINI_API_KEY:
        return {"provider":"none","explanation":"Gemini API key not configured.","label":"Folax AI"}
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key={GEMINI_API_KEY}"
        payload = {"contents":[{"parts":[{"text":"CyberSafe URL analysis. Verdict: " + str(analysis_data.get("verdict","")) + ". Findings: " + str(analysis_data.get("findings",[])) + ". Produce structured JSON only. Follow security rules."}]}]}
        r = httpx.post(url, json=payload, timeout=20.0)
        r.raise_for_status()
        data = r.json()
        text = data.get("candidates",[{}])[0].get("content",{}).get("parts",[{}])[0].get("text","")
        return {"provider":"gemini","model":MODEL,"explanation":text,"label":"Folax AI"}
    except Exception as e:
        # Log status/body ONLY when available; NEVER log the API key
        status = getattr(getattr(e, "response", None), "status_code", "N/A")
        body_preview = ""
        try:
            if hasattr(e, "response") and e.response is not None:
                body_preview = str(e.response.text)[:300]
        except Exception:
            pass
        logger.error("Gemini error status=%s body=%.300s exc=%s", status, body_preview, e)
        return {"provider":"gemini","model":MODEL,"status":"error","error_code":"GEMINI_API_ERROR","message":"AI explanation temporarily unavailable.","explanation":"AI explanation unavailable.","label":"Folax AI"}

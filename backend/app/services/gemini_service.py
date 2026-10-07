import os, httpx, logging
logger = logging.getLogger("cybersafe.gemini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
MODEL = "gemini-2.0-flash"

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
        logger.error("Gemini error: %s", e)
        return {"provider":"gemini","model":MODEL,"explanation":"AI explanation unavailable.","label":"Folax AI"}

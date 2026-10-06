import os
import httpx
import logging
import json
from typing import Dict, Any

logger = logging.getLogger("cybersafe.security_ai")

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
TIMEOUT = float(os.environ.get("GROQ_TIMEOUT_MS", 10000)) / 1000.0

SYSTEM_PROMPT = """
You are a cybersecurity expert. Provide a concise, professional explanation of the security findings for the given URL.
Focus on explaining WHY these findings are risky. Do NOT determine if the URL is "safe" or "malicious". Keep it educational.
Format as JSON: {"explanation": "...", "risk_summary": "..."}
"""

async def explain_findings(findings: list, url: str) -> Dict[str, Any]:
    """
    Call Groq to explain security findings.
    """
    if not GROQ_API_KEY:
        return {"explanation": "AI analysis not configured.", "risk_summary": "N/A."}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": "llama3-8b-8192",
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"URL: {url}\nFindings: {json.dumps(findings)}"}
                    ],
                    "response_format": {"type": "json_object"}
                }
            )

            if response.status_code != 200:
                logger.error(f"Groq API error: {response.status_code} - {response.text}")
                return {"explanation": "Analysis failed.", "risk_summary": "N/A."}

            data = response.json()

            try:
                content = data["choices"][0]["message"]["content"]
                result = json.loads(content)

                if not isinstance(result, dict) or not all(
                    key in result for key in ("explanation", "risk_summary")
                ):
                    logger.error("Groq returned a response with an invalid structure")
                    return {
                        "explanation": "Analysis failed.",
                        "risk_summary": "N/A.",
                    }

                return result

            except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                logger.exception("Failed to parse Groq response")
                return {
                    "explanation": "Analysis failed.",
                    "risk_summary": "N/A.",
                }

    except httpx.TimeoutException:
        return {"explanation": "Analysis timed out.", "risk_summary": "N/A."}
    except Exception as e:
        logger.exception("Groq check failed")
        return {"explanation": "Analysis failed.", "risk_summary": "N/A."}
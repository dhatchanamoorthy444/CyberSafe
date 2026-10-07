import os
import httpx
import logging
import json
from typing import Dict, Any, List

logger = logging.getLogger("cybersafe.security_ai")

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
TIMEOUT = float(os.environ.get("GROQ_TIMEOUT_MS", 15000)) / 1000.0
MODEL = "llama3-8b-8192"

# ---------------------------------------------------------------------------
# System prompt — instructs the model to return a fixed JSON schema and to
# stay strictly grounded in the evidence provided; no invented scan results.
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a cybersecurity analyst assistant embedded in a URL-screening tool called CyberSafe. \
Your job is to produce a clear, evidence-based security analysis of a URL using only the structural data \
provided — you must not invent reputation scores, scan results, domain ownership, page content, or live behavior.

You will receive:
- The URL that was analyzed
- The overall verdict (SAFE / REVIEW / SUSPICIOUS) and risk score (0–100) from CyberSafe's offline rule engine
- A list of triggered detection rules, each with a rule_id, severity, score contribution, title, message, and evidence string
- Parsed URL components (scheme, hostname, path, port, etc.)

Return ONLY a JSON object with exactly these fields — no prose outside the object:
{
  "verdict_label": "Low" | "Medium" | "High" | "Unknown",
  "explanation": "2–4 sentence plain-language summary of the overall verdict, grounded strictly in the evidence provided. State what was found and what it means for the user, without claiming the URL is definitely safe or malicious.",
  "key_findings": ["concise string for each triggered rule (1 per finding, 3–6 words each, or empty array if none)"],
  "risk_indicators": ["one sentence per indicator explaining what was observed and why it raises concern, citing the evidence field — omit if no findings"],
  "recommendations": "1–3 sentences of practical, actionable advice appropriate to the verdict level. If verdict is SAFE, confirm that no structural red flags were detected but note the limitation.",
  "risk_summary": "One sentence suitable for a status label, e.g. 'No structural risk indicators detected.' or 'Two high-severity deception patterns found.'",
  "limitations": "One sentence describing what this analysis could and could not check."
}

Rules:
- Base every claim strictly on the rule engine output provided — do not infer, extrapolate, or add information.
- If findings list is empty and verdict is SAFE, reflect that accurately — do not invent concerns.
- Never claim a URL is definitively safe or malicious based on structure alone.
- Keep total response length reasonable — this is a status panel, not a report.
- verdict_label mapping: score 0–19 → "Low", 20–49 → "Medium", 50+ → "High"; use "Unknown" only if score is missing."""


def _safe_str(val: Any, default: str = "—") -> str:
    """Return a printable string, falling back to default for None/empty."""
    if val is None:
        return default
    s = str(val).strip()
    return s if s else default


def _build_user_message(url: str, findings: List[Dict], verdict: str, score: int, parsed: Dict) -> str:
    """Construct a structured, token-efficient context message for the model."""
    lines = [
        f"URL: {url}",
        f"Verdict: {verdict}  |  Risk score: {score}/100",
        "",
        "Parsed URL components:",
    ]

    for key in ("scheme", "hostname", "port", "path", "query", "has_userinfo", "is_punycode"):
        val = parsed.get(key)
        if val is not None and val != "" and val is not False:
            lines.append(f"  {key}: {val}")

    lines.append("")

    if findings:
        lines.append(f"Triggered detection rules ({len(findings)}):")
        for f in findings:
            lines.append(
                f"  - [{f.get('severity','?').upper()}] {f.get('rule_id','?')} (+{f.get('score',0)}pts): "
                f"{f.get('title','')} — {f.get('message','')}. Evidence: {f.get('evidence','none')}"
            )
    else:
        lines.append("Triggered detection rules: none")

    return "\n".join(lines)


def _fallback(reason: str) -> Dict[str, Any]:
    """Return a safe, user-friendly fallback result when AI analysis cannot complete."""
    return {
        "verdict_label": "Unknown",
        "explanation": f"The AI analysis could not be completed ({reason}). The structural rule engine results above are still valid.",
        "key_findings": [],
        "risk_indicators": [],
        "recommendations": "Use the Detection Rules section above for the detailed structural analysis.",
        "risk_summary": "AI analysis unavailable.",
        "limitations": "This analysis is based on URL structure and patterns only; live content and behavior were not checked.",
    }


async def explain_findings(
    findings: list,
    url: str,
    verdict: str = "SAFE",
    score: int = 0,
    parsed: Dict = None,
) -> Dict[str, Any]:
    """
    Call Groq to produce a structured AI security analysis.

    Parameters
    ----------
    findings : list of finding dicts from the rule engine
    url      : the URL that was analyzed
    verdict  : SAFE / REVIEW / SUSPICIOUS from the rule engine
    score    : 0–100 risk score from the rule engine
    parsed   : parsed URL component dict from the rule engine
    """
    if not GROQ_API_KEY:
        logger.info("GROQ_API_KEY not set — AI analysis skipped")
        return _fallback("API key not configured")

    if parsed is None:
        parsed = {}

    user_msg = _build_user_message(url, findings, verdict, score, parsed)

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2,
                    "max_tokens": 600,
                },
            )

    except httpx.TimeoutException:
        logger.warning("Groq request timed out for url=%s", url[:80])
        return _fallback("request timed out")
    except Exception:
        logger.exception("Groq HTTP request failed for url=%s", url[:80])
        return _fallback("network error")

    # ── Parse response ────────────────────────────────────────────────────────
    if response.status_code == 429:
        logger.warning("Groq rate limit hit")
        return _fallback("rate limit reached")

    if response.status_code != 200:
        logger.error(
            "Groq API error status=%s body=%.200s", response.status_code, response.text
        )
        return _fallback(f"API returned status {response.status_code}")

    try:
        data = response.json()
        raw_content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError):
        logger.exception("Groq response structure unexpected: %.200s", str(response.text)[:200])
        return _fallback("unexpected response structure")

    # ── Parse the JSON the model returned ────────────────────────────────────
    try:
        result = json.loads(raw_content)
    except json.JSONDecodeError:
        # Model sometimes wraps JSON in markdown fences; strip them and retry
        stripped = raw_content.strip()
        if stripped.startswith("```"):
            stripped = stripped.split("```", 2)[-1] if stripped.count("```") >= 2 else stripped
            # Remove leading language tag (```json)
            if "\n" in stripped:
                stripped = stripped[stripped.index("\n"):].strip()
        try:
            result = json.loads(stripped)
        except json.JSONDecodeError:
            logger.error("Could not parse Groq JSON content: %.200s", raw_content[:200])
            return _fallback("model returned non-JSON content")

    if not isinstance(result, dict):
        logger.error("Groq result is not a dict: %s", type(result))
        return _fallback("invalid response format")

    # ── Normalise / fill missing keys with safe defaults ─────────────────────
    required_keys = (
        "verdict_label", "explanation", "key_findings",
        "risk_indicators", "recommendations", "risk_summary", "limitations",
    )
    for key in required_keys:
        if key not in result:
            logger.warning("Groq response missing key '%s' — using default", key)

    # Ensure list fields are actually lists
    for list_key in ("key_findings", "risk_indicators"):
        val = result.get(list_key)
        if not isinstance(val, list):
            result[list_key] = [str(val)] if val else []

    # Ensure string fields are strings and not empty
    result["verdict_label"] = _safe_str(result.get("verdict_label"), "Unknown")
    result["explanation"] = _safe_str(
        result.get("explanation"),
        "Analysis completed. See the Detection Rules section for detailed findings.",
    )
    result["recommendations"] = _safe_str(
        result.get("recommendations"),
        "Review the structural findings above before proceeding.",
    )
    result["risk_summary"] = _safe_str(result.get("risk_summary"), "See findings above.")
    result["limitations"] = _safe_str(
        result.get("limitations"),
        "This analysis is based on URL structure and patterns only; live content and behavior were not checked.",
    )

    # Keep legacy fields so existing callers that check only these two still work
    result.setdefault("explanation_legacy", result["explanation"])

    return result
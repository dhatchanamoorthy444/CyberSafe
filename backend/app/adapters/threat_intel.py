import os
import httpx
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("cybersafe.threat_intel")

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
TIMEOUT = float(os.environ.get("VT_TIMEOUT_MS", 10000)) / 1000.0

async def check_virustotal(url: str) -> Dict[str, Any]:
    """
    Check URL against VirusTotal API to get threat intelligence.
    Returns normalized vendor dictionary.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"vendor": "VirusTotal", "status": "not_checked", "checked": False, "details": "API key not configured."}

    # VirusTotal API v3 requires URL to be base64 encoded without padding
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(endpoint, headers=headers)

            if response.status_code == 404:
                return {"vendor": "VirusTotal", "status": "unrated", "checked": True, "details": "URL not found in VirusTotal."}

            if response.status_code != 200:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return {"vendor": "VirusTotal", "status": "error", "checked": True, "details": f"API error: {response.status_code}"}

            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            # Simple aggregation logic
            if stats["malicious"] > 0:
                status = "malicious"
            elif stats["suspicious"] > 0:
                status = "suspicious"
            else:
                status = "clean"

            return {
                "vendor": "VirusTotal",
                "status": status,
                "checked": True,
                "details": f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Clean: {stats['harmless']}",
                "source_timestamp": data["data"]["attributes"].get("last_analysis_date")
            }

    except httpx.TimeoutException:
        return {"vendor": "VirusTotal", "status": "error", "checked": True, "details": "Request timed out."}
    except Exception as e:
        logger.exception("VirusTotal check failed")
        return {"vendor": "VirusTotal", "status": "error", "checked": True, "details": str(e)}

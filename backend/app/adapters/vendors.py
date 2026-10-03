# Provider adapter — genuine only, no fabricated verdicts
import os, requests, logging
from app.adapters.base import VENDOR_LIST, STATUSES

logger = logging.getLogger("cybersafe")

# If no provider API key / endpoint configured, return empty results with clear message.
CONFIGURED_PROVIDERS = {
    # Add real configurations here when keys/endorsed endpoints exist.
    # Example (commented — requires key):
    # "urlhaus": {"enabled": True, "endpoint": "...", "key_env": "URLHAUS_KEY"},
}


def check_providers(indicator: str, indicator_type: str = "url") -> dict:
    results = []
    checked = 0
    # Only genuinely configured providers are queried.
    for name, cfg in CONFIGURED_PROVIDERS.items():
        if not cfg.get("enabled"):
            results.append({
                "vendor": name,
                "status": "not_checked",
                "checked": False,
                "indicator_type": indicator_type,
                "details": "No request was made to this source.",
                "error": None,
                "source_timestamp": None,
            })
            continue
        # Real integration would call endpoint here with timeout + error handling.
        # For this build with no configured integrations:
        results.append({
            "vendor": name,
            "status": "not_checked",
            "checked": False,
            "indicator_type": indicator_type,
            "details": "Provider not configured.",
            "error": None,
            "source_timestamp": None,
        })
    # Build full vendor list with not_checked for unconfigured vendors
    full = []
    for v in VENDOR_LIST:
        found = next((r for r in results if r["vendor"] == v), None)
        if found:
            full.append(found)
        else:
            full.append({
                "vendor": v,
                "status": "not_checked",
                "checked": False,
                "indicator_type": indicator_type,
                "details": "No request was made to this source.",
                "error": None,
                "source_timestamp": None,
            })
    # Actual counts only from checked results
    checked = sum(1 for r in full if r["checked"])
    malicious = sum(1 for r in full if r["status"] == "malicious")
    suspicious = sum(1 for r in full if r["status"] == "suspicious")
    clean = sum(1 for r in full if r["status"] == "clean")
    unrated = sum(1 for r in full if r["status"] == "unrated")
    errors = sum(1 for r in full if r["status"] == "error")
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "scan_timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "providers_checked": checked,
        "results": full,
        "summary": {
            "vendors_checked": checked,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "unrated": unrated,
            "errors": errors,
        },
        "message": (
            "Vendor results are unavailable because no threat-intelligence providers are configured. "
            "The local CyberSafe analysis is shown separately."
            if checked == 0 else None
        ),
    }

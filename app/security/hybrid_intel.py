"""Optional reputation enrichment for CyberShield.

All lookups are reputation-only: files are queried by hash and URLs by URL
identifier. CyberShield never uploads a file from this module and never opens
the target URL.
"""
from __future__ import annotations
import base64, json, os, urllib.error, urllib.request
from typing import Any

VT_API = "https://www.virustotal.com/api/v3"

def _get(path: str, timeout: float = 5.0) -> dict[str, Any]:
    key = os.getenv("CYBERSHIELD_VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"enabled": False, "status": "NOT_CONFIGURED", "malicious": False}
    req = urllib.request.Request(f"{VT_API}{path}", headers={"x-apikey": key, "User-Agent": "CyberShield/25.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"enabled": True, "status": f"HTTP_{e.code}", "malicious": False}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return {"enabled": True, "status": "ERROR", "malicious": False}

def virus_total_hash(sha256: str) -> dict[str, Any]:
    if not sha256 or len(sha256) != 64:
        return {"enabled": False, "status": "INVALID_HASH", "malicious": False}
    raw = _get(f"/files/{sha256}")
    if raw.get("status") in {"NOT_CONFIGURED", "ERROR"} or not raw.get("data"):
        return raw
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0) > 0
    suspicious = int(stats.get("suspicious", 0) or 0)
    return {"enabled": True, "status": "THREAT" if malicious else "SUSPICIOUS" if suspicious else "CLEAN",
            "malicious": malicious, "suspicious": suspicious, "stats": stats,
            "reputation": attrs.get("reputation"), "type_description": attrs.get("type_description")}

def virus_total_url(url: str) -> dict[str, Any]:
    if not url:
        return {"enabled": False, "status": "INVALID_URL", "malicious": False}
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    raw = _get(f"/urls/{url_id}")
    if raw.get("status") in {"NOT_CONFIGURED", "ERROR"} or not raw.get("data"):
        # VT returns 404 when a URL has not been seen; that is not evidence of safety.
        return {"enabled": raw.get("enabled", True), "status": raw.get("status", "NOT_FOUND"), "malicious": False}
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0) > 0
    suspicious = int(stats.get("suspicious", 0) or 0) > 0
    return {"enabled": True, "status": "THREAT" if malicious else "SUSPICIOUS" if suspicious else "CLEAN",
            "malicious": malicious, "suspicious": suspicious, "stats": stats,
            "categories": attrs.get("categories", {})}

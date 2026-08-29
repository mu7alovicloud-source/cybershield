"""Optional real-world URL reputation lookups.

The local heuristic engine remains the first line. When a Google Safe Browsing
API key is configured, CyberShield can also ask Google's threat database about
URLs. No key means no remote request and the engine stays local-only.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def google_safe_browsing(url: str, timeout: float = 3.5) -> dict[str, Any]:
    key = os.getenv("CYBERSHIELD_GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not key:
        return {"enabled": False, "status": "NOT_CONFIGURED", "malicious": False}
    payload = {
        "client": {"clientId": "cybershield", "clientVersion": "25.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    req = urllib.request.Request(
        f"{GSB_URL}?key={key}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "CyberShield/25.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8")) if response else {}
        matches = data.get("matches") or []
        return {
            "enabled": True,
            "status": "THREAT" if matches else "CLEAN",
            "malicious": bool(matches),
            "matches": [
                {"threatType": m.get("threatType"), "platformType": m.get("platformType")}
                for m in matches[:8]
            ],
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"enabled": True, "status": "ERROR", "malicious": False, "error": type(exc).__name__}

"""Unified analysis service shared by desktop UI and local API."""
from __future__ import annotations
from pathlib import Path
from app.security.scanner import analyze_file
from app.security.advanced_detection import analyze_file_deep, analyze_url_deep
from app.ai.analyst import analyze_file_result, analyze_phishing_url
from app.database.database import add_scan, add_url_scan


def scan_file(path: str | Path) -> dict:
    result = analyze_file_deep(path, endpoint_scan=True, reputation=True)
    ai = analyze_file_result(result)
    result = {**result, "ai": ai}
    try:
        add_scan(result["path"], result["sha256"], ai["score"], ai["level"], result.get("evidence"))
    except Exception:
        # Analysis must still be usable if the local DB is temporarily locked.
        pass
    return result


def scan_url(url: str) -> dict:
    result = analyze_url_deep(url, reputation=True)
    try:
        add_url_scan(url, result["score"], result["level"], result["confidence"], result.get("reasons"))
    except Exception:
        pass
    return {"url": url, "ai": result}

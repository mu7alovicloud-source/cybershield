"""Minimal Vercel health API for the CyberShield repository.

The real CyberShield application is a Windows desktop/PySide6 program.
Vercel only exposes this small health/version API; it never starts the
desktop GUI, background protection, scanner, or local database.
"""
from pathlib import Path

from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[1]
version_file = ROOT / "VERSION.txt"
VERSION = version_file.read_text(encoding="utf-8").splitlines()[0] if version_file.exists() else "CyberShield"

app = FastAPI(title="CyberShield Release API", version="1.0.0")


@app.get("/api")
def api_root():
    return {
        "ok": True,
        "service": "CyberShield",
        "release": VERSION,
        "desktop_entrypoint": "python -m app.main",
        "web_deployment": "health-api-only",
    }


@app.get("/api/health")
def health():
    return {"ok": True, "release": VERSION}


@app.get("/api/version")
def version():
    return {
        "release": VERSION,
        "canonical_entrypoint": "python -m app.main",
    }

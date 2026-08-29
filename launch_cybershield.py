"""Launcher for the standalone CyberShield Desktop edition.

The extracted desktop build intentionally has no web/server dependency. This
prevents the old launcher from trying to import a removed ``server`` package.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _run(module: str, *args: str) -> int:
    return subprocess.call([sys.executable, "-m", module, *args], cwd=str(ROOT))


def start_desktop() -> int:
    print("[CyberShield] Starting standalone desktop protection...")
    return _run("app.main")


def start_terminal(*args: str) -> int:
    # Keep the CLI independent from the optional Qt desktop dependency.
    return subprocess.call([sys.executable, str(ROOT / "main.py"), "terminal", *args], cwd=str(ROOT))


MODES = {"desktop": start_desktop, "terminal": start_terminal, "security-terminal": start_terminal}


if __name__ == "__main__":
    mode = (sys.argv[1] if len(sys.argv) > 1 else "desktop").strip().lower()
    fn = MODES.get(mode)
    if fn is None:
        print("Usage: python launch_cybershield.py [desktop|terminal]")
        raise SystemExit(2)
    raise SystemExit(fn())

"""Safe terminal-like inspection for CyberShield AI.

This module intentionally exposes *read-only* inspection primitives.  It does
not provide arbitrary shell execution, command injection, file deletion, or
process termination.  The AI can inspect a Windows host broadly and return
structured evidence that can be fed into the reasoning layer.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _run_readonly(command: list[str], timeout: float = 4.0) -> tuple[bool, str]:
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                           shell=False, stdin=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or p.stderr or "").strip()
        return p.returncode == 0, out[:12000]
    except Exception as exc:
        return False, f"inspection unavailable: {type(exc).__name__}"


def system_identity() -> dict[str, Any]:
    return {
        "platform": platform.platform(), "os": os.name, "release": platform.release(),
        "version": platform.version(), "machine": platform.machine(),
        "python": platform.python_version(), "hostname": platform.node(),
        "cpu_count": os.cpu_count() or 1,
    }


def disk_snapshot() -> dict[str, Any]:
    rows = []
    if os.name == "nt":
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            root = Path(f"{letter}:\\")
            if root.exists():
                try:
                    u = shutil.disk_usage(root)
                    rows.append({"drive": str(root), "total": u.total, "used": u.used,
                                 "free": u.free, "percent": round(u.used / max(1, u.total) * 100, 1)})
                except OSError:
                    pass
    else:
        u = shutil.disk_usage("/")
        rows.append({"drive": "/", "total": u.total, "used": u.used, "free": u.free,
                     "percent": round(u.used / max(1, u.total) * 100, 1)})
    return {"drives": rows}


def windows_services() -> dict[str, Any]:
    if os.name != "nt":
        return {"available": False, "services": []}
    ok, out = _run_readonly(["sc.exe", "query", "state=", "all"], 8)
    if not ok:
        return {"available": False, "error": out}
    services = []
    name = state = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("SERVICE_NAME:"):
            name = s.split(":", 1)[1].strip()
        elif s.startswith("STATE") and ":" in s:
            state = s.split(":", 1)[1].strip()
            if name:
                services.append({"name": name, "state": state})
                name = None
    return {"available": True, "count": len(services), "services": services[:300]}


def startup_entries() -> dict[str, Any]:
    if os.name != "nt":
        return {"available": False, "entries": []}
    ok, out = _run_readonly(["schtasks.exe", "/Query", "/FO", "CSV", "/NH"], 10)
    if not ok:
        return {"available": False, "error": out}
    entries = []
    import csv, io
    try:
        for row in csv.reader(io.StringIO(out)):
            if len(row) >= 3:
                entries.append({"task": row[0], "next_run": row[1], "status": row[2]})
    except Exception:
        pass
    return {"available": True, "count": len(entries), "tasks": entries[:500]}


def security_products() -> dict[str, Any]:
    if os.name != "nt":
        return {"available": False, "products": []}
    # PowerShell is used only for a fixed, read-only Defender query.
    ps = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
          "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureVersion | ConvertTo-Json -Compress"]
    ok, out = _run_readonly(ps, 8)
    return {"available": ok, "raw": out}


def environment_summary() -> dict[str, Any]:
    # Do not expose secret-looking values.  Only names and safe runtime facts.
    secret_words = ("key", "token", "secret", "password", "passwd", "credential")
    names = sorted(k for k in os.environ if not any(w in k.lower() for w in secret_words))
    return {"variable_names": names[:300], "count": len(names)}


def inspect_host() -> dict[str, Any]:
    """Collect a broad, read-only host inventory in one bounded operation."""
    return {
        "identity": system_identity(),
        "disks": disk_snapshot(),
        "services": windows_services(),
        "scheduled_tasks": startup_entries(),
        "security_products": security_products(),
        "environment": environment_summary(),
    }

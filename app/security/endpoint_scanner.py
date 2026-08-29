"""Bounded real endpoint scan orchestration.

Quick scan inspects high-value user locations and executable paths from running
processes without opening or executing files. Full scan is deliberately explicit
and bounded by a configurable file count/byte budget.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app.security.scanner import analyze_file, EXECUTABLE_EXTENSIONS
from app.security.process_monitor import get_processes
from app.security.defender_scan import scan_file_with_defender


def _candidate_roots() -> list[Path]:
    roots: list[Path] = []
    home = Path.home()
    for name in ("Desktop", "Downloads", "Documents", "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"):
        p = home / name
        if p.exists():
            roots.append(p)
    temp = Path(os.environ.get("TEMP", ""))
    if temp.exists():
        roots.append(temp)
    return list(dict.fromkeys(roots))


def _scan_paths(paths: list[Path], limit: int, max_bytes: int) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned = 0
    bytes_seen = 0
    errors: list[str] = []
    for root in paths:
        if not root.exists():
            continue
        iterator = [root] if root.is_file() else root.rglob("*")
        for p in iterator:
            if scanned >= limit or bytes_seen >= max_bytes:
                break
            try:
                if not p.is_file() or p.is_symlink():
                    continue
                size = p.stat().st_size
                if size > max_bytes - bytes_seen:
                    continue
                # Quick endpoint triage focuses on executables/scripts and small files
                # likely to represent persistence payloads.
                if p.suffix.lower() not in EXECUTABLE_EXTENSIONS and size > 8 * 1024 * 1024:
                    continue
                r = analyze_file(p)
                scanned += 1
                bytes_seen += size
                if r.get("risk", 0) >= 20 or r.get("verdict") not in {"CLEAN", "UNKNOWN"}:
                    findings.append(r)
            except (OSError, PermissionError) as exc:
                errors.append(f"{p}: {type(exc).__name__}")
    return {"scanned_files": scanned, "bytes_seen": bytes_seen, "findings": findings, "errors": errors[:50]}


def quick_scan(include_defender: bool = True) -> dict[str, Any]:
    """Run a real, bounded endpoint triage without executing any sample."""
    process_paths: list[Path] = []
    for row in get_processes(80):
        exe = row.get("exe")
        if exe:
            p = Path(str(exe))
            if p.exists() and p.is_file():
                process_paths.append(p)
    result = _scan_paths(list(dict.fromkeys(_candidate_roots() + process_paths)), limit=250, max_bytes=512 * 1024 * 1024)
    defender = None
    if include_defender and os.name == "nt":
        # Quick Defender scan is the primary endpoint AV signal.
        exe = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
        if exe.exists():
            try:
                proc = __import__("subprocess").run(
                    [str(exe), "-Scan", "-ScanType", "1"], capture_output=True, text=True,
                    timeout=180, shell=False, stdin=__import__("subprocess").DEVNULL,
                    creationflags=getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0),
                )
                defender = {"available": True, "status": "COMPLETED" if proc.returncode == 0 else "THREAT_OR_ERROR", "exit_code": proc.returncode, "output": ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-8000:]}
            except Exception as exc:
                defender = {"available": True, "status": "ERROR", "error": type(exc).__name__}
        else:
            defender = {"available": False, "status": "UNAVAILABLE"}
    result["defender"] = defender
    result["execution_performed"] = False
    result["scan_mode"] = "QUICK_ENDPOINT_TRIAGE"
    return result

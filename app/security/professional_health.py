"""Non-destructive professional health and repair helpers.

These routines deliberately avoid changing application source, Windows security
settings, or user files.  They only inspect runtime state and, for safe_repair,
create CyberShield's own data directories and initialize its local database.
"""
from __future__ import annotations

import importlib
import platform
import shutil
import time
from pathlib import Path
from typing import Any

from app.config import DATABASE_FILE
from app.database.database import initialize_database

CORE_MODULES = (
    "app.security.scanner",
    "app.security.quarantine",
    "app.security.process_monitor",
    "app.security.phishing_guard",
    "app.security.threat_correlator",
    "app.security.sandbox_runner",
    "app.ai.cybershield_terminal",
)
TOOLS = ("git", "gh", "vercel", "pyinstaller")


def _tool_status() -> dict[str, bool]:
    return {tool: bool(shutil.which(tool)) for tool in TOOLS}


def doctor(root: Path) -> dict[str, Any]:
    """Run bounded, read-only application diagnostics."""
    root = root.resolve()
    modules: dict[str, str] = {}
    for name in CORE_MODULES:
        try:
            importlib.import_module(name)
            modules[name] = "PASS"
        except Exception as exc:  # pragma: no cover - platform/dependency dependent
            modules[name] = f"FAIL: {type(exc).__name__}: {exc}"
    expected_dirs = [
        root / "data" / "logs",
        root / "data" / "quarantine",
        root / "data" / "samples",
        root / "data" / "lab",
    ]
    dirs = {str(p.relative_to(root)): p.is_dir() for p in expected_dirs}
    return {
        "ok": all(v == "PASS" for v in modules.values()),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "root": str(root),
        "database": str(DATABASE_FILE),
        "database_exists": Path(DATABASE_FILE).exists(),
        "core_modules": modules,
        "data_directories": dirs,
        "external_tools": _tool_status(),
        "policy": "read-only; no source files, security settings, or user files modified",
    }


def safe_repair(root: Path) -> dict[str, Any]:
    """Repair only CyberShield-owned runtime prerequisites.

    No source code is edited, no files are deleted, and no Windows security
    configuration is changed.
    """
    root = root.resolve()
    created: list[str] = []
    for rel in ("data/logs", "data/quarantine", "data/samples", "data/lab"):
        p = root / rel
        if not p.exists():
            p.mkdir(parents=True, exist_ok=True)
            created.append(rel)
    initialize_database()
    return {
        "ok": True,
        "created_directories": created,
        "database_ready": Path(DATABASE_FILE).exists(),
        "changed_source": False,
        "deleted_files": False,
        "changed_windows_security": False,
    }


def performance(root: Path) -> dict[str, Any]:
    """Cheap performance readiness check; does not stress the machine."""
    start = time.perf_counter()
    result = doctor(root)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    result["diagnostic_latency_ms"] = elapsed_ms
    result["bounded_analysis_policy"] = {
        "max_parallel_workers": 8,
        "max_directory_files": 5000,
        "target_execution": "BLOCKED",
        "large_file_reads": "chunked",
    }
    return result

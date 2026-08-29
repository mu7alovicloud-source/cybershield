"""Fast Windows process containment layer.

This is a defensive user-mode guard. It does not execute samples. It watches
new processes, statically analyzes their executable, optionally asks Microsoft
Defender to scan the exact file, and can terminate/quarantine high-confidence
malicious processes. It is intentionally conservative around Windows/system
paths.

A Python user-mode application cannot guarantee true pre-execution prevention;
that requires an OS security driver/EDR or Microsoft Defender's own enforcement.
This module therefore provides rapid post-process-creation containment.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

import psutil

from app.security.containment_engine import assess_containment, contain_if_safe
from app.security.defender_scan import scan_file_with_defender

PROTECTED = (
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
    "\\windows\\servicing\\", "\\boot\\", "\\efi\\", "\\recovery\\",
)


class ExecutionGuard:
    def __init__(self, interval: float = 0.35):
        self.interval = max(0.2, float(interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: set[int] = set()
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.enabled = os.name == "nt"

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if not self.enabled or self.running:
            return
        self._seen = {p.pid for p in psutil.process_iter(["pid"]) if p.info.get("pid")}
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="CyberShieldExecutionGuard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    @staticmethod
    def _protected(exe: Path) -> bool:
        p = str(exe).replace("/", "\\").lower()
        return any(x in p for x in PROTECTED)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.scan_once()
            except Exception as exc:
                self._record({"type": "execution_guard_error", "error": type(exc).__name__})

    def scan_once(self) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        actions: list[dict[str, Any]] = []
        current: set[int] = set()
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = int(proc.info["pid"])
                current.add(pid)
                if pid in self._seen:
                    continue
                exe_raw = proc.info.get("exe")
                if not exe_raw:
                    continue
                exe = Path(str(exe_raw))
                if not exe.is_file() or self._protected(exe):
                    continue
                assessment = assess_containment(exe)
                # Defender is an independent evidence source for executable threats.
                defender = None
                if assessment.get("risk", 0) >= 60 or assessment.get("verdict") in {"MALICIOUS", "LIKELY MALICIOUS"}:
                    defender = scan_file_with_defender(exe, timeout=25)
                strong = assessment.get("allowed", False)
                defender_output = str((defender or {}).get("output", "")).lower()
                defender_threat = bool(
                    defender
                    and defender.get("status") == "THREAT_OR_ERROR"
                    and any(token in defender_output for token in ("threat", "malware", "virus", "found"))
                )
                if strong or (defender_threat and assessment.get("risk", 0) >= 65):
                    terminated = False
                    try:
                        proc.terminate()
                        proc.wait(timeout=1.5)
                        terminated = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                        try:
                            proc.kill()
                            terminated = True
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    containment = contain_if_safe(exe, automatic=True) if terminated else {"contained": False}
                    event = {
                        "type": "malicious_process_contained" if containment.get("contained") else "malicious_process_block_attempt",
                        "pid": pid,
                        "process": proc.info.get("name") or "Unknown",
                        "path": str(exe),
                        "terminated": terminated,
                        "contained": bool(containment.get("contained")),
                        "risk": assessment.get("risk", 0),
                        "confidence": assessment.get("confidence", 0),
                        "verdict": assessment.get("verdict"),
                        "defender": defender,
                    }
                    self._record(event)
                    actions.append(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
        self._seen = current
        return actions

    def _record(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)
            del self.events[:-500]

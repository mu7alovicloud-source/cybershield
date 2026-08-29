"""Always-on local protection coordinator."""
from __future__ import annotations

import ctypes
import re
import threading
from pathlib import Path

from app.security.scanner import analyze_file
from app.security.advanced_detection import analyze_file_deep, analyze_url_deep
from app.security.quarantine import quarantine_file
from app.security.phishing_guard import analyze_url
from app.security.containment_engine import contain_if_safe
from app.security.execution_guard import ExecutionGuard
from app.security.realtime_files import RealtimeFileGuard

WATCH_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf",
    ".wsh", ".msi", ".msp", ".jar", ".reg", ".url", ".website", ".html",
    ".htm", ".lnk",
}
PHISHING_EXTENSIONS = {".url", ".website", ".html", ".htm"}
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)


class BackgroundProtection:
    MAX_FILES_PER_CYCLE = 500
    PROCESS_RISK = 90
    PROCESS_CONFIDENCE = 0.95
    """Quiet protection engine used by both the desktop UI and service mode.

    Layers:
      1. event-driven filesystem monitoring (watchdog) with a polling fallback;
      2. fast Windows process creation monitoring;
      3. clipboard URL analysis;
      4. explainable static malware analysis + reversible quarantine.
    """
    def __init__(self, interval=1.5, clipboard=True):
        self.interval = max(0.5, float(interval))
        self._stop = threading.Event()
        self._thread = None
        self.events = []
        self._lock = threading.Lock()
        self.clipboard_enabled = bool(clipboard)
        self._last_clipboard = ""
        self.execution_guard = ExecutionGuard(interval=0.35)
        self.file_guard = None

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.execution_guard.start()
        self.file_guard = RealtimeFileGuard(self._roots(), self._record)
        self.file_guard.start()
        self._thread = threading.Thread(target=self._run, name="CyberShieldProtection", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self.execution_guard.stop()
        if self.file_guard:
            self.file_guard.stop()
            self.file_guard = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _roots(self):
        home = Path.home()
        return [p for p in (home / "Downloads", home / "Desktop", home / "Documents") if p.is_dir()]

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                # Process guard is independently faster; this catches environments
                # where watchdog is unavailable and also gives periodic confirmation.
                self.execution_guard.scan_once()
                if self.clipboard_enabled:
                    self.scan_clipboard_url()
            except Exception as exc:
                self._record({"type": "engine_error", "error": str(exc)})

    def scan_once(self):
        actions = []
        # Public compatibility method: perform a synchronous endpoint pass.
        scanned = 0
        for root in self._roots():
            try:
                for path in root.rglob("*"):
                    if self._stop.is_set() or scanned >= self.MAX_FILES_PER_CYCLE:
                        break
                    if not path.is_file() or path.suffix.lower() not in WATCH_EXTENSIONS:
                        continue
                    scanned += 1
                    result = self._inspect(path)
                    if result:
                        actions.append(result)
            except (OSError, PermissionError):
                continue
        actions.extend(self.execution_guard.scan_once())
        return actions

    def scan_clipboard_url(self):
        value = self._read_clipboard()
        if not value or value == self._last_clipboard or len(value) > 4096:
            return None
        self._last_clipboard = value
        m = URL_RE.search(value.strip())
        if not m:
            return None
        url = m.group(0).rstrip(".,);'")
        analysis = analyze_url_deep(url, reputation=True)
        event = {"type": "clipboard_url_analyzed", "url": url, "analysis": analysis}
        if analysis.get("score", 0) >= 80:
            event["action"] = "BLOCK_RECOMMENDED"
        self._record(event)
        return event

    @staticmethod
    def _read_clipboard():
        if not hasattr(ctypes, "windll"):
            return None
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            if not user32.OpenClipboard(0):
                return None
            try:
                handle = user32.GetClipboardData(13)
                if not handle:
                    return None
                kernel32.GlobalLock.restype = ctypes.c_wchar_p
                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    return None
                try:
                    return ctypes.wstring_at(ptr)
                finally:
                    kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()
        except Exception:
            return None

    def _inspect(self, path):
        ext = path.suffix.lower()
        if ext in PHISHING_EXTENSIONS:
            url = self._extract_url(path)
            if url:
                analysis = analyze_url_deep(url, reputation=True)
                if analysis.get("score", 0) >= 80:
                    q = quarantine_file(path)
                    event = {"type": "phishing_contained", "path": str(path), "quarantine": str(q), "analysis": analysis}
                    self._record(event)
                    return event
                event = {"type": "phishing_review", "path": str(path), "analysis": analysis}
                self._record(event)
                return event
            return None
        result = analyze_file_deep(path, endpoint_scan=True, reputation=True)
        if result.get("risk", 0) >= 85 and result.get("confidence", 0) >= .90 and result.get("verdict") in {"MALICIOUS", "LIKELY MALICIOUS"}:
            containment = contain_if_safe(path, automatic=True)
            if containment.get("contained"):
                event = {"type": "malware_contained", "path": str(path), "quarantine": containment.get("quarantine_path"), "analysis": result, "verification": containment.get("verification", {})}
                self._record(event)
                return event
            event = {"type": "malware_high_risk_review", "path": str(path), "analysis": result, "reason": containment.get("reason", "policy_refused")}
            self._record(event)
            return event
        return None

    @staticmethod
    def _extract_url(path):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:250000]
        except OSError:
            return None
        if path.suffix.lower() in {".url", ".website"}:
            for line in text.splitlines():
                if line.strip().lower().startswith("url="):
                    return line.split("=", 1)[1].strip()
        m = URL_RE.search(text)
        return m.group(0) if m else None

    def _record(self, event):
        with self._lock:
            self.events.append(event)
            del self.events[:-500]

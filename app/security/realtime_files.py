"""Real-time file creation/move monitoring with a polling fallback."""
from __future__ import annotations

import queue
import threading
import time
from pathlib import Path
from typing import Callable

from app.security.scanner import EXECUTABLE_EXTENSIONS, analyze_file
from app.security.advanced_detection import analyze_file_deep
from app.security.containment_engine import contain_if_safe

WATCH_EXTENSIONS = EXECUTABLE_EXTENSIONS | {".url", ".website", ".html", ".htm", ".lnk"}


class RealtimeFileGuard:
    def __init__(self, roots: list[Path], on_event: Callable[[dict], None] | None = None):
        self.roots = [Path(p) for p in roots if Path(p).is_dir()]
        self.on_event = on_event or (lambda _event: None)
        self._observer = None
        self._stop = threading.Event()
        self._fallback: threading.Thread | None = None
        self._seen: dict[str, tuple[int, int]] = {}
        self._queue: queue.Queue[Path] = queue.Queue(maxsize=128)
        self._worker: threading.Thread | None = None
        self._queued: set[str] = set()
        self._lock = threading.Lock()
        self._recent: dict[str, tuple[int, int, float]] = {}

    def start(self) -> None:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            self._start_fallback()
            return

        guard = self
        class Handler(FileSystemEventHandler):
            def _check(self, path: str) -> None:
                guard.inspect(Path(path))
            def on_created(self, event):
                if not event.is_directory: self._check(event.src_path)
            def on_moved(self, event):
                if not event.is_directory: self._check(event.dest_path)

        self._stop.clear()
        self._worker = threading.Thread(target=self._worker_loop, name="CyberShieldFileAnalysis", daemon=True)
        self._worker.start()
        observer = Observer()
        handler = Handler()
        for root in self.roots:
            observer.schedule(handler, str(root), recursive=True)
        observer.start()
        self._observer = observer

    def stop(self) -> None:
        self._stop.set()
        if self._observer:
            self._observer.stop(); self._observer.join(timeout=3); self._observer = None
        if self._fallback and self._fallback.is_alive():
            self._fallback.join(timeout=2)
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=3)
        self._worker = None
        with self._lock:
            self._queued.clear()

    def inspect(self, path: Path) -> None:
        """Queue analysis so filesystem callbacks never perform heavy work."""
        try:
            path = Path(path)
            if not path.is_file() or path.suffix.lower() not in WATCH_EXTENSIONS:
                return
            key = str(path.resolve())
            with self._lock:
                if key in self._queued:
                    return
                self._queued.add(key)
            try:
                self._queue.put_nowait(path)
            except queue.Full:
                with self._lock:
                    self._queued.discard(key)
                self.on_event({"type": "realtime_queue_full", "path": str(path), "action": "DEFERRED"})
        except (OSError, PermissionError):
            return

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            key = str(path.resolve())
            try:
                try:
                    st = path.stat()
                    now = time.monotonic()
                    recent = self._recent.get(key)
                    signature = (int(st.st_size), int(st.st_mtime_ns))
                    if recent and recent[:2] == signature and now - recent[2] < 30.0:
                        continue
                except OSError:
                    continue
                result = analyze_file_deep(path, endpoint_scan=True, reputation=True)
                try:
                    self._recent[key] = (int(st.st_size), int(st.st_mtime_ns), time.monotonic())
                except OSError:
                    pass
                if result.get("risk", 0) >= 85 and result.get("confidence", 0) >= 0.90 and result.get("verdict") in {"MALICIOUS", "LIKELY MALICIOUS"}:
                    containment = contain_if_safe(path, automatic=True)
                    event = {"type": "realtime_file_containment", "path": str(path), "analysis": result, "containment": containment}
                else:
                    event = {"type": "realtime_file_analyzed", "path": str(path), "analysis": result}
                self.on_event(event)
            except (OSError, PermissionError) as exc:
                self.on_event({"type": "realtime_file_error", "path": str(path), "error": type(exc).__name__})
            except Exception as exc:
                self.on_event({"type": "realtime_file_error", "path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            finally:
                with self._lock:
                    self._queued.discard(key)
                self._queue.task_done()

    def _start_fallback(self) -> None:
        self._stop.clear()
        self._fallback = threading.Thread(target=self._poll, name="CyberShieldFileFallback", daemon=True)
        self._fallback.start()

    def _poll(self) -> None:
        while not self._stop.wait(1.0):
            for root in self.roots:
                try:
                    for p in root.rglob("*"):
                        if self._stop.is_set() or not p.is_file() or p.suffix.lower() not in WATCH_EXTENSIONS:
                            continue
                        try: st = p.stat()
                        except OSError: continue
                        key = str(p.resolve()); sig = (st.st_size, st.st_mtime_ns)
                        if self._seen.get(key) == sig or st.st_size == 0:
                            continue
                        self._seen[key] = sig
                        self.inspect(p)
                except (OSError, PermissionError):
                    continue

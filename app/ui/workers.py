"""Small Qt workers used to keep security scans off the GUI thread."""
from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, QThread, Signal


class FunctionWorker(QObject):
    """Run one callable in a dedicated QThread and report success/failure."""

    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, fn: Callable[[], Any]):
        super().__init__()
        self.fn = fn

    def run(self) -> None:
        try:
            self.finished.emit(self.fn())
        except Exception as exc:  # pragma: no cover - depends on runtime/OS
            self.failed.emit(f"{type(exc).__name__}: {exc}")


def start_worker(owner: QObject, fn: Callable[[], Any], on_done, on_error):
    """Start a worker and return its QThread; owner keeps the thread alive."""
    thread = QThread(owner)
    worker = FunctionWorker(fn)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.finished.connect(on_done)
    worker.failed.connect(on_error)
    worker.finished.connect(thread.quit)
    worker.failed.connect(thread.quit)
    worker.finished.connect(worker.deleteLater)
    worker.failed.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    # Keep strong references until the Qt thread has stopped.
    if not hasattr(owner, "_worker_threads"):
        owner._worker_threads = []
    owner._worker_threads.append(thread)

    def cleanup():
        try:
            owner._worker_threads.remove(thread)
        except (ValueError, AttributeError):
            pass

    thread.finished.connect(cleanup)
    thread.start()
    return thread

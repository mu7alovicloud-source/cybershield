"""Efficient filesystem metadata monitoring for defensive detection."""
from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Iterable


class FileMonitor:
    def __init__(self, directory):
        self.directory = Path(directory)

    def list_files(self):
        if not self.directory.exists():
            return []
        try:
            return [str(p) for p in self.directory.rglob("*") if p.is_file()]
        except OSError:
            return []

    def snapshot(self):
        snap = {}
        if not self.directory.exists():
            return snap
        try:
            iterator = self.directory.rglob("*")
            for p in iterator:
                if p.is_file():
                    try:
                        st = p.stat()
                        snap[str(p)] = (st.st_size, st.st_mtime_ns)
                    except OSError:
                        continue
        except OSError:
            pass
        return snap

    @staticmethod
    def diff(before, after):
        return {
            "created": sorted(set(after) - set(before)),
            "deleted": sorted(set(before) - set(after)),
            "modified": sorted(k for k in set(before) & set(after) if before[k] != after[k]),
        }

    @staticmethod
    def events_from_diff(diff: dict, *, timestamp: float | None = None) -> list[dict]:
        ts = monotonic() if timestamp is None else float(timestamp)
        events = []
        for action in ("created", "deleted", "modified"):
            for path in diff.get(action, ()):
                events.append({"path": str(path), "action": action, "timestamp": ts})
        # Rename attribution requires a platform event source; do not guess it
        # from filenames. A later Windows event backend can supply old_path/new_path.
        return events

    @staticmethod
    def summarize(diff: dict) -> dict:
        counts = {k: len(diff.get(k, ())) for k in ("created", "deleted", "modified")}
        total = sum(counts.values())
        extensions = {}
        for action in counts:
            for path in diff.get(action, ()):
                suffix = Path(path).suffix.lower()
                if suffix:
                    extensions[suffix] = extensions.get(suffix, 0) + 1
        return {"counts": counts, "total": total, "extensions": extensions}

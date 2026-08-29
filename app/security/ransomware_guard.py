"""Defensive ransomware-behavior heuristics.

Static, metadata-only detection. This module never executes samples and never
creates ransomware. It aggregates filesystem activity over bounded time windows
and emits explainable assessments/evidence for the central risk pipeline.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Iterable, Mapping


@dataclass(frozen=True)
class RansomwareAssessment:
    score: int
    confidence: float
    level: str
    indicators: tuple[str, ...] = ()
    affected_paths: tuple[str, ...] = ()
    process_context: Mapping[str, object] = field(default_factory=dict)
    evidence: tuple[dict, ...] = ()
    recommended_action: str = "MONITOR"


def _level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def detect_mass_extension_changes(paths: Iterable[object], threshold: int = 20):
    """Backward-compatible extension counter used by existing callers."""
    threshold = max(1, int(threshold))
    counts = Counter(Path(p).suffix.lower() for p in paths if Path(p).suffix)
    return {ext: n for ext, n in counts.items() if n >= threshold}


def assess_activity(*, events: Iterable[Mapping[str, object]] = (),
                    window_seconds: float = 60.0,
                    process_context: Mapping[str, object] | None = None) -> RansomwareAssessment:
    """Assess a bounded batch of filesystem events without destructive actions.

    Events may contain: path, action (created/modified/deleted/renamed),
    timestamp, old_path, new_path, extension, process_name/pid.
    """
    now = monotonic()
    window = max(1.0, float(window_seconds))
    recent = []
    for raw in events:
        e = dict(raw)
        try:
            ts = float(e.get("timestamp", now))
        except (TypeError, ValueError):
            ts = now
        # Accept monotonic timestamps and tolerate wall-clock-like values by
        # keeping events with no usable age information.
        if ts <= now and now - ts <= window:
            recent.append(e)
        elif "timestamp" not in e:
            recent.append(e)

    actions = Counter(str(e.get("action", "modified")).lower() for e in recent)
    paths = [str(e.get("path") or e.get("new_path") or "") for e in recent]
    paths = [p for p in paths if p]
    extensions = Counter(Path(p).suffix.lower() for p in paths if Path(p).suffix)
    changed = sum(actions[a] for a in ("modified", "created", "deleted", "renamed"))
    renamed = actions["renamed"]
    deleted = actions["deleted"]
    modified = actions["modified"]

    indicators: list[str] = []
    score = 0
    if changed >= 100:
        score += 35; indicators.append("very_high_file_activity")
    elif changed >= 50:
        score += 25; indicators.append("high_file_activity")
    elif changed >= 20:
        score += 12; indicators.append("elevated_file_activity")

    if renamed >= 20:
        score += 25; indicators.append("mass_rename_activity")
    elif renamed >= 8:
        score += 12; indicators.append("rename_burst")

    if deleted >= 30:
        score += 15; indicators.append("high_delete_activity")
    if modified >= 50:
        score += 10; indicators.append("mass_modification_activity")

    extension_burst = max(extensions.values(), default=0)
    if extension_burst >= 30:
        score += 20; indicators.append("mass_extension_transition")
    elif extension_burst >= 15:
        score += 8; indicators.append("extension_burst")

    score = min(100, score)
    # Independent behavioral indicators raise confidence; a single weak signal
    # remains intentionally conservative.
    confidence = min(0.99, 0.45 + 0.08 * len(indicators))
    level = _level(score)
    action = "CONTAIN_AND_INVESTIGATE" if score >= 85 else "INVESTIGATE" if score >= 65 else "MONITOR"

    evidence = tuple({
        "source": "ransomware_guard",
        "category": "file",
        "indicator": indicator,
        "score": min(100, max(0, score if len(indicators) > 1 else score // 2)),
        "confidence": confidence,
        "reason": indicator.replace("_", " "),
        "metadata": {"event_count": changed, "window_seconds": window},
    } for indicator in indicators)

    return RansomwareAssessment(score, round(confidence, 2), level,
                                tuple(indicators), tuple(paths[-200:]),
                                dict(process_context or {}), evidence, action)


class RansomwareBehaviorMonitor:
    """Bounded in-memory activity aggregator for continuous protection."""
    def __init__(self, window_seconds: float = 60.0, max_events: int = 5000):
        self.window_seconds = max(1.0, float(window_seconds))
        self._events = deque(maxlen=max(100, int(max_events)))
        self._lock = RLock()

    def record(self, path: object, action: str = "modified", *, timestamp: float | None = None,
               process_name: str | None = None, pid: int | None = None,
               old_path: object | None = None) -> None:
        event = {"path": str(path), "action": str(action).lower(),
                 "timestamp": monotonic() if timestamp is None else float(timestamp)}
        if process_name: event["process_name"] = process_name
        if pid is not None: event["pid"] = pid
        if old_path is not None: event["old_path"] = str(old_path)
        with self._lock:
            self._events.append(event)
            self._prune()

    def _prune(self):
        cutoff = monotonic() - self.window_seconds
        while self._events and float(self._events[0].get("timestamp", cutoff)) < cutoff:
            self._events.popleft()

    def snapshot(self) -> list[dict]:
        with self._lock:
            self._prune()
            return [dict(e) for e in self._events]

    def assess(self, process_context: Mapping[str, object] | None = None) -> RansomwareAssessment:
        return assess_activity(events=self.snapshot(), window_seconds=self.window_seconds,
                               process_context=process_context)

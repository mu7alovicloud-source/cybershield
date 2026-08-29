"""Advanced defensive AI intelligence layer.

This layer adds bounded planning, evidence quality scoring, contradiction
tracking, and a next-best-observation selector.  It is deliberately read-only:
AI recommendations cannot directly execute OS commands or destructive actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from app.ai.agent_tools import ToolResult


@dataclass(frozen=True)
class Evidence:
    statement: str
    source: str
    kind: str
    confidence: float
    independence: str
    polarity: str = "supporting"  # supporting | counter | neutral


@dataclass
class IntelligenceReport:
    risk_score: int = 0
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    next_tools: list[str] = field(default_factory=list)

    @property
    def decision_band(self) -> str:
        if self.risk_score >= 85 and self.confidence >= .78:
            return "HIGH_CONFIDENCE_HIGH_RISK"
        if self.risk_score >= 60:
            return "ELEVATED_REVIEW"
        if self.risk_score >= 30:
            return "MONITOR"
        return "LOW_EVIDENCE_RISK"


def _add_unique(items: list[Evidence], item: Evidence) -> None:
    key = (item.source, item.independence, item.statement)
    if not any((x.source, x.independence, x.statement) == key for x in items):
        items.append(item)


def evaluate_results(results: Iterable[ToolResult]) -> IntelligenceReport:
    """Turn telemetry into calibrated evidence without pretending heuristics are proof."""
    report = IntelligenceReport()
    successful = 0
    independent = set()
    supporting_weight = 0.0
    counter_weight = 0.0

    for result in results:
        if not result.ok:
            report.unknown.append(f"{result.name}: telemetry unavailable")
            continue
        successful += 1
        data = result.data or {}

        if result.name == "system_health":
            cpu = float((data.get("cpu") or {}).get("total_cpu", 0) or 0)
            _add_unique(report.evidence, Evidence(
                f"System health telemetry collected; CPU {cpu:.1f}%.", result.name,
                "telemetry", .99, "system"))
            if cpu >= 90:
                _add_unique(report.evidence, Evidence(
                    f"CPU usage is very high ({cpu:.1f}%).", result.name,
                    "resource", .62, "cpu", "supporting"))
                independent.add("cpu")
                supporting_weight += 4

        elif result.name == "host_snapshot":
            _add_unique(report.evidence, Evidence(
                "Host snapshot was collected successfully.", result.name,
                "telemetry", .99, "host"))
            mem = float((data.get("memory") or {}).get("percent", 0) or 0)
            disk = float((data.get("disk") or {}).get("percent", 0) or 0)
            if mem >= 95:
                _add_unique(report.evidence, Evidence(
                    f"Memory pressure is high ({mem:.1f}%).", result.name,
                    "resource", .65, "memory"))
                independent.add("memory"); supporting_weight += 3
            if disk >= 95:
                _add_unique(report.evidence, Evidence(
                    f"Disk utilization is high ({disk:.1f}%).", result.name,
                    "resource", .68, "disk"))
                independent.add("disk"); supporting_weight += 2

        elif result.name == "process_snapshot":
            candidates = data.get("review_candidates") or []
            count = int(data.get("count", 0) or 0)
            _add_unique(report.evidence, Evidence(
                f"Process telemetry observed {count} processes.", result.name,
                "process", .99, "process-inventory"))
            if candidates:
                _add_unique(report.evidence, Evidence(
                    f"{len(candidates)} process(es) merit review under conservative heuristics; this is not proof of malware.",
                    result.name, "process-review", .68, "process-review"))
                independent.add("process-review")
                supporting_weight += min(10, 3 * len(candidates))

        elif result.name == "network_snapshot":
            established = data.get("established") or []
            _add_unique(report.evidence, Evidence(
                f"Network telemetry observed {len(established)} ESTABLISHED connection(s).",
                result.name, "network", .99, "network-inventory"))
            # Presence of connections is neutral, not malicious evidence.
            if established:
                _add_unique(report.evidence, Evidence(
                    "Active network connectivity was observed; this alone does not indicate compromise.",
                    result.name, "network-context", .74, "network-active", "neutral"))

        elif result.name == "recent_security_history":
            scans = data.get("recent_scans") or []
            incidents = data.get("incidents") or []
            _add_unique(report.evidence, Evidence(
                f"Historical context contains {len(scans)} scan(s) and {len(incidents)} incident(s).",
                result.name, "history", .98, "history"))
            elevated = any(
                isinstance(row, (list, tuple)) and len(row) >= 2 and
                str(row[1]).upper() in {"MALWARE", "CRITICAL", "HIGH"}
                for row in scans
            )
            if elevated:
                _add_unique(report.evidence, Evidence(
                    "Recent history contains an elevated verdict; this is contextual evidence, not proof of current compromise.",
                    result.name, "history-elevated", .82, "history-elevated"))
                independent.add("history-elevated")
                supporting_weight += 6

    # Duplicate/overlap protection: independent sources matter more than raw count.
    diversity = len(independent)
    report.risk_score = min(100, round(supporting_weight + max(0, diversity - 1) * 5))
    availability = successful / max(1, len(list(results)) if not isinstance(results, list) else len(results))
    # The list conversion above is intentionally avoided for the normal list path;
    # for generators, callers should pass a list. Keep confidence conservative.
    if not isinstance(results, list):
        availability = min(1.0, successful / max(1, successful))
    report.confidence = min(.97, .40 + .28 * availability + .08 * min(diversity, 3))

    if not successful:
        report.confidence = .10
        report.unknown.append("No live telemetry source returned usable data.")

    # Explicitly expose uncertainty instead of manufacturing a verdict.
    if report.risk_score < 60:
        report.unknown.append("No independent high-confidence indicator establishes active compromise.")
    if diversity >= 2 and report.risk_score >= 30:
        report.next_tools = ["host_snapshot", "process_snapshot", "network_snapshot"]

    return report


def next_best_tools(question: str, executed: set[str], report: IntelligenceReport, limit: int = 2) -> list[str]:
    """Select missing observations using information value, not arbitrary tool spam."""
    q = (question or "").lower()
    candidates = [
        ("host_snapshot", 8 if any(x in q for x in ("virus", "malware", "infect", "xavf", "system", "kompyuter")) else 3),
        ("process_snapshot", 9 if any(x in q for x in ("process", "jarayon", "pid", "virus", "malware", "infect")) else 4),
        ("network_snapshot", 8 if any(x in q for x in ("network", "tarmoq", "connection", "ulanish", "virus", "malware")) else 3),
        ("recent_security_history", 7 if any(x in q for x in ("history", "tarix", "previous", "oldin", "incident")) else 2),
        ("system_health", 5 if any(x in q for x in ("health", "holat", "cpu", "ram", "system")) else 2),
    ]
    # If evidence is already diverse, prioritize missing context instead of repeating it.
    if report.risk_score >= 60:
        candidates = [(n, s + 3) for n, s in candidates]
    candidates.sort(key=lambda x: (-x[1], x[0]))
    return [n for n, _ in candidates if n not in executed][:limit]

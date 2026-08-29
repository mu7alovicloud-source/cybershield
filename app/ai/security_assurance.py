"""CyberShield AI 22.0 continuous-assurance layer.

Deterministic, defensive quality controls for the AI orchestration path:
- bounded multi-pass investigations
- tool failure isolation
- evidence freshness/quality checks
- decision stability checks
- explicit UNKNOWN/DEGRADED states
- no LLM or arbitrary OS authority
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Any


@dataclass(frozen=True)
class AssuranceResult:
    stable: bool
    quality: float
    state: str
    reasons: tuple[str, ...]


class ContinuousAssurance22:
    MAX_PASSES = 2
    MIN_CONFIDENCE_FOR_STABLE = 0.72

    @staticmethod
    def assess(*, evidence_count: int, confidence: float, gaps: Iterable[str],
               failed_tools: int, verdict: str, risk: int) -> AssuranceResult:
        reasons: list[str] = []
        gap_list = tuple(str(x) for x in gaps)
        quality = 0.0
        if evidence_count:
            quality += min(0.45, evidence_count / 20)
        quality += min(0.35, max(0.0, float(confidence)) * 0.35)
        quality += 0.20 if not gap_list else max(0.0, 0.20 - 0.03 * len(gap_list))
        if failed_tools:
            quality -= min(0.25, failed_tools * 0.08)
            reasons.append(f"{failed_tools} security tool(s) unavailable")
        if gap_list:
            reasons.append("missing telemetry: " + ", ".join(gap_list[:4]))
        if verdict == "HIGH_CONFIDENCE_THREAT" and risk < 88:
            reasons.append("threat verdict/risk mismatch")
        if float(confidence) < ContinuousAssurance22.MIN_CONFIDENCE_FOR_STABLE:
            reasons.append("confidence below stable threshold")
        quality = max(0.0, min(1.0, quality))
        stable = quality >= 0.62 and not failed_tools and float(confidence) >= ContinuousAssurance22.MIN_CONFIDENCE_FOR_STABLE and not any("mismatch" in r for r in reasons)
        state = "STABLE" if stable else ("DEGRADED" if failed_tools or gap_list else "UNCERTAIN")
        return AssuranceResult(stable, round(quality, 3), state, tuple(reasons))

    @staticmethod
    def choose_followups(gaps: Iterable[str], available: Iterable[str], already_run: Iterable[str]) -> list[str]:
        available_set = set(available)
        ran = set(already_run)
        mapping = (
            ("URL/phishing analysis", "url_analysis"),
            ("process attribution", "process_snapshot"),
            ("network context", "network_snapshot"),
            ("file-level evidence", "file_analysis"),
            ("fresh telemetry", "host_snapshot"),
        )
        out: list[str] = []
        for gap in gaps:
            for phrase, tool in mapping:
                if phrase in gap and tool in available_set and tool not in ran and tool not in out:
                    out.append(tool)
        return out[:4]

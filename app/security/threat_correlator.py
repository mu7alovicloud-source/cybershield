"""Evidence correlation for defensive threat assessment. No sample execution."""
from dataclasses import dataclass, field
from typing import Iterable

@dataclass
class ThreatChain:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)


def correlate(evidence: Iterable[dict]) -> ThreatChain:
    items = list(evidence)
    score = 0
    reasons: list[str] = []
    for item in items:
        value = max(0, min(100, int(item.get("score", 0))))
        weight = float(item.get("weight", 1.0))
        score += round(value * max(0.0, min(1.0, weight)))
        reason = item.get("reason")
        if reason:
            reasons.append(str(reason))
    # Correlation bonus: independent signals are stronger together.
    if len(items) >= 2:
        score += min(20, 5 * (len(items) - 1))
        reasons.append("Multiple independent security signals correlate")
    score = min(100, score)
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
    return ThreatChain(score, level, reasons, items)

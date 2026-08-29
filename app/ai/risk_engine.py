"""Central risk scoring with explainable evidence and confidence.

Scores are risk estimates, not proof of malware. Extension-only signals remain
weak; independent behavioral/evidence signals have stronger weight.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    counter_evidence: list[str] = field(default_factory=list)
    decision: str = "ALLOW_WITH_MONITORING"


def _level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def calculate_risk(file_risk=0, extension_risk=0, behavior_risk=0,
                  reputation_risk=0, network_risk=0, cpu_risk=0,
                  persistence_risk=0, confidence=0.0):
    """Backward-compatible tuple API used by existing modules/tests."""
    weights = {"file": .30, "extension": .15, "behavior": .25,
               "reputation": .15, "network": .10, "cpu": .03, "persistence": .02}
    score = round(min(100, max(0,
        file_risk * weights["file"] + extension_risk * weights["extension"] +
        behavior_risk * weights["behavior"] + reputation_risk * weights["reputation"] +
        network_risk * weights["network"] + cpu_risk * weights["cpu"] +
        persistence_risk * weights["persistence"])))
    return score, _level(score)


def assess(*, file_risk=0, extension_risk=0, behavior_risk=0,
           reputation_risk=0, network_risk=0, cpu_risk=0,
           persistence_risk=0, reasons=None, counter_evidence=None,
           confidence=0.0) -> RiskAssessment:
    reasons = list(reasons or [])
    counter_evidence = list(counter_evidence or [])
    score, level = calculate_risk(file_risk, extension_risk, behavior_risk,
                                  reputation_risk, network_risk, cpu_risk,
                                  persistence_risk, confidence)
    # Independent evidence gets a small correlation bonus, but clean evidence
    # can reduce a borderline score instead of being ignored.
    independent = len({r.split(":", 1)[0] for r in reasons if r})
    score = min(100, score + min(15, max(0, independent - 1) * 3))
    if counter_evidence:
        score = max(0, score - min(12, 3 * len(counter_evidence)))
    level = _level(score)
    confidence = float(confidence or .60)
    confidence = max(.45, min(.99, confidence + min(.10, independent * .02)))
    if level == "CRITICAL":
        decision = "CONTAIN"
    elif level == "HIGH":
        decision = "CONTAIN"
    elif level == "MEDIUM":
        decision = "REVIEW"
    else:
        decision = "ALLOW_WITH_MONITORING"
    return RiskAssessment(score, level, round(confidence, 2), reasons, counter_evidence, decision)


def from_file_result(result: dict) -> tuple[int, str]:
    indicators = [x.lower() for x in result.get("indicators", [])]
    behavior = min(100, 18 * sum(any(k in x for k in (
        "process", "powershell", "download", "execution", "script", "api"
    )) for x in indicators))
    persistence = 45 if any(any(k in x for k in ("registry", "startup", "persistence")) for x in indicators) else 0
    network = 25 if any(any(k in x for k in ("network", "url", "download", "dns")) for x in indicators) else 0
    extension = 10 if result.get("extension") in {".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi"} else 0
    return calculate_risk(file_risk=result.get("risk", 0), extension_risk=extension,
                          behavior_risk=behavior, network_risk=network,
                          persistence_risk=persistence)

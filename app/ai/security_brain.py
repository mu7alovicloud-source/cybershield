"""Evidence-first defensive reasoning core."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ai.risk_engine import assess


@dataclass
class BrainDecision:
    score: int
    level: str
    confidence: float
    decision: str
    reasons: list[str] = field(default_factory=list)
    safe_actions: list[str] = field(default_factory=list)
    escalation: str | None = None


class SecurityBrain:
    """Combines independent signals while keeping weak file-type signals weak."""

    def assess(self, *, file_risk=0, extension_risk=0, behavior_risk=0,
               reputation_risk=0, network_risk=0, cpu_risk=0,
               persistence_risk=0, evidence=None,
               confidence_hint=None) -> BrainDecision:
        evidence = list(evidence or [])
        d = assess(file_risk=file_risk, extension_risk=extension_risk,
                   behavior_risk=behavior_risk, reputation_risk=reputation_risk,
                   network_risk=network_risk, cpu_risk=cpu_risk,
                   persistence_risk=persistence_risk, reasons=evidence,
                   confidence=float(confidence_hint or .70))
        actions = ["Evidence saqlash", "Audit log yozish"]
        if d.level in ("HIGH", "CRITICAL"):
            actions += ["Containment", "Quarantine tavsiya", "Qayta tekshirish"]
        elif d.level == "MEDIUM":
            actions += ["Qo‘shimcha dalil yig‘ish", "Analyst review"]
        else:
            actions += ["Monitoringni davom ettirish"]
        escalation = None
        if d.confidence < .70:
            escalation = "CYBERSHIELD ANALYST REVIEW"
        return BrainDecision(d.score, d.level, d.confidence, d.decision, evidence, actions, escalation)

    def file_assessment(self, result: dict[str, Any]) -> BrainDecision:
        indicators = list(result.get("indicators") or [])
        low = [x.lower() for x in indicators]
        raw_evidence = list(result.get("evidence") or [])
        strong = sum(1 for e in raw_evidence if str(e.get("severity", "")).lower() in {"high", "critical"})
        independent_codes = len({str(e.get("code", "")) for e in raw_evidence if e.get("code")})
        behavior = min(100, 22 * sum(any(k in x for k in (
            "process", "powershell", "download", "execution", "script", "api", "remote", "encoded"
        )) for x in low))
        if strong >= 2 and independent_codes >= 2:
            behavior = max(behavior, 72)
        persistence = 50 if any(any(k in x for k in ("registry", "startup", "persistence")) for x in low) else 0
        network = 30 if any(any(k in x for k in ("network", "url", "download", "dns")) for x in low) else 0
        if strong >= 2 and any(k in " ".join(low) for k in ("download", "url", "network")):
            network = max(network, 55)
        cpu = 20 if any(any(k in x for k in ("cpu", "mining")) for x in low) else 0
        extension = 8 if result.get("extension") in {
            ".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi"
        } else 0
        d = self.assess(
            file_risk=result.get("risk", 0), extension_risk=extension,
            behavior_risk=behavior, network_risk=network,
            persistence_risk=persistence, cpu_risk=cpu,
            evidence=indicators, confidence_hint=result.get("confidence", .80),
        )
        # Correlated high-severity independent evidence should not be diluted
        # by a weak weighted average. It still requires multiple independent
        # signals, avoiding the false-positive problem of a single heuristic.
        if strong >= 2 and independent_codes >= 2:
            correlated_score = min(100, d.score + 20)
            level = "CRITICAL" if correlated_score >= 85 else "HIGH"
            decision = "CONTAIN"
            actions = ["Evidence saqlash", "Audit log yozish", "Containment", "Quarantine tavsiya", "Qayta tekshirish"]
            return BrainDecision(correlated_score, level, d.confidence, decision, indicators, actions, d.escalation)
        return d

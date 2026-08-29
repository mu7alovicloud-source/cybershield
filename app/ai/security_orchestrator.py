"""CyberShield AI 21.0 unified security orchestrator.

This is a defensive, evidence-first control plane. It coordinates existing
read-only telemetry and deterministic decision engines, but never gives the
LLM direct OS authority. Actions must pass the existing containment policy.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import hashlib

from app.ai.agent_tools import SecurityToolRegistry, ToolResult, investigation_tools_for
from app.ai.intelligence_v20 import SecurityIntelligence20, Decision20
from app.ai.security_assurance import ContinuousAssurance22, AssuranceResult


@dataclass(frozen=True)
class OrchestrationReport:
    question: str
    status: str
    tools: tuple[str, ...]
    evidence_count: int
    verdict: str
    risk: int
    confidence: float
    gaps: tuple[str, ...]
    next_best: tuple[str, ...]
    action_gate: str
    ledger_id: str
    generated_at: str
    assurance_state: str = "STABLE"
    assurance_quality: float = 0.0
    assurance_reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityOrchestrator21:
    """Bounded cross-engine investigation coordinator."""

    MAX_TOOLS = 6

    def __init__(self, registry: SecurityToolRegistry | None = None) -> None:
        self.registry = registry or SecurityToolRegistry()

    @staticmethod
    def _source(name: str) -> str:
        n = name.lower()
        for key in ("scanner", "file", "url", "phishing", "ransomware", "process", "network", "host", "system", "history"):
            if key in n:
                return key
        return "unknown"

    def _evidence_from_result(self, result: ToolResult) -> list[dict[str, Any]]:
        if not result.ok:
            return [{"source": self._source(result.name), "claim": f"{result.name} telemetry unavailable", "confidence": .2,
                     "polarity": "counter", "category": "telemetry_gap", "key": f"gap:{result.name}"}]
        source = self._source(result.name)
        rows = [{"source": source, "claim": result.summary, "confidence": .88,
                 "category": result.name, "key": f"summary:{result.name}"}]
        # Selected high-signal fields are converted to evidence without
        # blindly trusting arbitrary nested LLM text.
        if result.name == "process_snapshot" and result.data.get("review_candidates"):
            rows.append({"source": "process", "claim": f"{len(result.data['review_candidates'])} process candidates require review",
                         "confidence": .64, "category": "process_review", "key": "process:candidates"})
        if result.name == "network_snapshot" and result.data.get("established"):
            rows.append({"source": "network", "claim": f"{len(result.data['established'])} established connections observed",
                         "confidence": .55, "category": "network_activity", "key": "network:established"})
        if result.name == "system_health":
            cpu = float((result.data.get("cpu") or {}).get("total_cpu", 0) or 0)
            if cpu >= 90:
                rows.append({"source": "system", "claim": f"CPU utilization is {cpu:.1f}%",
                             "confidence": .70, "category": "resource_pressure", "key": "system:high_cpu"})
        return rows

    def investigate(self, question: str, requested: list[str] | None = None) -> OrchestrationReport:
        q = (question or "").strip()
        if not q:
            return self._empty("A security question is required.")
        plan = list(dict.fromkeys(requested or investigation_tools_for(q)))
        # A broad threat question gets a compact, bounded baseline.
        if not plan and any(k in q.lower() for k in ("virus", "malware", "threat", "xavf", "zararli")):
            plan = ["system_health", "process_snapshot", "network_snapshot", "host_snapshot"]
        plan = plan[: self.MAX_TOOLS]
        # Pass 1: bounded baseline. Pass 2 is allowed only to close a high-value
        # telemetry gap; this prevents runaway autonomous probing.
        results = [self.registry.run(name) for name in plan]
        evidence: list[dict[str, Any]] = []
        for result in results:
            evidence.extend(self._evidence_from_result(result))
        decision = SecurityIntelligence20.decide(evidence, question=q)
        followups = ContinuousAssurance22.choose_followups(decision.gaps, self.registry.available(), [r.name for r in results])
        if followups and len(results) < self.MAX_TOOLS:
            for name in followups[: max(0, self.MAX_TOOLS - len(results))]:
                result = self.registry.run(name)
                results.append(result)
                evidence.extend(self._evidence_from_result(result))
            decision = SecurityIntelligence20.decide(evidence, question=q)
        failed = sum(1 for r in results if not r.ok)
        assurance = ContinuousAssurance22.assess(
            evidence_count=len(SecurityIntelligence20.normalize(evidence)),
            confidence=decision.confidence, gaps=decision.gaps, failed_tools=failed,
            verdict=decision.verdict, risk=decision.risk,
        )
        status = "DEGRADED" if failed else ("UNCERTAIN" if not assurance.stable else "READY")
        # Never allow a low-quality/unstable reasoning state to authorize action.
        action_gate = decision.action_gate if assurance.stable else "OBSERVE_ONLY"
        ledger = hashlib.sha256((decision.ledger_id + "|" + assurance.state + "|" + q[:400]).encode()).hexdigest()[:20]
        return OrchestrationReport(
            question=q[:1000], status=status, tools=tuple(r.name for r in results),
            evidence_count=len(SecurityIntelligence20.normalize(evidence)), verdict=decision.verdict,
            risk=decision.risk, confidence=decision.confidence, gaps=decision.gaps,
            next_best=decision.next_best, action_gate=action_gate, ledger_id=ledger,
            generated_at=datetime.now(timezone.utc).isoformat(),
            assurance_state=assurance.state, assurance_quality=assurance.quality,
            assurance_reasons=assurance.reasons,
        )

    @staticmethod
    def _empty(question: str) -> OrchestrationReport:
        return OrchestrationReport(question, "INVALID", tuple(), 0, "NO_STRONG_EVIDENCE", 0, .05,
                                   ("usable evidence",), tuple(), "OBSERVE_ONLY",
                                   hashlib.sha256(question.encode()).hexdigest()[:20],
                                   datetime.now(timezone.utc).isoformat())

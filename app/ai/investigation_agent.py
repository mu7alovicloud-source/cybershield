"""Bounded autonomous defensive investigation loop.

This module upgrades the Copilot from a one-shot tool caller into a small,
stateful investigation planner.  It is deliberately read-only: the agent can
collect telemetry and correlate it, but it cannot execute arbitrary commands
or authorize destructive actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.ai.agent_tools import SecurityToolRegistry, ToolResult, investigation_tools_for
from app.ai.meta_reasoner import EvidenceItem, MetaReasoner, ReasoningDecision
from app.ai.intelligence_v18 import AIIntelligence18


@dataclass
class InvestigationFinding:
    category: str
    statement: str
    confidence: float
    source: str


@dataclass
class InvestigationSession:
    question: str
    planned_tools: list[str]
    executed_tools: list[str] = field(default_factory=list)
    results: list[ToolResult] = field(default_factory=list)
    verified: list[InvestigationFinding] = field(default_factory=list)
    inferred: list[InvestigationFinding] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    risk_score: int = 0
    decision: ReasoningDecision | None = None

    def evidence_blob(self) -> str:
        blocks = []
        for result in self.results:
            blocks.append(
                f"TOOL={result.name}\nOK={result.ok}\nSUMMARY={result.summary}\nDATA={result.data}"
            )
        return "\n\n".join(blocks) or "No telemetry was collected."


class DefensiveInvestigationAgent:
    """Perform a bounded multi-step read-only endpoint investigation."""

    MAX_TOOLS = 4

    def __init__(self, registry: SecurityToolRegistry | None = None) -> None:
        self.registry = registry or SecurityToolRegistry()

    def investigate(self, question: str, requested: list[str] | None = None) -> InvestigationSession:
        adaptive_plan = AIIntelligence18.plan(question)
        base_plan = requested or investigation_tools_for(question)
        planned = list(dict.fromkeys(list(base_plan) + list(adaptive_plan.tools)))[: self.MAX_TOOLS]
        # Broad threat questions should start with host health and process
        # context. Network telemetry is added only when it can improve context.
        if not planned and any(k in (question or '').lower() for k in ("threat", "virus", "malware", "xavf")):
            planned = ["system_health", "process_snapshot", "network_snapshot"]
        session = InvestigationSession(question=question, planned_tools=planned)

        # Step 1: execute the explicit plan.
        for name in planned:
            result = self.registry.run(name)
            session.results.append(result)
            session.executed_tools.append(name)

        self._derive_findings(session)
        self._meta_decide(session)

        # Step 2: bounded adaptive follow-up. If process telemetry contains
        # review candidates, a host health snapshot gives the model context;
        # if network evidence exists without process context, collect process
        # context. Never exceed MAX_TOOLS and never execute arbitrary tools.
        if len(session.executed_tools) < self.MAX_TOOLS:
            names = set(session.executed_tools)
            follow_up = None
            if "process_snapshot" not in names and any("process" in x.category for x in session.inferred):
                follow_up = "process_snapshot"
            elif "network_snapshot" not in names and any("network" in x.category for x in session.inferred):
                follow_up = "network_snapshot"
            if follow_up:
                result = self.registry.run(follow_up)
                session.results.append(result)
                session.executed_tools.append(follow_up)
                self._derive_findings(session)
                self._meta_decide(session)

        return session

    def _meta_decide(self, session: InvestigationSession) -> None:
        evidence = []
        for f in session.verified:
            evidence.append(EvidenceItem(f.category, f.statement, f.confidence, "supporting", key=f.source))
        for f in session.inferred:
            evidence.append(EvidenceItem(f.category, f.statement, f.confidence, "supporting", key=f.source))
        try:
            available = self.registry.available() if hasattr(self.registry, "available") else []
        except Exception:
            available = []
        session.decision = MetaReasoner().fuse(evidence, available_tools=available)
        session.risk_score = max(session.risk_score, session.decision.risk)

    def _derive_findings(self, session: InvestigationSession) -> None:
        session.verified.clear()
        session.inferred.clear()
        session.unknown.clear()
        score = 0
        successful = 0
        for result in session.results:
            if not result.ok:
                session.unknown.append(f"{result.name}: telemetry unavailable")
                continue
            successful += 1
            if result.name == "system_health":
                cpu = float((result.data.get("cpu") or {}).get("total_cpu", 0) or 0)
                session.verified.append(InvestigationFinding("system", f"System health snapshot collected; CPU {cpu:.1f}%.", .99, result.name))
                if cpu >= 90:
                    session.inferred.append(InvestigationFinding("system", "Very high CPU usage warrants process-level review; it is not malware proof.", .62, result.name))
                    score += 8
            elif result.name == "process_snapshot":
                candidates = result.data.get("review_candidates") or []
                session.verified.append(InvestigationFinding("process", f"Process snapshot collected; {result.data.get('count', 0)} processes observed.", .99, result.name))
                if candidates:
                    session.inferred.append(InvestigationFinding("process", f"{len(candidates)} process(es) need review under conservative heuristics.", .68, result.name))
                    score += min(20, 5 * len(candidates))
            elif result.name == "network_snapshot":
                established = result.data.get("established") or []
                session.verified.append(InvestigationFinding("network", f"Network snapshot collected; {len(established)} ESTABLISHED connections observed.", .99, result.name))
                if established:
                    session.inferred.append(InvestigationFinding("network", "Established connections were observed; external connectivity alone does not establish maliciousness.", .70, result.name))
                    score += min(12, len(established))
        if successful == 0:
            session.unknown.append("No live telemetry source returned usable data.")
        session.risk_score = min(100, score)

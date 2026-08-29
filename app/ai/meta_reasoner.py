"""High-integrity meta reasoning for CyberShield AI 16.0.

Deterministic layer that ranks evidence, detects gaps/contradictions, selects
bounded next investigations, and produces a grounded answer contract for an
optional LLM. It never executes OS commands and never grants the LLM action
authority.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable

@dataclass(frozen=True)
class EvidenceItem:
    source: str
    claim: str
    confidence: float
    polarity: str = "supporting"
    key: str = ""
    freshness: float = 1.0

@dataclass(frozen=True)
class ReasoningDecision:
    verdict: str
    risk: int
    confidence: float
    next_tools: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()

class MetaReasoner:
    """Fuse independent evidence without letting repeated signals dominate."""
    MAX_TOOLS = 4
    TOOL_ORDER = ("host_snapshot", "system_health", "process_snapshot", "network_snapshot", "recent_security_history")

    def fuse(self, evidence: Iterable[EvidenceItem], *, available_tools: Iterable[str] = ()) -> ReasoningDecision:
        rows = list(evidence)
        # Deduplicate identical observations while retaining the strongest fresh record.
        best: dict[tuple[str, str], EvidenceItem] = {}
        for e in rows:
            k = (e.source, e.key or e.claim.strip().lower(), e.polarity)
            if k not in best or (e.confidence * e.freshness) > (best[k].confidence * best[k].freshness):
                best[k] = e
        rows = list(best.values())
        support = [e for e in rows if e.polarity == "supporting"]
        counter = [e for e in rows if e.polarity == "counter"]
        sources = {e.source for e in support}
        score = min(100, round(sum(max(0,min(1,e.confidence))*14*max(.25,min(1,e.freshness)) for e in support)
                              + max(0,len(sources)-1)*9
                              - sum(max(0,min(1,e.confidence))*12 for e in counter)))
        contradictions = []
        for s in support:
            for c in counter:
                if s.key and c.key and s.key == c.key:
                    contradictions.append(f"Conflicting evidence for {s.key}")
        if not rows:
            conf = .10
        else:
            avg = sum(e.confidence for e in rows)/len(rows)
            diversity = min(5, len(sources))
            agreement = max(.45, 1 - .12*len(contradictions))
            conf = min(.99, (.28 + .42*avg + .06*diversity) * agreement)
        gaps = []
        source_set = {e.source for e in rows}
        if "process" not in source_set:
            gaps.append("process attribution is missing")
        if "network" not in source_set:
            gaps.append("network context is missing")
        if "file" not in source_set:
            gaps.append("file-level evidence is missing")
        if contradictions:
            gaps.append("conflicting evidence requires resolution")
        available = [x for x in self.TOOL_ORDER if x in set(available_tools)]
        next_tools = tuple(x for x in available if (x.startswith("process") and "process" not in source_set) or (x.startswith("network") and "network" not in source_set) or (x.startswith("host") and not source_set))[:self.MAX_TOOLS]
        if score >= 85 and conf >= .90 and not contradictions:
            verdict = "HIGH_CONFIDENCE_THREAT"
        elif score >= 60:
            verdict = "SUSPICIOUS"
        elif score >= 35:
            verdict = "NEEDS_REVIEW"
        else:
            verdict = "NO_STRONG_EVIDENCE"
        rationale = tuple(x for x in (
            f"{len(sources)} independent supporting source(s)",
            f"{len(counter)} counter-evidence item(s)",
            f"{len(contradictions)} contradiction(s)",
        ) if x)
        return ReasoningDecision(verdict, score, round(conf,3), next_tools, tuple(gaps[:6]), tuple(dict.fromkeys(contradictions))[:6], rationale)

    @staticmethod
    def grounded_prompt(*, question: str, evidence: str, decision: ReasoningDecision) -> str:
        return ("You are CyberShield's security intelligence analyst.\n"
                "Use only supplied evidence. Never claim an action occurred unless an explicit verified action result is supplied.\n"
                "Clearly label VERIFIED, INFERRED, and UNKNOWN. Do not invent telemetry.\n"
                f"QUESTION: {question[:2000]}\nDECISION: {decision.verdict} risk={decision.risk} confidence={decision.confidence}\n"
                f"GAPS: {', '.join(decision.gaps) or 'none'}\nEVIDENCE:\n{evidence[:12000]}")

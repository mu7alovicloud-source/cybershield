"""CyberShield AI 18.0 intelligence layer.

Adds a deterministic hypothesis/evidence engine above the existing AI stack.
It improves calibration, target-aware investigation planning, and final-answer
quality without exposing hidden chain-of-thought or giving an LLM OS authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Iterable, Any


@dataclass(frozen=True)
class Hypothesis:
    name: str
    support: float
    counter: float
    confidence: float
    status: str
    missing: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvestigationPlan:
    target: str
    tools: tuple[str, ...]
    priority: tuple[str, ...]
    rationale: tuple[str, ...]


@dataclass(frozen=True)
class IntelligenceDecision:
    verdict: str
    risk: int
    confidence: float
    hypotheses: tuple[Hypothesis, ...]
    gaps: tuple[str, ...]
    plan: InvestigationPlan


class AIIntelligence18:
    """Deterministic security intelligence kernel used before/after an LLM."""

    MAX_EVIDENCE = 96
    MAX_TOOLS = 5
    URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.I)
    FILE_RE = re.compile(r"(?:[A-Za-z]:[\\/][^\s<>\"']+|[^\s<>\"']+\.(?:exe|dll|scr|msi|bat|cmd|ps1|vbs|js|docm|xlsm))", re.I)

    @staticmethod
    def _confidence(value: Any) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.5

    @classmethod
    def evidence_id(cls, item: dict[str, Any]) -> str:
        raw = "|".join(str(item.get(k, "")) for k in ("source", "type", "key", "claim", "target"))
        return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]

    @classmethod
    def normalize_evidence(cls, items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalize and deduplicate heterogeneous evidence records."""
        best: dict[str, dict[str, Any]] = {}
        for raw in items:
            if not isinstance(raw, dict):
                continue
            row = dict(raw)
            row["confidence"] = cls._confidence(row.get("confidence", 0.5))
            row["freshness"] = cls._confidence(row.get("freshness", 1.0))
            row["polarity"] = str(row.get("polarity", "supporting")).lower()
            row["source"] = str(row.get("source", "unknown"))[:80]
            row["claim"] = str(row.get("claim", row.get("statement", "")))[:1000]
            row["evidence_id"] = cls.evidence_id(row)
            previous = best.get(row["evidence_id"])
            if previous is None or (row["confidence"] * row["freshness"]) > (previous["confidence"] * previous["freshness"]):
                best[row["evidence_id"]] = row
            if len(best) >= cls.MAX_EVIDENCE:
                break
        return sorted(best.values(), key=lambda x: x["confidence"] * x["freshness"], reverse=True)

    @classmethod
    def plan(cls, question: str) -> InvestigationPlan:
        q = (question or "").strip()
        low = q.lower()
        tools: list[str] = []
        priority: list[str] = []
        rationale: list[str] = []
        target = "system"
        if cls.URL_RE.search(q):
            target = "url"
            tools += ["url_analysis", "network_snapshot"]
            priority += ["url_analysis", "network_snapshot"]
            rationale.append("An explicit URL is present, so URL intelligence has the highest information value.")
        elif cls.FILE_RE.search(q):
            target = "file"
            tools += ["file_analysis", "process_snapshot"]
            priority += ["file_analysis", "process_snapshot"]
            rationale.append("An explicit file target is present, so static file analysis should precede broad telemetry.")
        else:
            if any(x in low for x in ("process", "jarayon", "pid")):
                tools.append("process_snapshot")
                priority.append("process_snapshot")
            if any(x in low for x in ("network", "tarmoq", "connection", "ip", "port")):
                tools.append("network_snapshot")
                priority.append("network_snapshot")
            if any(x in low for x in ("virus", "malware", "threat", "xavf", "infect", "security", "xavfsizlik")):
                tools += ["host_snapshot", "system_health"]
                priority += ["host_snapshot", "system_health"]
                rationale.append("Threat-oriented questions benefit from a compact host and health snapshot.")
            target = "system" if tools else "general"
        if not tools:
            tools = ["system_health", "recent_security_history"]
            priority = list(tools)
            rationale.append("No concrete target was identified; start with low-cost, read-only context.")
        tools = list(dict.fromkeys(tools))[:cls.MAX_TOOLS]
        priority = list(dict.fromkeys(priority))[:cls.MAX_TOOLS]
        return InvestigationPlan(target, tuple(tools), tuple(priority), tuple(rationale))

    @classmethod
    def decide(cls, evidence: Iterable[dict[str, Any]], question: str = "") -> IntelligenceDecision:
        rows = cls.normalize_evidence(evidence)
        supporting = [r for r in rows if r["polarity"] == "supporting"]
        counter = [r for r in rows if r["polarity"] == "counter"]
        independent = {r.get("key") or r["source"] for r in supporting}
        support = sum(r["confidence"] * r["freshness"] for r in supporting)
        opposing = sum(r["confidence"] * r["freshness"] for r in counter)
        risk = int(max(0, min(100, round(support * 18 + max(0, len(independent)-1) * 8 - opposing * 16))))
        avg = sum(r["confidence"] * r["freshness"] for r in rows) / len(rows) if rows else 0.1
        contradiction_penalty = min(0.35, 0.10 * min(len(counter), 3))
        confidence = max(0.05, min(0.99, 0.32 + 0.40 * avg + 0.07 * min(len(independent), 4) - contradiction_penalty))

        gaps: list[str] = []
        sources = {str(r.get("source")) for r in rows}
        if question and ("process" in question.lower() or "virus" in question.lower() or "malware" in question.lower()) and "process" not in sources:
            gaps.append("process attribution is not established")
        if question and any(x in question.lower() for x in ("network", "tarmoq", "internet")) and "network" not in sources:
            gaps.append("network context is not established")
        if not rows:
            gaps.append("no usable evidence was collected")

        if risk >= 85 and confidence >= .90 and not counter:
            verdict = "HIGH_CONFIDENCE_THREAT"
        elif risk >= 60:
            verdict = "SUSPICIOUS"
        elif risk >= 35:
            verdict = "NEEDS_REVIEW"
        else:
            verdict = "NO_STRONG_EVIDENCE"

        hypotheses = (
            Hypothesis("malicious_activity", min(1.0, support / 3.0), min(1.0, opposing / 2.0), confidence,
                       "supported" if risk >= 60 else "unproven", tuple(gaps)),
            Hypothesis("benign_activity", min(1.0, opposing / 2.0), min(1.0, support / 3.0),
                       max(.05, 1.0-confidence), "plausible" if opposing else "not_established", tuple(gaps)),
        )
        plan = cls.plan(question)
        return IntelligenceDecision(verdict, risk, round(confidence, 3), hypotheses, tuple(gaps[:8]), plan)

    @staticmethod
    def answer_contract(decision: IntelligenceDecision) -> str:
        return (
            f"VERDICT={decision.verdict}; RISK={decision.risk}/100; CONFIDENCE={decision.confidence:.2f}. "
            "Separate VERIFIED observations from INFERRED interpretation and UNKNOWN gaps. "
            "Do not claim actions or detections that are absent from verified evidence. "
            f"GAPS={'; '.join(decision.gaps) or 'none'}. "
            f"NEXT_TOOLS={','.join(decision.plan.tools)}."
        )

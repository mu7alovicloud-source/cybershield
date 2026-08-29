"""CyberShield AI 19.0: calibrated hypothesis and investigation intelligence.

Deterministic layer only. It improves evidence quality, temporal freshness,
source reliability, hypothesis competition and next-best-investigation choice.
It never executes commands or grants destructive authority to an LLM.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import math
from typing import Any, Iterable


@dataclass(frozen=True)
class Evidence19:
    source: str
    claim: str
    confidence: float = .5
    freshness: float = 1.0
    polarity: str = "supporting"
    key: str = ""
    reliability: float = .7
    timestamp: str = ""


@dataclass(frozen=True)
class Hypothesis19:
    name: str
    score: float
    confidence: float
    status: str
    supporting: tuple[str, ...]
    counter: tuple[str, ...]
    missing: tuple[str, ...]


@dataclass(frozen=True)
class Investigation19:
    target: str
    priority: tuple[str, ...]
    information_gain: tuple[tuple[str, float], ...]
    rationale: tuple[str, ...]


@dataclass(frozen=True)
class Decision19:
    verdict: str
    risk: int
    confidence: float
    hypotheses: tuple[Hypothesis19, ...]
    gaps: tuple[str, ...]
    investigation: Investigation19


class AIIntelligence19:
    """Evidence-first security intelligence kernel for AI 19.0."""

    MAX_EVIDENCE = 120
    MAX_GAPS = 12
    SOURCE_RELIABILITY = {
        "scanner": .95, "file_analysis": .95, "url_analysis": .93,
        "ransomware": .92, "phishing": .92, "process_snapshot": .82,
        "network_snapshot": .80, "host_snapshot": .88,
        "system_health": .72, "recent_security_history": .70,
        "llm": .45, "user": .60,
    }

    @staticmethod
    def clamp(v: Any, default=.5) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return default

    @classmethod
    def source_weight(cls, source: str, supplied: Any = None) -> float:
        if supplied is not None:
            return cls.clamp(supplied)
        name = str(source or "unknown").lower()
        for key, value in cls.SOURCE_RELIABILITY.items():
            if key in name:
                return value
        return .60

    @classmethod
    def freshness(cls, timestamp: str | None, supplied: Any = None) -> float:
        if supplied is not None:
            return cls.clamp(supplied)
        if not timestamp:
            return 1.0
        try:
            raw = str(timestamp).replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
            return max(.15, min(1.0, math.exp(-age / 3600.0)))
        except (TypeError, ValueError, OverflowError):
            return .80

    @classmethod
    def normalize(cls, records: Iterable[dict[str, Any]]) -> list[Evidence19]:
        best: dict[str, Evidence19] = {}
        for raw in records:
            if not isinstance(raw, dict):
                continue
            source = str(raw.get("source", "unknown"))[:80]
            claim = str(raw.get("claim", raw.get("statement", ""))).strip()[:1200]
            if not claim:
                continue
            polarity = str(raw.get("polarity", "supporting")).lower()
            if polarity not in {"supporting", "counter", "neutral"}:
                polarity = "neutral"
            reliability = cls.source_weight(source, raw.get("reliability"))
            freshness = cls.freshness(raw.get("timestamp"), raw.get("freshness"))
            confidence = cls.clamp(raw.get("confidence", .5))
            key = str(raw.get("key") or raw.get("type") or claim[:120])[:160]
            digest = hashlib.sha256(f"{source}|{key}|{polarity}|{claim}".encode("utf-8", "ignore")).hexdigest()[:20]
            item = Evidence19(source, claim, confidence, freshness, polarity, key, reliability, str(raw.get("timestamp", "")))
            quality = confidence * freshness * reliability
            old = best.get(digest)
            if old is None or quality > old.confidence * old.freshness * old.reliability:
                best[digest] = item
            if len(best) >= cls.MAX_EVIDENCE:
                break
        return sorted(best.values(), key=lambda x: x.confidence * x.freshness * x.reliability, reverse=True)

    @classmethod
    def _weighted(cls, rows: Iterable[Evidence19], polarity: str) -> float:
        return sum(x.confidence * x.freshness * x.reliability for x in rows if x.polarity == polarity)

    @classmethod
    def decide(cls, records: Iterable[dict[str, Any]], question: str = "") -> Decision19:
        rows = cls.normalize(records)
        supporting = [x for x in rows if x.polarity == "supporting"]
        counter = [x for x in rows if x.polarity == "counter"]
        support = cls._weighted(rows, "supporting")
        opposing = cls._weighted(rows, "counter")
        independent = {x.key or x.source for x in supporting}
        diversity = len({x.source for x in supporting})
        agreement = max(0.0, 1.0 - min(.40, .08 * len(counter)))
        risk = int(max(0, min(100, round(support * 30 + max(0, diversity - 1) * 7 - opposing * 26))))
        evidence_quality = sum(x.confidence * x.reliability * x.freshness for x in rows) / len(rows) if rows else .05
        confidence = min(.995, max(.05, (.34 + .50 * evidence_quality + .06 * min(4, diversity)) * agreement))

        gaps: list[str] = []
        q = (question or "").lower()
        sources = {x.source.lower() for x in rows}
        if any(k in q for k in ("virus", "malware", "infect", "xavf", "threat")) and not any("process" in s for s in sources):
            gaps.append("process attribution is not established")
        if any(k in q for k in ("network", "tarmoq", "internet", "ip", "ulanish")) and not any("network" in s for s in sources):
            gaps.append("network context is not established")
        if any(k in q for k in ("fishing", "phishing", "url", "link", "havola")) and not any("url" in s or "phishing" in s for s in sources):
            gaps.append("URL/phishing-specific analysis is not established")
        if any(x.freshness < .35 for x in rows):
            gaps.append("some evidence is stale and should not be treated as current proof")
        if not rows:
            gaps.append("no usable evidence was collected")

        malicious_score = min(1.0, support / 2.5)
        benign_score = min(1.0, opposing / 1.8)
        malicious_status = "supported" if risk >= 60 else "unproven"
        benign_status = "supported" if opposing > support * .75 and opposing else "plausible" if opposing else "not_established"
        malicious = Hypothesis19("malicious_activity", malicious_score, confidence, malicious_status,
                                 tuple(x.claim for x in supporting[:6]), tuple(x.claim for x in counter[:6]), tuple(gaps[:6]))
        benign = Hypothesis19("benign_activity", benign_score, max(.05, 1-confidence), benign_status,
                              tuple(x.claim for x in counter[:6]), tuple(x.claim for x in supporting[:6]), tuple(gaps[:6]))

        if risk >= 85 and confidence >= .90 and not counter:
            verdict = "HIGH_CONFIDENCE_THREAT"
        elif risk >= 65:
            verdict = "SUSPICIOUS"
        elif risk >= 35:
            verdict = "NEEDS_REVIEW"
        else:
            verdict = "NO_STRONG_EVIDENCE"

        inv = cls.next_investigation(question, rows)
        return Decision19(verdict, risk, round(confidence, 3), (malicious, benign), tuple(gaps[:cls.MAX_GAPS]), inv)

    @classmethod
    def next_investigation(cls, question: str, rows: list[Evidence19]) -> Investigation19:
        q = (question or "").lower()
        have = {x.source.lower() for x in rows}
        candidates: list[tuple[str, float, str]] = []
        def add(name: str, score: float, why: str):
            if not any(name in h for h in have):
                candidates.append((name, score, why))
        if any(k in q for k in ("virus", "malware", "infect", "xavf", "threat")):
            add("process_snapshot", 9.5, "process attribution can distinguish an isolated signal from active execution")
            add("network_snapshot", 8.5, "network context can test whether suspicious activity has external communication")
            add("host_snapshot", 8.0, "host context can reveal persistence and related activity")
        if any(k in q for k in ("phishing", "fishing", "url", "link", "havola")):
            add("url_analysis", 10.0, "URL-specific analysis has the highest information value for a URL claim")
        add("recent_security_history", 4.0, "history can identify recurrence but cannot prove current compromise")
        candidates.sort(key=lambda x: (-x[1], x[0]))
        return Investigation19(
            target="url" if any(k in q for k in ("url", "link", "havola", "phishing", "fishing")) else "system",
            priority=tuple(x[0] for x in candidates[:4]),
            information_gain=tuple((x[0], x[1]) for x in candidates[:4]),
            rationale=tuple(x[2] for x in candidates[:4]),
        )

    @classmethod
    def contract(cls, decision: Decision19) -> str:
        hyp = "; ".join(f"{h.name}={h.status}:{h.confidence:.2f}" for h in decision.hypotheses)
        return (
            f"VERDICT={decision.verdict}; RISK={decision.risk}/100; CONFIDENCE={decision.confidence:.2f}; "
            f"HYPOTHESES={hyp}; GAPS={'; '.join(decision.gaps) or 'none'}; "
            f"NEXT_BEST={','.join(decision.investigation.priority) or 'none'}. "
            "Never turn inference into a verified fact and never claim an action without a verified action result."
        )

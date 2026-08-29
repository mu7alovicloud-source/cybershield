"""CyberShield AI 20.0 — Security Intelligence Fabric.

A deterministic orchestration-quality layer that sits above the existing AI
reasoning modules. It provides temporal normalization, evidence provenance,
independence-aware scoring, hypothesis competition, decision ledgers and
policy gates. It never grants an LLM direct OS authority.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib, math
from typing import Any, Iterable

@dataclass(frozen=True)
class Evidence20:
    source: str
    claim: str
    confidence: float
    reliability: float
    freshness: float
    polarity: str = "supporting"
    category: str = "general"
    key: str = ""

@dataclass(frozen=True)
class Hypothesis20:
    name: str
    score: float
    confidence: float
    support: tuple[str, ...]
    counter: tuple[str, ...]

@dataclass(frozen=True)
class Decision20:
    verdict: str
    risk: int
    confidence: float
    hypotheses: tuple[Hypothesis20, ...]
    gaps: tuple[str, ...]
    next_best: tuple[str, ...]
    action_gate: str
    ledger_id: str

class SecurityIntelligence20:
    """Cross-engine, evidence-first decision fabric for CyberShield AI."""
    MAX_EVIDENCE = 160
    MAX_NEXT = 5
    RELIABILITY = {
        "scanner": .97, "file": .95, "url": .94, "phishing": .94,
        "ransomware": .94, "process": .84, "network": .82,
        "host": .89, "system": .75, "history": .68, "user": .58,
        "llm": .30,
    }

    @staticmethod
    def clamp(value: Any, default=.5):
        try: return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError): return default

    @classmethod
    def reliability(cls, source: str, supplied=None):
        if supplied is not None: return cls.clamp(supplied)
        s = str(source or "unknown").lower()
        return next((v for k,v in cls.RELIABILITY.items() if k in s), .60)

    @staticmethod
    def freshness(timestamp: Any = None, supplied=None):
        if supplied is not None: return SecurityIntelligence20.clamp(supplied)
        if not timestamp: return 1.0
        try:
            dt = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            age = max(0.0, (datetime.now(timezone.utc)-dt).total_seconds())
            return max(.10, min(1.0, math.exp(-age/3600)))
        except (TypeError, ValueError, OverflowError): return .75

    @classmethod
    def normalize(cls, records: Iterable[dict[str, Any]]) -> list[Evidence20]:
        unique = {}
        for raw in records:
            if not isinstance(raw, dict): continue
            claim = str(raw.get("claim", raw.get("statement", raw.get("text", "")))).strip()[:1600]
            if not claim: continue
            source = str(raw.get("source", "unknown"))[:80]
            polarity = str(raw.get("polarity", "supporting")).lower()
            if polarity not in {"supporting","counter","neutral"}: polarity = "neutral"
            item = Evidence20(source, claim, cls.clamp(raw.get("confidence", .5)),
                cls.reliability(source, raw.get("reliability")),
                cls.freshness(raw.get("timestamp"), raw.get("freshness")),
                polarity, str(raw.get("category", raw.get("type", "general")))[:80],
                str(raw.get("key", raw.get("type", claim[:100])))[:120])
            digest = hashlib.sha256((source+"|"+item.key+"|"+polarity+"|"+claim).encode()).hexdigest()[:24]
            quality = item.confidence*item.reliability*item.freshness
            old = unique.get(digest)
            if old is None or quality > old.confidence*old.reliability*old.freshness: unique[digest] = item
            if len(unique) >= cls.MAX_EVIDENCE: break
        return sorted(unique.values(), key=lambda x:x.confidence*x.reliability*x.freshness, reverse=True)

    @classmethod
    def decide(cls, records: Iterable[dict[str, Any]], question: str = "") -> Decision20:
        rows = cls.normalize(records)
        sup = [x for x in rows if x.polarity == "supporting"]
        ctr = [x for x in rows if x.polarity == "counter"]
        sup_score = sum(x.confidence*x.reliability*x.freshness for x in sup)
        ctr_score = sum(x.confidence*x.reliability*x.freshness for x in ctr)
        independent_sources = len({x.source for x in sup})
        categories = len({x.category for x in sup})
        diversity_bonus = min(18, independent_sources*4 + categories*2)
        contradiction_penalty = min(30, ctr_score*22)
        risk = int(max(0, min(100, round(sup_score*28 + diversity_bonus - contradiction_penalty))))
        quality = (sum(x.confidence*x.reliability*x.freshness for x in rows)/len(rows)) if rows else .05
        agreement = max(.25, 1.0 - min(.45, ctr_score*.12))
        confidence = max(.05, min(.995, (.28 + quality*.60 + min(.12, independent_sources*.025))*agreement))

        malicious = Hypothesis20("malicious_activity", min(1, sup_score/2.8), confidence,
            tuple(x.claim for x in sup[:7]), tuple(x.claim for x in ctr[:7]))
        benign = Hypothesis20("benign_activity", min(1, ctr_score/2.2), max(.05, 1-confidence),
            tuple(x.claim for x in ctr[:7]), tuple(x.claim for x in sup[:7]))

        gaps=[]; q=(question or "").lower(); sources={x.source.lower() for x in rows}
        if any(k in q for k in ("virus","malware","xavf","threat","infect")) and not any("process" in s for s in sources): gaps.append("process attribution")
        if any(k in q for k in ("network","tarmoq","internet","ulanish")) and not any("network" in s for s in sources): gaps.append("network context")
        if any(k in q for k in ("phishing","fishing","url","link","havola")) and not any("url" in s or "phishing" in s for s in sources): gaps.append("URL/phishing analysis")
        if any(x.freshness < .30 for x in rows): gaps.append("fresh telemetry")
        if not rows: gaps.append("usable evidence")

        if risk >= 88 and confidence >= .93 and not ctr: verdict="HIGH_CONFIDENCE_THREAT"
        elif risk >= 68: verdict="SUSPICIOUS"
        elif risk >= 35: verdict="NEEDS_REVIEW"
        else: verdict="NO_STRONG_EVIDENCE"

        next_best=[]
        preferred=("url_analysis","file_analysis","process_snapshot","network_snapshot","host_snapshot","system_health","recent_security_history")
        have={x.source.lower() for x in rows}
        for tool in preferred:
            if not any(tool.split('_')[0] in h or tool in h for h in have): next_best.append(tool)
        next_best=next_best[:cls.MAX_NEXT]
        if risk >= 88 and confidence >= .93 and not ctr: gate="ALLOW_REVERSIBLE_POLICY_ACTION_ONLY"
        elif risk >= 68: gate="INVESTIGATE_BEFORE_ACTION"
        else: gate="OBSERVE_ONLY"
        ledger=hashlib.sha256((verdict+str(risk)+f"{confidence:.3f}"+"|".join(x.claim for x in rows[:12])).encode()).hexdigest()[:20]
        return Decision20(verdict,risk,round(confidence,3),(malicious,benign),tuple(gaps),tuple(next_best),gate,ledger)

    @classmethod
    def contract(cls, decision: Decision20) -> str:
        return (f"V20 VERDICT={decision.verdict}; RISK={decision.risk}/100; CONFIDENCE={decision.confidence:.2f}; "
                f"ACTION_GATE={decision.action_gate}; GAPS={','.join(decision.gaps) or 'none'}; "
                f"NEXT={','.join(decision.next_best) or 'none'}; LEDGER={decision.ledger_id}. "
                "Treat VERIFIED facts as facts, INFERRED findings as hypotheses, and UNKNOWN as unknown. "
                "Never claim an action occurred without a deterministic verified action result.")

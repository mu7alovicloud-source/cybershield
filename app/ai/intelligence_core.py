"""Unified deterministic intelligence layer for CyberShield AI.

This module does not replace the LLM. It gives every AI path the same:
- bounded memory
- evidence ledger and deduplication
- confidence calibration
- contradiction tracking
- claim/action verification
- prompt/context hygiene

It is intentionally deterministic and safe: it cannot execute OS commands or
authorize destructive actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from collections import deque
from typing import Any, Iterable


@dataclass(frozen=True)
class EvidenceRecord:
    source: str
    statement: str
    confidence: float = 0.5
    polarity: str = "supporting"  # supporting | counter | neutral
    key: str = ""


@dataclass
class IntelligenceState:
    evidence: list[EvidenceRecord] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    risk_score: int = 0
    confidence: float = 0.1


class SecurityAICore:
    """Shared safety/intelligence services for all CyberShield AI surfaces."""

    MAX_MEMORY = 24
    MAX_EVIDENCE = 80
    MAX_CONTEXT_CHARS = 12000

    _secret_re = re.compile(
        r"(?i)(api[_ -]?key|authorization|bearer|password|passwd|secret|token)\s*[:=]\s*[^\s,;]+"
    )
    _unsupported_action_re = re.compile(
        r"(?i)\b(i|we|ai|cybershield)\s+(deleted|removed|quarantined|killed|blocked|executed|ran|disabled|fixed)\b"
    )

    def __init__(self) -> None:
        self.memory: deque[dict[str, str]] = deque(maxlen=self.MAX_MEMORY)

    @staticmethod
    def dedupe_evidence(records: Iterable[EvidenceRecord]) -> list[EvidenceRecord]:
        out: list[EvidenceRecord] = []
        seen: set[tuple[str, str, str]] = set()
        for item in records:
            key = (item.source, item.key or item.statement, item.polarity)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
            if len(out) >= SecurityAICore.MAX_EVIDENCE:
                break
        return out

    def assess(self, records: Iterable[EvidenceRecord], unknown: Iterable[str] = ()) -> IntelligenceState:
        evidence = self.dedupe_evidence(records)
        supporting = [e for e in evidence if e.polarity == "supporting"]
        counter = [e for e in evidence if e.polarity == "counter"]
        independent = {e.key or e.source for e in supporting}
        score = min(100, round(sum(max(0.0, min(1.0, e.confidence)) * 12 for e in supporting)
                              + max(0, len(independent) - 1) * 7
                              - sum(max(0.0, min(1.0, e.confidence)) * 8 for e in counter)))
        # Confidence depends on source availability, independence and agreement;
        # it never becomes high merely because many weak signals repeat.
        if not evidence:
            confidence = 0.10
        else:
            avg = sum(e.confidence for e in evidence) / len(evidence)
            diversity = min(4, len(independent))
            agreement = 1.0 if not counter else max(0.45, 1.0 - 0.12 * len(counter))
            confidence = min(0.98, 0.35 + 0.35 * avg + 0.07 * diversity) * agreement
        contradictions: list[str] = []
        for s in supporting:
            for c in counter:
                if s.key and c.key and s.key == c.key:
                    contradictions.append(f"Conflicting evidence for {s.key}: supporting and counter signals both exist.")
        return IntelligenceState(
            evidence=evidence,
            unknown=list(dict.fromkeys(str(x) for x in unknown if str(x).strip()))[:30],
            contradictions=list(dict.fromkeys(contradictions))[:20],
            risk_score=score,
            confidence=confidence,
        )

    def remember(self, *, user: str, intent: str, target: str | None = None, summary: str = "") -> None:
        self.memory.append({
            "user": self.redact(user)[:800],
            "intent": self.redact(intent)[:80],
            "target": self.redact(target or "")[:500],
            "summary": self.redact(summary)[:1000],
        })

    def context(self, limit: int = 8) -> str:
        rows = list(self.memory)[-max(1, min(limit, self.MAX_MEMORY)):]
        if not rows:
            return "no prior AI session context"
        lines = []
        for r in rows:
            target = f" target={r['target']}" if r.get("target") else ""
            summary = f" summary={r['summary']}" if r.get("summary") else ""
            lines.append(f"intent={r['intent']}{target}{summary} user={r['user']}")
        return "\n".join(lines)[-self.MAX_CONTEXT_CHARS:]

    @classmethod
    def redact(cls, text: Any) -> str:
        value = str(text or "")
        return cls._secret_re.sub(r"\1=[REDACTED]", value)

    @classmethod
    def verify_llm_claims(cls, text: str, *, supplied_actions: Iterable[str] = ()) -> tuple[str, list[str]]:
        """Flag action claims not backed by a supplied action result.

        We do not silently rewrite factual security content. The caller gets
        warnings and can choose a deterministic fallback instead.
        """
        value = cls.redact(text).strip()
        actions = {str(x).lower() for x in supplied_actions}
        warnings: list[str] = []
        for match in cls._unsupported_action_re.finditer(value):
            verb = match.group(2).lower()
            stem = verb[:-2] if verb.endswith("ed") else verb
            if not any(verb in action or stem in action for action in actions):
                warnings.append(f"LLM claimed action '{verb}' without a matching verified action result.")
        return value[:12000], warnings

    @staticmethod
    def safe_action_allowed(*, risk: int, confidence: float, reversible: bool, fresh_evidence: bool) -> bool:
        """Deterministic gate used by AI-facing action paths."""
        return bool(reversible and fresh_evidence and risk >= 85 and confidence >= 0.90)

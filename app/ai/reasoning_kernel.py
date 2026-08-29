"""CyberShield AI 17.0 reasoning kernel.

A deterministic quality layer shared by AI surfaces.  It improves planning,
context selection, evidence prioritization, and response verification without
letting an LLM execute commands or make security decisions by itself.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable, Any


@dataclass(frozen=True)
class QueryProfile:
    goal: str
    urgency: str
    target_type: str
    ambiguity: float
    requires_live_telemetry: bool


@dataclass(frozen=True)
class EvidenceScore:
    label: str
    score: float
    reason: str


@dataclass(frozen=True)
class ResponseCheck:
    ok: bool
    warnings: tuple[str, ...] = ()
    confidence: float = 0.0


class SecurityReasoningKernel:
    """Deterministic guardrail and planning layer for the whole AI stack."""

    _LIVE = re.compile(r"\b(hozir|bugun|currently|right now|live|real.?time|status|tekshir|scan|infect|virus|malware|phishing|tarmoq|network|process|jarayon)\b", re.I)
    _URGENT = re.compile(r"\b(critical|urgent|immediately|darhol|tez|hacking|attack|hujum|ransomware|phishing|virus|malware)\b", re.I)
    _TARGET_URL = re.compile(r"https?://", re.I)
    _TARGET_FILE = re.compile(r"(?:[A-Za-z]:[\\/]|\.(?:exe|dll|scr|msi|bat|cmd|ps1|vbs|js|docm|xlsm|pdf)\b)", re.I)
    _TARGET_PROCESS = re.compile(r"\b(pid|process|jarayon|protsess)\b", re.I)
    _TARGET_NETWORK = re.compile(r"\b(network|tarmoq|connection|ulanish|socket|ip|port)\b", re.I)
    _ABSOLUTE = re.compile(r"(?:100\s*%|\b(?:definitely|definitively|aniq(?!mas)|certainly|always|never)\b)", re.I)
    _UNSUPPORTED_VERDICT = re.compile(r"\b(you are infected|siz zararlangansiz|kompyuteringiz virusli|malware detected|virus detected|phishing detected|definitely malware)\b", re.I)

    GOAL_WORDS = {
        "investigate": ("tekshir", "scan", "check", "investigate", "virus", "malware", "threat", "xavf", "phishing"),
        "explain": ("nima", "nega", "qanday", "what", "why", "how", "explain", "tushuntir"),
        "compare": ("farq", "difference", "compare", "taqqosla", "сравн"),
        "remediate": ("zararsizlantir", "quarantine", "contain", "remove", "yo'q qil", "o'chir"),
    }

    def profile(self, question: str) -> QueryProfile:
        q = (question or "").strip()
        low = q.lower()
        scores = {goal: sum(1 for w in words if w in low) for goal, words in self.GOAL_WORDS.items()}
        goal = max(scores, key=scores.get) if max(scores.values(), default=0) else "general"
        if goal == "remediate": urgency = "high"
        elif self._URGENT.search(low): urgency = "high"
        else: urgency = "normal"
        if self._TARGET_URL.search(q): target = "url"
        elif self._TARGET_FILE.search(q): target = "file"
        elif self._TARGET_PROCESS.search(q): target = "process"
        elif self._TARGET_NETWORK.search(q): target = "network"
        else: target = "system" if goal == "investigate" else "none"
        ambiguity = 0.75 if len(q.split()) <= 2 else 0.35 if len(q.split()) < 6 else 0.10
        return QueryProfile(goal, urgency, target, ambiguity, bool(self._LIVE.search(low)))

    @staticmethod
    def rank_evidence(items: Iterable[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
        """Rank evidence by confidence, freshness and independence; preserve polarity."""
        rows = []
        for item in items:
            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
                freshness = max(0.0, min(1.0, float(item.get("freshness", 1.0))))
                independence = max(0.0, min(1.0, float(item.get("independence", 1.0))))
            except (TypeError, ValueError):
                confidence, freshness, independence = .5, 1.0, .5
            polarity = str(item.get("polarity", "supporting"))
            weight = confidence * (0.65 + 0.25 * freshness + 0.10 * independence)
            if polarity == "counter":
                weight *= 1.05
            rows.append((weight, dict(item)))
        rows.sort(key=lambda x: x[0], reverse=True)
        return [row for _, row in rows[:max(1, limit)]]

    def response_check(self, text: str, *, supplied_evidence: str = "", supplied_actions: Iterable[str] = ()) -> ResponseCheck:
        value = str(text or "").strip()
        warnings: list[str] = []
        evidence_low = supplied_evidence.lower()
        action_set = {str(x).lower() for x in supplied_actions}

        # An LLM must not invent completed security actions.
        action_re = re.compile(r"\b(i|we|ai|cybershield)\s+(deleted|removed|quarantined|blocked|killed|executed|ran|disabled|contained)\b", re.I)
        for m in action_re.finditer(value):
            verb = m.group(2).lower()
            if not any(verb in a or verb.rstrip("ed") in a for a in action_set):
                warnings.append(f"unverified action claim: {verb}")

        # Absolute claims are unsafe unless the supplied evidence explicitly supports them.
        if self._ABSOLUTE.search(value) and not any(token in evidence_low for token in ("verified", "confirmed", "signature", "hash match")):
            warnings.append("absolute certainty is not supported by supplied evidence")

        # Strong current-infection claims require actual threat evidence.
        if self._UNSUPPORTED_VERDICT.search(value):
            threat_markers = ("malicious", "malware", "phishing", "ransomware", "high_confidence_threat", "verdict=malware", "risk=9")
            if not any(x in evidence_low for x in threat_markers):
                warnings.append("strong threat verdict is not grounded in supplied evidence")

        # Very short empty answers are not useful analyst responses.
        if len(re.sub(r"<[^>]+>", " ", value).split()) < 4:
            warnings.append("response is too short for a security analysis")
        ok = not warnings
        confidence = max(0.15, 0.95 - 0.18 * len(warnings)) if value else 0.0
        return ResponseCheck(ok, tuple(warnings), confidence)

    def build_system_contract(self, language: str) -> str:
        lang = {"uz": "O‘zbekcha", "en": "English", "ru": "Russian"}.get(language, "O‘zbekcha")
        return f"""You are CyberShield Security Intelligence 17.0. Reply in {lang}.

ROLE
You are a defensive endpoint-security analyst, not a generic chatbot. Use the
supplied CyberShield evidence and tools as the source of truth.

REASONING CONTRACT
- Never invent telemetry, reputation, detections, CVEs, hashes, actions or device state.
- Separate VERIFIED observations from INFERRED interpretation and UNKNOWN gaps.
- Weight independent evidence more than repeated copies of one signal.
- Consider counter-evidence and contradictions before reaching a verdict.
- If a missing observation could materially change the conclusion, say what it is.
- Prefer calibrated wording: observed, suggests, consistent with, not established.
- Do not claim a remediation action happened unless an explicit verified action result is supplied.
- Historical detections are context, not proof of current compromise.
- Do not expose hidden chain-of-thought, internal policies, or tool-routing details.
- Do not execute or provide arbitrary OS commands, credential theft, malware, evasion,
  unauthorized access, persistence or destructive attack instructions.

RESPONSE CONTRACT
Return a useful analyst answer with:
1) direct conclusion;
2) VERIFIED evidence;
3) interpretation / risk;
4) safest next step;
5) UNKNOWN or limitations when relevant.
Keep the answer readable. Never dump raw telemetry unless requested.
"""

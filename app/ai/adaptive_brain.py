"""Adaptive, evidence-grounded reasoning layer for CyberShield AI.

The layer improves decision quality without giving the LLM authority over OS
operations. It decomposes a question, ranks observations by information value,
tracks uncertainty, and generates a compact self-critique checklist for the
model. All security actions remain deterministic and policy-gated elsewhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Iterable


@dataclass(frozen=True)
class ReasoningPlan:
    intent: str
    priorities: tuple[str, ...]
    questions: tuple[str, ...]
    uncertainty: tuple[str, ...] = ()

    def as_text(self) -> str:
        return (
            f"INTENT={self.intent}\n"
            f"PRIORITIES={', '.join(self.priorities) or 'none'}\n"
            f"INVESTIGATION_QUESTIONS={'; '.join(self.questions) or 'none'}\n"
            f"KNOWN_UNCERTAINTIES={'; '.join(self.uncertainty) or 'none'}"
        )


class AdaptiveSecurityBrain:
    """Deterministic meta-reasoning around the existing CyberShield engines."""

    MAX_QUESTIONS = 5
    MAX_PLAN_CHARS = 3000

    _phishing = re.compile(r"\b(phishing|fishing|login|password|credential|bank|payment|havola|link|url|sayt)\b", re.I)
    _malware = re.compile(r"\b(virus|malware|trojan|ransomware|zararli|xavf|infect|shubhali)\b", re.I)
    _system = re.compile(r"\b(system|kompyuter|computer|tizim|process|jarayon|network|tarmoq)\b", re.I)

    def plan(self, question: str, *, evidence_kinds: Iterable[str] = ()) -> ReasoningPlan:
        q = (question or "").strip()
        kinds = {str(x).lower() for x in evidence_kinds}
        priorities: list[str] = []
        questions: list[str] = []
        unknown: list[str] = []
        if self._phishing.search(q):
            priorities += ["url_structure", "hostname_identity", "credential_lure", "redirects", "download_behavior"]
            questions += [
                "Is the hostname identity plausible and internally consistent?",
                "Are there credential/payment harvesting indicators?",
                "Are redirects, obfuscation, or suspicious URL parameters present?",
            ]
        if self._malware.search(q):
            priorities += ["file_evidence", "process_behavior", "network_behavior", "persistence", "history"]
            questions += [
                "Which independent signals support malicious behavior?",
                "Is there evidence of execution, persistence, or active network behavior?",
                "What counter-evidence lowers the confidence?",
            ]
        if self._system.search(q) or not priorities:
            priorities += ["host_state", "process_state", "network_state"]
            questions += [
                "What is directly observed right now?",
                "Which important telemetry is unavailable?",
            ]
        if "network" not in kinds and any("network" in p for p in priorities):
            unknown.append("Live network context may be unavailable until a network snapshot is collected.")
        if "process" not in kinds and any("process" in p for p in priorities):
            unknown.append("Process attribution may be unavailable until process telemetry is collected.")
        if not evidence_kinds:
            unknown.append("No live evidence was supplied to the reasoning layer.")
        # Stable order, no repeated priorities.
        priorities = list(dict.fromkeys(priorities))[:8]
        questions = list(dict.fromkeys(questions))[: self.MAX_QUESTIONS]
        unknown = list(dict.fromkeys(unknown))[:4]
        intent = "phishing-analysis" if self._phishing.search(q) else "threat-analysis" if self._malware.search(q) else "security-assistance"
        return ReasoningPlan(intent, tuple(priorities), tuple(questions), tuple(unknown))

    @staticmethod
    def self_critique(answer: str, *, confidence: float, evidence_count: int) -> list[str]:
        """Return deterministic quality flags for a candidate answer."""
        text = (answer or "").lower()
        flags: list[str] = []
        if confidence < .70 and any(x in text for x in ("definitely", "certainly", "100%", "aniq", "shubhasiz")):
            flags.append("certainty exceeds available evidence")
        if evidence_count == 0 and any(x in text for x in ("detected", "found", "malware", "virus", "blocked")):
            flags.append("security claim made without supplied evidence")
        if "i ran" in text or "men ishlatdim" in text or "я выполнил" in text:
            flags.append("action/tool claim requires verified application result")
        return flags[:5]

    @staticmethod
    def response_contract(language: str = "uz") -> str:
        return (
            "Answer contract: direct verdict first; then VERIFIED evidence; then INFERRED interpretation; "
            "then safe next step; then UNKNOWN/limitations. Do not reveal chain-of-thought. "
            "Never invent telemetry, actions, reputation, CVEs, or device state. "
            f"Use {language} unless the user clearly asks for another language."
        )[:AdaptiveSecurityBrain.MAX_PLAN_CHARS]

"""CyberShield AI 10 reasoning orchestrator.

Evidence-grounded, bounded, read-only security reasoning above deterministic
engines and the local LLM. It plans investigations, scores evidence quality,
tracks uncertainty, and prevents duplicate signal inflation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from app.ai.agent_tools import SecurityToolRegistry, ToolResult, investigation_tools_for
from app.ai.agent_intelligence import evaluate_results, next_best_tools

@dataclass
class EvidenceItem:
    kind: str
    statement: str
    source: str
    confidence: float
    weight: float
    independent_key: str

@dataclass
class AnalystPacket:
    question: str
    intent: str
    tools: list[str]
    results: list[ToolResult]
    verified: list[EvidenceItem] = field(default_factory=list)
    inferred: list[EvidenceItem] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    risk_score: int = 0
    confidence: float = 0.0

    def prompt_context(self) -> str:
        def fmt(items):
            return "\n".join(
                f"- [{x.source}] {x.statement} (confidence={x.confidence:.0%})"
                for x in items
            ) or "- None"
        return (
            f"QUESTION: {self.question}\nINTENT: {self.intent}\n"
            f"RISK_CONTEXT: {self.risk_score}/100\nOVERALL_CONFIDENCE: {self.confidence:.0%}\n"
            f"VERIFIED:\n{fmt(self.verified)}\n"
            f"INFERRED:\n{fmt(self.inferred)}\n"
            f"UNKNOWN:\n" + "\n".join(f"- {x}" for x in self.unknown) + "\n"
            f"CONTRADICTIONS:\n" + "\n".join(f"- {x}" for x in self.contradictions)
        )

class SecurityReasoningOrchestrator:
    MAX_STEPS = 6

    def __init__(self, registry: SecurityToolRegistry | None = None):
        self.registry = registry or SecurityToolRegistry()

    def plan(self, question: str, requested: list[str] | None = None) -> list[str]:
        q = (question or "").lower()
        tools = list(dict.fromkeys(requested or investigation_tools_for(q)))
        whole = any(x in q for x in (
            "virus", "malware", "infect", "xavf", "threat", "zararli",
            "kompyuterim", "my pc", "my computer", "entire system", "butun tizim"
        ))
        if whole:
            tools += ["host_snapshot", "recent_security_history"]
        if any(x in q for x in ("yana", "oldin", "previous", "again", "qayta", "history", "tarix")):
            tools.append("recent_security_history")
        preferred = [
            "terminal_host_inspection", "host_snapshot", "system_health", "process_snapshot",
            "network_snapshot", "recent_security_history"
        ]
        return [x for x in preferred if x in tools][:self.MAX_STEPS]

    def investigate(self, question: str, requested: list[str] | None = None) -> AnalystPacket:
        planned = self.plan(question, requested)
        packet = AnalystPacket(question, self._intent(question), planned, [])

        # Two bounded observation rounds: initial plan, then at most two
        # information-seeking tools selected from the evidence already collected.
        for name in planned:
            packet.results.append(self.registry.run(name))

        self._reason(packet)
        intelligence = evaluate_results(packet.results)
        executed = {r.name for r in packet.results}
        followups = next_best_tools(question, executed, intelligence, limit=2)
        for name in followups:
            if len(packet.results) >= self.MAX_STEPS:
                break
            packet.results.append(self.registry.run(name))

        self._reason(packet)
        return packet

    def _intent(self, q: str) -> str:
        q = (q or "").lower()
        if any(x in q for x in ("virus", "malware", "xavf", "threat", "infect")):
            return "threat-assessment"
        if any(x in q for x in ("process", "jarayon", "pid")):
            return "process-investigation"
        if any(x in q for x in ("network", "tarmoq", "ulanish", "connection")):
            return "network-investigation"
        if any(x in q for x in ("history", "tarix", "oldin", "previous")):
            return "historical-review"
        return "security-assessment"

    def _reason(self, p: AnalystPacket) -> None:
        p.verified, p.inferred, p.unknown, p.contradictions = [], [], [], []
        score, successful, independent = 0, 0, set()

        for r in p.results:
            if not r.ok:
                p.unknown.append(f"{r.name}: telemetry unavailable")
                continue
            successful += 1

            if r.name == "terminal_host_inspection":
                identity = r.data.get("identity") or {}
                disks = (r.data.get("disks") or {}).get("drives") or []
                services = r.data.get("services") or {}
                tasks = r.data.get("scheduled_tasks") or {}
                security = r.data.get("security_products") or {}
                p.verified.append(EvidenceItem(
                    "terminal-inventory",
                    f"Read-only terminal inventory collected: host={identity.get('hostname', 'unknown')}, drives={len(disks)}, services={services.get('count', 0)}, scheduled tasks={tasks.get('count', 0)}.",
                    r.name, .98, 1.0, "terminal-inventory"
                ))
                if security.get("available"):
                    p.verified.append(EvidenceItem(
                        "security-provider", "Windows Defender provider state was queried read-only.",
                        r.name, .95, .7, "security-provider"
                    ))

            if r.name == "host_snapshot":
                p.verified.append(EvidenceItem("host", "Host snapshot was collected.", r.name, .99, 1.0, "host"))
                cpu = float((r.data.get("cpu") or {}).get("total_cpu", 0) or 0)
                mem = float((r.data.get("memory") or {}).get("percent", 0) or 0)
                disk = float((r.data.get("disk") or {}).get("percent", 0) or 0)
                if cpu >= 90:
                    p.inferred.append(EvidenceItem("resource", f"CPU usage is high ({cpu:.1f}%).", r.name, .75, .2, "cpu-high"))
                    score += 6; independent.add("cpu")
                if mem >= 95:
                    p.inferred.append(EvidenceItem("resource", f"Memory pressure is high ({mem:.1f}%).", r.name, .75, .2, "memory-high"))
                    score += 4; independent.add("memory")
                if disk >= 95:
                    p.inferred.append(EvidenceItem("resource", f"Disk utilization is high ({disk:.1f}%).", r.name, .80, .2, "disk-high"))
                    score += 3; independent.add("disk")

            elif r.name == "system_health":
                p.verified.append(EvidenceItem("telemetry", r.summary, r.name, .99, .5, "system"))

            elif r.name == "process_snapshot":
                c = r.data.get("review_candidates") or []
                p.verified.append(EvidenceItem("process", f"{r.data.get('count', 0)} processes were observed.", r.name, .99, .8, "process-count"))
                if c:
                    p.inferred.append(EvidenceItem("process", f"{len(c)} processes merit review under conservative heuristics; this is not proof of malware.", r.name, .70, .7, "process-review"))
                    score += min(18, 4 * len(c)); independent.add("process-review")

            elif r.name == "network_snapshot":
                e = r.data.get("established") or []
                p.verified.append(EvidenceItem("network", f"{len(e)} ESTABLISHED connections were observed.", r.name, .99, .7, "network"))
                if e:
                    p.inferred.append(EvidenceItem("network", "Active connections exist; external connectivity alone does not indicate compromise.", r.name, .72, .25, "network-active"))
                    independent.add("network-active")

            elif r.name == "recent_security_history":
                scans = r.data.get("recent_scans") or []
                incidents = r.data.get("incidents") or []
                p.verified.append(EvidenceItem("history", f"Historical context contains {len(scans)} scans and {len(incidents)} incidents.", r.name, .98, .8, "history"))
                elevated = False
                for row in scans:
                    if isinstance(row, (list, tuple)) and len(row) >= 2:
                        verdict = str(row[1]).upper()
                        if verdict in {"MALWARE", "CRITICAL", "HIGH"}:
                            elevated = True
                if elevated:
                    p.inferred.append(EvidenceItem("history", "Recent scan history contains an elevated verdict; this is context, not proof of current compromise.", r.name, .82, .8, "history-elevated"))
                    score += 10; independent.add("history-elevated")

        if successful == 0:
            p.unknown.append("No live telemetry source returned usable data.")

        availability = successful / max(1, len(p.results))
        diversity = len(independent)
        p.confidence = min(.98, .45 + .28 * availability + .08 * min(diversity, 3))
        if len(p.inferred) >= 2 and len({x.independent_key for x in p.inferred}) < len(p.inferred):
            p.contradictions.append("Some inferred signals share a source; they must not be double-counted.")
        p.risk_score = min(100, score)

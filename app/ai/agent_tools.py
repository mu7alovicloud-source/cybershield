"""Safe read-only tool layer for CyberShield AI.

The AI can inspect CyberShield telemetry through explicit, bounded tools.  The
agent never executes arbitrary shell commands and never performs destructive
security actions directly.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable

from app.security.cpu_monitor import get_cpu_snapshot
from app.security.process_monitor import get_processes
from app.security.network_monitor import get_connections
from app.security.host_snapshot import collect_host_snapshot
from app.database.database import get_recent_scans, get_incidents
from app.security.scanner import analyze_file
from app.security.containment_engine import contain_if_safe
from app.security.phishing_guard import analyze_url
from app.ai.terminal_intelligence import inspect_host
from app.security.endpoint_scanner import quick_scan


@dataclass
class ToolResult:
    name: str
    ok: bool
    summary: str
    data: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class SecurityToolRegistry:
    """Bounded, deterministic telemetry tools exposed to the AI planner."""

    def __init__(self) -> None:
        self._tools: dict[str, Callable[[], ToolResult]] = {
            "system_health": self.system_health,
            "process_snapshot": self.process_snapshot,
            "network_snapshot": self.network_snapshot,
            "host_snapshot": self.host_snapshot,
            "recent_security_history": self.recent_security_history,
            "terminal_host_inspection": self.terminal_host_inspection,
            "endpoint_quick_scan": self.endpoint_quick_scan,
        }

    def analyze_file(self, path: str) -> ToolResult:
        """Analyze one explicit file without executing it."""
        try:
            result = analyze_file(path)
            return ToolResult(
                "file_analysis", True,
                f"{result.get('name', path)}: {result.get('verdict', 'UNKNOWN')} risk={result.get('risk', 0)}/100.",
                result,
            )
        except Exception as exc:
            return ToolResult("file_analysis", False, "File analysis failed safely", {"error": str(exc)})

    def contain_file(self, path: str) -> ToolResult:
        """High-confidence, reversible containment of an explicit target."""
        try:
            result = contain_if_safe(path, automatic=True)
            if result.get("contained"):
                summary = f"Threat contained and verified: {result.get('quarantine_path')}"
            else:
                summary = f"Automatic containment refused: {result.get('reason', 'policy threshold not met')}"
            return ToolResult("contain_file", True, summary, result)
        except Exception as exc:
            return ToolResult("contain_file", False, "Containment failed safely", {"error": str(exc)})

    def analyze_url(self, url: str) -> ToolResult:
        """Analyze an explicit URL locally without making a network request."""
        try:
            result = analyze_url(url)
            return ToolResult("url_analysis", True, f"URL verdict={result.get('verdict')} risk={result.get('score', 0)}/100.", result)
        except Exception as exc:
            return ToolResult("url_analysis", False, "URL analysis failed safely", {"error": str(exc)})

    def available(self) -> list[str]:
        # Public compatibility list stays focused on the original stable API.
        # The additional terminal inspection tool remains callable by the
        # reasoning orchestrator through run(), but is not advertised as a
        # generic tool to legacy callers.
        return ["system_health", "process_snapshot", "network_snapshot", "host_snapshot", "recent_security_history"]

    def run(self, name: str) -> ToolResult:
        fn = self._tools.get(name)
        if not fn:
            return ToolResult(name, False, "Unknown tool", {})
        try:
            return fn()
        except Exception as exc:
            return ToolResult(name, False, "Tool failed safely", {"error": str(exc)})

    def investigate(self, requested: list[str]) -> list[ToolResult]:
        # Hard cap prevents an accidental prompt from turning into an endless
        # telemetry loop.
        return [self.run(name) for name in requested[:6]]

    def system_health(self) -> ToolResult:
        cpu = get_cpu_snapshot(2)
        processes = get_processes(25)
        connections = get_connections(30)
        return ToolResult(
            "system_health",
            True,
            f"CPU {cpu.get('total_cpu', 0)}%; {len(processes)} processes; {len(connections)} connections.",
            {
                "cpu": cpu,
                "process_count": len(processes),
                "connection_count": len(connections),
            },
        )

    def process_snapshot(self) -> ToolResult:
        rows = get_processes(40)
        suspicious = [
            p for p in rows
            if float(p.get("cpu", 0) or 0) >= 25
            or not p.get("exe")
        ]
        return ToolResult(
            "process_snapshot",
            True,
            f"Observed {len(rows)} processes; {len(suspicious)} need review based on limited heuristics.",
            {"count": len(rows), "review_candidates": suspicious[:12]},
        )

    def network_snapshot(self) -> ToolResult:
        rows = get_connections(40)
        established = [r for r in rows if str(r.get("status", "")).upper() == "ESTABLISHED"]
        return ToolResult(
            "network_snapshot",
            True,
            f"Observed {len(rows)} connections; {len(established)} are ESTABLISHED.",
            {"count": len(rows), "established": established[:15]},
        )


    def host_snapshot(self) -> ToolResult:
        """Read-only whole-host snapshot using existing CyberShield collectors."""
        data = collect_host_snapshot()
        return ToolResult(
            "host_snapshot", True,
            f"Host snapshot collected for {data.get('hostname', 'unknown')}; "
            f"{len(data.get('processes', []))} processes and "
            f"{len(data.get('connections', []))} connections.",
            data,
        )

    def terminal_host_inspection(self) -> ToolResult:
        """Terminal-like broad host inspection; read-only and bounded."""
        try:
            data = inspect_host()
            return ToolResult(
                "terminal_host_inspection", True,
                "Broad read-only host inspection completed: identity, disks, services, scheduled tasks, security provider state and safe environment metadata.",
                data,
            )
        except Exception as exc:
            return ToolResult("terminal_host_inspection", False, "Host inspection failed safely", {"error": str(exc)})

    def endpoint_quick_scan(self) -> ToolResult:
        """Real bounded endpoint triage: local files + running-process binaries + Defender."""
        try:
            data = quick_scan(include_defender=True)
            return ToolResult(
                "endpoint_quick_scan", True,
                f"Endpoint quick scan inspected {data.get('scanned_files', 0)} files and found {len(data.get('findings', []))} review candidates.",
                data,
            )
        except Exception as exc:
            return ToolResult("endpoint_quick_scan", False, "Endpoint scan failed safely", {"error": str(exc)})

    def recent_security_history(self) -> ToolResult:
        """Read-only historical context; never authorizes an action."""
        try:
            scans = get_recent_scans(8)
            incidents = get_incidents()
            return ToolResult(
                "recent_security_history", True,
                f"Loaded {len(scans)} recent scans and {len(incidents)} incidents.",
                {"recent_scans": scans, "incidents": incidents[:12]},
            )
        except Exception as exc:
            return ToolResult("recent_security_history", False, "History unavailable", {"error": str(exc)})


def investigation_tools_for(question: str) -> list[str]:
    """Map natural-language investigation requests to safe read-only tools."""
    q = (question or "").lower()
    requested: list[str] = []
    # Bare scan commands must trigger local security telemetry, never web
    # research. A scan is an endpoint operation: collect host identity/drives,
    # services/tasks/security providers, processes and network state.
    scan_commands = {
        "scan", "skan", "skan qil", "full scan", "deep scan", "quick scan", "system scan",
        "scan system", "scan my system", "scan the system", "scan computer", "scan my computer",
        "scan pc", "scan my pc", "check system", "check my system", "check computer",
        "check my computer", "computer scan", "pc scan", "device scan", "to'liq skan",
        "chuqur skan", "tizimni skan qil", "tizimni tekshir", "kompyuterni skan qil",
        "kompyuterni tekshir", "полное сканирование", "скан", "сканируй систему", "проверь систему",
    }
    scan_phrase = (
        ("scan" in q or "skan" in q or "скan" in q)
        and any(x in q for x in ("system", "tizim", "computer", "kompyuter", "pc", "device"))
    )
    if q.strip() in scan_commands or scan_phrase:
        requested.extend([
            "terminal_host_inspection", "host_snapshot", "system_health",
            "process_snapshot", "network_snapshot", "endpoint_quick_scan",
        ])
        return requested[:6]
    if any(x in q for x in ("kompyuter", "tizim", "system", "computer", "holat", "security status", "xavfsizlik holati")):
        requested.append("system_health")
    if any(x in q for x in ("process", "jarayon", "protsess", "pid", "ishlayotgan")):
        requested.append("process_snapshot")
    if any(x in q for x in ("network", "tarmoq", "ulanish", "connection", "internet")):
        requested.append("network_snapshot")
    if any(x in q for x in ("history", "tarix", "oldingi skan", "incident", "hodisa", "previous scan")):
        requested.append("recent_security_history")
    # Broad threat questions deserve a compact whole-host investigation.
    if any(x in q for x in ("virus bormi", "malware bormi", "xavf bormi", "threat", "zararli", "infected", "yuqtirgan")):
        requested.extend(["host_snapshot", "system_health", "process_snapshot", "network_snapshot"])
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(requested))[:6]

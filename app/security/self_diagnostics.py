"""Non-destructive CyberShield runtime self-diagnostics."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import importlib
import sys

CORE_MODULES = (
    "app.ai.agent_tools", "app.ai.intelligence_v20", "app.ai.security_orchestrator",
    "app.security.scanner", "app.security.phishing_guard", "app.security.quarantine",
    "app.security.containment_engine",
)

@dataclass(frozen=True)
class DiagnosticResult:
    ok: bool
    python: str
    modules: dict[str, bool]
    failed: tuple[str, ...]

    def as_dict(self):
        return asdict(self)


def run_self_diagnostics() -> DiagnosticResult:
    modules = {}
    failed = []
    for name in CORE_MODULES:
        try:
            importlib.import_module(name)
            modules[name] = True
        except Exception:
            modules[name] = False
            failed.append(name)
    return DiagnosticResult(not failed, sys.version.split()[0], modules, tuple(failed))

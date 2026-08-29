"""Post-action verification for defensive containment."""
from dataclasses import dataclass
from pathlib import Path

@dataclass
class VerificationResult:
    state: str
    checks: dict[str, bool]
    message: str


def verify_quarantine(path: str, quarantine_path: str) -> VerificationResult:
    original = Path(path)
    isolated = Path(quarantine_path)
    q = Path(quarantine_path)
    checks = {
        "original_absent": not original.exists(),
        "isolated_exists": isolated.exists(),
        "quarantine_exists": q.exists(),
    }
    ok = all(checks.values())
    return VerificationResult("RESOLVED" if ok else "FAILED", checks,
                              "Containment verified" if ok else "Containment verification failed")

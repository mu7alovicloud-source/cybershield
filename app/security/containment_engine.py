"""Policy-gated autonomous defensive containment.

CyberShield can automatically neutralize a high-confidence local threat by
moving the exact original bytes into its reversible quarantine vault and then
verifying containment. It never executes or edits malware bytes.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import QUARANTINE_DIR
from app.security.scanner import analyze_file
from app.security.advanced_detection import analyze_file_deep
from app.security.quarantine import quarantine_file
from app.security.verifier import verify_quarantine

AUTO_RISK = 85
AUTO_CONFIDENCE = 0.95


def _is_protected_path(path: Path) -> bool:
    """Return True for OS-critical locations where automatic movement is unsafe."""
    p = str(path).replace("/", "\\").lower()
    if os.name != "nt":
        # Test environments may use Windows-looking paths; do not over-block
        # ordinary POSIX temp paths.
        return False
    protected = (
        r"\\windows\\system32\\",
        r"\\windows\\syswow64\\",
        r"\\windows\\winsxs\\",
        r"\\program files\\",
        r"\\program files (x86)\\",
        r"\\boot\\",
        r"\\efi\\",
        r"\\recovery\\",
    )
    return any(token in p for token in protected)


def _strong_evidence(result: dict[str, Any]) -> int:
    return sum(
        1 for item in (result.get("evidence") or [])
        if str(item.get("severity", "")).lower() in {"high", "critical"}
    )


def assess_containment(path: str | Path) -> dict[str, Any]:
    """Statically assess whether automatic containment is permitted."""
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        return {"allowed": False, "reason": "target_not_found", "path": str(p)}
    if _is_protected_path(p):
        return {"allowed": False, "reason": "protected_os_path", "path": str(p)}

    result = analyze_file_deep(p, endpoint_scan=True, reputation=True)
    risk = int(result.get("risk", 0) or 0)
    confidence = float(result.get("confidence", 0) or 0)
    verdict = str(result.get("verdict", "")).upper()
    strong = _strong_evidence(result)
    allowed = (
        risk >= AUTO_RISK
        and confidence >= AUTO_CONFIDENCE
        and verdict in {"MALICIOUS", "LIKELY MALICIOUS"}
        and (strong >= 2 or (verdict == "MALICIOUS" and risk >= 92))
    )
    return {
        "allowed": allowed,
        "path": str(p),
        "risk": risk,
        "confidence": confidence,
        "verdict": verdict,
        "strong_evidence": strong,
        "analysis": result,
        "reason": "high_confidence_threat" if allowed else "policy_threshold_not_met",
    }


def contain_if_safe(path: str | Path, *, automatic: bool = True) -> dict[str, Any]:
    """Analyze and, only when policy allows, quarantine and verify the target."""
    assessment = assess_containment(path)
    if not assessment.get("allowed"):
        assessment["action"] = "NO_ACTION"
        assessment["contained"] = False
        return assessment

    target = Path(assessment["path"])
    if automatic and not assessment.get("allowed"):
        return {**assessment, "action": "NO_ACTION", "contained": False}

    before = assessment["analysis"].get("sha256")
    quarantine_path = quarantine_file(target)
    verification = verify_quarantine(str(target), str(quarantine_path))
    ok = verification.state == "RESOLVED"
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "AUTO_QUARANTINE" if automatic else "QUARANTINE",
        "target": str(target),
        "quarantine_path": str(quarantine_path),
        "sha256": before,
        "risk": assessment["risk"],
        "confidence": assessment["confidence"],
        "verdict": assessment["verdict"],
        "verification": verification.checks,
        "result": "CONTAINED" if ok else "VERIFICATION_FAILED",
    }
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        audit = QUARANTINE_DIR / "containment_audit.jsonl"
        with audit.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        # Containment itself has already happened; audit failure is reported.
        event["audit_warning"] = "Containment audit could not be persisted"

    return {
        **assessment,
        "action": event["action"],
        "contained": ok,
        "quarantine_path": str(quarantine_path),
        "verification": verification.checks,
        "event": event,
    }

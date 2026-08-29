"""Non-destructive defensive remediation.

CyberShield does not pretend it can surgically remove arbitrary malware from
an executable while guaranteeing byte-for-byte application correctness. The
safe generic operation is verified quarantine, which preserves the original
bytes and records enough metadata for exact restoration.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from datetime import datetime, timezone

from app.security.quarantine import quarantine_file
from app.security.hash_analyzer import sha256_file
from app.config import QUARANTINE_DIR


def remediate_file(path: str | Path, *, confidence: float, risk: int) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(str(p))
    if confidence < 0.90 or risk < 85:
        return {
            "ok": False,
            "action": "HUMAN_REVIEW",
            "message": "Confidence/risk is not high enough for automatic containment.",
        }
    before = sha256_file(p)
    dst = quarantine_file(p)
    after = sha256_file(dst)
    if before != after:
        raise IOError("Remediation integrity check failed: file bytes changed")
    return {
        "ok": True,
        "action": "QUARANTINED",
        "original_path": str(p),
        "quarantine_path": str(dst),
        "sha256": before,
        "bytes_preserved": True,
        "reversible": True,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


def restore_quarantine(quarantine_path: str | Path) -> dict:
    q = Path(quarantine_path).expanduser().resolve()
    meta_path = q.with_suffix(q.suffix + ".json")
    if not q.is_file() or not meta_path.is_file():
        raise FileNotFoundError("Quarantine object or metadata is missing")
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    target = Path(meta["original_path"]).expanduser().resolve()
    expected = str(meta["sha256"])
    if sha256_file(q) != expected:
        raise IOError("Quarantine integrity check failed")
    if target.exists():
        return {"ok": False, "message": "Original path already exists; restore refused to avoid overwrite.", "path": str(target)}
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(q, target)
    if sha256_file(target) != expected:
        target.unlink(missing_ok=True)
        raise IOError("Restore verification failed; restored file was removed")
    return {"ok": True, "restored_path": str(target), "sha256": expected, "bytes_preserved": True}

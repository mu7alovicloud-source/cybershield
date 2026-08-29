"""Reversible quarantine with hash verification and audit metadata."""
import json, shutil, os
from datetime import datetime, timezone
from pathlib import Path
from app.config import QUARANTINE_DIR
from app.security.hash_analyzer import sha256_file


def quarantine_file(path):
    src = Path(path).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(str(src))
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(src)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = QUARANTINE_DIR / f"{stamp}_{digest[:12]}_{src.name}"
    dst = base
    counter = 1
    while dst.exists():
        dst = QUARANTINE_DIR / f"{stamp}_{digest[:12]}_{counter}_{src.name}"
        counter += 1
    shutil.copy2(src, dst)
    copied_digest = sha256_file(dst)
    if copied_digest != digest:
        dst.unlink(missing_ok=True)
        raise IOError("Quarantine integrity verification failed")
    os.replace(src, dst)
    if sha256_file(dst) != digest:
        raise IOError("Post-move quarantine verification failed")
    isolated = dst
    metadata = {
        "original_path": str(src), "isolated_path": str(isolated), "quarantine_path": str(dst),
        "sha256": digest, "quarantined_at": datetime.now(timezone.utc).isoformat(),
        "action": "COPY_VERIFY_ISOLATE", "reversible": True,
    }
    (dst.with_suffix(dst.suffix + ".json")).write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return dst


class Quarantine:
    """Compatibility facade for the reversible quarantine service.

    The implementation remains evidence-preserving and never executes a sample.
    """
    def quarantine(self, path):
        return quarantine_file(path)

    def quarantine_file(self, path):
        return quarantine_file(path)

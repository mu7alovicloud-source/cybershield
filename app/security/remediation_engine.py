"""Safety-gated defensive remediation operations."""
from pathlib import Path
from app.security.quarantine import quarantine_file

ALLOWED_ACTIONS = {"BLOCK_EXECUTION", "QUARANTINE_FILE", "RESTORE_OBJECT"}


def quarantine(path: str):
    return quarantine_file(path)


def plan(action: str, target: str) -> dict:
    action = action.upper().strip()
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported defensive action: {action}")
    if not target:
        raise ValueError("Target is required")
    return {"action": action, "target": str(Path(target)), "requires_confirmation": action != "BLOCK_EXECUTION"}

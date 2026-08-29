from app.security.quarantine import quarantine_file

ALLOWED_ACTIONS = {"quarantine", "collect_evidence", "block_indicator", "notify_user", "escalate"}

def safe_response(action, path=None):
    if action == 'quarantine' and path:
        return {"ok": True, "action": "quarantine", "destination": str(quarantine_file(path))}
    if action in {"collect_evidence", "block_indicator", "notify_user", "escalate"}:
        return {"ok": True, "action": action, "message": "Policy-controlled defensive action recorded; OS-destructive commands are not executed."}
    return {"ok": False, "message": "Unknown or unsafe response action"}

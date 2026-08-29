from dataclasses import dataclass
from pathlib import Path
from app.config import LAB_DYNAMIC_ENABLED, LAB_NETWORK_MODE, LAB_REQUIRE_SNAPSHOT

@dataclass
class LabDecision:
    status: str
    message: str
    actions: list

def assess_dynamic_lab_readiness():
    failures = []
    if not LAB_DYNAMIC_ENABLED: failures.append("Dynamic execution is disabled until an external disposable VM is configured.")
    if LAB_NETWORK_MODE != "DISABLED": failures.append("Lab network must be fully disabled or controlled by an isolated hypervisor policy.")
    if not LAB_REQUIRE_SNAPSHOT: failures.append("A disposable snapshot is mandatory.")
    if failures:
        return LabDecision("ESCALATE", "CYBERSHIELD'GA MUROJAAT QILING: xavfsiz dinamik tahlil uchun izolyatsiyalangan VM tayyor emas.", failures)
    return LabDecision("READY", "Isolated lab policy is ready.", [])

def prepare_sample(path):
    p = Path(path)
    if not p.is_file(): raise FileNotFoundError(str(p))
    d = assess_dynamic_lab_readiness()
    if d.status != "READY":
        return {"status": d.status, "message": d.message, "actions": d.actions, "sample": str(p), "executed": False}
    return {"status": "READY_FOR_EXTERNAL_SANDBOX", "message": "Sample is never executed by the desktop host; submit only to a separately managed disposable VM.", "actions": ["Snapshot", "Network isolation", "Controlled execution", "Collect telemetry", "Rollback"], "sample": str(p), "executed": False}

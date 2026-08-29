"""Best-effort Windows Authenticode verification via built-in PowerShell."""
from __future__ import annotations
import json, os, subprocess
from pathlib import Path

def verify_signature(path: str | Path, timeout: int = 8) -> dict:
    if os.name != "nt":
        return {"enabled": False, "status": "NON_WINDOWS"}
    p = Path(path).resolve()
    if not p.is_file():
        return {"enabled": True, "status": "NOT_FOUND"}
    script = "Get-AuthenticodeSignature -LiteralPath $args[0] | Select-Object Status,StatusMessage,SignerCertificate | ConvertTo-Json -Compress"
    try:
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, str(p)], capture_output=True, text=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        data = json.loads(cp.stdout) if cp.stdout.strip() else {}
        status = str(data.get("Status", "Unknown"))
        cert = data.get("SignerCertificate") or {}
        return {"enabled": True, "status": status, "message": data.get("StatusMessage", ""),
                "signer": cert.get("Subject") if isinstance(cert, dict) else None,
                "trusted": status.lower() == "valid"}
    except Exception as exc:
        return {"enabled": True, "status": "ERROR", "error": type(exc).__name__}

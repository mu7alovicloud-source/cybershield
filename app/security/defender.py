"""Windows Defender integration.

Uses the Microsoft Defender command-line scanner when available. The target is
passed as an argument (never through a shell) and is never executed by
CyberShield itself.
"""
from __future__ import annotations
import os
import shutil
import subprocess
from pathlib import Path

def find_mpcmdrun() -> str | None:
    candidates = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     "Windows Defender", "MpCmdRun.exe"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                     "Microsoft", "Windows Defender", "Platform"),
    ]
    for c in candidates:
        p=Path(c)
        if p.is_file() and p.name.lower()=="mpcmdrun.exe":
            return str(p)
        if p.is_dir():
            versions=sorted(p.glob(r"*\MpCmdRun.exe"), reverse=True)
            if versions:
                return str(versions[0])
    return shutil.which("MpCmdRun.exe")

def defender_available() -> bool:
    return bool(find_mpcmdrun())

def scan_file_with_defender(path: str | Path, timeout: int = 120) -> dict:
    target=str(Path(path).expanduser().resolve())
    exe=find_mpcmdrun()
    if not exe:
        return {"enabled": False, "status":"NOT_AVAILABLE", "detected":False, "returncode":None}
    if not Path(target).is_file():
        raise FileNotFoundError(target)
    try:
        cp=subprocess.run(
            [exe, "-Scan", "-ScanType", "3", "-File", target, "-DisableRemediation"],
            capture_output=True, text=True, timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out=(cp.stdout or "") + "\n" + (cp.stderr or "")
        low=out.lower()
        detected=cp.returncode != 0 or any(x in low for x in (
            "threat detected", "threats detected", "malware detected",
            "detection", "found threats",
        ))
        return {
            "enabled": True,
            "status": "THREAT" if detected else "CLEAN",
            "detected": detected,
            "returncode": cp.returncode,
            "engine": "Microsoft Defender",
            "output": out[-4000:],
        }
    except subprocess.TimeoutExpired:
        return {"enabled":True,"status":"TIMEOUT","detected":False,"returncode":None}
    except OSError as exc:
        return {"enabled":True,"status":"ERROR","detected":False,"returncode":None,"error":type(exc).__name__}

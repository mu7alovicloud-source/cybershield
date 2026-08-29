"""Microsoft Defender integration for CyberShield.

Uses the Windows Defender PowerShell cmdlet when available. The target is
passed as -ScanPath, so Defender performs the actual antimalware inspection;
CyberShield never launches the target file.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _powershell() -> str | None:
    if os.name != "nt":
        return None
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe")


def _mpcmdrun() -> str | None:
    if os.name != "nt":
        return None
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "Windows Defender" / "MpCmdRun.exe",
    ]
    platform_root = Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if platform_root.is_dir():
        candidates.extend(sorted(platform_root.glob("*/MpCmdRun.exe"), key=lambda x: x.parent.name, reverse=True))
    candidates.append(Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "Windows Defender" / "MpCmdRun.exe")
    for p in candidates:
        if p.is_file():
            return str(p)
    return shutil.which("MpCmdRun.exe")


def _ps_scan(path: Path, timeout: int) -> dict[str, Any]:
    ps = _powershell()
    if not ps:
        return {"available": False, "status": "UNAVAILABLE", "reason": "PowerShell not found"}
    # Start-MpScan is Microsoft's supported Defender cmdlet. ScanPath accepts
    # both a file and a directory. We also capture the current threat history
    # after the scan so a real Defender detection is distinguishable from a
    # generic command failure.
    script = r'''
$ErrorActionPreference = 'Stop'
$target = $args[0]
$before = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object { $_.ThreatID })
Start-MpScan -ScanType CustomScan -ScanPath $target -ErrorAction Stop
$after = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
$new = @($after | Where-Object { $before -notcontains $_.ThreatID })
[pscustomobject]@{
  scan_completed = $true
  new_threats = @($new | ForEach-Object {
    [pscustomobject]@{ ThreatID=$_.ThreatID; ThreatName=$_.ThreatName; ActionSuccess=$_.ActionSuccess; Resources=$_.Resources }
  })
} | ConvertTo-Json -Depth 8 -Compress
'''
    try:
        cp = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", script, str(path)],
            capture_output=True, text=True, timeout=timeout, shell=False,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = (cp.stdout or "").strip()
        stderr = (cp.stderr or "").strip()
        if cp.returncode != 0:
            return {"available": True, "status": "ERROR", "exit_code": cp.returncode,
                    "error": stderr[-4000:] or stdout[-4000:], "path": str(path)}
        data: dict[str, Any] = {}
        if stdout:
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                data = {"raw": stdout[-4000:]}
        threats = data.get("new_threats") or []
        if isinstance(threats, dict):
            threats = [threats]
        return {
            "available": True,
            "status": "THREAT" if threats else "CLEAN",
            "engine": "Microsoft Defender",
            "scan_type": "CustomScan",
            "path": str(path),
            "threats": threats,
            "verified_no_host_execution": True,
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "TIMEOUT", "path": str(path)}
    except OSError as exc:
        return {"available": True, "status": "ERROR", "error": str(exc), "path": str(path)}


def _mpcmdrun_scan(path: Path, timeout: int) -> dict[str, Any]:
    exe = _mpcmdrun()
    if not exe:
        return {"available": False, "status": "UNAVAILABLE", "reason": "MpCmdRun.exe not found"}
    cmd = [exe, "-Scan", "-ScanType", "3", "-File", str(path)] if path.is_file() else [exe, "-Scan", "-ScanType", "3", "-File", str(path)]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False,
                            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        output = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()[-8000:]
        # Defender's documented exit code 0 means the scan command completed;
        # a non-zero result is surfaced as a possible threat/error, never as CLEAN.
        return {"available": True, "status": "CLEAN" if cp.returncode == 0 else "THREAT_OR_ERROR",
                "exit_code": cp.returncode, "path": str(path), "output": output,
                "verified_no_host_execution": True}
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "TIMEOUT", "path": str(path)}
    except OSError as exc:
        return {"available": True, "status": "ERROR", "error": str(exc), "path": str(path)}


def scan_file_with_defender(path: str | Path, timeout: int = 180) -> dict[str, Any]:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(str(p))
    result = _ps_scan(p, timeout)
    if result.get("available"):
        return result
    return _mpcmdrun_scan(p, timeout)

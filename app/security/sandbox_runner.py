"""Windows Sandbox launcher for safe malware-analysis workflows.

The host never executes the sample. The sample is copied into a disposable
Windows Sandbox with networking disabled and a read-only host mapping.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def sandbox_available() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Windows Sandbox is available only on Windows."
    if shutil.which("WindowsSandbox.exe"):
        return True, "Windows Sandbox launcher found."
    return False, "WindowsSandbox.exe was not found; enable Windows Sandbox in Windows Features."


def build_wsb(sample: str | Path, *, network: bool = False, protected_client: bool = True) -> Path:
    p = Path(sample).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(str(p))
    # Read-only mapping prevents the guest from modifying the original sample.
    xml = f'''<Configuration>
  <Networking>{"Enable" if network else "Disable"}</Networking>
  <ProtectedClient>{"Enable" if protected_client else "Disable"}</ProtectedClient>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{p.parent}</HostFolder>
      <SandboxFolder>C:\\Samples</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c echo CYBERSHIELD SAFE LAB: sample is mounted read-only at C:\\Samples && start explorer.exe C:\\Samples</Command>
  </LogonCommand>
</Configuration>'''
    fd, path = tempfile.mkstemp(prefix="CyberShield_", suffix=".wsb")
    os.close(fd)
    Path(path).write_text(xml, encoding="utf-8")
    return Path(path)


def launch_sandbox(sample: str | Path, *, network: bool = False) -> dict[str, Any]:
    ok, msg = sandbox_available()
    if not ok:
        return {"ok": False, "status": "UNAVAILABLE", "message": msg}
    wsb = build_wsb(sample, network=network, protected_client=True)
    try:
        subprocess.Popen(["WindowsSandbox.exe", str(wsb)], shell=False)
    except Exception as exc:
        return {"ok": False, "status": "FAILED", "message": f"Sandbox launch failed safely: {exc}"}
    return {
        "ok": True,
        "status": "LAUNCHED",
        "message": "Disposable Windows Sandbox launched. Host sample is read-only mapped; networking disabled.",
        "config": str(wsb),
        "network": network,
        "protected_client": True,
    }

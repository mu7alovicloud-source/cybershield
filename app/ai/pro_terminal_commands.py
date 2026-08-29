"""Professional CyberShield terminal command pack.

This module adds read-only diagnostics, evidence reporting, local inventory and
operator convenience commands to the CyberShield terminal.  It intentionally
never exposes arbitrary operating-system command execution.

Design goals:
    * deterministic output suitable for a SOC-style console;
    * bounded resource usage;
    * explicit safety boundaries;
    * JSON-friendly records for the GUI and API;
    * useful commands on Windows, while remaining import-safe elsewhere.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import socket
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from app.config import APP_NAME, APP_VERSION, APP_RELEASE_CHANNEL, DATABASE_FILE
from app.database.database import (
    add_audit,
    get_incident_counts,
    get_incidents,
    get_recent_audit,
    get_recent_scans,
    get_recent_url_scans,
)
from app.security.network_monitor import connection_evidence, get_connections
from app.security.process_monitor import get_processes
from app.security.scanner import analyze_file, scan_directory
from app.security.professional_health import doctor, safe_repair, performance
from app.security.deep_audit import (deep_scan, entropy_scan, extension_audit, hash_manifest, string_audit, image_audit, screenshot_audit, duplicate_scan, permission_audit, inventory, quick_report)

try:
    import psutil
except Exception:  # pragma: no cover - optional at import time
    psutil = None


MAX_TREE_ENTRIES = 300
MAX_SCAN_RESULTS = 300
MAX_REPORT_BYTES = 2_000_000
SAFE_ENV_NAMES = {
    "COMPUTERNAME",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "NUMBER_OF_PROCESSORS",
    "PYTHON_VERSION",
    "USERNAME",
    "USERDOMAIN",
    "WINDIR",
}
SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL")


@dataclass(frozen=True)
class CommandSpec:
    name: str
    summary: str
    usage: str
    category: str
    destructive: bool = False


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    CommandSpec("version", "Application and runtime version", "version", "system"),
    CommandSpec("uptime", "Host uptime and boot time", "uptime", "system"),
    CommandSpec("system-info", "Detailed read-only operating-system inventory", "system-info", "system"),
    CommandSpec("memory", "RAM and swap utilization", "memory", "system"),
    CommandSpec("disks", "Disk capacity and utilization", "disks", "system"),
    CommandSpec("python-info", "Python runtime information", "python-info", "system"),
    CommandSpec("env-safe", "Non-secret environment inventory", "env-safe", "system"),
    CommandSpec("file-info", "File metadata and cryptographic hashes", "file-info <file>", "evidence"),
    CommandSpec("tree", "Bounded directory inventory", "tree <directory> [depth]", "evidence"),
    CommandSpec("scan-ext", "Scan files by extension", "scan-ext <directory> <.ext> [limit]", "detection"),
    CommandSpec("risk-summary", "Aggregate local scan risk", "risk-summary", "detection"),
    CommandSpec("process-risk", "Rank process telemetry by resource and indicators", "process-risk [limit]", "monitoring"),
    CommandSpec("network-risk", "Rank local connections using CyberShield evidence", "network-risk [limit]", "monitoring"),
    CommandSpec("audit", "Read recent security audit events", "audit [limit]", "audit"),
    CommandSpec("scans", "Read recent file scan history", "scans [limit]", "audit"),
    CommandSpec("url-history", "Read recent URL analysis history", "url-history [limit]", "audit"),
    CommandSpec("incident-list", "List security incidents", "incident-list [open|closed|all]", "audit"),
    CommandSpec("capabilities", "Show enabled safe terminal capabilities", "capabilities", "system"),
    CommandSpec("integrity", "Verify important application files by SHA-256", "integrity", "integrity"),
    CommandSpec("report", "Create a bounded JSON security snapshot", "report [path]", "report"),
    CommandSpec("health", "Fast local health summary", "health", "system"),
    CommandSpec("limits", "Show terminal resource and safety limits", "limits", "system"),
    CommandSpec("socket-summary", "Summarize connection states", "socket-summary", "monitoring"),
    CommandSpec("process-tree", "Show parent/child process relationships", "process-tree [limit]", "monitoring"),
    CommandSpec("large-files", "Find bounded largest files in a directory", "large-files <directory> [limit]", "evidence"),
    CommandSpec("extension-summary", "Summarize file extensions in a directory", "extension-summary <directory>", "evidence"),
    CommandSpec("threat-check", "Layered multi-engine threat check for one file", "threat-check <file>", "detection"),
    CommandSpec("engine-status", "Show available malware-detection engines", "engine-status", "detection"),
    CommandSpec("av-self-test", "Run a harmless EICAR signature self-test", "av-self-test", "detection"),
    CommandSpec("yara-scan", "Scan a file with local YARA rules when installed", "yara-scan <file>", "detection"),
    CommandSpec("url-check", "Layered phishing and URL check", "url-check <url>", "detection"),
    CommandSpec("full-audit", "Bounded multi-layer read-only audit", "full-audit <file|directory>", "forensics"),
    CommandSpec("deep-audit", "Deep static audit without execution", "deep-audit <file|directory>", "forensics"),
    CommandSpec("entropy-audit", "Entropy/packing signal audit", "entropy-audit <file|directory>", "forensics"),
    CommandSpec("extension-audit", "Extension/header masquerade audit", "extension-audit <file|directory>", "forensics"),
    CommandSpec("hash-manifest", "Bounded SHA-256 manifest", "hash-manifest <file|directory>", "forensics"),
    CommandSpec("string-audit", "Suspicious printable-string audit", "string-audit <file|directory>", "forensics"),
    CommandSpec("image-audit", "Pixel-level image integrity/statistics", "image-audit <image>", "forensics"),
    CommandSpec("screen-audit", "Pixel statistics of current desktop, not persisted", "screen-audit", "forensics"),
    CommandSpec("duplicate-audit", "Duplicate-file hash audit", "duplicate-audit <directory>", "forensics"),
    CommandSpec("permission-audit", "Read/write/execute permission inventory", "permission-audit <file|directory>", "forensics"),
    CommandSpec("inventory", "Bounded filesystem inventory", "inventory <file|directory>", "forensics"),
    CommandSpec("quick-audit", "Fast combined audit summary", "quick-audit <file|directory>", "forensics"),
    CommandSpec("headers", "Binary header and type audit", "headers <file|directory>", "forensics"),
    CommandSpec("macro-audit", "Macro/document extension audit", "macro-audit <file|directory>", "forensics"),
    CommandSpec("script-audit", "Script/execution-tool marker audit", "script-audit <file|directory>", "forensics"),
    CommandSpec("archive-audit", "Archive/image extension inventory", "archive-audit <directory>", "forensics"),
    CommandSpec("size-audit", "Large-file/resource footprint audit", "size-audit <directory>", "forensics"),
    CommandSpec("risk-files", "Rank files by static risk signals", "risk-files <file|directory>", "forensics"),
    CommandSpec("sample-audit", "Bounded sample audit with resource limits", "sample-audit <file|directory>", "forensics"),
    CommandSpec("lab-status", "Safe Lab readiness and isolation policy", "lab-status", "lab"),
    CommandSpec("doctor", "Non-destructive application and dependency diagnostics", "doctor", "system"),
    CommandSpec("safe-repair", "Repair only CyberShield-owned runtime prerequisites", "safe-repair", "maintenance"),
    CommandSpec("performance", "Fast performance/readiness diagnostics", "performance", "system"),
    CommandSpec("hostname", "Read Windows computer hostname", "hostname", "windows"),
    CommandSpec("ver", "Read platform/runtime version information", "ver", "windows"),
    CommandSpec("date", "Read local date", "date", "system"),
    CommandSpec("time", "Read local time and timezone", "time", "system"),
    CommandSpec("dir", "Bounded directory listing", "dir [directory]", "evidence"),
    CommandSpec("where", "Locate an installed executable without executing it", "where <program>", "system"),
    CommandSpec("get-process", "Safe PowerShell read-only diagnostic", "get-process", "powershell"),
    CommandSpec("get-service", "Safe PowerShell read-only diagnostic", "get-service", "powershell"),
    CommandSpec("get-netadapter", "Safe PowerShell read-only diagnostic", "get-netadapter", "powershell"),
    CommandSpec("get-netipconfiguration", "Safe PowerShell read-only diagnostic", "get-netipconfiguration", "powershell"),
    CommandSpec("get-nettcpconnection", "Safe PowerShell read-only diagnostic", "get-nettcpconnection", "powershell"),
    CommandSpec("get-netudpendpoint", "Safe PowerShell read-only diagnostic", "get-netudpendpoint", "powershell"),
    CommandSpec("get-dnsclientservers", "Safe PowerShell read-only diagnostic", "get-dnsclientservers", "powershell"),
    CommandSpec("get-netroute", "Safe PowerShell read-only diagnostic", "get-netroute", "powershell"),
    CommandSpec("get-firewallprofile", "Safe PowerShell read-only diagnostic", "get-firewallprofile", "powershell"),
    CommandSpec("get-mpcomputerstatus", "Safe PowerShell read-only diagnostic", "get-mpcomputerstatus", "powershell"),
    CommandSpec("get-mpthreatdetection", "Safe PowerShell read-only diagnostic", "get-mpthreatdetection", "powershell"),
    CommandSpec("get-scheduledtask", "Safe PowerShell read-only diagnostic", "get-scheduledtask", "powershell"),
    CommandSpec("get-hotfix", "Safe PowerShell read-only diagnostic", "get-hotfix", "powershell"),
    CommandSpec("get-computerinfo", "Safe PowerShell read-only diagnostic", "get-computerinfo", "powershell"),
    CommandSpec("get-ciminstance-os", "Safe PowerShell read-only diagnostic", "get-ciminstance-os", "powershell"),
    CommandSpec("get-ciminstance-computer", "Safe PowerShell read-only diagnostic", "get-ciminstance-computer", "powershell"),
    CommandSpec("get-startupapps", "Safe PowerShell read-only diagnostic", "get-startupapps", "powershell"),
    CommandSpec("get-eventlog-security", "Safe PowerShell read-only diagnostic", "get-eventlog-security", "powershell"),
    CommandSpec("get-eventlog-system", "Safe PowerShell read-only diagnostic", "get-eventlog-system", "powershell"),
    CommandSpec("get-eventlog-application", "Safe PowerShell read-only diagnostic", "get-eventlog-application", "powershell"),
    CommandSpec("defender-status", "Microsoft Defender health status", "defender-status", "security"),
    CommandSpec("defender-threats", "Recent Microsoft Defender detections", "defender-threats", "security"),
    CommandSpec("firewall-rules", "Read Windows Firewall rules", "firewall-rules", "security"),
    CommandSpec("listening-ports", "List listening TCP/UDP endpoints", "listening-ports", "network"),
    CommandSpec("dns-cache", "Read local DNS client cache", "dns-cache", "network"),
    CommandSpec("network-profile", "Read Windows network profiles", "network-profile", "network"),
    CommandSpec("volumes", "Read mounted volume inventory", "volumes", "system"),
    CommandSpec("physical-disks", "Read physical disk inventory", "physical-disks", "system"),
    CommandSpec("net-users", "Read local Windows user inventory", "net-users", "windows"),
    CommandSpec("whoami", "Read current Windows identity and group context", "whoami", "windows"),
    CommandSpec("ipconfig", "Read Windows network interface configuration", "ipconfig", "network"),
    CommandSpec("routes", "Read Windows routing table", "routes", "network"),
    CommandSpec("arp", "Read local ARP cache", "arp", "network"),
    CommandSpec("netstat", "Read active TCP/UDP sockets and owning PIDs", "netstat", "network"),
    CommandSpec("tasklist", "Read running Windows processes", "tasklist", "monitoring"),
    CommandSpec("drivers", "Read installed Windows driver inventory", "drivers", "system"),
    CommandSpec("firewall", "Read Windows Firewall profile state", "firewall", "security"),
    CommandSpec("github-publish", "Verified GitHub repository publish", "github-publish [OWNER/REPO|GitHub URL]", "developer"),
    CommandSpec("systeminfo", "Read Windows system inventory", "systeminfo", "windows"),
    CommandSpec("netsh-interfaces", "Read Windows network interface details", "netsh-interfaces", "network"),
    CommandSpec("netsh-wlan", "Read current Wi-Fi interface details", "netsh-wlan", "network"),
    CommandSpec("powercfg", "Read active Windows power plan", "powercfg", "system"),
    CommandSpec("whoami-groups", "Read current identity and group membership", "whoami-groups", "windows"),
    CommandSpec("net-accounts", "Read local account policy summary", "net-accounts", "windows"),
    CommandSpec("net-share", "Read configured Windows shares", "net-share", "windows"),
    CommandSpec("schtasks", "Read scheduled-task inventory", "schtasks", "monitoring"),
)

# Windows read-only operator pack.  These are fixed argv wrappers around
# familiar CMD/Windows utilities; user text is never passed to a shell.
WINDOWS_READONLY_COMMANDS = {
    "hostname": ["hostname"],
    "whoami": ["whoami", "/all"],
    "ipconfig": ["ipconfig", "/all"],
    "routes": ["route", "print"],
    "arp": ["arp", "-a"],
    "netstat": ["netstat", "-ano"],
    "tasklist": ["tasklist", "/FO", "CSV", "/NH"],
    "drivers": ["driverquery", "/FO", "CSV", "/NH"],
    "systeminfo": ["systeminfo"],
    "netsh-interfaces": ["netsh", "interface", "show", "interface"],
    "netsh-wlan": ["netsh", "wlan", "show", "interfaces"],
    "powercfg": ["powercfg", "/GETACTIVESCHEME"],
    "whoami-groups": ["whoami", "/groups"],
    "net-accounts": ["net", "accounts"],
    "net-share": ["net", "share"],
    "schtasks": ["schtasks", "/Query", "/FO", "CSV", "/NH"],
}


def _fixed_windows_command(name: str, timeout: float = 12.0) -> dict[str, Any]:
    """Run one predefined, read-only Windows utility with no shell."""
    if platform.system().lower() != "windows":
        return {"available": False, "command": name, "reason": "Windows-only diagnostic"}
    argv = WINDOWS_READONLY_COMMANDS.get(name)
    if not argv:
        return {"available": False, "command": name, "reason": "not in read-only allowlist"}
    exe = shutil.which(argv[0])
    if not exe:
        return {"available": False, "command": name, "reason": f"{argv[0]} not found"}
    try:
        import subprocess
        proc = subprocess.run(
            [exe, *argv[1:]],
            capture_output=True, text=True, timeout=timeout,
            shell=False, stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        text = (proc.stdout or proc.stderr or "").strip()
        return {
            "available": proc.returncode == 0,
            "command": name,
            "return_code": proc.returncode,
            "output": text[:20000],
        }
    except subprocess.TimeoutExpired:
        return {"available": False, "command": name, "reason": "timeout"}
    except OSError as exc:
        return {"available": False, "command": name, "reason": type(exc).__name__}


def hostname() -> dict[str, Any]:
    return _fixed_windows_command("hostname")


def whoami() -> dict[str, Any]:
    return _fixed_windows_command("whoami")


def ipconfig() -> dict[str, Any]:
    return _fixed_windows_command("ipconfig")


def routes() -> dict[str, Any]:
    return _fixed_windows_command("routes")


def arp_table() -> dict[str, Any]:
    return _fixed_windows_command("arp")


def netstat() -> dict[str, Any]:
    return _fixed_windows_command("netstat")


def tasklist() -> dict[str, Any]:
    return _fixed_windows_command("tasklist")


def drivers() -> dict[str, Any]:
    return _fixed_windows_command("drivers")


def firewall_status() -> dict[str, Any]:
    """Read Windows Firewall profiles using a fixed PowerShell expression."""
    if platform.system().lower() != "windows":
        return {"available": False, "reason": "Windows-only diagnostic"}
    ps = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps:
        return {"available": False, "reason": "PowerShell not found"}
    expression = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress"
    try:
        import subprocess
        proc = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", expression],
            capture_output=True, text=True, timeout=12,
            shell=False, stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
        text = (proc.stdout or proc.stderr or "").strip()
        try:
            parsed = json.loads(text) if text else None
        except json.JSONDecodeError:
            parsed = text[:12000]
        return {"available": proc.returncode == 0, "profiles": parsed, "return_code": proc.returncode}
    except Exception as exc:
        return {"available": False, "reason": type(exc).__name__}



# Safe PowerShell read-only pack. These are fixed command templates; user input
# is never interpolated into a PowerShell expression. The goal is to expose
# useful defensive Windows telemetry without turning CIBER into an arbitrary
# shell.
POWERSHELL_READONLY_COMMANDS = {
    "get-process": "Get-Process | Select-Object -First 200 Id,ProcessName,CPU,WS,Path | ConvertTo-Json -Compress",
    "get-service": "Get-Service | Select-Object Status,Name,DisplayName | ConvertTo-Json -Compress",
    "get-netadapter": "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed | ConvertTo-Json -Compress",
    "get-netipconfiguration": "Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,DNSServer,NetProfile | ConvertTo-Json -Compress",
    "get-nettcpconnection": "Get-NetTCPConnection | Select-Object -First 300 LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress",
    "get-netudpendpoint": "Get-NetUDPEndpoint | Select-Object -First 300 LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress",
    "get-dnsclientservers": "Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress",
    "get-netroute": "Get-NetRoute | Select-Object -First 300 DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,State | ConvertTo-Json -Compress",
    "get-firewallprofile": "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress",
    "get-mpcomputerstatus": "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,BehaviorMonitorEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,NISEnabled,QuickScanAge,FullScanAge | ConvertTo-Json -Compress",
    "get-mpthreatdetection": "Get-MpThreatDetection | Select-Object -First 100 ThreatID,InitialDetectionTime,Resources,ActionSuccess | ConvertTo-Json -Compress",
    "get-scheduledtask": "Get-ScheduledTask | Select-Object -First 300 TaskName,TaskPath,State,Author | ConvertTo-Json -Compress",
    "get-hotfix": "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 100 HotFixID,Description,InstalledOn,InstalledBy | ConvertTo-Json -Compress",
    "get-computerinfo": "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture,CsName,CsNumberOfLogicalProcessors | ConvertTo-Json -Compress",
    "get-ciminstance-os": "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,OSArchitecture,FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json -Compress",
    "get-ciminstance-computer": "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Domain,PartOfDomain,TotalPhysicalMemory,NumberOfLogicalProcessors | ConvertTo-Json -Compress",
    "get-startupapps": "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress",
    "get-eventlog-security": "Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress",
    "get-eventlog-system": "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress",
    "get-eventlog-application": "Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 100 | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress",
    "get-netfirewallrule": "Get-NetFirewallRule | Select-Object -First 250 DisplayName,Enabled,Direction,Action,Profile | ConvertTo-Json -Compress",
    "get-mppreference": "Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,PUAProtection,ExclusionPath,ExclusionExtension | ConvertTo-Json -Compress",
    "get-bitlockervolume": "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod | ConvertTo-Json -Compress",
    "get-localuser": "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,UserMayChangePassword | ConvertTo-Json -Compress",
    "get-localgroup": "Get-LocalGroup | Select-Object Name,Description | ConvertTo-Json -Compress",
    "get-localgroupmember-admin": "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass,PrincipalSource | ConvertTo-Json -Compress",
    "get-bitsjob": "Get-BitsTransfer -AllUsers | Select-Object -First 100 DisplayName,JobState,OwnerAccount,BytesTotal,BytesTransferred | ConvertTo-Json -Compress",
}

POWERSHELL_ALIASES = {
    "ps-processes": "get-process", "ps-services": "get-service",
    "ps-netadapter": "get-netadapter", "ps-ip": "get-netipconfiguration",
    "ps-tcp": "get-nettcpconnection", "ps-udp": "get-netudpendpoint",
    "ps-dns": "get-dnsclientservers", "ps-routes": "get-netroute",
    "ps-firewall": "get-firewallprofile", "ps-defender": "get-mpcomputerstatus",
    "ps-threats": "get-mpthreatdetection", "ps-tasks": "get-scheduledtask",
    "ps-hotfix": "get-hotfix", "ps-computer": "get-computerinfo",
    "ps-os": "get-ciminstance-os", "ps-hardware": "get-ciminstance-computer",
    "ps-startup": "get-startupapps", "ps-security-events": "get-eventlog-security",
    "ps-system-events": "get-eventlog-system", "ps-app-events": "get-eventlog-application",
    "ps-firewall-rules": "get-netfirewallrule", "ps-defender-preferences": "get-mppreference",
    "ps-bitlocker": "get-bitlockervolume", "ps-users": "get-localuser",
    "ps-groups": "get-localgroup", "ps-admins": "get-localgroupmember-admin",
    "ps-bits": "get-bitsjob",
}

def powershell_readonly(name: str) -> dict[str, Any]:
    """Execute one fixed, read-only PowerShell diagnostic template."""
    if platform.system().lower() != "windows":
        return {"available": False, "command": name, "reason": "Windows-only PowerShell diagnostic"}
    key = POWERSHELL_ALIASES.get(name.lower(), name.lower())
    expression = POWERSHELL_READONLY_COMMANDS.get(key)
    if not expression:
        return {"available": False, "command": name, "reason": "not in PowerShell read-only allowlist"}
    ps = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not ps:
        return {"available": False, "command": key, "reason": "PowerShell not found"}
    try:
        proc = __import__("subprocess").run(
            [ps, "-NoProfile", "-NonInteractive", "-Command", expression],
            capture_output=True, text=True, timeout=20, shell=False,
            stdin=__import__("subprocess").DEVNULL,
            creationflags=getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0),
            check=False,
        )
        text = (proc.stdout or proc.stderr or "").strip()
        try:
            parsed = json.loads(text) if text else None
        except json.JSONDecodeError:
            parsed = text[:30000]
        return {"available": proc.returncode == 0, "command": key, "return_code": proc.returncode, "data": parsed}
    except __import__("subprocess").TimeoutExpired:
        return {"available": False, "command": key, "reason": "timeout"}
    except OSError as exc:
        return {"available": False, "command": key, "reason": type(exc).__name__}

def powershell_commands() -> list[str]:
    return sorted(POWERSHELL_READONLY_COMMANDS)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _human_bytes(value: int | float) -> str:
    n = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _json(value: Any, limit: int = MAX_REPORT_BYTES) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… output truncated by CyberShield safety limit"


def _safe_path(value: str) -> Path:
    """Resolve a user supplied path without executing it."""
    p = Path(value).expanduser()
    return p.resolve()


def _hash_file(path: Path, algorithms: Iterable[str] = ("sha256",)) -> dict[str, str]:
    """Hash a file in bounded chunks.

    The function reads bytes only.  It never loads an entire large file into
    memory and never executes the target file.
    """
    wanted = tuple(algorithms)
    hashes = {name: hashlib.new(name) for name in wanted}
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            for digest in hashes.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in hashes.items()}


def version() -> dict[str, Any]:
    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "release_channel": APP_RELEASE_CHANNEL,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "timestamp_utc": _now(),
    }


def uptime() -> dict[str, Any]:
    if psutil is None:
        return {"available": False, "reason": "psutil is not installed"}
    boot = psutil.boot_time()
    seconds = max(0.0, time.time() - boot)
    return {
        "available": True,
        "seconds": round(seconds, 1),
        "hours": round(seconds / 3600, 2),
        "boot_time_utc": datetime.fromtimestamp(boot, tz=timezone.utc).isoformat(),
    }


def system_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "architecture": platform.architecture()[0],
        "python": platform.python_version(),
        "executable": sys.executable,
        "cwd": str(Path.cwd()),
    }
    if psutil is not None:
        info.update({
            "cpu_logical": psutil.cpu_count(logical=True),
            "cpu_physical": psutil.cpu_count(logical=False),
            "cpu_percent": psutil.cpu_percent(interval=0.1),
        })
    return info


def memory() -> dict[str, Any]:
    if psutil is None:
        return {"available": False, "reason": "psutil is not installed"}
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "available": True,
        "ram": {
            "total": vm.total,
            "used": vm.used,
            "available": vm.available,
            "percent": vm.percent,
            "total_human": _human_bytes(vm.total),
            "used_human": _human_bytes(vm.used),
        },
        "swap": {
            "total": swap.total,
            "used": swap.used,
            "free": swap.free,
            "percent": swap.percent,
        },
    }


def disks() -> list[dict[str, Any]]:
    if psutil is None:
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for part in psutil.disk_partitions(all=False):
        mount = str(part.mountpoint)
        if mount in seen:
            continue
        seen.add(mount)
        try:
            usage = psutil.disk_usage(mount)
            rows.append({
                "device": part.device,
                "mountpoint": mount,
                "filesystem": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
                "total_human": _human_bytes(usage.total),
                "free_human": _human_bytes(usage.free),
            })
        except (OSError, PermissionError):
            rows.append({"device": part.device, "mountpoint": mount, "filesystem": part.fstype, "error": "unavailable"})
    return rows


def python_info() -> dict[str, Any]:
    return {
        "version": sys.version,
        "version_info": list(sys.version_info[:5]),
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
        "path_count": len(sys.path),
    }


def env_safe() -> dict[str, str]:
    result: dict[str, str] = {}
    for key in sorted(os.environ):
        upper = key.upper()
        if upper in SAFE_ENV_NAMES or (not any(marker in upper for marker in SECRET_MARKERS) and upper in {"PATH", "TEMP", "TMP", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA", "APPDATA"}):
            value = os.environ.get(key, "")
            if len(value) > 400:
                value = value[:400] + "…"
            result[key] = value
    result["_policy"] = "Secret-looking environment variables are intentionally omitted."
    return result


def file_info(raw_path: str) -> dict[str, Any]:
    path = _safe_path(raw_path)
    if not path.exists():
        raise FileNotFoundError(str(path))
    st = path.stat()
    record: dict[str, Any] = {
        "path": str(path),
        "name": path.name,
        "suffix": path.suffix.lower(),
        "exists": True,
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
        "size": st.st_size if path.is_file() else None,
        "size_human": _human_bytes(st.st_size) if path.is_file() else None,
        "modified_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "created_utc": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
    }
    if path.is_file():
        record["hashes"] = _hash_file(path, ("sha256", "sha1", "md5"))
    return record


def tree(raw_path: str, depth: int = 2) -> dict[str, Any]:
    root = _safe_path(raw_path)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    depth = _clamp(depth, 0, 8)
    entries: list[dict[str, Any]] = []
    queue: list[tuple[Path, int]] = [(root, 0)]
    while queue and len(entries) < MAX_TREE_ENTRIES:
        current, level = queue.pop(0)
        try:
            children = sorted(current.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except (OSError, PermissionError):
            continue
        for child in children:
            if len(entries) >= MAX_TREE_ENTRIES:
                break
            try:
                is_dir = child.is_dir()
                size = child.stat().st_size if child.is_file() else 0
            except OSError:
                is_dir, size = False, 0
            entries.append({"path": str(child), "relative": str(child.relative_to(root)), "depth": level + 1, "type": "dir" if is_dir else "file", "size": size})
            if is_dir and level < depth:
                queue.append((child, level + 1))
    return {"root": str(root), "depth": depth, "entries": entries, "truncated": len(entries) >= MAX_TREE_ENTRIES}


def scan_by_extension(raw_dir: str, extension: str, limit: int = 100) -> dict[str, Any]:
    root = _safe_path(raw_dir)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    ext = extension.lower().strip()
    if not ext.startswith("."):
        ext = "." + ext
    limit = _clamp(limit, 1, MAX_SCAN_RESULTS)
    candidates = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ext][:limit]
    results = []
    for path in candidates:
        try:
            result = analyze_file(path)
            results.append({k: result.get(k) for k in ("path", "size", "sha256", "risk", "verdict", "confidence")})
        except Exception as exc:
            results.append({"path": str(path), "error": f"{type(exc).__name__}: {exc}"})
    return {"directory": str(root), "extension": ext, "files_considered": len(candidates), "results": results}


def risk_summary() -> dict[str, Any]:
    rows = get_recent_scans(100)
    counts: dict[str, int] = {}
    total_risk = 0
    for row in rows:
        verdict = str(row[1])
        counts[verdict] = counts.get(verdict, 0) + 1
        total_risk += int(row[2] or 0)
    return {"sample_size": len(rows), "verdicts": counts, "average_risk": round(total_risk / len(rows), 2) if rows else 0, "incident_counts": get_incident_counts()}


def process_risk(limit: int = 30) -> list[dict[str, Any]]:
    rows = get_processes(_clamp(limit, 1, 100))
    output = []
    for row in rows:
        name = str(row.get("name", ""))
        cpu = float(row.get("cpu_percent", 0) or 0)
        memory_percent = float(row.get("memory_percent", 0) or 0)
        score = min(100, round(cpu * 0.7 + memory_percent * 0.3))
        output.append({"pid": row.get("pid"), "name": name, "cpu_percent": cpu, "memory_percent": memory_percent, "telemetry_score": score, "path": row.get("exe") or row.get("path")})
    return sorted(output, key=lambda x: x["telemetry_score"], reverse=True)


def network_risk(limit: int = 50) -> dict[str, Any]:
    rows = get_connections(_clamp(limit, 1, 100))
    evidence = connection_evidence(rows)
    return {"connections": rows, "evidence": evidence, "count": len(rows)}


def audit(limit: int = 50) -> list[dict[str, Any]]:
    return get_recent_audit(_clamp(limit, 1, 200))


def scans(limit: int = 30) -> list[Any]:
    return get_recent_scans(_clamp(limit, 1, 100))


def url_history(limit: int = 30) -> list[dict[str, Any]]:
    return get_recent_url_scans(_clamp(limit, 1, 100))


def incident_list(mode: str = "open") -> list[Any]:
    m = mode.lower()
    if m == "all":
        return get_incidents()
    if m == "closed":
        return get_incidents("Closed")
    return get_incidents("Open")


def capabilities() -> dict[str, Any]:
    return {
        "safe_terminal": True,
        "arbitrary_shell": False,
        "cmd_execution": False,
        "powershell_execution": False,
        "sample_execution": False,
        "file_quarantine": True,
        "static_scanning": True,
        "deep_scanning": True,
        "url_analysis": True,
        "host_inventory": True,
        "process_telemetry": psutil is not None,
        "network_telemetry": psutil is not None,
        "audit_logging": True,
        "json_reporting": True,
    }


def _important_files(root: Path) -> list[Path]:
    candidates = [
        root / "main.py",
        root / "launch_cybershield.py",
        root / "app" / "main.py",
        root / "app" / "config.py",
        root / "app" / "ai" / "cybershield_terminal.py",
        root / "api" / "index.py",
        root / "pyproject.toml",
    ]
    return [p for p in candidates if p.is_file()]


def integrity(root: str | Path | None = None) -> dict[str, Any]:
    base = _safe_path(str(root or Path.cwd()))
    rows = []
    for path in _important_files(base):
        try:
            rows.append({"path": str(path.relative_to(base)), "sha256": _hash_file(path)["sha256"], "size": path.stat().st_size})
        except OSError as exc:
            rows.append({"path": str(path), "error": str(exc)})
    return {"root": str(base), "files": rows, "policy": "Runtime integrity is observational; no files are modified."}


def report(path: str | None = None) -> dict[str, Any]:
    snapshot = {
        "generated_at_utc": _now(),
        "application": version(),
        "system": system_info(),
        "uptime": uptime(),
        "memory": memory(),
        "disks": disks(),
        "risk_summary": risk_summary(),
        "incidents": get_incident_counts(),
        "capabilities": capabilities(),
        "integrity": integrity(),
        "recent_scans": scans(10),
        "recent_urls": url_history(10),
        "recent_audit": audit(10),
    }
    if path:
        target = _safe_path(path)
        if target.suffix.lower() != ".json":
            target = target.with_suffix(".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(snapshot, ensure_ascii=False, indent=2, default=str)
        if len(payload.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError("report exceeds safety size limit")
        target.write_text(payload, encoding="utf-8")
        add_audit("terminal_report", str(target), "created", {"bytes": len(payload.encode("utf-8"))})
        snapshot["saved_to"] = str(target)
    return snapshot


def health() -> dict[str, Any]:
    checks = {
        "python": sys.version_info >= (3, 12),
        "database_file_parent": Path(DATABASE_FILE).parent.exists(),
        "psutil": psutil is not None,
        "cwd_readable": os.access(Path.cwd(), os.R_OK),
    }
    return {"ok": all(checks.values()), "checks": checks, "timestamp_utc": _now()}


def limits() -> dict[str, Any]:
    return {
        "max_tree_entries": MAX_TREE_ENTRIES,
        "max_scan_results": MAX_SCAN_RESULTS,
        "max_report_bytes": MAX_REPORT_BYTES,
        "process_limit": 100,
        "connection_limit": 100,
        "audit_limit": 200,
        "terminal_history": 100,
        "arbitrary_shell": "disabled",
    }


def socket_summary() -> dict[str, Any]:
    rows = get_connections(100)
    states: dict[str, int] = {}
    for row in rows:
        state = str(row.get("status", "UNKNOWN"))
        states[state] = states.get(state, 0) + 1
    return {"states": states, "total": len(rows)}


def process_tree(limit: int = 60) -> list[dict[str, Any]]:
    rows = get_processes(_clamp(limit, 1, 100))
    by_pid = {int(r.get("pid", 0)): r for r in rows if r.get("pid") is not None}
    result = []
    for row in rows:
        pid = int(row.get("pid", 0))
        parent = int(row.get("ppid", 0) or 0)
        result.append({"pid": pid, "ppid": parent, "name": row.get("name"), "parent_seen": parent in by_pid if parent else False})
    return result


def large_files(raw_dir: str, limit: int = 20) -> list[dict[str, Any]]:
    root = _safe_path(raw_dir)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    limit = _clamp(limit, 1, 100)
    found: list[tuple[int, Path]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            found.append((path.stat().st_size, path))
        except OSError:
            continue
    found.sort(reverse=True, key=lambda item: item[0])
    return [{"path": str(p), "size": size, "size_human": _human_bytes(size)} for size, p in found[:limit]]


def extension_summary(raw_dir: str) -> dict[str, Any]:
    root = _safe_path(raw_dir)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    counts: dict[str, int] = {}
    total = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        total += 1
        ext = path.suffix.lower() or "[no-extension]"
        counts[ext] = counts.get(ext, 0) + 1
        if total >= 5000:
            break
    return {"directory": str(root), "files_counted": total, "extensions": dict(sorted(counts.items(), key=lambda x: (-x[1], x[0]))), "truncated": total >= 5000}


def command_specs() -> list[dict[str, Any]]:
    return [asdict(spec) for spec in COMMAND_SPECS]

# ---------------------------------------------------------------------------
# Operator catalog
# ---------------------------------------------------------------------------
# The catalog is deliberately explicit.  A security terminal benefits from a
# predictable command contract instead of clever parsing or shell pass-through.
# Each entry below documents the operator intent, output shape, safety model,
# and common validation rules.  The GUI can use this metadata in future releases
# without duplicating command policy.

OPERATOR_CATALOG: dict[str, dict[str, Any]] = {
    "version": {
        "title": "Release identity",
        "purpose": "Show the exact application and Python runtime identity.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "uptime": {
        "title": "Host uptime",
        "purpose": "Measure host uptime from the operating system boot timestamp.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "system-info": {
        "title": "System inventory",
        "purpose": "Collect non-secret OS, CPU and Python metadata.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "memory": {
        "title": "Memory telemetry",
        "purpose": "Read RAM and swap utilization through psutil.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "disks": {
        "title": "Disk telemetry",
        "purpose": "Enumerate mounted filesystems and capacity.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "python-info": {
        "title": "Python runtime",
        "purpose": "Expose interpreter and installation metadata for support diagnostics.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "env-safe": {
        "title": "Safe environment inventory",
        "purpose": "Expose selected non-secret environment variables while suppressing secret-like names.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "file-info": {
        "title": "Evidence file metadata",
        "purpose": "Collect filesystem metadata and cryptographic hashes without opening the file as executable code.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "tree": {
        "title": "Bounded filesystem tree",
        "purpose": "Inspect a directory hierarchy with a strict entry cap.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "scan-ext": {
        "title": "Extension-targeted scan",
        "purpose": "Run the existing static scanner against a bounded set of files sharing an extension.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "risk-summary": {
        "title": "Risk summary",
        "purpose": "Aggregate recent scanner verdicts into a compact SOC view.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "process-risk": {
        "title": "Process telemetry ranking",
        "purpose": "Rank observed processes using CPU and memory telemetry only.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "network-risk": {
        "title": "Network telemetry ranking",
        "purpose": "Review existing local connection telemetry and CyberShield risk evidence.",
        "read_only": True,
        "writes_files": False,
        "network": True,
        "sample_execution": False,
        "output": "JSON object",
    },
    "audit": {
        "title": "Audit trail",
        "purpose": "Read recent CyberShield operator and engine audit events.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "scans": {
        "title": "Scan history",
        "purpose": "Read recent file scanning history from the local database.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "url-history": {
        "title": "URL history",
        "purpose": "Read stored URL analysis results without revisiting URLs.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "incident-list": {
        "title": "Incident list",
        "purpose": "List open, closed or all incidents from the local database.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "capabilities": {
        "title": "Capability policy",
        "purpose": "Display the terminal's explicit defensive boundaries.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "integrity": {
        "title": "Application integrity",
        "purpose": "Hash selected application files so operators can compare release state.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "report": {
        "title": "Security snapshot",
        "purpose": "Create a bounded JSON snapshot from local telemetry and database evidence.",
        "read_only": False,
        "writes_files": True,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "health": {
        "title": "Local health",
        "purpose": "Perform fast availability checks without changing the host.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "limits": {
        "title": "Safety limits",
        "purpose": "Show resource and output limits applied by the terminal.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
    "socket-summary": {
        "title": "Socket state summary",
        "purpose": "Aggregate connection states from existing local telemetry.",
        "read_only": True,
        "writes_files": False,
        "network": True,
        "sample_execution": False,
        "output": "JSON object",
    },
    "process-tree": {
        "title": "Process relationship view",
        "purpose": "Show observed parent-child relationships without controlling processes.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "large-files": {
        "title": "Large file discovery",
        "purpose": "Identify large files for operator triage using bounded recursive enumeration.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON array",
    },
    "extension-summary": {
        "title": "Extension inventory",
        "purpose": "Count file extensions in a bounded directory traversal.",
        "read_only": True,
        "writes_files": False,
        "network": False,
        "sample_execution": False,
        "output": "JSON object",
    },
}


def operator_catalog() -> dict[str, dict[str, Any]]:
    """Return a copy of the operator policy catalog."""
    return {name: dict(values) for name, values in OPERATOR_CATALOG.items()}


def command_reference() -> list[dict[str, Any]]:
    """Return command specs merged with the operator safety catalog."""
    rows: list[dict[str, Any]] = []
    for spec in COMMAND_SPECS:
        row = asdict(spec)
        row.update(OPERATOR_CATALOG.get(spec.name, {}))
        rows.append(row)
    return rows


def validate_limit(value: str | None, default: int, maximum: int) -> int:
    """Parse a user limit with a deterministic safety cap."""
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    return _clamp(parsed, 1, maximum)


def validate_depth(value: str | None, default: int = 2) -> int:
    """Parse a directory traversal depth with a strict maximum."""
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("depth must be an integer") from exc
    return _clamp(parsed, 0, 8)


def normalize_extension(value: str) -> str:
    """Normalize a file extension for deterministic matching."""
    ext = str(value).strip().lower()
    if not ext:
        raise ValueError("extension cannot be empty")
    if not ext.startswith("."):
        ext = "." + ext
    if len(ext) > 32 or any(ch in ext for ch in ("/", "\\", "\x00")):
        raise ValueError("invalid extension")
    return ext


def is_secret_environment_name(name: str) -> bool:
    """Return whether an environment variable name looks credential-like."""
    upper = str(name).upper()
    return any(marker in upper for marker in SECRET_MARKERS)


def redact_value(value: Any, maximum: int = 256) -> str:
    """Convert diagnostic values to bounded strings."""
    text = str(value)
    if len(text) <= maximum:
        return text
    return text[:maximum] + "…"


def summarize_scan_rows(rows: Iterable[Any]) -> dict[str, Any]:
    """Summarize scan tuples without exposing full evidence payloads."""
    counts: dict[str, int] = {}
    risks: list[int] = []
    for row in rows:
        try:
            verdict = str(row[1])
            risk = int(row[2])
        except (IndexError, TypeError, ValueError):
            continue
        counts[verdict] = counts.get(verdict, 0) + 1
        risks.append(risk)
    return {
        "count": sum(counts.values()),
        "verdicts": counts,
        "min_risk": min(risks) if risks else 0,
        "max_risk": max(risks) if risks else 0,
        "average_risk": round(sum(risks) / len(risks), 2) if risks else 0,
    }


def summarize_incidents(rows: Iterable[Any]) -> dict[str, Any]:
    """Summarize incident records by severity and status."""
    severity: dict[str, int] = {}
    status: dict[str, int] = {}
    total = 0
    for row in rows:
        try:
            sev = str(row[2])
            state = str(row[4])
        except (IndexError, TypeError):
            continue
        severity[sev] = severity.get(sev, 0) + 1
        status[state] = status.get(state, 0) + 1
        total += 1
    return {"total": total, "severity": severity, "status": status}


def database_summary() -> dict[str, Any]:
    """Return a compact database summary using existing public database APIs."""
    incidents = get_incidents()
    recent_scans = get_recent_scans(100)
    urls = get_recent_url_scans(100)
    return {
        "scan_summary": summarize_scan_rows(recent_scans),
        "incident_summary": summarize_incidents(incidents),
        "url_count": len(urls),
        "audit_count": len(get_recent_audit(100)),
    }


def release_snapshot() -> dict[str, Any]:
    """Return release identity plus local database state for support tickets."""
    return {
        "release": version(),
        "health": health(),
        "database": database_summary(),
        "capabilities": capabilities(),
        "limits": limits(),
    }


def report_manifest() -> dict[str, Any]:
    """Describe report sections and their data sources."""
    return {
        "generated_at_utc": _now(),
        "sections": [
            {"name": "application", "source": "CyberShield configuration", "network": False},
            {"name": "system", "source": "platform/psutil", "network": False},
            {"name": "memory", "source": "psutil", "network": False},
            {"name": "disks", "source": "psutil", "network": False},
            {"name": "risk_summary", "source": "CyberShield SQLite database", "network": False},
            {"name": "incidents", "source": "CyberShield SQLite database", "network": False},
            {"name": "integrity", "source": "local application files", "network": False},
            {"name": "recent_scans", "source": "CyberShield SQLite database", "network": False},
            {"name": "recent_urls", "source": "CyberShield SQLite database", "network": False},
            {"name": "recent_audit", "source": "CyberShield SQLite database", "network": False},
        ],
        "size_limit_bytes": MAX_REPORT_BYTES,
    }


# The following small adapters keep command execution deterministic and make
# the module straightforward to exercise from tests or future UI widgets.

def run_version_json() -> str:
    return _json(version())


def run_uptime_json() -> str:
    return _json(uptime())


def run_system_json() -> str:
    return _json(system_info())


def run_memory_json() -> str:
    return _json(memory())


def run_disks_json() -> str:
    return _json(disks())


def run_python_json() -> str:
    return _json(python_info())


def run_environment_json() -> str:
    return _json(env_safe())


def run_capabilities_json() -> str:
    return _json(capabilities())


def run_health_json() -> str:
    return _json(health())


def run_limits_json() -> str:
    return _json(limits())


def run_integrity_json() -> str:
    return _json(integrity())


def run_release_snapshot_json() -> str:
    return _json(release_snapshot())


def run_report_manifest_json() -> str:
    return _json(report_manifest())


# Explicit safety assertions are kept as executable code so a future refactor
# cannot silently turn a read-only command into an OS shell bridge.
FORBIDDEN_EXECUTION_CAPABILITIES = frozenset({
    "cmd.exe",
    "powershell.exe",
    "pwsh",
    "bash",
    "sh",
    "subprocess-shell",
    "os.system",
    "os.popen",
})


def safety_policy() -> dict[str, Any]:
    """Return machine-readable terminal safety policy."""
    return {
        "shell_execution": False,
        "forbidden_execution_capabilities": sorted(FORBIDDEN_EXECUTION_CAPABILITIES),
        "sample_execution": False,
        "automatic_delete": False,
        "automatic_process_termination": False,
        "automatic_firewall_changes": False,
        "automatic_registry_changes": False,
        "operator_confirmation_for_quarantine": True,
    }


def validate_report_destination(raw_path: str) -> Path:
    """Validate a report destination without creating or executing it."""
    target = _safe_path(raw_path)
    if target.suffix.lower() != ".json":
        target = target.with_suffix(".json")
    if len(str(target)) > 900:
        raise ValueError("report path is too long")
    return target


def bounded_text(value: Any, maximum: int = 12000) -> str:
    """Bound arbitrary diagnostic text before terminal rendering."""
    return redact_value(value, maximum)


def telemetry_timestamp() -> str:
    """Return a UTC timestamp suitable for telemetry records."""
    return _now()


def module_status() -> dict[str, Any]:
    """Report availability of optional telemetry dependencies."""
    return {
        "psutil": psutil is not None,
        "database": Path(DATABASE_FILE).parent.exists(),
        "scanner": True,
        "terminal_pack": True,
    }


def safe_path_description(raw_path: str) -> dict[str, Any]:
    """Describe path characteristics without reading executable contents."""
    path = _safe_path(raw_path)
    return {
        "path": str(path),
        "exists": path.exists(),
        "file": path.is_file(),
        "directory": path.is_dir(),
        "absolute": path.is_absolute(),
        "suffix": path.suffix.lower(),
        "name": path.name,
    }


def storage_health() -> dict[str, Any]:
    """Check whether the application storage location is writable."""
    parent = Path(DATABASE_FILE).parent
    result = {"path": str(parent), "exists": parent.exists(), "writable": False}
    try:
        result["writable"] = os.access(parent, os.W_OK)
    except OSError:
        result["writable"] = False
    return result


def performance_snapshot() -> dict[str, Any]:
    """Return a lightweight CPU/RAM snapshot for the operator dashboard."""
    if psutil is None:
        return {"available": False}
    vm = psutil.virtual_memory()
    return {
        "available": True,
        "cpu_percent": psutil.cpu_percent(interval=0.05),
        "memory_percent": vm.percent,
        "memory_available": vm.available,
        "timestamp_utc": _now(),
    }


def operator_summary() -> dict[str, Any]:
    """One-call summary intended for a future terminal status panel."""
    return {
        "release": version(),
        "health": health(),
        "performance": performance_snapshot(),
        "storage": storage_health(),
        "database": database_summary(),
        "policy": safety_policy(),
    }


# --- Extended read-only audit wrappers ---
def _extended_audit(name: str, target: str | None = None):
    if name == "full-audit": return quick_report(target or ".")
    if name == "deep-audit": return deep_scan(target or ".")
    if name == "entropy-audit": return entropy_scan(target or ".")
    if name == "extension-audit": return extension_audit(target or ".")
    if name == "hash-manifest": return hash_manifest(target or ".")
    if name == "string-audit": return string_audit(target or ".")
    if name == "image-audit": return image_audit(target or "")
    if name == "screen-audit": return screenshot_audit()
    if name == "duplicate-audit": return duplicate_scan(target or ".")
    if name == "permission-audit": return permission_audit(target or ".")
    if name == "inventory": return inventory(target or ".")
    if name == "quick-audit": return quick_report(target or ".")
    if name == "headers": return extension_audit(target or ".")
    if name == "macro-audit": return {"target": target, "extensions": [".docm", ".xlsm", ".pptm"], "inventory": inventory(target or ".")}
    if name == "script-audit": return string_audit(target or ".")
    if name == "archive-audit": return {"target": target, "extensions": [".zip", ".7z", ".rar", ".iso", ".img"], "inventory": inventory(target or ".")}
    if name == "size-audit": return {"target": target, "largest": sorted(_safe_file_rows(target or "."), key=lambda x:x.get("size",0), reverse=True)[:50]}
    if name == "risk-files":
        data=deep_scan(target or "."); return {"target": target, "ranked": sorted(data.get("results",[]), key=lambda x:x.get("signal_count",0), reverse=True)[:100]}
    if name == "sample-audit": return deep_scan(target or ".")
    raise ValueError(name)

def _safe_file_rows(target: str):
    root=Path(target).expanduser().resolve(); paths=[root] if root.is_file() else list(root.rglob("*"))[:400]
    rows=[]
    for p in paths:
        if p.is_file():
            try: rows.append({"path":str(p),"size":p.stat().st_size})
            except OSError: pass
    return rows

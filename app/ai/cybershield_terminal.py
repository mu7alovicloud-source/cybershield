"""CyberShield Security Terminal.

A deterministic, terminal-like command layer for defensive operations.
It deliberately does NOT expose arbitrary cmd.exe/PowerShell execution.
Every command maps to a bounded CyberShield security function.
"""
from __future__ import annotations

import json
import shlex
import socket
import platform
import shutil
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from app.ai.terminal_intelligence import inspect_host
from app.security.scanner import analyze_file, scan_directory
from app.security.phishing_guard import analyze_url
from app.security.enhanced_detection import url_signals
from app.security.advanced_detection import analyze_file_deep, analyze_url_deep
from app.security.process_monitor import get_processes
from app.security.network_monitor import get_connections, get_local_network_info
from app.security.defender_scan import scan_file_with_defender
from app.security.quarantine import quarantine_file
from app.security.lab_controller import assess_dynamic_lab_readiness
from app.security.self_diagnostics import run_self_diagnostics
from app.database.database import (
    add_scan, add_url_scan, get_recent_scans, get_recent_url_scans,
    get_recent_audit, get_incident_counts, add_audit, initialize_database
)
from app.i18n import terminal_tr
from app.ai import pro_terminal_commands as procmd
from app.ai.github_terminal import github_command, GitHubTerminalError
from app.ai.ciber_operator import dispatch as operator_dispatch, ActionError
from app.security.sandbox_runner import launch_sandbox
from app.security.malware_engines import engine_status, eicar_self_test, yara_scan_file
from app.security.professional_health import doctor, safe_repair, performance


class CommandError(ValueError):
    pass


ALIASES = {
    "help": {"help", "yordam", "помощь", "?"},
    "status": {"status", "holat", "статус", "security-status"},
    "scan": {"scan", "tekshir", "скан", "проверить", "scan-file", "file-scan"},
    "deep-scan": {"deep-scan", "deep_scan", "chuqur-tekshir", "глубокий-скан", "deep", "deepcheck"},
    "engine-status": {"engine-status", "engines", "av-status", "malware-engines", "dvigatellar"},
    "av-self-test": {"av-self-test", "eicar-test", "antivirus-test", "av-test"},
    "yara-scan": {"yara-scan", "yara-check", "local-yara"},
    "host": {"host", "inspect", "system", "tizim", "компьютер", "система"},
    "processes": {"processes", "process", "jarayonlar", "процессы"},
    "network": {"network", "net", "tarmoq", "сеть"},
    "services": {"services", "xizmatlar", "службы"},
    "tasks": {"tasks", "vazifalar", "задачи"},
    "defender": {"defender", "himoya", "защитник"},
    "hash": {"hash", "xesh", "хэш", "sha256"},
    "url": {"url", "fishing", "phishing", "url-check", "link", "havola", "ссылка"},
    "threat-check": {"threat-check", "file-threat-check", "malware-check", "virus-check", "virus-scan", "malware-scan"},
    "quarantine": {"quarantine", "karantin", "карантин"},
    "lab": {"lab", "sandbox", "xavfsiz-lab", "лаборатория"},
    "diagnostics": {"diagnostics", "diag", "diagnostika", "диагностика", "self-test", "selftest"},
    "history": {"history", "tarix", "история"},
    "incidents": {"incidents", "hodisalar", "инциденты"},
    "clear": {"clear", "toza", "очистить", "cls"},
    "commands": {"commands", "command", "buyruqlar", "komandalar", "команды", "list-commands"},
    "commands-by-category": {"commands-by-category", "commands category", "command-category", "buyruqlar kategoriyasi"},
    "version": {"version", "versiya", "версия", "about", "info"},
    "uptime": {"uptime", "ish-vaqti", "время-работы"},
    "system-info": {"system-info", "system_info", "tizim-info", "система-инфо"},
    "memory": {"memory", "ram", "xotira", "память"},
    "disks": {"disks", "disk", "disklar", "диски"},
    "python-info": {"python-info", "python", "python-info"},
    "env-safe": {"env-safe", "environment", "muhit", "окружение"},
    "file-info": {"file-info", "fayl-info", "файл-инфо"},
    "tree": {"tree", "daraxt", "дерево"},
    "scan-ext": {"scan-ext", "extension-scan", "kengaytma-skan", "скан-расширения"},
    "risk-summary": {"risk-summary", "risk", "xavf-xulosa", "риск"},
    "process-risk": {"process-risk", "jarayon-xavfi", "риск-процессов"},
    "network-risk": {"network-risk", "tarmoq-xavfi", "риск-сети"},
    "audit": {"audit", "audit-log", "audit-tarix", "аудит"},
    "scans": {"scans", "skanlar", "сканы"},
    "url-history": {"url-history", "havola-tarix", "история-url"},
    "incident-list": {"incident-list", "hodisa-list", "список-инцидентов"},
    "capabilities": {"capabilities", "imkoniyatlar", "возможности"},
    "integrity": {"integrity", "butlik", "целостность"},
    "report": {"report", "hisobot", "отчёт"},
    "health": {"health", "soglomlik", "здоровье"},
    "limits": {"limits", "chegaralar", "лимиты"},
    "socket-summary": {"socket-summary", "ulanish-xulosasi", "сокеты"},
    "process-tree": {"process-tree", "jarayon-daraxt", "дерево-процессов"},
    "large-files": {"large-files", "katta-fayllar", "большие-файлы"},
    "extension-summary": {"extension-summary", "kengaytma-xulosa", "расширения"},
    "hostname": {"hostname", "host-name", "kompyuter-nomi", "kompyuter nomi"},
    "whoami": {"whoami", "men-kimman", "kimman", "foydalanuvchi"},
    "ipconfig": {"ipconfig", "ip-info", "ip", "adapterlar", "tarmoq-info"},
    "routes": {"routes", "route", "routing", "marshrutlar", "yo‘nalishlar", "yonalishlar"},
    "arp": {"arp", "arp-table", "arp-jadval"},
    "netstat": {"netstat", "sockets", "ulanishlar", "portlar", "ports", "connections"},
    "tasklist": {"tasklist", "process-list", "process-listing", "jarayon-list", "jarayonlar-listi"},
    "drivers": {"drivers", "driverlar", "drayverlar", "driver-list"},
    "get-process": {'ps processes', 'get-process', 'ps-processes', 'powershell processes'},
    "get-service": {'powershell services', 'ps services', 'get-service', 'ps-services'},
    "get-netadapter": {'get-netadapter', 'network adapters', 'ps-netadapter', 'net adapters'},
    "get-netipconfiguration": {'get-netipconfiguration', 'ps-ip', 'powershell ip'},
    "get-nettcpconnection": {'ps-tcp', 'tcp connections', 'get-nettcpconnection'},
    "get-netudpendpoint": {'udp endpoints', 'ps-udp', 'get-netudpendpoint'},
    "get-dnsclientservers": {'ps-dns', 'get-dnsclientservers', 'dns servers'},
    "get-netroute": {'ps-routes', 'powershell routes', 'get-netroute'},
    "get-firewallprofile": {'powershell firewall', 'ps-firewall', 'get-firewallprofile'},
    "get-mpcomputerstatus": {'get-mpcomputerstatus', 'powershell defender', 'ps-defender'},
    "get-mpthreatdetection": {'ps-threats', 'get-mpthreatdetection', 'powershell threats'},
    "get-scheduledtask": {'get-scheduledtask', 'ps-tasks', 'powershell tasks'},
    "get-hotfix": {'ps-hotfix', 'windows hotfixes', 'get-hotfix'},
    "get-computerinfo": {'powershell computer info', 'get-computerinfo', 'ps-computer'},
    "get-ciminstance-os": {'get-ciminstance-os', 'powershell os', 'ps-os'},
    "get-ciminstance-computer": {'powershell hardware', 'ps-hardware', 'get-ciminstance-computer'},
    "get-startupapps": {'ps-startup', 'get-startupapps', 'startup commands'},
    "get-eventlog-security": {'get-eventlog-security', 'ps-security-events', 'security events'},
    "get-eventlog-system": {'ps-system-events', 'system events', 'get-eventlog-system'},
    "get-eventlog-application": {'ps-app-events', 'get-eventlog-application', 'application events'},
    "get-netfirewallrule": {'get-netfirewallrule', 'ps-firewall-rules', 'firewall rules'},
    "get-mppreference": {'get-mppreference', 'ps-defender-preferences', 'defender preferences'},
    "get-bitlockervolume": {'get-bitlockervolume', 'ps-bitlocker', 'bitlocker status'},
    "get-localuser": {'get-localuser', 'ps-users', 'local users'},
    "get-localgroup": {'get-localgroup', 'ps-groups', 'local groups'},
    "get-localgroupmember-admin": {'get-localgroupmember-admin', 'ps-admins', 'administrators', 'local administrators'},
    "get-bitsjob": {'get-bitsjob', 'ps-bits', 'bits jobs'},
    "get-netfirewallrule": {'get-netfirewallrule', 'ps-firewall-rules', 'firewall rules'},
    "get-mppreference": {'get-mppreference', 'ps-defender-preferences', 'defender preferences'},
    "get-bitlockervolume": {'get-bitlockervolume', 'ps-bitlocker', 'bitlocker status'},
    "get-localuser": {'get-localuser', 'ps-users', 'local users'},
    "get-localgroup": {'get-localgroup', 'ps-groups', 'local groups'},
    "get-localgroupmember-admin": {'get-localgroupmember-admin', 'ps-admins', 'administrators'},
    "get-bitsjob": {'get-bitsjob', 'ps-bits', 'bits jobs'},
    "firewall": {"firewall", "fw", "brandmauer", "firewall-status", "xavfsizlik-devori"},
    "systeminfo": {"systeminfo", "system-info-cmd", "windows-systeminfo"},
    "netsh-interfaces": {"netsh-interfaces", "interfaces", "net interfaces", "adapter-state"},
    "netsh-wlan": {"netsh-wlan", "wifi-info", "wlan-info", "wifi"},
    "powercfg": {"powercfg", "power-plan", "powerplan"},
    "whoami-groups": {"whoami-groups", "groups", "user-groups"},
    "net-accounts": {"net-accounts", "account-policy", "account-policy-info"},
    "net-share": {"net-share", "shares", "windows-shares"},
    "schtasks": {"schtasks", "scheduled-task-list", "scheduled-tasks-cmd"},
    "ver": {"ver", "windows-version", "windows version"},
    "date": {"date", "today", "sana"},
    "time": {"time", "clock", "vaqt", "soat"},
    "dir": {"dir", "ls", "list-files", "fayllar"},
    "where": {"where", "where.exe", "find-program", "program-location"},
    "github": {"github", "git", "github-cli", "github-terminal"},
    "ciber": {"ciber", "cyber", "ciber-terminal", "cybershield-terminal", "operator", "ai-terminal", "ai"},
    "github-publish": {"github-publish", "publish-github", "github-deploy", "github-push", "githubga-joyla", "githubga yubor", "githubga yuborish", "githubga joyla", "githubga joylash", "githubga yukla", "githubga yuklash", "githubga chiqar", "githubga nashr qil"},
    "vercel-deploy": {"vercel-deploy", "deploy-vercel", "vercelga-joyla", "vercelga deploy", "vercelga joyla", "vercelga yubor", "vercelga yukla", "vercel-publish", "vercelga chiqar", "vercelga nashr qil"},
    "build-exe": {"build-exe", "make-exe", "exe", "exe-yarat", "exe-qil", "exe yarat", "exe qil"},
    "operator-status": {"operator-status", "ciber-status", "tool-status"},
    "sandbox-run": {"sandbox-run", "run-sandbox", "xavfsiz-ishga-tushir", "sandbox-test", "lab-run"},
    "full-audit": {"full-audit", "100-audit", "full-check", "to-liq-audit"},
    "deep-audit": {"deep-audit", "chuqur-audit", "forensic-scan", "deep-analysis"},
    "entropy-audit": {"entropy-audit", "entropy", "packing-audit"},
    "extension-audit": {"extension-audit", "header-audit", "masquerade-audit"},
    "hash-manifest": {"hash-manifest", "hash-all", "manifest"},
    "string-audit": {"string-audit", "strings-audit"},
    "image-audit": {"image-audit", "pixel-audit", "pixel-analysis"},
    "screen-audit": {"screen-audit", "screen-pixel-audit", "desktop-audit"},
    "duplicate-audit": {"duplicate-audit", "duplicates"},
    "permission-audit": {"permission-audit", "access-audit"},
    "inventory": {"inventory", "file-inventory"},
    "quick-audit": {"quick-audit", "tez-audit", "quick-check"},
    "headers": {"headers", "header-check"},
    "macro-audit": {"macro-audit", "macro-check"},
    "script-audit": {"script-audit", "script-check"},
    "archive-audit": {"archive-audit", "archive-check"},
    "size-audit": {"size-audit", "resource-audit"},
    "risk-files": {"risk-files", "risk-rank"},
    "sample-audit": {"sample-audit", "bounded-audit"},
    "lab-status": {"lab-status", "sandbox-status", "lab-ready"},
    "doctor": {"doctor", "health-check", "system-doctor", "tekshir-tizim", "diagnostika-pro"},
    "safe-repair": {"safe-repair", "safe-repair-runtime", "xavfsiz-tuzat", "tikla-xavfsiz"},
    "performance": {"performance", "perf", "unumdorlik", "tezlik-test"},
}


def _canonical(name: str) -> str | None:
    n = name.strip().lower()
    for command, values in ALIASES.items():
        if n in values:
            return command
    # Professional catalog commands are also first-class command names.
    # This keeps `help`/`commands` and the executable allowlist in sync.
    try:
        if any(n == str(row.get("name", "")).lower() for row in procmd.command_reference()):
            return n
    except Exception:
        pass
    return None


def _fmt_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return str(value)


def _json(data: Any, limit: int = 12000) -> str:
    text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    return text if len(text) <= limit else text[:limit] + "\n… output truncated"


class CyberShieldTerminal:
    """Safe command interpreter usable by the GUI and real console."""

    def __init__(self, language: str = "uz"):
        self.language = language
        self.history: list[str] = []
        # The terminal is also used independently by the GUI and support tools.
        # Ensure its read-only history/status queries have a valid local schema.
        initialize_database()

    def set_language(self, language: str) -> None:
        self.language = language

    def help_text(self) -> str:
        if self.language == "en":
            return (
                "CyberShield Security Terminal\n"
                "────────────────────────────────────────\n"
                "scan <file|dir>              — static malware scan\n"
                "deep-scan <file>             — deeper static + Defender/reputation checks\n"
                "hash <file>                  — SHA-256 / SHA-1 / MD5\n"
                "url <https://…>              — phishing/URL analysis; no page execution\n"
                "host                         — read-only host inventory\n"
                "processes                    — running process telemetry\n"
                "network                      — interfaces + connections\n"
                "services                     — Windows services (read-only)\n"
                "tasks                        — scheduled tasks (read-only)\n"
                "defender                     — Microsoft Defender status\n"
                "lab                          — isolated-lab readiness check\n"
                "diagnostics                  — CyberShield self-diagnostics\n"
                "incidents                    — open incident counts\n"
                "history                      — recent terminal commands\n"
                "quarantine <file> --confirm  — reversible quarantine\n"
                "status                       — security engine status\n"
                "help                         — this help (all commands + safety policy)\n"
                "clear                        — clear terminal output\n"
                "github <auth|status|open|publish|commit|push|pull|clone> — safe GitHub CLI actions\n"
                "sandbox-run <file>          — launch disposable Windows Sandbox (network off)\n"
                "full-audit <file|dir>       — bounded multi-layer forensic audit\n"
                "deep-audit <file|dir>       — deep static analysis, never executes target\n"
                "image-audit <image>         — pixel-level image statistics\n"
                "screen-audit                — desktop pixel statistics, not saved\n"
                "risk-files <file|dir>       — rank static risk signals\n"
                "commands                     — list all registered commands/aliases\n"
                "ciber                        — enter Claude-like CIBER AI operator mode\n"
                "ciber help                   — CIBER operator help and action catalog\n\n"
                "SAFE MODE: arbitrary cmd.exe / PowerShell / shell execution is blocked."
            )
        if self.language == "ru":
            return (
                "Терминал безопасности CyberShield\n"
                "────────────────────────────────────────\n"
                "скан <файл|папка>            — статический анализ\n"
                "глубокий-скан <файл>         — углублённый анализ + Defender/репутация\n"
                "хэш <файл>                   — SHA-256 / SHA-1 / MD5\n"
                "ссылка <https://…>           — анализ фишинга без открытия страницы\n"
                "система                      — инвентаризация хоста (только чтение)\n"
                "процессы                     — телеметрия процессов\n"
                "сеть                         — интерфейсы и соединения\n"
                "службы                       — службы Windows\n"
                "задачи                       — планировщик задач\n"
                "защитник                     — состояние Microsoft Defender\n"
                "лаборатория                  — проверка готовности изолированной лаборатории\n"
                "диагностика                  — самодиагностика CyberShield\n"
                "инциденты                    — открытые инциденты\n"
                "история                      — история команд\n"
                "карантин <файл> --confirm    — обратимый карантин\n"
                "статус                       — состояние движка\n"
                "помощь                       — эта справка\n"
                "очистить                     — очистить терминал\n"
                "команды                      — список всех зарегистрированных команд/алиасов\n\n"
                "БЕЗОПАСНЫЙ РЕЖИМ: произвольный CMD/PowerShell/shell заблокирован."
            )
        return (
            "CyberShield Xavfsizlik Terminali\n"
            "────────────────────────────────────────\n"
            "tekshir <fayl|papka>          — statik zararli dastur skani\n"
            "chuqur-tekshir <fayl>        — chuqur statik + Defender/reputatsiya\n"
            "xesh <fayl>                  — SHA-256 / SHA-1 / MD5\n"
            "havola <https://…>           — fishing/URL tahlili; sahifa ochilmaydi\n"
            "tizim                        — host inventarizatsiyasi (faqat o‘qish)\n"
            "jarayonlar                   — ishlayotgan jarayonlar\n"
            "tarmoq                       — interfeyslar va ulanishlar\n"
            "xizmatlar                    — Windows xizmatlari\n"
            "vazifalar                    — rejalashtirilgan vazifalar\n"
            "himoya                       — Microsoft Defender holati\n"
            "xavfsiz-lab                  — izolyatsiyalangan lab tayyorgarligi\n"
            "diagnostika                  — CyberShield o‘z-o‘zini tekshirish\n"
            "hodisalar                    — ochiq hodisalar\n"
            "tarix                        — terminal buyruqlari tarixi\n"
            "karantin <fayl> --confirm    — qaytariladigan karantin\n"
            "holat                        — xavfsizlik dvigateli holati\n"
            "yordam                       — shu yordam\n"
            "toza                         — terminalni tozalash\n"
            "buyruqlar                    — barcha ro‘yxatdan o‘tgan buyruq/aliaslar\n"
            "hostname                     — Windows kompyuter nomi\n"
            "whoami                       — joriy Windows foydalanuvchi konteksti\n"
            "ipconfig                     — tarmoq adapterlari konfiguratsiyasi\n"
            "routes                       — routing jadvali\n"
            "arp                          — ARP jadvali\n"
            "netstat                      — TCP/UDP ulanishlari va PIDlar\n"
            "tasklist                     — Windows process ro‘yxati\n"
            "drivers                      — Windows driver inventarizatsiyasi\n"
            "firewall                     — Windows Firewall profillari holati\n"
            "PowerShell SAFE PACK: get-process, get-service, get-netadapter, get-nettcpconnection, get-netroute, get-dnsclientservers, get-mpcomputerstatus, get-mpthreatdetection, get-scheduledtask, get-hotfix, get-computerinfo, get-ciminstance-os, get-startupapps, get-eventlog-*\n"
            "ps-* aliaslari                 — shu PowerShell diagnostikalarining qisqa nomlari\n\n"
            "threat-check <fayl> — qatlamli fayl tahdid tekshiruvi\n"
            "url-check <url>   — qatlamli phishing/URL tekshiruvi\n"
            "ciber — AI operator rejimiga kirish (terminal ichida)\n"
            "\n"
            + self._professional_help_catalog()
            + "\n\nXAVFSIZ REJIM: ixtiyoriy CMD/PowerShell/shell bajarilishi bloklangan."
        )

    def _detect_language(self, token: str) -> None:
        t = token.strip().lower()
        if t in {"tekshir", "chuqur-tekshir", "tizim", "jarayonlar", "tarmoq", "xizmatlar", "vazifalar", "himoya", "xesh", "havola", "karantin", "xavfsiz-lab", "diagnostika", "hodisalar", "tarix", "yordam", "holat", "toza", "buyruqlar", "komandalar"}:
            self.language = "uz"
        elif t in {"проверить", "глубокий-скан", "система", "компьютер", "процессы", "сеть", "службы", "задачи", "защитник", "хэш", "ссылка", "карантин", "лаборатория", "диагностика", "инциденты", "история", "помощь", "статус", "очистить", "команды"}:
            self.language = "ru"
        elif t in {"scan", "deep-scan", "host", "processes", "network", "services", "tasks", "defender", "hash", "url", "quarantine", "lab", "diagnostics", "incidents", "history", "status", "clear", "inspect", "system", "net", "link", "phishing", "threat-check", "url-check", "sandbox", "command"}:
            self.language = "en"
        # Generic navigation commands such as `help` and `commands` do not
        # change the operator language. This keeps the default Uzbek terminal
        # from unexpectedly switching to English when the user types `help`.

    def execute(self, line: str) -> str:
        raw = line.strip()
        if not raw:
            return ""
        self.history.append(raw)
        self.history = self.history[-100:]
        try:
            tokens = shlex.split(raw, posix=False)
        except ValueError as exc:
            return f"ERROR: invalid command syntax: {exc}"
        if not tokens:
            return ""
        tokens = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in {chr(34), chr(39)} else t for t in tokens]
        # `powershell <approved-command>` is accepted only as a friendly
        # alias for the fixed read-only PowerShell pack. Anything else remains
        # blocked; no user-supplied PowerShell expression is ever executed.
        if tokens[0].lower() in {"powershell", "powershell.exe", "pwsh", "ps"}:
            if len(tokens) >= 2:
                ps_alias = tokens[1].lower()
                ps_key = procmd.POWERSHELL_ALIASES.get(ps_alias, ps_alias)
                if ps_key in procmd.POWERSHELL_READONLY_COMMANDS:
                    tokens = [ps_key, *tokens[2:]]
                else:
                    return "BLOCKED: only CyberShield allowlisted PowerShell read-only commands are available."
            else:
                return ("PowerShell SAFE PACK: use `powershell get-process`, `powershell get-service`, "
                        "`powershell get-nettcpconnection`, `powershell get-mpcomputerstatus`, "
                        "or `commands` to see the full allowlist.")
        self._detect_language(tokens[0])
        if tokens[0].lower() in {"cs", "cybershield", "cybershield.exe"}:
            tokens = tokens[1:]
        if not tokens:
            return self.help_text()
        command = _canonical(tokens[0])
        if command is None:
            return (
                "BLOCKED: command not in CyberShield security command set.\n"
                "Arbitrary cmd.exe / PowerShell / shell execution is disabled.\n\n" + self.help_text()
            )
        args = tokens[1:]
        try:
            if command == "help": return self.help_text()
            if command == "commands": return self._commands()
            if command == "commands-by-category":
                category = " ".join(args).strip().lower() if args else "system"
                rows = [r for r in procmd.command_reference() if str(r.get("category", "")).lower() == category]
                if not rows:
                    return _json({"category": category, "commands": [], "available_categories": sorted({str(r.get("category", "")) for r in procmd.command_reference()})})
                return _json({"category": category, "commands": rows})
            if command == "version": return _json(procmd.version())
            if command == "ver": return _json({"platform": platform.platform(), "python": platform.python_version(), "system": platform.system(), "release": platform.release(), "version": platform.version()})
            if command == "date": return _json({"local_date": datetime.now().astimezone().strftime("%Y-%m-%d"), "weekday": datetime.now().astimezone().strftime("%A")})
            if command == "time": return _json({"local_time": datetime.now().astimezone().strftime("%H:%M:%S"), "timezone": datetime.now().astimezone().tzname()})
            if command == "dir":
                target = Path(" ".join(args) if args else ".").expanduser().resolve()
                if not target.exists(): raise FileNotFoundError(str(target))
                if not target.is_dir(): raise CommandError("dir expects a directory")
                entries = []
                for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))[:200]:
                    try: entries.append({"name": child.name, "type": "directory" if child.is_dir() else "file", "size": child.stat().st_size if child.is_file() else None})
                    except OSError: entries.append({"name": child.name, "type": "unreadable"})
                return _json({"directory": str(target), "count": len(entries), "entries": entries})
            if command == "where":
                if not args: raise CommandError("Usage: where <program>")
                name = args[0].strip()
                if not name or any(c in name for c in "&|;<>\"'`$"):
                    raise CommandError("Invalid program name")
                found = shutil.which(name)
                return _json({"program": name, "found": bool(found), "path": found})
            if command == "uptime": return _json(procmd.uptime())
            if command == "system-info": return _json(procmd.system_info())
            if command == "memory": return _json(procmd.memory())
            if command == "disks": return _json(procmd.disks())
            if command == "python-info": return _json(procmd.python_info())
            if command == "hostname": return _json(procmd.hostname())
            if command == "firewall": return _json(procmd.firewall_status())
            if command in procmd.WINDOWS_READONLY_COMMANDS:
                return _json(procmd._fixed_windows_command(command), limit=30000)
            if command in procmd.POWERSHELL_READONLY_COMMANDS:
                return _json(procmd.powershell_readonly(command), limit=30000)
            if command == "env-safe": return _json(procmd.env_safe())
            if command == "file-info":
                if not args: raise CommandError("Usage: file-info <file>")
                return _json(procmd.file_info(" ".join(args)))
            if command == "tree":
                if not args: raise CommandError("Usage: tree <directory> [depth]")
                depth = int(args[1]) if len(args) > 1 else 2
                return _json(procmd.tree(args[0], depth))
            if command == "scan-ext":
                if len(args) < 2: raise CommandError("Usage: scan-ext <directory> <extension> [limit]")
                limit = int(args[2]) if len(args) > 2 else 100
                return _json(procmd.scan_by_extension(args[0], args[1], limit))
            if command == "risk-summary": return _json(procmd.risk_summary())
            if command == "process-risk": return _json(procmd.process_risk(int(args[0]) if args else 30))
            if command == "network-risk": return _json(procmd.network_risk(int(args[0]) if args else 50))
            if command == "audit": return _json(procmd.audit(int(args[0]) if args else 50))
            if command == "scans": return _json(procmd.scans(int(args[0]) if args else 30))
            if command == "url-history": return _json(procmd.url_history(int(args[0]) if args else 30))
            if command == "incident-list": return _json(procmd.incident_list(args[0] if args else "open"))
            if command == "capabilities": return _json(procmd.capabilities())
            if command == "integrity": return _json(procmd.integrity())
            if command == "report": return _json(procmd.report(" ".join(args) if args else None))
            if command == "health": return _json(procmd.health())
            if command == "limits": return _json(procmd.limits())
            if command == "socket-summary": return _json(procmd.socket_summary())
            if command == "process-tree": return _json(procmd.process_tree(int(args[0]) if args else 60))
            if command == "large-files":
                if not args: raise CommandError("Usage: large-files <directory> [limit]")
                return _json(procmd.large_files(args[0], int(args[1]) if len(args) > 1 else 20))
            if command == "extension-summary":
                if not args: raise CommandError("Usage: extension-summary <directory>")
                return _json(procmd.extension_summary(args[0]))
            # Additional defensive Windows telemetry commands from the
            # professional catalog. They map to fixed, read-only templates.
            ps_catalog_map = {
                "defender-status": "get-mpcomputerstatus",
                "defender-threats": "get-mpthreatdetection",
                "listening-ports": "get-nettcpconnection",
                "dns-cache": "get-dnsclientservers",
                "network-profile": "get-netipconfiguration",
                "volumes": "get-bitlockervolume",
                "physical-disks": "get-ciminstance-computer",
                "net-users": "get-localuser",
            }
            if command in ps_catalog_map:
                return _json(procmd.powershell_readonly(ps_catalog_map[command]), limit=30000)
            if command == "ciber":
                if not args:
                    return self._ciber(["help"])
                return self._ciber(args)
            if command == "operator-status":
                return _json(operator_dispatch("status", Path.cwd(), []))
            if command == "github-publish":
                return _json(operator_dispatch("github-publish", Path.cwd(), args), limit=24000)
            if command == "vercel-deploy":
                return _json(operator_dispatch("vercel-deploy", Path.cwd(), args), limit=24000)
            if command == "build-exe":
                return _json(operator_dispatch("build-exe", Path.cwd(), args), limit=24000)
            if command == "github":
                try:
                    return _json(github_command(args, Path.cwd()))
                except GitHubTerminalError as exc:
                    return _json({"ok": False, "error": str(exc)})
            if command == "engine-status": return _json(engine_status())
            if command == "av-self-test": return _json(eicar_self_test())
            if command == "yara-scan":
                if not args: raise CommandError("Usage: yara-scan <file>")
                return _json(yara_scan_file(Path(" ".join(args))))
            if command == "sandbox-run":
                if not args: raise CommandError("Usage: sandbox-run <file>")
                return _json(launch_sandbox(Path(" ".join(args)), network=False))
            if command == "threat-check":
                if not args: raise CommandError("Usage: threat-check <file>")
                return _json(analyze_file_deep(Path(" ".join(args)), endpoint_scan=True, reputation=True))
            if command == "url-check":
                if not args: raise CommandError("Usage: url-check <url>")
                return _json(analyze_url(" ".join(args)))
            if command in {"full-audit","deep-audit","entropy-audit","extension-audit","hash-manifest","string-audit","image-audit","screen-audit","duplicate-audit","permission-audit","inventory","quick-audit","headers","macro-audit","script-audit","archive-audit","size-audit","risk-files","sample-audit"}:
                if command != "screen-audit" and not args: raise CommandError(f"Usage: {command} <file|directory>")
                return _json(procmd._extended_audit(command, " ".join(args) if args else None), limit=24000)
            if command == "lab-status":
                return _json({"readiness": assess_dynamic_lab_readiness().__dict__, "host_execution": False, "network_default": "DISABLED", "note": "Untrusted samples must run only in a disposable isolated environment."})
            if command == "status": return self._status()
            if command == "scan": return self._scan(args, deep=False)
            if command == "deep-scan": return self._scan(args, deep=True)
            if command == "host": return self._host()
            if command == "processes": return self._processes(args)
            if command == "network": return self._network(args)
            if command == "services": return self._host_section("services")
            if command == "tasks": return self._host_section("scheduled_tasks")
            if command == "defender": return self._defender_status()
            if command == "hash": return self._hash(args)
            if command == "url": return self._url(args)
            if command == "quarantine": return self._quarantine(args)
            if command == "lab": return self._lab()
            if command == "diagnostics": return self._diagnostics()
            if command == "history": return self._history()
            if command == "incidents": return _json(get_incident_counts())
            if command == "doctor": return _json(doctor(Path.cwd()), limit=24000)
            if command == "safe-repair": return _json(safe_repair(Path.cwd()), limit=12000)
            if command == "performance": return _json(performance(Path.cwd()), limit=24000)
            if command == "clear": return "__CLEAR__"
        except Exception as exc:
            return f"ERROR: {type(exc).__name__}: {exc}"
        return "ERROR: command handler unavailable"

    def _ciber(self, args: list[str]) -> str:
        """Safe natural-language operator with deterministic action routing.

        This is intentionally not a shell. Natural language is mapped only to
        CyberShield allowlisted operations; unknown requests are refused rather
        than guessed into an OS command.
        """
        if not args:
            return (
                "CIBER operator ready — AI operator READY\n"
                "────────────────────────────────────────\n"
                "Natural requests are accepted, but only safe CyberShield actions run.\n\n"
                "Examples:\n"
                "  ciber status\n"
                "  ciber shu loyihani to‘liq tekshir\n"
                "  ciber diagnostika qil\n"
                "  ciber settingsni och\n"
                "  ciber githubga private qilib yubor OWNER/REPO\n"
                "  ciber Vercelga production qilib deploy qil\n"
                "  ciber exe yarat\n"
                "  ciber testlarni ishga tushir\n"
                "  ciber loyihani tekshir\n"
                "  ciber git status\n"
                "  ciber demo\n"
                "  ciber scan suspicious.exe  (multi-engine)\n"
                "  ciber deep-scan C:\\Samples  (bounded multi-engine directory scan)\n"
                "  ciber engine-status  (Defender/ClamAV/YARA/VT availability)\n"
                "  ciber av-self-test  (harmless EICAR validation)\n"
                "  ciber loyiha xaritasini ko‘rsat\n"
                "  ciber <so‘z>ni loyihadan qidir\n"
                "  ciber <faylni> o‘qi\n"
                "  ciber dependencylarni tekshir\n"
                "  ciber help\n\n"
                "SAFETY: arbitrary cmd.exe / PowerShell / eval / shell text is BLOCKED.\n"
                "PASS is reported only after the requested operation is actually verified."
            )
        text = " ".join(args).strip()
        low = text.lower()
        # Safe PowerShell facade: `ciber powershell get-process` is allowed
        # only for a registered read-only template. Arbitrary -Command/-File
        # and expression execution remain blocked below.
        if low.startswith(("powershell ", "powershell.exe ", "pwsh ", "ps ")):
            parts = low.split()
            if len(parts) >= 2:
                ps_key = procmd.POWERSHELL_ALIASES.get(parts[1], parts[1])
                if ps_key in procmd.POWERSHELL_READONLY_COMMANDS:
                    return _json(procmd.powershell_readonly(ps_key), limit=30000)
                return "BLOCKED: only CyberShield allowlisted PowerShell read-only commands are available."
            return "Use `ciber powershell get-process` or `ciber commands`."
        # Safety boundary comes before semantic convenience routing.  A shell
        # invocation must remain blocked even if its payload contains a benign
        # diagnostic word such as "whoami" or "ipconfig".
        if low.startswith(("powershell ", "powershell.exe ", "pwsh ", "cmd ", "cmd.exe ", "shell ", "bash ", "sh ", "python -c ", "python -m")) or "-command" in low:
            return "BLOCKED: arbitrary shell execution is disabled by CyberShield policy."
        if low in {"help", "yordam", "commands", "komandalar", "what can you do", "nima qila olasan", "ciber"}:
            return self._ciber([])
        if low in {"demo", "presentation", "taqdimot", "showcase"}:
            return self._ciber_demo()
        # Explicit actions remain deterministic.
        if low in {"status", "holat", "operator status"} or "operator status" in low:
            return _json(operator_dispatch("status", Path.cwd(), []))
        if any(x in low for x in ("github", "git hub")) and any(x in low for x in ("joyla", "joylash", "yubor", "yukla", "publish", "push", "repo", "repository", "jo‘nat", "jonat")):
            repo = next((a for a in args if ("/" in a or a.startswith(("https://github.com/", "http://github.com/")))), None)
            # A full GitHub repository URL is accepted directly. If omitted,
            # the operator uses CYBERSHIELD_GITHUB_REPO or the project name.
            # Omitted target uses the verified operator default:
            # mu7alovicloud-source/CyberShield (or CYBERSHIELD_GITHUB_REPO).
            if not repo:
                repo = os.environ.get("CYBERSHIELD_GITHUB_REPO", "mu7alovicloud-source/CyberShield")
            return _json(operator_dispatch("github-publish", Path.cwd(), [repo]), limit=24000)
        if "vercel" in low and any(x in low for x in ("deploy", "joyla", "publish", "production")):
            extra = ["production"] if "production" in low else []
            return _json(operator_dispatch("vercel-deploy", Path.cwd(), extra), limit=24000)
        if any(x in low for x in ("exe yarat", "exe qil", "exe build", "build exe", "create exe", "make exe")):
            return _json(operator_dispatch("build-exe", Path.cwd(), []), limit=24000)
        if any(x in low for x in ("testlarni ishga tushir", "testlarni tekshir", "run tests", "run test", "pytest", "testlarni bajar")):
            return self._ciber_run_tests()
        if any(x in low for x in ("git status", "git holat", "o'zgarishlarni ko'rsat", "ozgarishlarni korsat", "changes", "changed files")):
            return _json(operator_dispatch("git-status", Path.cwd(), []), limit=16000)
        if any(x in low for x in ("git diff", "git farq", "o'zgarishlar farqi", "diffni ko'rsat", "diffni korsat")):
            return _json(operator_dispatch("git-diff", Path.cwd(), []), limit=20000)
        if any(x in low for x in ("git log", "git tarix", "commitlar tarixi", "commit history")):
            return _json(operator_dispatch("git-log", Path.cwd(), []), limit=16000)
        if any(x in low for x in ("loyiha xaritasi", "project map", "project tree", "loyiha tuzilmasi")):
            return _json(operator_dispatch("project-map", Path.cwd(), []), limit=24000)
        if any(x in low for x in ("dependencylarni tekshir", "dependenciesni tekshir", "kutubxonalarni tekshir", "bog‘liqliklarni tekshir", "check dependencies")):
            return _json(operator_dispatch("check-dependencies", Path.cwd(), []), limit=16000)
        if any(x in low for x in ("qidir", "qidirib top", "search project", "find in project")):
            # Natural Uzbek forms such as “CyberShield so‘zini loyihadan qidir”
            # are resolved by taking the meaningful phrase before the search verb.
            phrase = low
            for marker in ("loyihadan qidir", "projectdan qidir", "search project", "find in project", "qidirib top", "qidir"):
                if marker in phrase:
                    phrase = phrase.split(marker, 1)[0]
                    break
            phrase = phrase.replace("so‘zini", "").replace("so'zini", "").replace("so‘z", "").strip()
            if phrase.startswith("ciber "):
                phrase = phrase[6:].strip()
            if phrase:
                return _json(operator_dispatch("search-project", Path.cwd(), [phrase]), limit=24000)
        if any(x in low for x in ("faylni o‘qi", "faylini o‘qi", "faylni o'qi", "faylini o'qi", "read file", "open source file")):
            candidates = [a.strip('"') for a in args if ('.' in a or '\\' in a or '/' in a)]
            if candidates:
                return _json(operator_dispatch("read-file", Path.cwd(), [candidates[0]]), limit=30000)
        if any(x in low for x in ("loyihani tekshir", "project audit", "projectni audit", "kodni tekshir", "code audit")):
            return _json(procmd._extended_audit("deep-audit", str(Path.cwd())), limit=24000)
        if any(x in low for x in ("fayllarni ko'rsat", "fayllarni korsat", "project tree", "tree")):
            return _json(procmd.tree(str(Path.cwd()), 3), limit=16000)
        if any(x in low for x in ("python versiya", "python info", "python holati")):
            return _json(procmd.python_info())
        if any(x in low for x in ("diagnostika", "diagnostics", "self test", "self-test")):
            return self._diagnostics()
        if any(x in low for x in ("doctor", "system doctor", "tizimni tekshir", "pro tekshir", "professional diagnostika")):
            return _json(doctor(Path.cwd()), limit=24000)
        if any(x in low for x in ("safe repair", "xavfsiz tuzat", "runtime ni tuzat", "runtime repair")):
            return _json(safe_repair(Path.cwd()), limit=12000)
        if any(x in low for x in ("performance", "unumdorlik", "tezlikni tekshir")):
            return _json(performance(Path.cwd()), limit=24000)
        if any(x in low for x in ("settingsni och", "sozlamalarni och", "sozlamani och", "open settings", "settings och", "настройки")):
            return _json(operator_dispatch("open-panel", Path.cwd(), ["settings"]))
        if any(x in low for x in ("hostname", "kompyuter nomi", "kompyuterning nomi")):
            return _json(procmd.hostname())
        if any(x in low for x in ("whoami", "men kimman", "kimman", "joriy foydalanuvchi")):
            return _json(procmd.whoami())
        if any(x in low for x in ("ipconfig", "ip ma'lumot", "ip malumot", "adapterlar", "tarmoq adapter")):
            return _json(procmd.ipconfig())
        if any(x in low for x in ("route", "routing jadval", "marshrut jadval", "yo'nalish jadvali")):
            return _json(procmd.routes())
        if any(x in low for x in ("arp", "arp jadval")):
            return _json(procmd.arp_table())
        if any(x in low for x in ("netstat", "portlar", "ochiq portlar", "socketlar", "ulanishlar ro'yxati")):
            return _json(procmd.netstat())
        if any(x in low for x in ("tasklist", "process list", "jarayonlar ro'yxati", "processlarni ko'rsat")):
            return _json(procmd.tasklist())
        if any(x in low for x in ("driverlar", "drayverlar", "drivers")):
            return _json(procmd.drivers())
        if any(x in low for x in ("firewall holati", "firewall status", "brandmauer", "xavfsizlik devori")):
            return _json(procmd.firewall_status())
        ps_map = {
            "powershell process": "get-process", "powershell processes": "get-process", "ps processes": "get-process",
            "powershell service": "get-service", "powershell services": "get-service", "ps services": "get-service",
            "powershell network": "get-netadapter", "powershell adapter": "get-netadapter",
            "powershell tcp": "get-nettcpconnection", "powershell udp": "get-netudpendpoint",
            "powershell dns": "get-dnsclientservers", "powershell routes": "get-netroute",
            "powershell firewall": "get-firewallprofile", "powershell defender": "get-mpcomputerstatus",
            "powershell threats": "get-mpthreatdetection", "powershell tasks": "get-scheduledtask",
            "powershell hotfix": "get-hotfix", "powershell computer": "get-computerinfo",
            "powershell os": "get-ciminstance-os", "powershell hardware": "get-ciminstance-computer",
            "powershell startup": "get-startupapps", "security events": "get-eventlog-security",
            "system events": "get-eventlog-system", "application events": "get-eventlog-application",
        }
        for phrase, ps_command in ps_map.items():
            if phrase in low:
                return _json(procmd.powershell_readonly(ps_command), limit=30000)
        if any(x in low for x in ("status", "holat", "himoya ishlayaptimi", "protection status")):
            return self._status()
        # Delegate known desktop actions to the same allowlist used by the GUI.
        from app.ai.desktop_actions import execute_desktop_request
        desktop = execute_desktop_request(getattr(self, "desktop_controller", None), text)
        if desktop is not None:
            return _json({"ok": desktop.ok, "action": desktop.action, "message": desktop.message, "data": desktop.data})
        # Useful analysis requests are routed to existing bounded scanners.
        if any(x in low for x in ("to‘liq tekshir", "to'liq tekshir", "toliq tekshir", "full audit", "deep audit", "chuqur tekshir", "analyse", "analyze", "analiz")):
            if args and args[0].lower() in {"analyze", "analyse"}:
                candidate = " ".join(args[1:]).strip()
            else:
                candidate = " ".join(args[1:]).strip() if len(args) > 1 else ""
            candidate_path = Path(candidate).expanduser() if candidate else None
            if candidate_path and (candidate_path.exists() or candidate.startswith(("C:\\", "D:\\", "E:\\", "/", "\\"))):
                target = candidate
            else:
                target = str(Path.cwd())
            return _json(procmd._extended_audit("deep-audit", target), limit=24000)
        if low.startswith(("powershell ", "cmd ", "cmd.exe ", "shell ", "bash ", "python -c ", "python -m")) or "-command" in low:
            return "BLOCKED: arbitrary shell execution is disabled by CyberShield policy."
        # Generic questions are answered by the existing grounded LLM gateway when configured.
        # It is answer-only here: it cannot authorize tools or OS execution.
        if any(x in low for x in ("nima", "nega", "qanday", "tushuntir", "what", "why", "how", "explain", "объясни")):
            try:
                from app.ai.llm_provider import LLMProvider
                provider = LLMProvider()
                if provider.available():
                    system = (
                        "You are CyberShield CIBER, a defensive AI assistant. Answer the user's question clearly. "
                        "Do not claim to have executed actions. Do not invent local system facts. "
                        "For security topics, provide defensive guidance and refuse harmful operational abuse. "
                        "Never output shell commands intended to bypass CyberShield's safety boundary."
                    )
                    result = provider.ask(system, text)
                    if result.ok and result.text.strip():
                        return result.text.strip()
            except Exception:
                pass
        return ("CIBER: vazifani xavfsiz actionga aylantira olmadim.\n"
                "Sinab ko‘ring: `ciber help`, `ciber loyiha tekshir`, `ciber testlarni ishga tushir`, "
                "`ciber githubga yubor`, `ciber vercelga deploy qil`, `ciber exe yarat`.\n"
                "Men noma’lum OS buyruqlarini taxmin qilib bajarmayman.")

    def _ciber_run_tests(self) -> str:
        """Run the project's test suite through the bounded operator, never a shell string."""
        from app.ai.ciber_operator import run_project_tests
        return _json(run_project_tests(Path.cwd()), limit=24000)

    def _ciber_demo(self) -> str:
        """Safe presentation-mode health showcase; no destructive actions."""
        import platform
        diag = run_self_diagnostics()
        ops = operator_dispatch("status", Path.cwd(), [])
        return _json({
            "showcase": "CyberShield CIBER",
            "mode": "DEFENSIVE / VERIFIED",
            "platform": platform.platform(),
            "engine": "ONLINE",
            "diagnostics": diag.as_dict(),
            "operator_tools": ops,
            "safe_execution": {
                "arbitrary_shell": "BLOCKED",
                "host_malware_execution": "BLOCKED",
                "quarantine_confirmation": "REQUIRED",
                "deployment_pass": "VERIFICATION_REQUIRED",
            },
            "capabilities": [
                "AI operator terminal", "multi-layer file analysis",
                "phishing analysis", "process/network telemetry",
                "GitHub/Vercel operator", "verified EXE creation",
                "Safe Lab readiness", "self diagnostics"
            ]
        }, limit=24000)

    def _professional_help_catalog(self) -> str:
        """Render the complete professional defensive command catalog.

        The project already ships a large allowlist; help previously showed
        only a small subset. Keep the catalog generated from the same source
        used by command validation so the count and names cannot drift.
        """
        rows = procmd.command_reference()
        groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            category = str(row.get("category") or "other").upper()
            groups.setdefault(category, []).append(row)
        out = [f"CIBER SECURITY COMMAND CATALOG — {len(rows)} commands"]
        for category in sorted(groups):
            out.append(f"\n[{category}]")
            for row in sorted(groups[category], key=lambda x: str(x.get("name", ""))):
                name = str(row.get("name", ""))
                usage = str(row.get("usage", name))
                summary = str(row.get("summary", ""))
                out.append(f"  {usage:<34} — {summary}")
        out.append("\nTip: `commands` shows aliases; `commands-by-category <category>` filters the catalog.")
        return "\n".join(out)

    def _commands(self) -> str:
        """List every registered command and its aliases.

        This is only a static allowlist view; it never executes OS commands.
        """
        rows = []
        for command, aliases in ALIASES.items():
            rows.append(f"{command:14} : {', '.join(sorted(aliases))}")
        professional = []
        for spec in procmd.command_reference():
            professional.append(f"{spec['name']:18} | {spec.get('category','-'):11} | {spec.get('summary','')}")
        return (
            "Registered CyberShield commands (safe allowlist):\n"
            + "\n".join(rows)
            + "\n\nProfessional command catalog:\n"
            + "\n".join(professional)
            + "\n\nSafety policy:\n"
            + _json(procmd.safety_policy())
        )

    def _scan(self, args: list[str], deep: bool) -> str:
        if not args:
            raise CommandError("Usage: scan <file|directory>")
        clean_args = [a for a in args if a != "--static"]
        if not clean_args:
            raise CommandError("Usage: scan <file|directory> [--static]")
        target = Path(" ".join(clean_args)).expanduser()
        if not target.exists():
            raise FileNotFoundError(str(target))
        if target.is_dir():
            if not deep:
                rows = scan_directory(target, limit=500)
                risky = sorted(rows, key=lambda x: int(x.get("risk", 0)), reverse=True)
                return _json({"target": str(target.resolve()), "mode": "STATIC", "files_scanned": len(rows), "top_risks": risky[:20]})
            # Full multi-engine directory mode is deliberately bounded.
            # Each selected file is passed through Defender/ClamAV/YARA/VT as
            # available; no sample is executed by CyberShield.
            # Defender scans the whole requested directory itself. This is the
            # primary real-antivirus pass; static analysis is used for explainable
            # per-file evidence and does not decide which files Defender sees.
            from app.security.defender_scan import scan_file_with_defender
            defender_result = scan_file_with_defender(target, timeout=900)
            static_rows = scan_directory(target, limit=5000)
            selected = sorted(static_rows, key=lambda x: int(x.get("risk", 0)), reverse=True)[:200]
            # Run independent file analyses in a bounded pool. The terminal
            # itself is already on a worker thread, and this prevents a large
            # directory scan from looking frozen while Defender/ClamAV/YARA
            # work through files sequentially.
            from concurrent.futures import ThreadPoolExecutor, as_completed
            workers = min(4, max(1, (os.cpu_count() or 4) // 2))
            results = []
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="CyberShieldDeepScan") as pool:
                futures = {
                    pool.submit(analyze_file_deep, row["path"], endpoint_scan=True, reputation=True): row["path"]
                    for row in selected
                }
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except (OSError, PermissionError, ValueError):
                        continue
            results.sort(key=lambda x: int(x.get("risk", 0)), reverse=True)
            return _json({
                "target": str(target.resolve()),
                "mode": "DEEP_MULTI_ENGINE",
                "files_scanned": len(results),
                "files_selected": len(selected),
                "workers": workers,
                "top_risks": results[:30],
                "engines": engine_status(),
                "defender_directory_scan": defender_result,
                "execution_performed": False,
            }, limit=30000)
        # A single-file scan uses the real multi-engine stack by default.
        # Use --static only when a parser-only result is explicitly requested.
        static_only = "--static" in args
        result = analyze_file(target) if static_only else analyze_file_deep(target, endpoint_scan=True, reputation=True)
        add_scan(result["path"], result["sha256"], result.get("risk", 0), result.get("verdict", "UNKNOWN"), result.get("evidence", []))
        add_audit("terminal_scan", result["path"], result.get("verdict"), {"deep": deep, "risk": result.get("risk", 0)})
        summary = {k: result.get(k) for k in ("path", "size", "sha256", "risk", "verdict", "confidence", "signature_status", "execution_performed")}
        summary["size_human"] = _fmt_bytes(int(result.get("size", 0)))
        summary["evidence"] = result.get("evidence", result.get("indicators", []))[:30]
        return _json(summary)

    def _hash(self, args: list[str]) -> str:
        if not args: raise CommandError("Usage: hash <file>")
        p = Path(" ".join(args)).expanduser().resolve()
        result = analyze_file(p)
        return _json({"file": str(p), "sha256": result["sha256"], "sha1": result["sha1"], "md5": result["md5"], "size": result["size"]})

    def _url(self, args: list[str]) -> str:
        if not args: raise CommandError("Usage: url <https://example.com/>")
        url = " ".join(args).strip()
        result = analyze_url_deep(url, reputation=True)
        add_url_scan(url, result.get("score", result.get("risk", 0)), result.get("verdict", "UNKNOWN"), result.get("confidence", 0.0), result.get("reasons", []))
        add_audit("terminal_url_analysis", url, result.get("verdict"), {"network_request_performed": result.get("network_request_performed", False)})
        return _json(result)

    def _host(self) -> str:
        return _json(inspect_host())

    def _host_section(self, key: str) -> str:
        return _json(inspect_host().get(key, {}))

    def _processes(self, args: list[str]) -> str:
        limit = 30
        if args:
            try: limit = max(1, min(200, int(args[0])))
            except ValueError: pass
        return _json(get_processes(limit))

    def _network(self, args: list[str]) -> str:
        return _json({"local": get_local_network_info(), "connections": get_connections(100)})

    def _defender_status(self) -> str:
        host = inspect_host().get("security_products", {})
        return _json(host)

    def _quarantine(self, args: list[str]) -> str:
        if not args: raise CommandError("Usage: quarantine <file> --confirm")
        if "--confirm" not in args:
            return "CONFIRMATION REQUIRED: quarantine is reversible but moves the original file. Re-run with --confirm."
        clean = [a for a in args if a != "--confirm"]
        p = Path(" ".join(clean)).expanduser().resolve()
        dst = quarantine_file(p)
        add_audit("terminal_quarantine", str(p), "completed", {"quarantine_path": str(dst)})
        return _json({"status": "QUARANTINED", "original": str(p), "quarantine": str(dst), "reversible": True})

    def _lab(self) -> str:
        d = assess_dynamic_lab_readiness()
        return _json({"status": d.status, "message": d.message, "actions": d.actions, "host_execution": "BLOCKED"})

    def _diagnostics(self) -> str:
        return _json(run_self_diagnostics().as_dict())

    def _history(self) -> str:
        return "\n".join(f"{i+1:02d}  {v}" for i, v in enumerate(self.history[-30:])) or "No history"

    def _status(self) -> str:
        diag = run_self_diagnostics()
        return _json({
            "engine": "ONLINE",
            "mode": "DEFENSIVE",
            "host_execution": "BLOCKED",
            "terminal": "READY",
            "diagnostics_ok": diag.ok,
            "failed_modules": list(diag.failed),
            "open_incidents": get_incident_counts(),
            "recent_scans": get_recent_scans(5),
            "recent_urls": get_recent_url_scans(5),
            "hostname": socket.gethostname(),
        })

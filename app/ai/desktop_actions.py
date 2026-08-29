"""Bounded desktop-control layer for CyberShield AI.

Only explicit, allowlisted UI navigation/settings actions are supported.
No shell, eval, arbitrary command execution, or executable launching is used.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass
class DesktopActionResult:
    ok: bool
    action: str
    message: str
    data: dict[str, Any] | None = None


class DesktopController(Protocol):
    def open_panel(self, name: str) -> bool: ...
    def set_setting(self, name: str, value: bool) -> bool: ...
    def open_safe_path(self, path: str) -> bool: ...


PANEL_ALIASES = {
    "home": "Command Center", "dashboard": "Command Center", "bosh sahifa": "Command Center",
    "ai": "AI Security Copilot", "copilot": "AI Security Copilot", "ai copilot": "AI Security Copilot",
    "monitoring": "Live Monitoring", "monitor": "Live Monitoring", "live monitoring": "Live Monitoring",
    "incidents": "Incidents", "incident": "Incidents",
    "malware": "Malware Lab", "malware lab": "Malware Lab",
    "neutralizer": "AI Virus Neutralizer", "virus neutralizer": "AI Virus Neutralizer",
    "phishing": "Phishing Analyzer", "phishing analyzer": "Phishing Analyzer",
    "sandbox": "Sandbox", "forensics": "Forensics", "forensic": "Forensics",
    "settings": "Settings", "sozlamalar": "Settings", "настройки": "Settings",
    "terminal": "AI Security Copilot", "security terminal": "AI Security Copilot",
}

SETTING_ALIASES = {
    "protection": "protection", "himoya": "protection", "protection engine": "protection",
    "himoya tizimi": "protection", "auto incident": "auto_incident",
    "automatic incidents": "auto_incident", "incident": "auto_incident",
}


def parse_desktop_request(text: str) -> tuple[str, dict[str, Any]] | None:
    q = " ".join((text or "").strip().lower().split())
    if not q:
        return None

    # Open/navigate to a known CyberShield page.
    open_markers = ("och", "ochib ber", "ochib qo‘y", "open", "show", "ko‘rsat", "покажи", "открой")
    for alias, panel in sorted(PANEL_ALIASES.items(), key=lambda x: -len(x[0])):
        if alias in q and any(m in q for m in open_markers):
            return "open_panel", {"name": panel}

    # Settings changes. Enabling is safe and reversible; disabling protection is
    # deliberately rejected by the UI controller unless explicitly confirmed.
    enable = any(x in q for x in ("yoq", "yoqib", "yoqilsin", "enable", "turn on", "включи"))
    disable = any(x in q for x in ("o‘chir", "ochir", "o'chir", "disable", "turn off", "выключи"))
    for alias, setting in SETTING_ALIASES.items():
        if alias in q and (enable or disable):
            return "set_setting", {"name": setting, "value": bool(enable), "requested_disable": disable}

    # Safe open of an existing non-executable file/folder when the user names it.
    # The controller enforces extension/path policy; no shell command is built.
    if any(x in q for x in ("faylni och", "papkani och", "open file", "open folder", "открой файл", "открой папку")):
        # The actual path extraction is intentionally conservative.
        for raw in (text or "").replace('"', ' ').split():
            p = Path(raw.strip())
            if p.exists():
                return "open_safe_path", {"path": str(p)}
    return None


def execute_desktop_request(controller: DesktopController | None, text: str) -> DesktopActionResult | None:
    parsed = parse_desktop_request(text)
    if parsed is None:
        return None
    action, args = parsed
    if controller is None:
        return DesktopActionResult(False, action, "Desktop controller is not connected yet.")
    try:
        if action == "open_panel":
            ok = controller.open_panel(args["name"])
            return DesktopActionResult(ok, action, f"Panel opened: {args['name']}" if ok else f"Panel not found: {args['name']}")
        if action == "set_setting":
            if args.get("requested_disable"):
                return DesktopActionResult(False, action, "Protectionni AI o‘zi o‘chirib qo‘ymaydi. Buni Settings panelidan tasdiqlash kerak.")
            ok = controller.set_setting(args["name"], bool(args["value"]))
            state = "ON" if args["value"] else "OFF"
            return DesktopActionResult(ok, action, f"Setting updated: {args['name']}={state}" if ok else "Setting could not be changed.")
        if action == "open_safe_path":
            ok = controller.open_safe_path(args["path"])
            return DesktopActionResult(ok, action, f"Opened: {args['path']}" if ok else "Path blocked by desktop safety policy.")
    except Exception as exc:
        return DesktopActionResult(False, action, f"Desktop action failed safely: {type(exc).__name__}: {exc}")
    return None

"""Restricted CyberShield Security Console language.
Only defensive application operations are accepted; host shell commands are rejected.
"""
import shlex

COMMANDS = {"SCAN", "ANALYZE", "INSPECT", "TRACE", "TREE", "QUARANTINE", "INCIDENT", "EVIDENCE", "EXPLAIN", "VERIFY", "CONTAIN", "STATUS", "HELP", "CLEAR"}
BLOCKED = {"CMD", "POWERSHELL", "RM", "DEL", "FORMAT", "CURL", "WGET", "SH", "BASH", "EXEC", "SHELL"}


def parse(command: str, language: str = "en") -> dict:
    tokens = shlex.split(command or "")
    if not tokens:
        return {"ok": True, "command": "", "args": []}
    name = tokens[0].upper()
    if name in BLOCKED or name not in COMMANDS:
        messages = {"ru": "Разрешены только защитные команды CyberShield.", "uz": "Faqat CyberShield himoya buyruqlariga ruxsat berilgan.", "en": "Only defensive CyberShield commands are allowed."}
        return {"ok": False, "error": messages.get(str(language).lower(), messages["en"])}
    return {"ok": True, "command": name, "args": tokens[1:]}

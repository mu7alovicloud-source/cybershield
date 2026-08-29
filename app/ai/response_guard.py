"""Output guard for optional LLM responses.

The language model may explain and answer questions, but it cannot authorize
or emit arbitrary OS commands. Security decisions remain in deterministic
CyberShield components.
"""
from __future__ import annotations
import re

DANGEROUS_COMMAND_RE = re.compile(r"(?:powershell|cmd\.exe|bash|rm\s+-rf|del\s+/f|format\s+|invoke-webrequest|downloadstring|certutil|reg\s+add)", re.I)


def sanitize(text: str, *, max_chars: int = 8000) -> str:
    text = (text or "").strip()
    text = text[:max_chars]
    # Prevent a language model from accidentally turning an answer into an
    # executable-looking instruction block in the security UI.
    text = DANGEROUS_COMMAND_RE.sub("[command omitted by safety policy]", text)
    return text

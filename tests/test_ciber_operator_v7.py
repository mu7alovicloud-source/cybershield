from pathlib import Path
from app.ai.ciber_operator import operator_status
from app.ai.cybershield_terminal import CyberShieldTerminal

def test_ciber_alias_and_help():
    t=CyberShieldTerminal("en")
    out=t.execute("ciber help")
    assert "CIBER operator ready" in out

def test_operator_status():
    s=operator_status(Path.cwd())
    assert "git" in s and "gh" in s and "vercel" in s and "pyinstaller" in s

def test_arbitrary_shell_stays_blocked():
    t=CyberShieldTerminal("en")
    out=t.execute("ciber powershell -Command whoami")
    assert "BLOCKED" in out

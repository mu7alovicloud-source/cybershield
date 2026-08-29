from pathlib import Path

def test_terminal_import_and_allowlist():
    from app.ai.cybershield_terminal import CyberShieldTerminal
    t = CyberShieldTerminal()
    assert "CyberShield" in t.help_text()
    assert "tekshir" in t.help_text()
    out = t.execute("command-not-allowed")
    assert "BLOCKED" in out

def test_quarantine_compatibility_import():
    from app.security.quarantine import Quarantine, quarantine_file
    assert callable(quarantine_file)
    assert hasattr(Quarantine(), "quarantine")

def test_process_monitor_compatibility_import():
    from app.security.process_monitor import ProcessMonitor, get_processes
    assert callable(get_processes)
    assert hasattr(ProcessMonitor(), "snapshot")

def test_root_terminal_entrypoint_does_not_fall_through():
    text = Path("main.py").read_text(encoding="utf-8")
    assert 'return 0' in text
    assert 'security-terminal' in text

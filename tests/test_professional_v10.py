from pathlib import Path
from app.ai.cybershield_terminal import CyberShieldTerminal
from app.security.professional_health import doctor, safe_repair, performance


def test_professional_commands_registered():
    t = CyberShieldTerminal("en")
    for cmd in ("doctor", "safe-repair", "performance"):
        assert cmd in t.help_text() or cmd in t._commands()


def test_doctor_is_non_destructive():
    result = doctor(Path.cwd())
    assert "core_modules" in result
    assert result["policy"].startswith("read-only")


def test_safe_repair_does_not_delete_or_modify_source():
    result = safe_repair(Path.cwd())
    assert result["ok"] is True
    assert result["deleted_files"] is False
    assert result["changed_source"] is False
    assert result["changed_windows_security"] is False


def test_performance_is_bounded():
    result = performance(Path.cwd())
    assert result["bounded_analysis_policy"]["max_parallel_workers"] == 8
    assert result["bounded_analysis_policy"]["target_execution"] == "BLOCKED"

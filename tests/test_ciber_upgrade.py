from app.ai.cybershield_terminal import CyberShieldTerminal
from app.ai import pro_terminal_commands as procmd


def test_professional_windows_and_powershell_packs_are_registered():
    specs = {row["name"] for row in procmd.command_reference()}
    for name in {
        "defender-status", "defender-threats", "firewall-rules", "listening-ports",
        "dns-cache", "network-profile", "volumes", "physical-disks", "net-users",
    }:
        assert name in specs


def test_commands_category_filter_is_deterministic():
    term = CyberShieldTerminal("en")
    out = term.execute("commands-by-category powershell")
    assert "get-process" in out
    assert "powershell" in out.lower()


def test_arbitrary_shell_is_still_blocked():
    term = CyberShieldTerminal("en")
    out = term.execute("powershell -Command whoami")
    assert "BLOCKED" in out

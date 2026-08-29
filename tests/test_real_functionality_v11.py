from pathlib import Path
import hashlib

from app.ai.cybershield_terminal import CyberShieldTerminal
from app.security.scanner import analyze_file
from app.security.quarantine import quarantine_file


def test_static_scanner_hash_is_full_file(tmp_path):
    p = tmp_path / "sample.bin"
    data = (b"CYBERSHIELD-TEST\x00" * 50000)
    p.write_bytes(data)
    r = analyze_file(p)
    assert r["sha256"] == hashlib.sha256(data).hexdigest()
    assert r["sha1"] == hashlib.sha1(data).hexdigest()
    assert r["md5"] == hashlib.md5(data).hexdigest()
    assert r["static_only"] is True
    assert r["execution_performed"] is False


def test_quarantine_preserves_bytes_and_is_reversible_metadata(tmp_path, monkeypatch):
    import app.security.quarantine as q
    vault = tmp_path / "vault"
    monkeypatch.setattr(q, "QUARANTINE_DIR", vault)
    p = tmp_path / "sample.exe"
    data = b"safe test sample bytes"
    p.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    dst = q.quarantine_file(p)
    assert not p.exists()
    assert dst.exists()
    assert dst.read_bytes() == data
    assert hashlib.sha256(dst.read_bytes()).hexdigest() == digest
    meta = Path(str(dst) + ".json")
    assert meta.exists()


def test_terminal_real_security_commands_do_not_shell_out():
    t = CyberShieldTerminal("en")
    assert "help" in t.help_text().lower()
    assert "BLOCKED" in t.execute("powershell -Command whoami")


def test_eicar_marker_is_detected_without_execution(tmp_path):
    from app.security.scanner import analyze_file
    p = tmp_path / "eicar.txt"
    p.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    result = analyze_file(p)
    assert result["verdict"] in {"MALICIOUS", "LIKELY MALICIOUS"}
    assert any(e["code"] == "EICAR_TEST" for e in result["evidence"])
    assert result["execution_performed"] is False

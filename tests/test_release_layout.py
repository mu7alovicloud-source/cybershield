from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_canonical_desktop_entrypoint_exists():
    assert (ROOT / "main.py").exists()
    assert (ROOT / "app" / "main.py").exists()

def test_legacy_server_entrypoint_is_removed():
    assert not (ROOT / "server" / "main.py").exists()

def test_vercel_health_api_exists():
    text = (ROOT / "api" / "index.py").read_text(encoding="utf-8")
    assert "FastAPI" in text
    assert '@app.get("/api/health")' in text
    assert '@app.get("/api/version")' in text

def test_no_runtime_state_is_tracked_by_gitignore():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for item in ("data/cybershield.db", "data/logs/*", "data/quarantine/*", "data/samples/*"):
        assert item in text

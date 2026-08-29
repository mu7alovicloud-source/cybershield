from pathlib import Path


def test_ciber_self_reference_returns_help():
    from app.ai.cybershield_terminal import CyberShieldTerminal
    out = CyberShieldTerminal('uz').execute('ciber ciber')
    assert 'CIBER operator ready' in out


def test_github_publish_missing_gh_does_not_bootstrap_local_repo(tmp_path, monkeypatch):
    from app.ai.ciber_operator import github_publish
    monkeypatch.setattr('shutil.which', lambda name: None if name in {'gh'} else '/usr/bin/' + name)
    before = sorted(p.name for p in tmp_path.iterdir())
    result = github_publish(tmp_path)
    after = sorted(p.name for p in tmp_path.iterdir())
    assert result['ok'] is False
    assert result['passed_strategy'] is None
    assert before == after


def test_settings_is_allowlisted():
    from app.ai.ciber_operator import open_cybershield_panel
    result = open_cybershield_panel(Path.cwd(), 'not-a-real-panel')
    assert result['ok'] is False

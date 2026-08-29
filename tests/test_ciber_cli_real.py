from pathlib import Path


def test_ciber_cli_module_and_icon():
    from app.ai.ciber_cli import ICON, animate_start
    assert ICON.exists()
    assert callable(animate_start)


def test_root_ciber_command_files_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / "ciber.cmd").exists()
    assert (root / "INSTALL_CIBER.bat").exists()


def test_ciber_entrypoint_mode_is_distinct_from_desktop():
    import main
    # The direct argv form used by ciber.cmd must enter the CIBER sub-mode.
    text = Path(main.__file__).read_text(encoding="utf-8")
    assert '"ciber", "cyber", "ciber-terminal"' in text
    assert "_run_ciber_mode(term)" in text


def test_ciber_branding_uses_shipped_ico():
    from app.ai.ciber_cli import ICON, _icon_pixels
    assert ICON.suffix.lower() == ".ico"
    assert ICON.exists()
    # Pixel rendering is optional if Pillow is absent, but the asset itself is mandatory.
    pixels = _icon_pixels()
    if pixels is not None:
        assert len(pixels) > 0 and len(pixels[0]) > 0

def test_rotating_ico_frames_are_renderable():
    from app.ai.ciber_cli import _icon_pixels, _logo_frame
    frames = [_icon_pixels(24, 12, angle) for angle in (0, 45, 90, 135, 180)]
    assert all(frame for frame in frames)
    assert all(_logo_frame(frame, i) for i, frame in enumerate(frames))


def test_ciber_professional_project_actions():
    from app.ai.cybershield_terminal import CyberShieldTerminal
    t = CyberShieldTerminal("uz")
    assert "project" in t.execute("ciber loyiha xaritasini ko‘rsat").lower()
    assert "dependencies" in t.execute("ciber dependencylarni tekshir").lower()
    assert not t.execute("ciber powershell -Command whoami").startswith("ERROR:")


def test_ciber_animator_is_non_blocking_and_cached():
    from app.ai.ciber_cli import CiberShieldAnimator
    animator = CiberShieldAnimator(width=20, height=12, fps=30)
    assert animator.fps == 30
    animator.start()
    animator.stop()
    assert animator.thread is None
    if animator.frames:
        assert len(animator.frames) > 1

"""Single entry point for the standalone CyberShield Desktop edition."""
from __future__ import annotations

import sys
import threading
import time




def _run_live(term, command: str):
    """Execute one bounded CyberShield action while the branded spinner runs.

    The worker owns the real operation; the main thread only paints the UI.
    This prevents long scans/deployments/tests from freezing the terminal
    animation. Existing operator timeouts remain the hard execution bounds.
    """
    from app.ai.ciber_cli import live_thinking
    stop = threading.Event()
    result = {"value": None}
    started = time.monotonic()

    def worker():
        try:
            result["value"] = term.execute(command)
        except BaseException as exc:
            result["value"] = f"ERROR: {type(exc).__name__}: {exc}"
        finally:
            stop.set()

    thread = threading.Thread(target=worker, name="ciber-action", daemon=True)
    thread.start()
    live_thinking("CIBER working", stop, started)
    thread.join()
    return result["value"] or ""


def _ciber_banner() -> None:
    from app.ai.ciber_cli import animate_start
    animate_start()


def _run_ciber_mode_once(term, line: str) -> str:
    from app.ai.ciber_cli import thinking_animation
    out = _run_live(term, "ciber " + line.strip())
    if out == "__CLEAR__":
        return ""
    return out


def _run_ciber_mode(term, initial: str | None = None) -> None:
    _ciber_banner()
    from app.ai.ciber_cli import (
        CiberShieldAnimator,
        _ansi_supported,
        _TERMINAL_WRITE_LOCK,
        GREEN, CYAN, YELLOW, RESET,
    )

    # animate_start() already renders the shell header once. Do not clear and
    # redraw it here: doing so caused the CIBER banner to appear 2–3 times in
    # Windows CMD. Only reserve the hero area below the existing header.
    if _ansi_supported():
        with _TERMINAL_WRITE_LOCK:
            for _ in range(13):
                sys.stdout.write("\x1b[2K\n")
            sys.stdout.write(
                f"{GREEN}● ONLINE{RESET}   "
                f"CIBER secure operator  |  type {CYAN}help{RESET} for commands  |  "
                f"{YELLOW}exit{RESET} stops animation\n"
            )
            sys.stdout.flush()

    animator = CiberShieldAnimator(width=44, height=24, fps=30)
    animator.start()
    try:
        if initial:
            out = _run_ciber_mode_once(term, initial)
            if out:
                print(out)
        while True:
            try:
                from app.ai.ciber_cli import ciber_prompt
                line = input(ciber_prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if line.lower() in {"exit", "quit", "back", "ortga", "chiqish"}:
                return
            if not line:
                continue
            out = _run_live(term, "ciber " + line)
            if out == "__CLEAR__":
                print("\033[2J\033[H", end="")
            elif out:
                print(out)
    finally:
        animator.stop()


def _run_desktop(panel: str | None = None) -> int:
    from app.main import main
    main(initial_panel=panel)
    return 0


if __name__ == "__main__":
    mode = (sys.argv[1] if len(sys.argv) > 1 else "desktop").strip().lower()
    if mode in {"desktop", "cibershield", "cybershield"}:
        panel = None
        if "--panel" in sys.argv:
            i = sys.argv.index("--panel")
            if i + 1 < len(sys.argv):
                panel = sys.argv[i + 1]
        raise SystemExit(_run_desktop(panel))
    if mode == "ciber":
        from app.ai.cybershield_terminal import CyberShieldTerminal
        term = CyberShieldTerminal()
        initial = " ".join(sys.argv[2:]).strip()
        _run_ciber_mode(term, initial or None)
        raise SystemExit(0)
    if mode in {"terminal", "security-terminal", "security_terminal"}:
        from app.ai.cybershield_terminal import CyberShieldTerminal
        term = CyberShieldTerminal()
        command = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else None
        # `python main.py terminal ciber` and the installed `ciber` command
        # both enter the interactive AI sub-mode.  CIBER is not the desktop
        # launcher.  An optional trailing command is executed once inside the
        # same safe operator and then the session remains available.
        if command and command.strip().lower().split()[0] in {"ciber", "cyber", "ciber-terminal"}:
            remainder = command.strip().split(maxsplit=1)
            if len(remainder) > 1:
                print(_run_ciber_mode_once(term, remainder[1]))
            _run_ciber_mode(term)
            raise SystemExit(0)
        if command:
            print(term.execute(command))
        else:
            print(term.help_text())
            while True:
                try:
                    line = input("CyberShield> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if line.lower() in {"exit", "quit", "chiqish", "выход"}:
                    break
                if line.lower() in {"ciber", "ciber mode", "ciber-mode"}:
                    _run_ciber_mode(term)
                    continue
                out = term.execute(line)
                if out == "__CLEAR__":
                    print("\033[2J\033[H", end="")
                elif out:
                    print(out)
        raise SystemExit(0)
    if mode == "background":
        from app.security.background_guard import BackgroundProtection
        guard = BackgroundProtection()
        guard.start()
        print("CyberShield background protection started. Press Ctrl+C to stop.")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            try:
                guard.stop()
            except Exception:
                pass
            raise SystemExit(0)
    print("CyberShield Desktop")
    print("Usage: cibershield [desktop|terminal|ciber]")
    raise SystemExit(2)

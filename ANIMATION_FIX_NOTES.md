# CIBER Animation Fix

- Shield animation is now non-blocking and runs in a daemon worker thread.
- ICO source is loaded once and rendered frames are cached.
- Runtime animation uses cached 12-degree frames at 30 FPS.
- One complete Y-axis turn takes about 1.2 seconds.
- The shield remains in a fixed terminal area and keeps rotating until `exit`, `quit`, `back`, `ortga`, or `chiqish`.
- Cursor save/restore and absolute row painting prevent the animation from overwriting the prompt.
- The prompt is no longer printed twice.
- Non-ANSI terminals cleanly fall back to a static prompt.

Verification performed:
- `python -m py_compile app/ai/ciber_cli.py main.py`
- `python -m compileall -q .`
- `PYTHONPATH=. pytest -q` -> 28 passed
- PTY smoke test with `python main.py ciber` + `exit` -> exit code 0, no stderr

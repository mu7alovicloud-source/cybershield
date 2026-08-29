"""Windows bootstrapper for CyberShield.

Terminal mode installs only dependencies required by the terminal.
YARA is optional because yara-python may require a local C/C++ toolchain
on Python versions without a compatible prebuilt wheel. The application
already handles YARA being absent gracefully.
"""
from __future__ import annotations
import importlib.util
import subprocess
import sys

TERMINAL = {
    "psutil": "psutil>=6.0",
    "watchdog": "watchdog>=4.0",
    "PIL": "Pillow>=10.4",
}
DESKTOP = {"PySide6": "PySide6>=6.8,<7"}
OPTIONAL = {"yara": "yara-python>=4.5.0"}

def _install(missing: list[str]) -> None:
    if not missing:
        return
    subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])

def ensure(desktop: bool = False) -> None:
    wanted = dict(TERMINAL)
    if desktop:
        wanted.update(DESKTOP)

    missing = [pkg for mod, pkg in wanted.items()
               if importlib.util.find_spec(mod) is None]
    if missing:
        print("[CyberShield] Missing required dependencies:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("[CyberShield] Installing required dependencies...\n")
        _install(missing)

    if importlib.util.find_spec("yara") is None:
        print("[CyberShield] YARA engine: optional / not installed")
        print("[CyberShield] CIBER will continue with built-in static and heuristic checks.")

if __name__ == "__main__":
    ensure("--desktop" in sys.argv)

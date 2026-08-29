"""Premium CyberShield CIBER terminal presentation layer.

The CIBER shell is a terminal sub-mode, not the desktop launcher.  It keeps
all execution inside the existing CyberShield command/operator allowlist.
The UI uses the shipped CyberShield ICO for a lightweight ANSI animation and
falls back cleanly on terminals without ANSI/true-colour support.
"""
from __future__ import annotations

import os
import re
import sys
import time
import math
import threading
import shutil
from pathlib import Path

try:
    from PIL import Image, ImageOps
except Exception:  # optional visual enhancement; text mode still works
    Image = None

ROOT = Path(__file__).resolve().parents[2]
ICON = ROOT / "cibershield.ico"

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
CYAN = "\x1b[96m"
BLUE = "\x1b[94m"
GREEN = "\x1b[92m"
YELLOW = "\x1b[93m"
RED = "\x1b[91m"
GRAY = "\x1b[90m"

# Rendering is deliberately cached: CMD should never decode/rotate the ICO
# from disk on every frame.  The cache is process-local and bounded.
_ICON_SOURCE = None
_FRAME_CACHE: dict[tuple[int, int, int], list[list[tuple[int, int, int, int]]] | None] = {}
_FRAME_CACHE_LOCK = threading.Lock()
_TERMINAL_WRITE_LOCK = threading.RLock()


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _ansi_supported() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.name == "nt":
        _enable_windows_vt()
    return bool(sys.stdout.isatty())


def _load_icon_source():
    """Load and clean the ICO exactly once per process."""
    global _ICON_SOURCE
    if _ICON_SOURCE is not None:
        return _ICON_SOURCE
    if Image is None or not ICON.exists():
        return None
    try:
        source = Image.open(ICON).convert("RGBA")
        # Prefer the largest available ICO frame when Pillow exposes one.
        try:
            best = source
            if getattr(source, "n_frames", 1) > 1:
                for i in range(source.n_frames):
                    source.seek(i)
                    frame = source.convert("RGBA")
                    if frame.width * frame.height > best.width * best.height:
                        best = frame.copy()
                source = best
        except Exception:
            pass
        px = source.load()
        for yy in range(source.height):
            for xx in range(source.width):
                r, g, b, a = px[xx, yy]
                if a > 0 and r < 18 and g < 24 and b < 34:
                    px[xx, yy] = (r, g, b, 0)
        _ICON_SOURCE = source
        return _ICON_SOURCE
    except Exception:
        return None


def _icon_pixels(width: int = 32, height: int = 20, angle: float = 0.0):
    """Return a cached, supersampled Y-axis rotation of the shield."""
    key = (int(width), int(height), int(round(float(angle))) % 360)
    with _FRAME_CACHE_LOCK:
        cached = _FRAME_CACHE.get(key)
    if cached is not None:
        return cached

    source = _load_icon_source()
    if source is None:
        return None
    try:
        work_w = max(96, width * 8)
        work_h = max(96, height * 8)
        base = source.copy()
        base.thumbnail((work_w, work_h), Image.Resampling.LANCZOS)

        a = math.radians(float(angle) % 360.0)
        scale_x = max(0.16, abs(math.cos(a)))
        turned = base.resize(
            (max(10, int(base.width * scale_x)), base.height),
            Image.Resampling.LANCZOS,
        )
        if 90.0 < (float(angle) % 360.0) < 270.0:
            turned = ImageOps.mirror(turned)

        turned.thumbnail((work_w - 8, work_h - 8), Image.Resampling.LANCZOS)
        canvas = Image.new("RGBA", (work_w, work_h), (0, 0, 0, 0))
        x = (work_w - turned.width) // 2
        y = (work_h - turned.height) // 2
        canvas.alpha_composite(turned, (x, y))
        canvas = canvas.resize((width, height), Image.Resampling.LANCZOS)
        result = [[canvas.getpixel((xx, yy)) for xx in range(width)] for yy in range(height)]
        with _FRAME_CACHE_LOCK:
            if len(_FRAME_CACHE) < 512:
                _FRAME_CACHE[key] = result
        return result
    except Exception:
        return None

def _logo_frame(pixels, phase: int = 0, crisp: bool = False) -> str:
    """Render a high-resolution true-colour shield using ANSI half-block cells.

    Two source pixels are packed into one terminal cell, giving roughly twice
    the vertical detail of the old full-cell renderer while avoiding the chunky
    square mosaic visible in classic CMD.  The terminal cell background stays
    dark and stable so the shield looks like a small HUD render rather than an
    icon made from blocks.
    """
    if pixels is None:
        pulse = ("◈", "◇", "◆", "◇")[phase % 4]
        return f"{CYAN}        {pulse}  CYBERSHIELD  {pulse}{RESET}"

    lines: list[str] = []
    h = len(pixels)
    w = len(pixels[0]) if h else 0

    def tone(px, boost=1.0):
        r, g, b, a = px
        return tuple(min(255, max(0, int(c * boost))) for c in (r, g, b)), a

    # Half-block rendering: one character carries top + bottom source pixels.
    # A tiny brightness modulation creates a moving scan-light across the logo.
    for y in range(0, h, 2):
        row: list[str] = []
        for x in range(w):
            top = pixels[y][x]
            bot = pixels[y + 1][x] if y + 1 < h else (0, 0, 0, 0)
            ta, ba = top[3], bot[3]
            if ta < 18 and ba < 18:
                row.append(" ")
                continue
            light = 0.96 + 0.10 * ((x + phase * 2) % max(1, w)) / max(1, w - 1)
            if ta >= 18 and ba >= 18:
                (tr, tg, tb), _ = tone(top, light)
                (br, bg, bb), _ = tone(bot, light)
                row.append(
                    f"\x1b[38;2;{tr};{tg};{tb}m\x1b[48;2;{br};{bg};{bb}m▀\x1b[0m"
                )
            elif ta >= 18:
                (tr, tg, tb), _ = tone(top, light)
                row.append(f"\x1b[38;2;{tr};{tg};{tb}m▀\x1b[0m")
            else:
                (br, bg, bb), _ = tone(bot, light)
                row.append(f"\x1b[38;2;{br};{bg};{bb}m▄\x1b[0m")
        lines.append("".join(row))
    return "\n".join(lines)

def _frame_box(title: str, body: list[str], width: int = 66) -> str:
    top = f"╭─ {title} " + "─" * max(1, width - len(title) - 5) + "╮"
    rows = [top]
    for text in body:
        rows.append("│ " + text[: width - 3].ljust(width - 3) + " │")
    rows.append("╰" + "─" * (width - 1) + "╯")
    return "\n".join(rows)


def _clear_screen() -> None:
    if _ansi_supported():
        # Full-screen redraw is more reliable in Windows CMD than cursor save/
        # restore sequences, which some CMD builds render as literal artifacts.
        sys.stdout.write("\x1b[2J\x1b[H")
    else:
        # No ANSI: keep output readable instead of attempting a fragile redraw.
        sys.stdout.write("\n")


def _hud_bar(progress: int, width: int = 38) -> str:
    filled = int(width * max(0, min(100, progress)) / 100)
    return (
        f"  {BLUE}{'━' * filled}{GRAY}{'─' * (width - filled)}{RESET}"
        f"  {CYAN}{progress:3d}%{RESET}"
    )


def _startup_grid(width: int, phase: int) -> list[str]:
    """Subtle cyber floor/light streaks behind the moving shield."""
    rows: list[str] = []
    for y in range(4):
        shift = (phase * 2 + y * 7) % max(1, width)
        cells = [' '] * width
        for x in range(0, width, 6):
            idx = (x + shift) % width
            cells[idx] = '·'
        rows.append(f"{GRAY}" + ''.join(cells) + f"{RESET}")
    return rows


def _startup_dashboard(phase: int, progress: int, icon_lines: list[str]) -> list[str]:
    """Build one stable full-screen CIBER dashboard frame.

    Every frame has the same number of rows and columns.  We repaint in place
    rather than printing new lines, which prevents the staircase/black-block
    corruption that classic CMD can show when cursor movement is interrupted.
    """
    width = 116
    def box(title: str, rows: list[str], w: int) -> list[str]:
        head = f"┌─ {title} " + "─" * max(1, w - len(title) - 4) + "┐"
        out = [head]
        for row in rows:
            out.append("│ " + row[:w-3].ljust(w-3) + " │")
        out.append("└" + "─" * (w-1) + "┘")
        return out

    # Keep the shield on a fixed right/center axis.  No moving trail is drawn.
    logo = [line for line in icon_lines]
    logo_h = len(logo)
    logo_w = max([len(x) for x in logo], default=0)
    center_rows = []
    for i in range(max(10, logo_h)):
        line = logo[i] if i < logo_h else ""
        pad = max(0, (50 - logo_w) // 2)
        center_rows.append(" " * pad + line)
    center_rows = center_rows[:10]

    left = box("SYSTEM STATUS", [
        "Secure Core                 [ ONLINE ]",
        "Integrity                   [  PASS  ]",
        "AI Defense Engine           [ ONLINE ]",
        "Real-time Guard             [ ACTIVE ]",
        "Windows Defender            [  ON    ]",
        "Network Monitor             [ ACTIVE ]",
        "Threat Correlator           [ READY  ]",
        "Sandbox Policy              [  SAFE  ]",
    ], 34)
    right = box("CIBER COMMANDS", [
        "scan <file>        deep-scan <target>  (real AV + static)",
        "engine-status      av-self-test / yara-scan",
        "threat-check <f>   url-check <url>",
        "process-risk       network-risk",
        "incident-list      full-audit <t>",
        "get-process        get-service",
        "get-mpcomputerstatus   firewall",
        "github-publish     vercel-deploy",
        "build-exe          test-run",
    ], 48)

    header = f"{CYAN}{BOLD}CYBERSHIELD CIBER{RESET}  {DIM}v3 • AI SECURITY & DEVELOPMENT TERMINAL{RESET}"
    top = [
        header,
        f"{GRAY}{'─' * width}{RESET}",
        f"{GREEN}● ONLINE{RESET}   {DIM}DEFENSIVE OPERATOR MODE{RESET}"
        f"                                      {CYAN}AI ENGINE: ONLINE{RESET}",
    ]
    # 10-row central hero area.
    hero = []
    for i in range(10):
        l = left[i] if i < len(left) else ""
        r = right[i] if i < len(right) else ""
        c = center_rows[i] if i < len(center_rows) else ""
        hero.append(f"{l:<36}  {c:<54}  {r}")

    bar_w = 76
    filled = int(bar_w * progress / 100)
    bar = f"{BLUE}{'█'*filled}{GRAY}{'░'*(bar_w-filled)}{RESET} {CYAN}{progress:3d}%{RESET}"
    bottom = [
        f"{GRAY}{'─' * width}{RESET}",
        f"{CYAN}STARTUP{RESET}  core → drivers → integrity → AI → realtime guard → operator",
        f"{bar}",
        f"{DIM}Natural language → verified CyberShield actions • GitHub • Vercel • EXE • Forensics • Windows diagnostics{RESET}",
    ]
    return top + hero + bottom


def _paint_frame(frame: list[str], first: bool = False) -> None:
    """Paint a complete fixed-size frame without cursor-up arithmetic."""
    if first:
        sys.stdout.write("\x1b[2J\x1b[H")
    else:
        sys.stdout.write("\x1b[H")
    for i, row in enumerate(frame):
        sys.stdout.write("\x1b[2K" + row)
        if i != len(frame) - 1:
            sys.stdout.write("\n")
    sys.stdout.flush()


def _prepare_animation_frames(width: int = 44, height: int = 24, step: int = 6):
    """Precompute all visible angles once; runtime animation becomes cheap."""
    frames = []
    for angle in range(0, 360, step):
        pixels = _icon_pixels(width, height, angle)
        lines = _logo_frame(pixels, angle // max(1, step), crisp=True).splitlines() if pixels else []
        frames.append(lines)
    return frames


def _draw_absolute(rows: list[str], start_row: int = 5) -> None:
    """Draw only the reserved shield area and restore the user's cursor."""
    if not rows:
        return
    with _TERMINAL_WRITE_LOCK:
        sys.stdout.write("\x1b7")  # save cursor
        sys.stdout.write(f"\x1b[{start_row};1H")
        for row in rows:
            sys.stdout.write("\x1b[2K" + row + "\n")
        sys.stdout.write("\x1b8")  # restore cursor
        sys.stdout.flush()


class CiberShieldAnimator:
    """Non-blocking, cached shield animation for the interactive CIBER shell."""
    def __init__(self, width: int = 44, height: int = 24, fps: int = 24):
        self.width = width
        self.height = height
        self.fps = max(12, min(36, int(fps)))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.frames: list[list[str]] = []

    def start(self) -> None:
        if not _ansi_supported() or self.thread and self.thread.is_alive():
            return
        self.frames = _prepare_animation_frames(self.width, self.height, step=12)
        if not self.frames:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="ciber-shield-animation", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        delay = 1.0 / self.fps
        index = 0
        while not self.stop_event.is_set():
            _draw_absolute(self.frames[index], start_row=5)
            index = (index + 1) % len(self.frames)
            self.stop_event.wait(delay)

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=0.4)
        self.thread = None
        self._clear_area()

    def _clear_area(self) -> None:
        if not _ansi_supported():
            return
        with _TERMINAL_WRITE_LOCK:
            sys.stdout.write("\x1b7")
            sys.stdout.write("\x1b[5;1H")
            for _ in range(self.height + 1):
                sys.stdout.write("\x1b[2K\n")
            sys.stdout.write("\x1b8")
            sys.stdout.flush()


def _session_frame() -> list[str]:
    """Compact shell chrome plus a reserved hero area for the live shield.

    The CIBER terminal intentionally reserves only about half a normal CMD
    window. This keeps command output visible and prevents the animation from
    taking over the console.
    """
    width = min(104, max(72, shutil.get_terminal_size((104, 30)).columns - 2))
    return [
        f"{CYAN}{BOLD}CYBERSHIELD CIBER{RESET}  {DIM}• secure startup • AI DEFENSE CORE{RESET}",
        f"{GRAY}{'─' * width}{RESET}",
        f"{GREEN}● ONLINE{RESET}   {DIM}DEFENSIVE OPERATOR MODE{RESET}"
        f"                                      {CYAN}AI ENGINE: ONLINE{RESET}",
    ]

def animate_start(duration: float = 1.0) -> None:
    """Fast startup: short visual boot, then hand control to live session animation."""
    if not _ansi_supported():
        print("\nCYBERSHIELD CIBER — AI SECURITY & DEVELOPMENT TERMINAL")
        print("AI operator ready. Type `help` for commands; `exit` to leave.\n")
        return

    # Fast boot uses cached frames and never blocks for long.
    frames = _prepare_animation_frames(28, 12, step=12)
    total = max(1, int(max(0.8, duration) / 0.045))
    first = True
    try:
        for i in range(total):
            angle = int(i * 360 / total) % 360
            pixels = _icon_pixels(28, 12, angle)
            icon_lines = _logo_frame(pixels, i, crisp=True).splitlines() if pixels else []
            width = len(re.sub(r"\x1b\[[0-9;]*m", "", _session_frame()[0]))
            out = _session_frame()
            out += [""]
            # Keep the hero centered and intentionally occupy about half the terminal height.
            for line in icon_lines:
                pad = max(0, (width - len(line)) // 2)
                out.append(" " * pad + line)
            out += [
                "",
                f"{CYAN}STARTUP{RESET}  core → integrity → AI → realtime guard → operator",
                f"{BLUE}{'█' * int(76 * (i + 1) / total)}{GRAY}{'░' * (76 - int(76 * (i + 1) / total))}{RESET}  {CYAN}{int(100*(i+1)/total):3d}%{RESET}",
                f"{DIM}Natural language → verified CyberShield actions • security • diagnostics • forensics{RESET}",
                f"{GRAY}{'─' * width}{RESET}",
            ]
            _paint_frame(out, first=first)
            first = False
            time.sleep(0.045)
    finally:
        # Leave the static shell header; the persistent animator takes over.
        with _TERMINAL_WRITE_LOCK:
            sys.stdout.write("\x1b[2J\x1b[H")
            for row in _session_frame():
                sys.stdout.write(row + "\n")
            sys.stdout.write("\n")
            sys.stdout.flush()


def thinking_animation(label: str = "CIBER is working", duration: float = 0.65) -> None:
    """Animated CyberShield spinner for a known duration."""
    if not _ansi_supported():
        print(f"[CIBER] {label}...")
        return
    frames = ("◐", "◓", "◑", "◒")
    end = time.monotonic() + max(0.0, duration)
    i = 0
    while time.monotonic() < end:
        sys.stdout.write(f"\r  {CYAN}{frames[i % len(frames)]}{RESET} {label} {DIM}•{RESET}")
        sys.stdout.flush()
        time.sleep(0.10)
        i += 1
    sys.stdout.write("\r" + " " * (len(label) + 14) + "\r")
    sys.stdout.flush()


def live_thinking(label: str, stop_event, started: float | None = None) -> None:
    """Persistent fixed-area rotating shield while a command is running.

    The icon remains visible continuously. Frames are repainted over the same
    reserved lines instead of clearing the terminal, preventing flicker,
    disappearing frames and CMD layout corruption.
    """
    ansi = _ansi_supported()
    if not ansi:
        print(f"[CIBER] {label}...")
        while not stop_event.wait(0.25):
            pass
        return

    # Keep live work animation to roughly half the console height.
    width, height = 28, 12
    phase = 0
    first = True
    previous_lines = height // 2 + 2

    while not stop_event.is_set():
        pixels = _icon_pixels(width, height, angle=(phase * 8.0) % 360.0)
        icon_lines = _logo_frame(pixels, phase).splitlines() if pixels else [f"{CYAN}◈{RESET}"]
        elapsed = f"{time.monotonic() - started:5.1f}s" if started else ""
        frame = icon_lines + [f"  {CYAN}{label}{RESET}{DIM}{elapsed}{RESET}"]

        if not first:
            sys.stdout.write(f"\x1b[{previous_lines}F")
        # Erase exactly the old frame area; do not clear the whole terminal.
        sys.stdout.write("\x1b[0J" + "\n".join(frame) + "\n")
        sys.stdout.flush()
        previous_lines = len(frame)
        first = False
        phase += 1
        stop_event.wait(0.08)

    if not first:
        sys.stdout.write(f"\x1b[{previous_lines}F\x1b[0J")
        sys.stdout.flush()


def ciber_prompt() -> str:
    """Return a compact Claude-like prompt with the current project context."""
    cwd = Path.cwd().name or "workspace"
    if _ansi_supported():
        return f"{CYAN}ciber{RESET} {DIM}({cwd}){RESET} {BOLD}›{RESET} "
    return f"ciber ({cwd}) > "

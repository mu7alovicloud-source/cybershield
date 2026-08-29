from pathlib import Path
import os
import tempfile
import sys

BASE_DIR = Path(__file__).resolve().parent.parent

# Frozen EXE (PyInstaller) ichidagi katalog vaqtinchalik/read-only bo‘lishi
# mumkin. Doimiy ma’lumotlarni foydalanuvchining writable profiliga chiqaramiz.
IS_FROZEN = bool(getattr(sys, "frozen", False))
IS_VERCEL = bool(os.getenv("VERCEL"))

if IS_FROZEN and not IS_VERCEL:
    _LOCAL_APPDATA = Path(os.getenv("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    RUNTIME_BASE_DIR = _LOCAL_APPDATA / "CyberShield"
else:
    RUNTIME_BASE_DIR = BASE_DIR


def _build_path(raw_value: str | None, default: Path) -> Path:
    if raw_value is None or not str(raw_value).strip():
        return default
    return Path(str(raw_value)).expanduser().resolve()


def _coerce_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


if IS_VERCEL:
    DATA_DIR = Path(tempfile.gettempdir()) / "cybershield"
else:
    DATA_DIR = _build_path(
        os.getenv("CYBERSHIELD_DATA_DIR"),
        RUNTIME_BASE_DIR / "data",
    )

LOG_DIR = _build_path(os.getenv("CYBERSHIELD_LOG_DIR"), DATA_DIR / "logs")
QUARANTINE_DIR = _build_path(os.getenv("CYBERSHIELD_QUARANTINE_DIR"), DATA_DIR / "quarantine")
SAMPLES_DIR = _build_path(os.getenv("CYBERSHIELD_SAMPLES_DIR"), DATA_DIR / "samples")
LAB_DIR = _build_path(os.getenv("CYBERSHIELD_LAB_DIR"), DATA_DIR / "lab")
DATABASE_FILE = _build_path(os.getenv("CYBERSHIELD_DB_PATH"), DATA_DIR / "cybershield.db")

APP_NAME = "CyberShield"
APP_VERSION = os.getenv(
    "CYBERSHIELD_APP_VERSION",
    "15.0-AI-ADAPTIVE-INTELLIGENCE",
)
APP_DESCRIPTION = os.getenv(
    "CYBERSHIELD_APP_DESCRIPTION",
    "Defensive Security Operations Platform",
)
APP_RELEASE_CHANNEL = os.getenv("CYBERSHIELD_RELEASE_CHANNEL", "stable").lower()
APP_BUILD_ID = os.getenv("CYBERSHIELD_BUILD_ID", "local")
APP_MODE = os.getenv("CYBERSHIELD_MODE", "defensive").lower()
APP_PORT = _coerce_int_env("CYBERSHIELD_WEB_PORT", 8765)

# Safety-first lab policy
LAB_DYNAMIC_ENABLED = os.getenv(
    "CYBERSHIELD_LAB_DYNAMIC",
    "false",
).lower() in {"1", "true", "yes", "on"}

LAB_NETWORK_MODE = os.getenv(
    "CYBERSHIELD_LAB_NETWORK_MODE",
    "DISABLED",
).upper()

LAB_REQUIRE_SNAPSHOT = os.getenv(
    "CYBERSHIELD_LAB_SNAPSHOT",
    "true",
).lower() not in {"0", "false", "no"}

RUNTIME_DIRS = {
    "data": DATA_DIR,
    "logs": LOG_DIR,
    "quarantine": QUARANTINE_DIR,
    "samples": SAMPLES_DIR,
    "lab": LAB_DIR,
}


def ensure_runtime_ready() -> dict[str, str]:
    """Guarantee required runtime directories exist and are writable."""
    created: dict[str, str] = {}
    for label, path in RUNTIME_DIRS.items():
        try:
            path.mkdir(parents=True, exist_ok=True)
            if not path.exists() or not path.is_dir():
                raise OSError(f"{path} is not a directory")
            if not os.access(path, os.W_OK):
                raise PermissionError(f"{path} is not writable")
            created[label] = str(path)
        except OSError as exc:
            raise RuntimeError(f"Unable to prepare '{label}' at {path}: {exc}") from exc
    if not DATABASE_FILE.parent.exists():
        DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not os.access(DATABASE_FILE.parent, os.W_OK):
        raise RuntimeError(f"Database directory {DATABASE_FILE.parent} is not writable")
    created["database"] = str(DATABASE_FILE)
    return created


# Create writable runtime directories.
for path in RUNTIME_DIRS.values():
    path.mkdir(parents=True, exist_ok=True)
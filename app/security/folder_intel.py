"""Safe folder discovery and containment for CyberShield AI.

The AI may discover folders by exact name and contain suspicious folders by
moving them into CyberShield's quarantine vault. It never executes files and
never deletes data. Searches are bounded to user-owned/common locations and
system/application directories are excluded by policy.
"""
from __future__ import annotations
import json
import os
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.config import QUARANTINE_DIR

MAX_RESULTS = 200
MAX_DEPTH = 7

SYSTEM_PARTS = {
    r"\windows", r"\program files", r"\program files (x86)",
    r"\programdata", r"\$recycle.bin",
}
PROTECTED_NAMES = {
    "windows", "system32", "program files", "program files (x86)",
    "programdata", "boot", "recovery",
}
SKIP_NAMES = {".git", "__pycache__", "node_modules", ".venv", "venv"}

@dataclass
class FolderMatch:
    name: str
    path: str
    depth: int

def _is_protected(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    normalized = str(resolved).lower().replace("/", "\\")
    parts = {part.lower() for part in resolved.parts if part and part not in ("/", "\\")}

    # Match only actual protected directory names and Windows system roots.
    if any(part in PROTECTED_NAMES for part in parts):
        return True

    if normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]

    windows_roots = (
        r"c:\windows",
        r"c:\program files",
        r"c:\program files (x86)",
        r"c:\programdata",
        r"c:\$recycle.bin",
    )
    if any(normalized.startswith(root) for root in windows_roots):
        return True

    # Never let the AI contain its own installation or its quarantine vault.
    try:
        if Path(QUARANTINE_DIR).resolve() in resolved.parents:
            return True
        if Path(__file__).resolve().parents[1] in resolved.parents:
            return True
    except OSError:
        pass
    return False

def _default_roots() -> list[Path]:
    home = Path.home()
    candidates = [
        home / "Desktop", home / "Downloads", home / "Documents",
        home / "OneDrive" / "Desktop", home / "OneDrive" / "Documents",
        Path.cwd(),
    ]
    out = []
    seen = set()
    for p in candidates:
        try:
            p = p.resolve()
        except OSError:
            continue
        if p.exists() and p.is_dir() and str(p).lower() not in seen:
            seen.add(str(p).lower())
            out.append(p)
    return out

def find_folders_by_name(name: str, roots: Iterable[str | Path] | None = None,
                          max_results: int = MAX_RESULTS) -> list[FolderMatch]:
    target = name.strip().strip('"\'').lower()
    if not target:
        return []
    roots = [Path(r).expanduser() for r in roots] if roots else _default_roots()
    matches: list[FolderMatch] = []
    visited = set()

    for root in roots:
        try:
            root = root.resolve()
        except OSError:
            continue
        if not root.is_dir() or _is_protected(root):
            continue
        stack = [(root, 0)]
        while stack and len(matches) < max_results:
            current, depth = stack.pop()
            if depth > MAX_DEPTH:
                continue
            try:
                real = str(current.resolve())
            except OSError:
                continue
            if real in visited:
                continue
            visited.add(real)
            try:
                entries = list(os.scandir(current))
            except (OSError, PermissionError):
                continue
            for entry in entries:
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                child = Path(entry.path)
                if child.name.lower() in SKIP_NAMES or _is_protected(child):
                    continue
                if child.name.lower() == target:
                    matches.append(FolderMatch(child.name, str(child.resolve()), depth + 1))
                    if len(matches) >= max_results:
                        break
                if depth < MAX_DEPTH:
                    stack.append((child, depth + 1))
    # stable unique result
    unique = {}
    for m in matches:
        unique[m.path.lower()] = m
    return list(unique.values())[:max_results]

def summarize_folder(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_dir():
        raise NotADirectoryError(str(p))
    files = dirs = 0
    bytes_total = 0
    samples = []
    try:
        for root, dirnames, filenames in os.walk(p, followlinks=False):
            dirs += len(dirnames)
            files += len(filenames)
            for fn in filenames:
                fp = Path(root) / fn
                try:
                    size = fp.stat().st_size
                    bytes_total += size
                    if len(samples) < 12:
                        samples.append(str(fp))
                except OSError:
                    pass
    except (OSError, PermissionError):
        pass
    return {
        "name": p.name, "path": str(p.resolve()), "files": files,
        "subdirectories": dirs, "bytes": bytes_total, "sample_files": samples
    }

def contain_folder(path: str | Path) -> Path:
    """Move a folder into the quarantine vault; no deletion or execution."""
    src = Path(path).expanduser().resolve()
    if not src.is_dir():
        raise NotADirectoryError(str(src))
    if _is_protected(src):
        raise PermissionError("Protected/system/application folder; containment refused.")
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = QUARANTINE_DIR / f"{stamp}_FOLDER_{src.name}"
    if dst.exists():
        dst = QUARANTINE_DIR / f"{stamp}_FOLDER_{src.name}_{os.getpid()}"
    shutil.move(str(src), str(dst))
    meta = {
        "type": "folder_containment",
        "original_path": str(src),
        "quarantine_path": str(dst),
        "contained_at": datetime.now(timezone.utc).isoformat(),
        "reversible": True,
    }
    (dst.parent / (dst.name + ".json")).write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return dst

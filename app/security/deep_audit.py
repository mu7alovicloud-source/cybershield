"""Bounded, non-destructive forensic analysis helpers for CyberShield.

All operations are read-only. Heavy work is capped by file count/size and is
performed in worker threads so the GUI/terminal event loop is not blocked by
large directory walks.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import math
import os
import re
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

MAX_FILES = 400
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_TEXT_BYTES = 2 * 1024 * 1024
WORKERS = 4

SUSPICIOUS_EXT = {".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".msi", ".lnk", ".iso", ".img", ".docm", ".xlsm", ".pptm"}
SCRIPT_MARKERS = (b"powershell", b"wscript", b"cscript", b"mshta", b"rundll32", b"regsvr32", b"certutil", b"bitsadmin")


def _path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def _sha256(p: Path, limit: int = MAX_FILE_BYTES) -> tuple[str, int]:
    h = hashlib.sha256(); n = 0
    with p.open("rb") as f:
        while n < limit:
            chunk = f.read(min(1024 * 1024, limit - n))
            if not chunk: break
            h.update(chunk); n += len(chunk)
    return h.hexdigest(), n


def _entropy_bytes(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def _iter_files(root: Path, max_files: int = MAX_FILES) -> list[Path]:
    if root.is_file(): return [root]
    out: list[Path] = []
    try:
        for p in root.rglob("*"):
            if p.is_file():
                out.append(p)
                if len(out) >= max_files: break
    except (OSError, PermissionError):
        pass
    return out


def _safe_stat(p: Path) -> dict[str, Any]:
    try:
        s = p.stat()
        return {"path": str(p), "size": s.st_size, "mtime": s.st_mtime, "suffix": p.suffix.lower()}
    except OSError as e:
        return {"path": str(p), "error": str(e)}


def _analyze_one(p: Path) -> dict[str, Any]:
    row = _safe_stat(p)
    if "error" in row: return row
    size = int(row["size"])
    row["size_capped"] = size > MAX_FILE_BYTES
    read_limit = min(size, MAX_FILE_BYTES)
    try:
        with p.open("rb") as f: data = f.read(read_limit)
        row["sha256"] = hashlib.sha256(data).hexdigest() if size <= MAX_FILE_BYTES else None
        row["header_hex"] = data[:32].hex()
        row["entropy"] = round(_entropy_bytes(data[: min(len(data), 1024 * 1024)]), 4)
        low = data.lower()
        row["mz"] = data[:2] == b"MZ"
        row["pe"] = b"PE\x00\x00" in data[:1024]
        row["script_markers"] = [m.decode(errors="ignore") for m in SCRIPT_MARKERS if m in low]
        row["suspicious_extension"] = p.suffix.lower() in SUSPICIOUS_EXT
        row["double_extension"] = len(p.suffixes) >= 2 and p.suffixes[-1].lower() in SUSPICIOUS_EXT
        row["risk_signals"] = []
        if row["pe"] and row["entropy"] >= 7.2: row["risk_signals"].append("high_entropy_pe")
        if row["script_markers"]: row["risk_signals"].append("execution_tool_marker")
        if row["double_extension"]: row["risk_signals"].append("double_extension")
        if row["suspicious_extension"] and not row["mz"] and p.suffix.lower() in {".exe", ".scr", ".dll", ".sys"}:
            row["risk_signals"].append("header_extension_mismatch")
        row["signal_count"] = len(row["risk_signals"])
    except (OSError, PermissionError) as e:
        row["error"] = str(e)
    return row


def _parallel(paths: Iterable[Path]) -> list[dict[str, Any]]:
    paths = list(paths)
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        return list(ex.map(_analyze_one, paths))


def inventory(target: str, max_files: int = MAX_FILES) -> dict[str, Any]:
    root = _path(target); files = _iter_files(root, max_files)
    total = 0; rows = []; skipped = 0
    for p in files:
        try:
            s = p.stat().st_size
            if total + s > MAX_TOTAL_BYTES: skipped += 1; continue
            total += s; rows.append(_safe_stat(p))
        except OSError: skipped += 1
    return {"target": str(root), "files_seen": len(files), "files_included": len(rows), "bytes_included": total, "skipped": skipped, "extensions": dict(Counter(r.get("suffix", "") for r in rows))}


def deep_scan(target: str) -> dict[str, Any]:
    start = time.perf_counter(); root = _path(target); paths = _iter_files(root)
    rows = _parallel(paths)
    signals = [r for r in rows if r.get("signal_count", 0)]
    return {"target": str(root), "files": len(rows), "flagged": len(signals), "risk_signals": dict(Counter(s for r in rows for s in r.get("risk_signals", []))), "duration_ms": round((time.perf_counter()-start)*1000, 1), "results": rows[:MAX_FILES]}


def entropy_scan(target: str) -> dict[str, Any]:
    rows = _parallel(_iter_files(_path(target), MAX_FILES))
    ranked = sorted((r for r in rows if "entropy" in r), key=lambda x: x.get("entropy", 0), reverse=True)
    return {"target": target, "high_entropy": [r for r in ranked if r.get("entropy", 0) >= 7.2][:100], "sample_count": len(rows)}


def extension_audit(target: str) -> dict[str, Any]:
    rows = _parallel(_iter_files(_path(target), MAX_FILES))
    mismatches = [r for r in rows if "header_extension_mismatch" in r.get("risk_signals", [])]
    doubles = [r for r in rows if r.get("double_extension")]
    return {"target": target, "mismatches": mismatches, "double_extensions": doubles}


def hash_manifest(target: str) -> dict[str, Any]:
    rows = []
    for p in _iter_files(_path(target), MAX_FILES):
        try:
            if p.stat().st_size <= MAX_FILE_BYTES:
                h, n = _sha256(p); rows.append({"path": str(p), "sha256": h, "bytes": n})
        except (OSError, PermissionError): pass
    return {"target": target, "count": len(rows), "files": rows}


def string_audit(target: str) -> dict[str, Any]:
    rows = []
    rx = re.compile(rb"[ -~]{8,}")
    for p in _iter_files(_path(target), MAX_FILES):
        try:
            data = p.read_bytes()[:MAX_TEXT_BYTES]
            strings = [m.decode("utf-8", "ignore") for m in rx.findall(data)]
            interesting = [s for s in strings if any(k in s.lower() for k in ("powershell", "http://", "https://", "cmd.exe", "rundll32", "regsvr32", "download"))][:50]
            if interesting: rows.append({"path": str(p), "strings": interesting})
        except (OSError, PermissionError): pass
    return {"target": target, "matches": rows}


def image_audit(target: str) -> dict[str, Any]:
    """Pixel-level image integrity/statistics; no image execution or modification."""
    try:
        from PIL import Image, ImageStat
    except Exception:
        return {"ok": False, "error": "Pillow is required for image-audit"}
    p = _path(target)
    try:
        with Image.open(p) as im:
            im.load()
            stat = ImageStat.Stat(im.convert("RGB"))
            hist = im.convert("RGB").histogram()
            pixels = im.width * im.height
            unique_est = len(set(im.convert("RGB").getdata())) if pixels <= 2_000_000 else None
            return {"ok": True, "path": str(p), "format": im.format, "mode": im.mode, "width": im.width, "height": im.height, "pixels": pixels, "aspect": round(im.width/im.height, 6) if im.height else None, "mean_rgb": [round(x,3) for x in stat.mean], "stddev_rgb": [round(x,3) for x in stat.stddev], "histogram_peak": max(hist) if hist else 0, "unique_rgb_exact": unique_est}
    except Exception as e:
        return {"ok": False, "path": str(p), "error": str(e)}


def screenshot_audit() -> dict[str, Any]:
    try:
        from PIL import ImageGrab
        im = ImageGrab.grab(all_screens=True)
    except Exception as e:
        return {"ok": False, "error": f"screen capture unavailable: {e}"}
    try:
        rgb = im.convert("RGB")
        # Compute deterministic pixel statistics without saving the screenshot.
        stat = __import__("PIL.ImageStat", fromlist=["ImageStat"]).ImageStat.Stat(rgb)
        return {"ok": True, "width": rgb.width, "height": rgb.height, "pixels": rgb.width*rgb.height, "mean_rgb": [round(x,2) for x in stat.mean], "stddev_rgb": [round(x,2) for x in stat.stddev], "note": "Pixel statistics only; screenshot is not persisted."}
    finally:
        im.close()


def duplicate_scan(target: str) -> dict[str, Any]:
    groups: dict[tuple[int, str], list[str]] = {}
    for p in _iter_files(_path(target), MAX_FILES):
        try:
            s = p.stat().st_size
            if s > MAX_FILE_BYTES: continue
            h, _ = _sha256(p)
            groups.setdefault((s,h), []).append(str(p))
        except (OSError, PermissionError): pass
    return {"duplicates": [paths for paths in groups.values() if len(paths) > 1]}


def permission_audit(target: str) -> dict[str, Any]:
    rows = []
    for p in _iter_files(_path(target), MAX_FILES):
        try:
            mode = p.stat().st_mode
            # Cross-platform informational flags only.
            rows.append({"path": str(p), "writable": os.access(p, os.W_OK), "readable": os.access(p, os.R_OK), "executable": os.access(p, os.X_OK), "mode": oct(mode & 0o777)})
        except OSError: pass
    return {"count": len(rows), "writable_count": sum(r["writable"] for r in rows), "files": rows[:200]}


def quick_report(target: str) -> dict[str, Any]:
    inv = inventory(target)
    deep = deep_scan(target)
    return {"inventory": inv, "deep_scan_summary": {k:v for k,v in deep.items() if k != "results"}}

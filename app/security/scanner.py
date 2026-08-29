"""Professional, safe static file analysis for CyberShield.

Design goals:
* never execute the target file;
* avoid false alarms for ordinary documents/media;
* produce explainable evidence rather than a magic malware score;
* expose enough metadata for the AI, incident and UI layers.

This is a static analyzer, not a claim of complete malware detection. Dynamic
execution is deliberately delegated to an isolated external lab.
"""
from __future__ import annotations

import hashlib
import math
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.security.hash_analyzer import sha256_file
from app.security.enhanced_detection import file_name_signals

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv", ".efi",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".wsh",
    ".msi", ".msp", ".jar", ".reg"
}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".wsh", ".reg"}
DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
    ".odt", ".ods", ".rtf", ".txt", ".csv", ".md", ".json", ".xml"
}
MEDIA_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".mp3", ".wav",
    ".mp4", ".mkv", ".avi", ".mov", ".flac", ".ogg"
}
ARCHIVE_EXTENSIONS = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods"}

SUSPICIOUS_STRINGS = {
    # needle: (score, title, severity)
    # Process-injection primitives are the strongest single-string signal
    # available to a static scanner (legitimate software almost never needs
    # to write into and spawn a thread inside another process), so they are
    # marked "high" instead of "medium". Everything else stays "medium":
    # individually common in legitimate admin/deployment tooling, but
    # meaningful once several appear together (see security_brain.py
    # correlation logic).
    b"powershell": (18, "PowerShell execution reference", "medium"),
    b"invoke-expression": (28, "PowerShell dynamic expression reference", "medium"),
    b"downloadstring": (30, "PowerShell remote content download reference", "medium"),
    b"frombase64string": (18, "Base64 decoding reference", "medium"),
    b"cmd.exe": (14, "Windows command shell reference", "medium"),
    b"rundll32": (18, "Rundll32 execution reference", "medium"),
    b"regsvr32": (18, "Regsvr32 execution reference", "medium"),
    b"mshta": (20, "MSHTA execution reference", "medium"),
    b"wscript": (16, "Windows Script Host reference", "medium"),
    b"cscript": (16, "Windows Script Host reference", "medium"),
    b"certutil": (18, "Certutil command reference", "medium"),
    b"bitsadmin": (18, "BITSAdmin transfer reference", "medium"),
    b"createprocess": (12, "CreateProcess API reference", "medium"),
    b"virtualalloc": (10, "VirtualAlloc API reference", "medium"),
    b"writeprocessmemory": (24, "WriteProcessMemory API reference", "high"),
    b"createremotethread": (24, "CreateRemoteThread API reference", "high"),
}

PDF_ACTIVE_MARKERS = {
    b"/javascript": (12, "PDF JavaScript action marker"),
    b"/js": (10, "PDF JS action marker"),
    b"/openaction": (8, "PDF automatic open action marker"),
    b"/launch": (16, "PDF launch action marker"),
    b"/submitform": (7, "PDF form submission marker"),
}

MAGIC = {
    ".pdf": (b"%PDF-", "PDF document"),
    ".png": (b"\x89PNG\r\n\x1a\n", "PNG image"),
    ".jpg": (b"\xff\xd8\xff", "JPEG image"),
    ".jpeg": (b"\xff\xd8\xff", "JPEG image"),
    ".gif": (b"GIF8", "GIF image"),
    ".zip": (b"PK\x03\x04", "ZIP archive"),
}


@dataclass(frozen=True)
class Evidence:
    code: str
    title: str
    detail: str
    score: int
    severity: str = "info"
    confidence: float = 0.75

    def as_dict(self) -> dict:
        return asdict(self)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((n / size) * math.log2(n / size) for n in counts.values())


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def _read_sample(path: Path, limit: int = 4 * 1024 * 1024) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def _pe_details(sample: bytes) -> tuple[bool, dict]:
    if len(sample) < 64 or sample[:2] != b"MZ":
        return False, {}
    try:
        pe_offset = int.from_bytes(sample[0x3C:0x40], "little")
        if pe_offset < 64 or pe_offset + 24 > len(sample):
            return False, {}
        if sample[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return False, {}
        machine = int.from_bytes(sample[pe_offset + 4:pe_offset + 6], "little")
        sections = int.from_bytes(sample[pe_offset + 6:pe_offset + 8], "little")
        characteristics = int.from_bytes(sample[pe_offset + 22:pe_offset + 24], "little")
        optional_offset = pe_offset + 24
        magic = int.from_bytes(sample[optional_offset:optional_offset + 2], "little") if optional_offset + 2 <= len(sample) else 0
        return True, {
            "machine": hex(machine),
            "sections": sections,
            "characteristics": hex(characteristics),
            "optional_magic": hex(magic),
            "format": "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else "unknown",
        }
    except (IndexError, ValueError):
        return False, {}


def _script_heuristics(ext: str, lowered: bytes) -> list[Evidence]:
    if ext not in SCRIPT_EXTENSIONS:
        return []
    evidence: list[Evidence] = []
    for needle, (score, title, _severity) in SUSPICIOUS_STRINGS.items():
        if needle in lowered:
            # In an active script, any of these references is already a
            # strong signal regardless of the PE-context severity tier.
            evidence.append(Evidence("SCRIPT_EXEC", title, needle.decode("ascii", "ignore"), score, "high", .90))
    if re.search(rb"https?://", lowered):
        evidence.append(Evidence("SCRIPT_NET", "Script contains a network URL", "URL literal found in script content", 12, "medium", .80))
    if b"-enc" in lowered or b"encodedcommand" in lowered:
        evidence.append(Evidence("PS_ENCODED", "Encoded PowerShell argument", "-EncodedCommand/encoded argument marker", 22, "high", .88))
    return evidence


def _archive_heuristics(path: Path, ext: str) -> list[Evidence]:
    if ext not in ARCHIVE_EXTENSIONS:
        return []
    evidence: list[Evidence] = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            lowered = [n.lower() for n in names]
            executables = [n for n in lowered if Path(n).suffix in EXECUTABLE_EXTENSIONS]
            macros = [n for n in lowered if "vbaproject.bin" in n]
            traversal = [n for n in names if Path(n).is_absolute() or ".." in Path(n).parts]
            if executables:
                evidence.append(Evidence("ARCHIVE_EXEC", "Archive contains executable content", ", ".join(executables[:4]), 18, "medium", .86))
            if macros:
                evidence.append(Evidence("OFFICE_MACRO", "Office VBA macro payload detected", ", ".join(macros[:3]), 28, "high", .94))
            if traversal:
                evidence.append(Evidence("ZIP_SLIP", "Archive contains unsafe path traversal", ", ".join(traversal[:3]), 40, "critical", .97))
            nested_archives = [n for n in lowered if Path(n).suffix in ARCHIVE_EXTENSIONS]
            if len(nested_archives) >= 3:
                evidence.append(Evidence("NESTED_ARCHIVE", "Multiple nested archives detected", f"{len(nested_archives)} nested entries", 7, "info", .70))
    except (zipfile.BadZipFile, OSError, RuntimeError):
        # A malformed archive is noteworthy but is not automatically malware.
        evidence.append(Evidence("ARCHIVE_INVALID", "Archive structure could not be inspected", "Format may be damaged or unsupported", 5, "info", .65))
    return evidence


def _magic_mismatch(ext: str, sample: bytes) -> Evidence | None:
    if ext not in MAGIC or not sample:
        return None
    magic, label = MAGIC[ext]
    if not sample.startswith(magic):
        return Evidence("MAGIC_MISMATCH", "File extension does not match its header", f"Expected {label} signature for {ext}", 18, "medium", .92)
    return None


def _masquerading(path: Path) -> Evidence | None:
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) < 2:
        return None
    if suffixes[-1] in EXECUTABLE_EXTENSIONS and suffixes[-2] in DOCUMENT_EXTENSIONS | MEDIA_EXTENSIONS:
        return Evidence("MASQUERADE", "Document/media-looking name ends in executable extension", " → ".join(suffixes[-2:]), 28, "high", .94)
    return None


def _signature_status(path: Path, is_pe: bool) -> str:
    """Return a truthful status without pretending to verify Authenticode."""
    if not is_pe:
        return "NOT_APPLICABLE"
    # A full WinTrust verification can be added as a Windows-native provider.
    # Until then, UNKNOWN is safer than a fake VALID result.
    return "UNKNOWN_WINDOWS_TRUST_PROVIDER"


def _verdict(score: int, strong: int) -> str:
    if score >= 85 and strong >= 2:
        return "MALICIOUS"
    if score >= 70 and strong >= 1:
        return "LIKELY MALICIOUS"
    if score >= 40:
        return "SUSPICIOUS"
    if score >= 20:
        return "UNKNOWN"
    return "CLEAN"


def analyze_file(path: str | Path) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(str(p))
    stat = p.stat()
    ext = p.suffix.lower()
    sample = _read_sample(p)
    hashes = _hashes(sample) if stat.st_size <= 4 * 1024 * 1024 else {"sha256": sha256_file(p), "sha1": "", "md5": ""}
    # For >4 MB, SHA-1/MD5 are computed streaming below so metadata remains correct.
    if not hashes["sha1"]:
        h1, hm = hashlib.sha1(), hashlib.md5()
        with p.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h1.update(chunk); hm.update(chunk)
        hashes["sha1"], hashes["md5"] = h1.hexdigest(), hm.hexdigest()

    evidence: list[Evidence] = []
    is_pe, pe = _pe_details(sample)
    if is_pe:
        evidence.append(Evidence("PE_HEADER", "Windows PE executable structure detected", f"{pe.get('format')} • {pe.get('sections')} sections", 12, "info", .98))
        if int(pe.get("sections", 0)) > 12:
            evidence.append(Evidence("PE_SECTIONS", "Unusually high PE section count", str(pe.get("sections")), 8, "medium", .78))
    elif sample.startswith(b"MZ"):
        evidence.append(Evidence("INVALID_PE", "MZ header present but PE structure is incomplete", "Static parser could not validate the PE header", 42, "high", .91))

    # Entropy is contextual: documents/media are not punished simply for being compressed.
    ent = _entropy(sample)
    if len(sample) >= 4096 and ent >= 7.2 and (is_pe or ext in EXECUTABLE_EXTENSIONS):
        evidence.append(Evidence("PACKED_CONTENT", "High entropy in executable content", f"{ent:.2f} bits/byte", 16, "medium", .82))

    # Harmless EICAR antivirus self-test marker. This is a deterministic
    # signature used to verify that the local detection pipeline is actually
    # recognizing a known AV test sample; it is not malware.
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in sample:
        evidence.append(Evidence("EICAR_TEST", "EICAR antivirus test marker detected",
                                 "Harmless standard AV self-test signature", 100, "critical", .999))

    lowered = sample.lower()
    if ext in SCRIPT_EXTENSIONS:
        evidence.extend(_script_heuristics(ext, lowered))
    elif is_pe or sample.startswith(b"MZ") or ext in EXECUTABLE_EXTENSIONS:
        # Run behavioral-string checks even when the PE header is malformed
        # or missing (a very common state for packed/dropper/incompletely
        # downloaded samples). Previously this branch required a fully
        # well-formed PE, so damaged executables only ever produced the
        # generic INVALID_PE evidence and skipped the specific API/tool
        # indicators entirely.
        for needle, (score, title, severity) in SUSPICIOUS_STRINGS.items():
            if needle in lowered:
                confidence = .90 if severity == "high" else .78
                evidence.append(Evidence("PE_STRING", title, needle.decode("ascii", "ignore"), score, severity, confidence))

    if ext == ".pdf":
        for needle, (score, title) in PDF_ACTIVE_MARKERS.items():
            if needle in lowered:
                evidence.append(Evidence("PDF_ACTIVE", title, needle.decode("ascii", "ignore"), score, "medium", .84))

    evidence.extend(_archive_heuristics(p, ext))
    for signal in file_name_signals(p):
        evidence.append(Evidence(signal["code"], signal["reason"], signal["reason"], signal["score"], signal["severity"], .93))
    mismatch = _magic_mismatch(ext, sample)
    if mismatch:
        evidence.append(mismatch)
    masquerade = _masquerading(p)
    if masquerade:
        evidence.append(masquerade)

    # Plain text is not made suspicious by entropy, length, or executable extension absence.
    raw_score = sum(e.score for e in evidence)
    if ext not in EXECUTABLE_EXTENSIONS and not is_pe and not any(e.severity == "critical" for e in evidence):
        raw_score = min(raw_score, 55)
    score = min(100, raw_score)
    strong = sum(e.severity in {"high", "critical"} for e in evidence)
    verdict = _verdict(score, strong)

    if not evidence:
        confidence = .97
    else:
        # Confidence reflects parser agreement, not malware probability.
        confidence = min(.98, .72 + .05 * min(len(evidence), 5))
        if any(e.code in {"MAGIC_MISMATCH", "INVALID_PE", "ZIP_SLIP"} for e in evidence):
            confidence = min(.99, confidence + .06)

    return {
        "path": str(p),
        "name": p.name,
        "size": stat.st_size,
        "extension": ext or "(none)",
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "entropy": round(ent, 3),
        "risk": score,
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "indicators": [e.detail for e in evidence],
        "evidence": [e.as_dict() for e in evidence],
        "pe": pe,
        "signature_status": _signature_status(p, is_pe),
        "static_only": True,
        "execution_performed": False,
        "analysis_limit_bytes": 4 * 1024 * 1024,
    }


def scan_directory(directory: str | Path, *, limit: int = 500, workers: int = 4) -> list[dict]:
    """Bounded parallel static scan that keeps the UI responsive.

    File contents are never executed. The file count and worker count are
    capped so a huge tree cannot create unbounded background work.
    """
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    limit = max(1, min(int(limit), 5000))
    workers = max(1, min(int(workers), 8))
    paths: list[Path] = []
    try:
        for p in root.rglob("*"):
            if len(paths) >= limit:
                break
            try:
                if p.is_file():
                    paths.append(p)
            except OSError:
                continue
    except (OSError, PermissionError):
        pass

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="CyberShieldScan") as pool:
        futures = {pool.submit(analyze_file, p): p for p in paths}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except (OSError, PermissionError, ValueError):
                continue
    results.sort(key=lambda row: (row.get("risk", 0), row.get("path", "")), reverse=True)
    return results

"""Multi-engine defensive detection and evidence fusion.

This module never executes samples or opens URLs as a browser. It combines
local static evidence with optional reputation/endpoint engines and reports
which engines actually produced evidence. A missing engine is UNKNOWN, never
CLEAN.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from app.security.scanner import analyze_file
from app.security.authenticode import verify_signature
from app.security.defender_scan import scan_file_with_defender
from app.security.hybrid_intel import virus_total_hash, virus_total_url
from app.security.phishing_guard import analyze_url as local_url_analysis
from app.security.malware_engines import yara_scan_file, engine_status as malware_engine_status


def _clamav_file(path: Path, timeout: int = 90) -> dict[str, Any]:
    exe = shutil.which("clamscan")
    if not exe:
        return {"available": False, "status": "UNAVAILABLE"}
    try:
        cp = subprocess.run(
            [exe, "--no-summary", str(path)],
            capture_output=True, text=True, timeout=timeout, shell=False,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = ((cp.stdout or "") + "\n" + (cp.stderr or "")).strip()[-6000:]
        infected = " FOUND" in output or cp.returncode == 1
        return {"available": True, "status": "THREAT" if infected else "CLEAN" if cp.returncode == 0 else "ERROR",
                "exit_code": cp.returncode, "output": output}
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "TIMEOUT"}
    except OSError as exc:
        return {"available": True, "status": "ERROR", "error": type(exc).__name__}


def _file_score(static: dict[str, Any], signature: dict[str, Any], defender: dict[str, Any], vt: dict[str, Any], clam: dict[str, Any]) -> tuple[int, float, str, list[dict[str, Any]]]:
    score = int(static.get("risk", 0) or 0)
    evidence = list(static.get("evidence") or [])
    independent = 0
    threat_engines = 0

    if defender.get("status") == "THREAT":
        details = defender.get("threats") or defender.get("output") or "Microsoft Defender reported a threat"
        evidence.append({"code": "DEFENDER_THREAT", "severity": "critical", "source": "Microsoft Defender", "detail": str(details)[:2000], "score": 100})
        score = 100
        threat_engines += 1
        independent += 1
    elif defender.get("status") == "THREAT_OR_ERROR":
        # Legacy MpCmdRun fallback: non-zero is not proof of malware. Surface it
        # as UNKNOWN evidence rather than falsely calling the file malicious.
        output = str(defender.get("output", ""))
        evidence.append({"code": "DEFENDER_SCAN_ERROR", "severity": "medium", "source": "Microsoft Defender", "detail": output[-1500:] or "Defender returned a non-zero scan result", "score": 5})
    if clam.get("status") == "THREAT":
        evidence.append({"code": "CLAMAV_THREAT", "severity": "critical", "source": "ClamAV", "detail": clam.get("output", "")[-1000:], "score": 90})
        score = max(score, 95); threat_engines += 1; independent += 1
    if vt.get("malicious"):
        evidence.append({"code": "VT_THREAT", "severity": "critical", "source": "VirusTotal", "detail": str(vt.get("stats", {})), "score": 95})
        score = 100; threat_engines += 1; independent += 1
    if signature.get("enabled") and signature.get("status") not in {"Valid", "VALID"} and static.get("pe"):
        evidence.append({"code": "AUTHENTICODE", "severity": "medium", "source": "Windows Authenticode", "detail": signature.get("status", "UNKNOWN"), "score": 12})

    # Corroboration raises confidence only when independent engines agree.
    if threat_engines >= 2:
        score = min(100, score + 10)
    score = min(100, score)
    if score >= 85 and threat_engines >= 1:
        verdict = "MALICIOUS"
    elif score >= 70:
        verdict = "LIKELY MALICIOUS"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    elif score >= 20:
        verdict = "UNKNOWN"
    else:
        verdict = "CLEAN"

    base_conf = float(static.get("confidence", .6) or .6)
    confidence = min(.995, base_conf + .08 * independent + .04 * min(len(evidence), 6))
    if vt.get("status") == "CLEAN" or defender.get("status") == "COMPLETED" or clam.get("status") == "CLEAN":
        # A clean reputation/scan does not prove safety; it only slightly improves
        # confidence in a low-risk result.
        if score < 40:
            confidence = min(.98, confidence + .02)
    return score, round(confidence, 3), verdict, evidence


def analyze_file_deep(path: str | Path, *, endpoint_scan: bool = True, reputation: bool = True) -> dict[str, Any]:
    """Run the strongest locally available non-executing file analysis stack.

    The sample is never launched by CyberShield. Independent engines are:
    static parser, YARA (when installed), Microsoft Defender, ClamAV,
    Authenticode and VirusTotal hash reputation. Missing engines are reported
    as UNKNOWN rather than being treated as clean.
    """
    p = Path(path).expanduser().resolve()
    static = analyze_file(p)
    signature = verify_signature(p) if static.get("pe") else {"enabled": False, "status": "NOT_APPLICABLE"}
    defender = {"available": False, "status": "SKIPPED"}
    if endpoint_scan:
        # A real endpoint engine should see every requested file, not only PE
        # files. Defender can inspect documents, archives and scripts too.
        defender = scan_file_with_defender(p)
    vt = virus_total_hash(static.get("sha256", "")) if reputation else {"enabled": False, "status": "DISABLED", "malicious": False}
    clam = _clamav_file(p) if endpoint_scan else {"available": False, "status": "SKIPPED"}
    yara = yara_scan_file(p) if endpoint_scan else {"available": False, "status": "SKIPPED"}
    score, confidence, verdict, evidence = _file_score(static, signature, defender, vt, clam)

    if yara.get("status") == "THREAT":
        evidence.append({"code": "YARA_THREAT", "severity": "high", "source": "CyberShield YARA",
                         "detail": ", ".join(yara.get("matches", []))[:1500], "score": 70})
        score = max(score, 85)
        verdict = "MALICIOUS" if score >= 85 else verdict
        confidence = min(.995, confidence + .08)

    available = [
        static.get("engines", {}).get("static", {}).get("status") if isinstance(static.get("engines"), dict) else "COMPLETED",
        "Defender" if defender.get("available") else None,
        "ClamAV" if clam.get("available") else None,
        "YARA" if yara.get("available") else None,
        "VirusTotal" if vt.get("enabled") else None,
    ]
    available = [x for x in available if x]
    return {
        **static,
        "risk": min(100, score),
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "evidence": evidence,
        "engines": {
            "static": {"status": "COMPLETED"},
            "authenticode": signature,
            "defender": defender,
            "virustotal_hash": vt,
            "clamav": clam,
            "yara": yara,
        },
        "engine_summary": {
            "available": available,
            "count": len(available),
            "external_detection": any(x in available for x in ("Defender", "ClamAV", "YARA", "VirusTotal")),
        },
        "execution_performed": False,
        "engine_policy": "multi_engine_evidence_fusion_no_host_execution",
    }

def _dns_intel(host: str) -> dict[str, Any]:
    if not host:
        return {"status": "INVALID"}
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({x[4][0] for x in infos})[:20]
        return {"status": "RESOLVED", "ips": ips}
    except (OSError, socket.gaierror) as exc:
        return {"status": "UNRESOLVED", "error": type(exc).__name__}


def analyze_url_deep(url: str, *, reputation: bool = True) -> dict[str, Any]:
    local = local_url_analysis(url)
    vt = virus_total_url(url) if reputation else {"enabled": False, "status": "DISABLED", "malicious": False}
    dns = _dns_intel(local.get("host", ""))
    score = int(local.get("score", 0) or 0)
    reasons = list(local.get("reasons") or [])
    evidence = list(local.get("evidence") or [])
    if vt.get("malicious"):
        score = 100
        reasons.append("VirusTotal URL reputation: malicious")
        evidence.append({"code": "VT_URL_THREAT", "severity": "critical", "source": "VirusTotal", "detail": str(vt.get("stats", {})), "score": 95})
    if dns.get("status") == "UNRESOLVED" and score >= 20:
        score = min(100, score + 8)
        reasons.append("Hostname DNS orqali yechilmadi")
    if local.get("reputation", {}).get("malicious"):
        score = 100
    score = min(100, score)
    verdict = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "SUSPICIOUS" if score >= 35 else "LOW"
    independent = 1 + int(bool(local.get("reputation", {}).get("malicious"))) + int(bool(vt.get("malicious")))
    confidence = min(.995, float(local.get("confidence", .6)) + .06 * independent)
    return {**local, "score": score, "verdict": verdict, "confidence": round(confidence, 3),
            "reasons": list(dict.fromkeys(reasons)), "evidence": evidence,
            "engines": {"local_heuristics": {"status": "COMPLETED"}, "google_safe_browsing": local.get("reputation", {}), "virustotal_url": vt, "dns": dns},
            "network_request_performed": bool(local.get("network_request_performed")),
            "page_opened": False, "javascript_executed": False}

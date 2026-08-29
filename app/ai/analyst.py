"""Explainable AI analyst layer.

The analyst turns structured security evidence into a consistent incident-style
report. It does not invent external intelligence or claim that a heuristic is
proof of malware.
"""
from __future__ import annotations

from urllib.parse import urlparse
import re

from app.ai.security_brain import SecurityBrain
from app.ai.risk_engine import assess
from app.security.phishing_guard import analyze_url

brain = SecurityBrain()


def analyze_event(**signals):
    d = brain.assess(**signals)
    return {
        "score": d.score, "level": d.level, "confidence": d.confidence,
        "decision": d.decision, "explanation": f"Evidence correlation: {d.score}/100 ({d.level}); confidence {d.confidence:.0%}.",
        "recommended_actions": d.safe_actions, "escalation": d.escalation, "reasons": d.reasons,
    }


def _file_sections(result: dict, score: int, level: str, confidence: float, decision: str, reasons: list[str]) -> dict:
    name = result.get("name", "unknown")
    evidence_text = "; ".join(reasons[:4]) if reasons else "No strong malicious static indicator was observed."
    happened = f"CyberShield statik tahlilda {name} obyektini tekshirdi; hostda kod ishga tushirilmadi."
    why = evidence_text
    caused = evidence_text if reasons else "Fayl turi, hash va umumiy strukturasi ko‘rib chiqildi; kuchli signal topilmadi."
    if decision == "CONTAIN":
        safe = "Avval containment/quarantine; keyin qayta skan va mustaqil verification."
        must_not = "Original faylni tasdiqsiz o‘chirmang va noma’lum kodni hostda ishga tushirmang."
    elif decision == "REVIEW":
        safe = "Qo‘shimcha evidence yig‘ish va izolyatsiyalangan labga eskalatsiya qilish."
        must_not = "Bitta indikator asosida malware deb e’lon qilmang."
    else:
        safe = "Monitoringni davom ettirish; kerak bo‘lsa reputation/dynamic lab evidence qo‘shish."
        must_not = "‘SAFE’ natijasini 100% kafolat deb talqin qilmang."
    return {
        "what_happened": happened,
        "why_suspicious": why,
        "what_caused_detection": caused,
        "what_can_be_safely_done": safe,
        "what_must_not_be_done": must_not,
        "summary": f"{level} • {score}/100 • confidence {confidence:.0%} • {decision}",
    }


def analyze_file_result(result):
    indicators = list(result.get("indicators") or [])
    # A completely clean document/media result stays SAFE. Entropy alone is not
    # enough, and the scanner already suppresses generic compression noise.
    if result.get("verdict") == "CLEAN" and not indicators:
        d = {
            "score": 0, "level": "SAFE", "confidence": result.get("confidence", .97),
            "decision": "ALLOW_WITH_MONITORING", "recommended_actions": ["MONITOR"],
            "escalation": None, "reasons": [],
        }
    else:
        brain_d = brain.file_assessment(result)
        d = {
            "score": brain_d.score, "level": brain_d.level, "confidence": brain_d.confidence,
            "decision": brain_d.decision, "recommended_actions": brain_d.safe_actions,
            "escalation": brain_d.escalation, "reasons": brain_d.reasons,
        }
    d["report"] = _file_sections(result, d["score"], d["level"], d["confidence"], d["decision"], d["reasons"])
    return d


def analyze_phishing_url(url):
    r = analyze_url(url)
    score = int(r.get("score", 0)); confidence = float(r.get("confidence", .55))
    u = url if "://" in url else "https://" + url
    p = urlparse(u); host = (p.hostname or "").lower()
    reasons = list(r.get("reasons") or [])
    extra = 0
    if host.count(".") >= 3:
        extra += 6; reasons.append("Hostname labellari ko‘pligi impersonation riskini oshiradi")
    if "-" in host and any(x in host for x in ("login", "secure", "verify", "microsoft", "google", "apple", "paypal", "bank")):
        extra += 10; reasons.append("Brand/security mavzusidagi hyphenated hostname")
    if re.search(r"(login|verify|password|wallet|payment|account|signin)", (p.path + "?" + p.query).lower()):
        extra += 8; reasons.append("URL path/query credential yoki payment lure saqlaydi")
    reasons = list(dict.fromkeys(reasons))
    score = min(100, score + extra)
    level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
    decision = "BLOCK" if level in ("HIGH", "CRITICAL") else ("REVIEW" if level == "MEDIUM" else "MONITOR")
    report = {
        "what_happened": f"URL strukturasi tekshirildi: {host or 'unknown host'}.",
        "why_suspicious": "; ".join(reasons) if reasons else "Kuchli phishing heuristic topilmadi.",
        "what_caused_detection": "; ".join(reasons[:4]) if reasons else "No strong indicator.",
        "what_can_be_safely_done": "URLni ochmasdan block/review qilish va kerak bo‘lsa reputation tekshirish.",
        "what_must_not_be_done": "Shubhali URLni foydalanuvchi sessiyasida bevosita ochib bermang.",
        "summary": f"{level} • {score}/100 • confidence {confidence:.0%} • {decision}",
    }
    return {
        "score": score, "level": level, "confidence": confidence, "decision": decision,
        "reasons": reasons, "indicators": reasons,
        "escalation": "Evidence yetarli emas; analyst review tavsiya etiladi." if confidence < .70 else None,
        "report": report,
    }

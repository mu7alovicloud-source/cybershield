"""Offline phishing heuristics with explainable, non-networked URL analysis."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from app.security.reputation import google_safe_browsing
from app.security.enhanced_detection import url_signals

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "password", "wallet", "bank",
    "payment", "account", "security", "update", "confirm", "support", "unlock",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "cutt.ly", "rb.gy"}
BRANDS = {
    "google", "microsoft", "apple", "paypal", "binance", "telegram", "facebook",
    "instagram", "amazon", "netflix", "steam", "payme", "click", "uzum", "humo",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[-1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand_similarity(host: str) -> list[tuple[str, int]]:
    labels = [x for x in re.split(r"[.\-]", host.lower()) if x]
    results = []
    for label in labels:
        for brand in BRANDS:
            distance = _levenshtein(label, brand)
            if 0 < distance <= 2 and len(label) >= 5:
                results.append((brand, distance))
    return results


def _advanced_signals(raw: str, u, host: str, path_query: str) -> tuple[int, list[str]]:
    score = 0; reasons = []
    if u.scheme in {'javascript','data','vbscript','file'}:
        score += 55; reasons.append(f'Xavfli URL scheme: {u.scheme}')
    if u.username or u.password:
        score += 35; reasons.append('URL ichida username/password user-info mavjud')
    if u.port is not None and u.port not in {80,443}:
        score += 8; reasons.append(f'Standart bo‘lmagan web port: {u.port}')
    encoded = len(re.findall(r'%[0-9a-fA-F]{2}', raw))
    if encoded >= 6:
        score += min(18, 6 + encoded); reasons.append('URL juda ko‘p percent-encoding ishlatadi')
    if re.search(r'https?%3a|https?://.*https?://', raw, re.I):
        score += 24; reasons.append('Nested/encoded redirect URL pattern')
    params = [x for x in (u.query or '').split('&') if x]
    if len(params) >= 8:
        score += 8; reasons.append('Juda ko‘p query parametrlar')
    suspicious_params = re.findall(r'(?i)(?:^|&)(?:redirect|redirect_uri|return|return_url|continue|next|url|target|dest|destination|token|session|auth)=', u.query or '')
    if suspicious_params:
        score += min(16, 5 * len(suspicious_params)); reasons.append('Redirect/authentication parametrlaridan foydalanilgan')
    if any(ord(ch) > 127 for ch in host):
        score += 28; reasons.append('Hostname non-ASCII Unicode belgilarini o‘z ichiga oladi')
    if re.search(r'[а-яА-Я].*[a-zA-Z]|[a-zA-Z].*[а-яА-Я]', host):
        score += 20; reasons.append('Hostname mixed-script belgilarini o‘z ichiga oladi')
    if path_query.count('//') >= 2:
        score += 12; reasons.append('Path ichida qo‘shimcha // obfuscation mavjud')
    if path_query.count('/') >= 8:
        score += 7; reasons.append('Juda chuqur URL path')
    if len(u.fragment or '') > 80:
        score += 6; reasons.append('Uzun fragment obfuscation ehtimolini oshiradi')
    if re.search(r'(?i)\.(?:exe|scr|msi|js|jse|vbs|bat|cmd|ps1|hta|zip|iso)(?:$|[?#])', u.path or ''):
        score += 25; reasons.append('URL executable/script/archive payloadga o‘xshash faylga olib boradi')
    if max((len(x) for x in host.split('.')), default=0) >= 45:
        score += 8; reasons.append('Hostname juda uzun labelga ega')
    return score, reasons

def analyze_url(url: str) -> dict:
    raw = (url or "").strip()
    reasons: list[str] = []
    evidence: list[dict] = []
    score = 0
    try:
        normalized = raw if "://" in raw else "https://" + raw
        u = urlsplit(normalized)
        host = (u.hostname or "").lower().rstrip(".")
        path_query = (u.path or "") + ("?" + u.query if u.query else "")
    except ValueError:
        return {"verdict": "HIGH", "score": 90, "confidence": .96,
                "reasons": ["URL sintaksisi noto‘g‘ri yoki ambiguous"], "evidence": []}

    if not host:
        score += 40; reasons.append("Hostname mavjud emas")
    if u.scheme not in {"http", "https"}:
        score += 30; reasons.append("Web bo‘lmagan URL scheme")
    if u.scheme == "http":
        score += 8; reasons.append("HTTPS o‘rniga HTTP ishlatilgan")
    try:
        ipaddress.ip_address(host)
        score += 30; reasons.append("URL raw IP address ishlatadi")
    except ValueError:
        pass
    if "@" in raw:
        score += 25; reasons.append("URL @ user-info sintaksisini o‘z ichiga oladi")
    if host.startswith("xn--") or ".xn--" in host:
        score += 30; reasons.append("Punycode/homograph xavfi")
    if host in SHORTENERS:
        score += 15; reasons.append("URL shortener redirectni yashiradi")
    if host.count(".") >= 4:
        score += 12; reasons.append("Juda chuqur subdomain struktura")
    if len(raw) > 180:
        score += 10; reasons.append("Juda uzun URL")

    tokens = set(re.findall(r"[a-z0-9]+", (host + " " + path_query).lower()))
    hits = sorted(tokens & SUSPICIOUS_WORDS)
    if hits:
        score += min(25, 6 * len(hits))
        reasons.append("Credential/payment mavzusidagi tokenlar: " + ", ".join(hits[:6]))

    similarities = _brand_similarity(host)
    for brand, distance in similarities[:3]:
        score += 35
        reasons.append(f"{brand} brendiga o‘xshash hostname (typosquatting ehtimoli, distance={distance})")

    # A trusted brand appearing in a non-brand registrable domain is a strong phishing signal.
    labels = [x for x in host.split(".") if x]
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for brand in BRANDS:
        if brand in host and registrable not in {f"{brand}.com", f"{brand}.net", f"{brand}.org"}:
            score += 25
            reasons.append(f"Trusted brand name appears outside its expected domain: {brand}")
            break

    # Host labels containing a trusted brand but ending in an unrelated domain are suspicious.
    for brand in BRANDS:
        if brand in host and not host.endswith(f".{brand}.com") and not host == f"{brand}.com":
            if any(x in host for x in ("login", "secure", "verify", "support")):
                score += 16
                reasons.append(f"Brand nomi boshqa hostname bilan birlashtirilgan: {brand}")
                break

    if re.search(r"(login|verify|password|wallet|payment|account|signin|confirm)", path_query.lower()):
        score += 8
        reasons.append("URL path/query credential yoki payment lure saqlaydi")

    adv_score, adv_reasons = _advanced_signals(raw, u, host, path_query)
    score += adv_score; reasons.extend(adv_reasons)
    layered = url_signals(raw)
    for sig in layered:
        score += int(sig.get("score", 0))
        reasons.append(str(sig.get("reason", sig.get("code", "signal"))))
        evidence.append({"code": sig.get("code"), "severity": sig.get("severity", "medium"), "source": "CyberShield layered URL detector"})
    reasons = list(dict.fromkeys(reasons))
    reputation = google_safe_browsing(raw)
    if reputation.get("malicious"):
        score = 100
        reasons.append("Google Safe Browsing real-time threat reputation: malicious URL")
        evidence.append({"code": "REMOTE_REPUTATION", "severity": "critical", "source": "Google Safe Browsing", "matches": reputation.get("matches", [])})
    score = min(score, 100)
    verdict = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "SUSPICIOUS" if score >= 35 else "LOW"
    confidence = min(.99, .56 + len(reasons) * .075)
    if reputation.get("malicious"):
        confidence = .99
    elif not reasons:
        confidence = .90
    return {
        "url": raw, "host": host, "scheme": u.scheme, "verdict": verdict,
        "score": score, "confidence": round(confidence, 2), "reasons": list(dict.fromkeys(reasons)),
        "evidence": evidence, "reputation": reputation,
        "network_request_performed": bool(reputation.get("enabled")),
    }

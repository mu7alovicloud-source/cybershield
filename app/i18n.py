"""CyberShield localization: Uzbek-first, English and Russian.

Language is persisted as a stable code (uz/en/ru), while the UI displays the
native language name. Translation is deliberately deterministic: no network
or AI call is needed to switch the interface.
"""
from __future__ import annotations

from typing import Dict
from app.database.database import get_setting, set_setting

LANGUAGES = {
    "uz": "O‘zbekcha",
    "en": "English",
    "ru": "Русский",
}
DISPLAY_TO_CODE = {v: k for k, v in LANGUAGES.items()}

T: Dict[str, Dict[str, str]] = {
    "SETTINGS": {"uz":"SOZLAMALAR", "en":"SETTINGS", "ru":"НАСТРОЙКИ"},
    "CyberShield behavior, localization and safety policy.": {"uz":"CyberShield xatti-harakati, til va xavfsizlik siyosati.","en":"CyberShield behavior, localization and safety policy.","ru":"Поведение CyberShield, язык интерфейса и политика безопасности."},
    "INTERFACE": {"uz":"INTERFEYS", "en":"INTERFACE", "ru":"ИНТЕРФЕЙС"},
    "Language": {"uz":"Til", "en":"Language", "ru":"Язык"},
    "Protection engine enabled": {"uz":"Himoya dvigateli yoqilgan", "en":"Protection engine enabled", "ru":"Модуль защиты включён"},
    "HIGH/CRITICAL aniqlansa incident yaratish": {"uz":"HIGH/CRITICAL aniqlansa hodisa yaratish", "en":"Create an incident when HIGH/CRITICAL is detected", "ru":"Создавать инцидент при обнаружении HIGH/CRITICAL"},
    "SAFETY POLICY": {"uz":"XAVFSIZLIK SIYOSATI", "en":"SAFETY POLICY", "ru":"ПОЛИТИКА БЕЗОПАСНОСТИ"},
    "• Unknown samples hostda ishga tushirilmaydi.\n• Default remediation: containment/quarantine.\n• Evidence saqlanadi.\n• Verificationsiz “resolved” deb ko‘rsatilmaydi.\n• Qaytarib bo‘lmaydigan harakatlar confirmation talab qiladi.": {
        "uz":"• Noma’lum namunalar hostda ishga tushirilmaydi.\n• Standart chorasi: containment/karantin.\n• Dalillar saqlanadi.\n• Tekshiruvsiz “hal qilindi” deb ko‘rsatilmaydi.\n• Qaytarib bo‘lmaydigan harakatlar tasdiqlashni talab qiladi.",
        "en":"• Unknown samples are never executed on the host.\n• Default remediation: containment/quarantine.\n• Evidence is preserved.\n• Nothing is marked resolved without verification.\n• Irreversible actions require confirmation.",
        "ru":"• Неизвестные образцы не запускаются на хосте.\n• Действие по умолчанию: изоляция/карантин.\n• Доказательства сохраняются.\n• Без проверки объект не помечается как устранённый.\n• Необратимые действия требуют подтверждения."
    },
    "Command Center": {"uz":"Boshqaruv markazi", "en":"Command Center", "ru":"Центр управления"},
    "AI Security Copilot": {"uz":"AI xavfsizlik Copilot", "en":"AI Security Copilot", "ru":"AI помощник безопасности"},
    "AI Security Analyst": {"uz":"AI xavfsizlik tahlilchisi", "en":"AI Security Analyst", "ru":"AI аналитик безопасности"},
    "Live Monitoring": {"uz":"Jonli monitoring", "en":"Live Monitoring", "ru":"Мониторинг в реальном времени"},
    "Incidents": {"uz":"Hodisalar", "en":"Incidents", "ru":"Инциденты"},
    "Malware Lab": {"uz":"Zararli dastur laboratoriyasi", "en":"Malware Lab", "ru":"Лаборатория вредоносных программ"},
    "Phishing Analyzer": {"uz":"Fishing tahlilchisi", "en":"Phishing Analyzer", "ru":"Анализатор фишинга"},
    "Sandbox": {"uz":"Sandbox", "en":"Sandbox", "ru":"Песочница"},
    "Forensics": {"uz":"Forensika", "en":"Forensics", "ru":"Форензика"},
    "Settings": {"uz":"Sozlamalar", "en":"Settings", "ru":"Настройки"},
    "SECURITY OPERATIONS CENTER": {"uz":"XAVFSIZLIK OPERATSIYALARI MARKAZI", "en":"SECURITY OPERATIONS CENTER", "ru":"ЦЕНТР ОПЕРАЦИЙ БЕЗОПАСНОСТИ"},
    "●  PROTECTION ENGINE ONLINE": {"uz":"●  HIMOYA DVIGATELI ONLAYN", "en":"●  PROTECTION ENGINE ONLINE", "ru":"●  МОДУЛЬ ЗАЩИТЫ ОНЛАЙН"},
    "Defensive Mode": {"uz":"Himoya rejimi", "en":"Defensive Mode", "ru":"Защитный режим"},
    "Module ready": {"uz":"Modul tayyor", "en":"Module ready", "ru":"Модуль готов"},
    "CyberShield protection engine online • host execution of unknown samples blocked": {
        "uz":"CyberShield himoya dvigateli onlayn • noma’lum namunalarni hostda ishga tushirish bloklangan",
        "en":"CyberShield protection engine online • host execution of unknown samples blocked",
        "ru":"Модуль защиты CyberShield онлайн • запуск неизвестных образцов на хосте заблокирован"
    },
    "UZBEK-FIRST": {"uz":"O‘ZBEKCHA-BIRINCHI", "en":"UZBEK-FIRST", "ru":"УЗБЕКСКИЙ-ПЕРВЫМ"},
    "LIVE MONITORING": {"uz":"JONLI MONITORING", "en":"LIVE MONITORING", "ru":"МОНИТОРИНГ В РЕАЛЬНОМ ВРЕМЕНИ"},
    "Read-only telemetry from the local machine.": {"uz":"Mahalliy kompyuter telemetriyasi — faqat o‘qish rejimi.","en":"Read-only telemetry from the local machine.","ru":"Телеметрия локального компьютера — только чтение."},
    "↻  REFRESH NOW": {"uz":"↻  HOZIR YANGILASH", "en":"↻  REFRESH NOW", "ru":"↻  ОБНОВИТЬ"},
    "AI SECURITY ANALYST": {"uz":"AI XAVFSIZLIK TAHLILCHISI", "en":"AI SECURITY ANALYST", "ru":"AI АНАЛИТИК БЕЗОПАСНОСТИ"},
    "Natural language • Uzbek semantic understanding • Context • Safe planning": {"uz":"Tabiiy til • o‘zbekcha semantik tushunish • kontekst • xavfsiz rejalashtirish","en":"Natural language • Uzbek semantic understanding • Context • Safe planning","ru":"Естественный язык • семантика узбекского • контекст • безопасное планирование"},
    "TUSHUNISH": {"uz":"TUSHUNISH", "en":"UNDERSTAND", "ru":"АНАЛИЗИРОВАТЬ"},
    "INCIDENT RESPONSE": {"uz":"HODISAGA JAVOB", "en":"INCIDENT RESPONSE", "ru":"РЕАГИРОВАНИЕ НА ИНЦИДЕНТ"},
    "Evidence, severity, source and lifecycle status.": {"uz":"Dalillar, jiddiylik, manba va hayotiy sikl holati.","en":"Evidence, severity, source and lifecycle status.","ru":"Доказательства, критичность, источник и статус жизненного цикла."},
    "↻ REFRESH": {"uz":"↻ YANGILASH", "en":"↻ REFRESH", "ru":"↻ ОБНОВИТЬ"},
    "AI SECURITY COPILOT": {"uz":"AI XAVFSIZLIK COPILOT", "en":"AI SECURITY COPILOT", "ru":"AI ПОМОЩНИК БЕЗОПАСНОСТИ"},
    "ANALYST CHAT": {"uz":"TAHLILCHI SUHBATI", "en":"ANALYST CHAT", "ru":"ЧАТ АНАЛИТИКА"},
    "PHISHING ANALYZER": {"uz":"FISHING TAHLILCHISI", "en":"PHISHING ANALYZER", "ru":"АНАЛИЗАТОР ФИШИНГА"},
    "CYBERSHIELD SAFE LAB": {"uz":"CYBERSHIELD XAVFSIZ LAB", "en":"CYBERSHIELD SAFE LAB", "ru":"БЕЗОПАСНАЯ ЛАБОРАТОРИЯ CYBERSHIELD"},
    "FILE ANALYSIS": {"uz":"FAYL TAHLILI", "en":"FILE ANALYSIS", "ru":"АНАЛИЗ ФАЙЛА"},
    "Multi-layer static inspection • SHA-256/SHA-1/MD5 • PE/script/archive heuristics • no execution": {"uz":"Ko‘p qatlamli statik tekshiruv • SHA-256/SHA-1/MD5 • PE/script/arxiv heuristikasi • ishga tushirish yo‘q","en":"Multi-layer static inspection • SHA-256/SHA-1/MD5 • PE/script/archive heuristics • no execution","ru":"Многоуровневый статический анализ • SHA-256/SHA-1/MD5 • эвристики PE/скриптов/архивов • без запуска"},
    "Fayl tanlanmagan": {"uz":"Fayl tanlanmagan", "en":"No file selected", "ru":"Файл не выбран"},
    "EVIDENCE": {"uz":"DALILLAR", "en":"EVIDENCE", "ru":"ДОКАЗАТЕЛЬСТВА"},
    "READY • STATIC ANALYSIS": {"uz":"TAYYOR • STATIK TAHLIL", "en":"READY • STATIC ANALYSIS", "ru":"ГОТОВО • СТАТИЧЕСКИЙ АНАЛИЗ"},
    "COMMAND CENTER": {"uz":"BOSHQARUV MARKAZI", "en":"COMMAND CENTER", "ru":"ЦЕНТР УПРАВЛЕНИЯ"},
    "Live local telemetry • evidence-based file analysis • AI-assisted defensive response": {"uz":"Jonli mahalliy telemetriya • dalillarga asoslangan fayl tahlili • AI yordamidagi himoya","en":"Live local telemetry • evidence-based file analysis • AI-assisted defensive response","ru":"Локальная телеметрия • анализ файлов на основе доказательств • AI-защита"},
    "RECENT ANALYSES": {"uz":"SO‘NGGI TAHLILLAR", "en":"RECENT ANALYSES", "ru":"ПОСЛЕДНИЕ АНАЛИЗЫ"},
    "DIGITAL FORENSICS": {"uz":"RAQAMLI FORENSIKA", "en":"DIGITAL FORENSICS", "ru":"ЦИФРОВАЯ ФОРЕНЗИКА"},
    "↻ REFRESH SNAPSHOT": {"uz":"↻ SNAPSHOTNI YANGILASH", "en":"↻ REFRESH SNAPSHOT", "ru":"↻ ОБНОВИТЬ СНИМОК"},
}


TERMINAL_T = {
    "THREAT_DETECTED": {"uz": "Tahdid aniqlandi", "ru": "Обнаружена угроза", "en": "Threat detected"},
    "ALLOWED": {"uz": "Ruxsat etilgan", "ru": "Разрешено", "en": "Allowed"},
    "BLOCKED": {"uz": "Bloklandi", "ru": "Заблокировано", "en": "Blocked"},
}

def terminal_tr(key: str, language: str = "uz") -> str:
    code = normalize_language(language)
    return TERMINAL_T.get(key, {}).get(code, key)


def normalize_language(value: str | None) -> str:
    if not value:
        return "uz"
    raw = str(value).strip()
    if raw in LANGUAGES:
        return raw
    lowered = raw.lower()
    if lowered in LANGUAGES:
        return lowered
    for display, code in DISPLAY_TO_CODE.items():
        if raw.casefold() == display.casefold():
            return code
    return "uz"


def get_language() -> str:
    code = normalize_language(get_setting("language", "uz"))
    if get_setting("language", None) != code:
        set_setting("language", code)
    return code


def set_language(code_or_display: str) -> str:
    code = normalize_language(code_or_display)
    set_setting("language", code)
    return code


def language_name(code: str | None = None) -> str:
    return LANGUAGES.get(normalize_language(code), LANGUAGES["uz"])


def tr(text: str, language: str | None = None) -> str:
    code = normalize_language(language or get_language())
    return T.get(text, {}).get(code, text)


def translate_tree(root, language: str | None = None):
    """Translate static Qt text while preserving dynamic runtime values."""
    from PySide6.QtWidgets import (QAbstractButton, QLabel, QComboBox, QGroupBox,
                                    QLineEdit, QTabWidget, QTableWidget, QMainWindow)
    code = normalize_language(language or get_language())

    def translate_value(obj, attr: str = "text"):
        try:
            value = getattr(obj, attr)()
        except Exception:
            return
        if not value:
            return
        source = obj.property("cs_i18n_source")
        if source is None:
            source = value
            obj.setProperty("cs_i18n_source", source)
        translated = tr(str(source), code)
        if attr == "text" and isinstance(obj, QAbstractButton): obj.setText(translated)
        elif attr == "text" and isinstance(obj, QLabel): obj.setText(translated)
        elif attr == "title" and isinstance(obj, QMainWindow): obj.setWindowTitle(translated)

    for obj in root.findChildren(QAbstractButton):
        translate_value(obj)
    for obj in root.findChildren(QLabel):
        translate_value(obj)
    for obj in root.findChildren(QGroupBox):
        translate_value(obj, "title")
    for obj in root.findChildren(QLineEdit):
        try:
            source = obj.property("cs_i18n_placeholder")
            if source is None:
                source = obj.placeholderText()
                obj.setProperty("cs_i18n_placeholder", source)
            if source: obj.setPlaceholderText(tr(str(source), code))
        except Exception: pass
    for combo in root.findChildren(QComboBox):
        for i in range(combo.count()):
            source = combo.itemData(i, 256)
            if source is None:
                source = combo.itemText(i)
                combo.setItemData(i, source, 256)
            combo.setItemText(i, tr(str(source), code))
    if isinstance(root, QMainWindow):
        root.setWindowTitle(f"CyberShield — Security Operations Center")

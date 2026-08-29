from __future__ import annotations

from html import escape
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QFileDialog, QFrame, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QTextEdit, QVBoxLayout, QWidget, QPushButton, QTabWidget

from app.ai.copilot_engine import CopilotEngine
from app.i18n import get_language
from app.ui.widgets import ActionButton, MetricCard, StatusBadge


class AICopilot(QWidget):
    """Unified CyberShield AI workspace: conversation + investigation + security context."""
    def __init__(self, desktop_controller=None):
        super().__init__()
        self.engine = CopilotEngine()
        if desktop_controller is not None:
            self.engine.set_desktop_controller(desktop_controller)
        self.build()
        self.write_intro()

    def build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 18); root.setSpacing(12)

        title = QLabel("CYBERSHIELD AI SECURITY INTELLIGENCE"); title.setObjectName("pageTitle"); root.addWidget(title)
        sub = QLabel("Unified AI workspace • Evidence-grounded reasoning • Adaptive investigation • Local-first intelligence")
        sub.setObjectName("pageSubtitle"); root.addWidget(sub)

        hero = QFrame(); hero.setObjectName("aiHero")
        hl = QHBoxLayout(hero); hl.setContentsMargins(16, 13, 16, 13); hl.setSpacing(14)
        orb = QLabel("✦"); orb.setObjectName("aiOrb"); hl.addWidget(orb, 0, Qt.AlignTop)
        self._ai_orb = orb
        self._orb_frames = ["✦", "✧", "✦", "✧"]
        self._orb_index = 0
        self._orb_timer = QTimer(self)
        self._orb_timer.timeout.connect(self._animate_ai_orb)
        self._orb_timer.start(220)
        hb = QVBoxLayout(); hb.setSpacing(2)
        h1 = QLabel("ADAPTIVE SECURITY BRAIN"); h1.setObjectName("aiHeroTitle"); hb.addWidget(h1)
        hs = QLabel("Reason • verify • explain • never invent evidence") ; hs.setObjectName("aiHeroSub"); hb.addWidget(hs)
        hl.addLayout(hb, 1)
        self.brain_badge = StatusBadge("REASONING ONLINE", "safe"); hl.addWidget(self.brain_badge, 0, Qt.AlignCenter)
        root.addWidget(hero)

        cards = QHBoxLayout(); cards.setSpacing(9)
        for label, value, hint, accent, icon in [
            ("BRAIN", "UNIFIED", "One AI surface", "blue", "brain"),
            ("EVIDENCE", "GROUNDED", "No invented findings", "purple", "shield"),
            ("ACTIONS", "SAFE-GATED", "Deterministic policy", "safe", "sandbox"),
            ("MODE", "LOCAL-FIRST", "Works without an API", "blue", "monitor"),
        ]:
            cards.addWidget(MetricCard(label, value, hint, accent, icon))
        root.addLayout(cards)

        intelligence = QFrame(); intelligence.setObjectName("aiTelemetry")
        il = QGridLayout(intelligence); il.setContentsMargins(12, 9, 12, 9); il.setHorizontalSpacing(18); il.setVerticalSpacing(3)
        self.ai_state = {}
        for col, (key, label, value) in enumerate([
            ("reasoning", "REASONING", "ADAPTIVE"), ("evidence", "EVIDENCE", "GROUNDED"),
            ("memory", "MEMORY", "BOUNDED"), ("actions", "ACTIONS", "POLICY-GATED"),
        ]):
            box = QVBoxLayout(); box.setSpacing(0)
            a = QLabel(label); a.setObjectName("aiTelemetryLabel"); box.addWidget(a)
            v = QLabel(value); v.setObjectName("aiTelemetryValue"); box.addWidget(v)
            il.addLayout(box, 0, col); self.ai_state[key] = v
        root.addWidget(intelligence)

        panel = QFrame(); panel.setObjectName("panel")
        pl = QVBoxLayout(panel); pl.setContentsMargins(8, 8, 8, 8); pl.setSpacing(6)
        self.tabs = QTabWidget(); self.tabs.setObjectName("intelligenceTabs")

        ai_tab = QWidget(); ail = QVBoxLayout(ai_tab); ail.setContentsMargins(4, 4, 4, 4); ail.setSpacing(7)
        head = QHBoxLayout(); head.addWidget(QLabel("AI SECURITY ANALYST", objectName="panelTitle")); head.addStretch()
        self.provider_badge = StatusBadge("LOCAL AI • AUTO", "info"); head.addWidget(self.provider_badge)
        clear = QPushButton("CLEAR CHAT"); clear.setObjectName("secondaryButton"); clear.clicked.connect(self.clear_chat); head.addWidget(clear)
        ail.addLayout(head)
        self.chat = QTextEdit(); self.chat.setReadOnly(True); self.chat.setObjectName("aiChat"); ail.addWidget(self.chat, 1)
        self.tabs.addTab(ai_tab, "AI ANALYST")

        pl.addWidget(self.tabs, 1)
        root.addWidget(panel, 1)

        hint = QLabel('Oddiy tilda yozing: “nega bu fayl xavfli?” • “oldingisini tushuntir” • “kompyuterimda nima bo‘lyapti?” • “EDR va antivirus farqi?” • “internetdan eng so‘nggi ma’lumotni top”')
        hint.setObjectName("pageSubtitle"); root.addWidget(hint)

        row = QHBoxLayout(); row.setSpacing(8)
        self.input = QLineEdit(); self.input.setPlaceholderText("CyberShield AI ga istalgan savolni yozing…"); self.input.returnPressed.connect(self.ask); row.addWidget(self.input, 1)
        send = ActionButton("ASK CYBERSHIELD AI", "brain", True); send.clicked.connect(self.ask); row.addWidget(send)
        file_btn = ActionButton("ANALYZE FILE", "file"); file_btn.clicked.connect(self.pick_file); row.addWidget(file_btn)
        root.addLayout(row)

        self.context_label = QLabel("Context: conversation memory • live telemetry • terminal-style host inspection • evidence-first")
        self.context_label.setObjectName("pageSubtitle"); root.addWidget(self.context_label)

    def _animate_ai_orb(self):
        if not hasattr(self, "_ai_orb"):
            return
        self._orb_index = (self._orb_index + 1) % len(self._orb_frames)
        self._ai_orb.setText(self._orb_frames[self._orb_index])

    def set_language(self, code: str):
        if hasattr(self, "tabs"):
            self.tabs.setTabText(0, {"uz":"AI TAHLILCHI", "en":"AI ANALYST", "ru":"AI АНАЛИТИК"}.get(code, "AI ANALYST"))

    def write_intro(self):
        self.add("CYBERSHIELD AI", "Salom! Men CyberShield'ning terminal-darajadagi AI Security Intelligence qatlamiman. Tizim, jarayonlar, tarmoq, disklar, xizmatlar, scheduled tasklar va Defender holatini read-only rejimda tekshiraman; real security evidence'ni tahlil qilaman va kerak bo‘lsa local LLM yoki web research yordamida javobni chuqurlashtiraman. Security actionlar esa alohida xavfsizlik policy'lari bilan boshqariladi.", "ai")

    def add(self, who: str, text: str, tone: str = "normal"):
        palette = {
            "normal": ("#dceaff", "#0b1727", "#203a58"),
            "ai": ("#74c8ff", "#0a1a2b", "#22527a"),
            "user": ("#ffffff", "#0b315c", "#2a71ad"),
            "warn": ("#ffd16a", "#211a08", "#765b1b"),
        }
        fg, bg, border = palette.get(tone, palette["normal"])
        safe = text if tone == "ai" else escape(str(text)).replace("\n", "<br>")
        self.chat.append(
            f"<div style='margin:10px 2px;padding:12px 14px;background:{bg};border:1px solid {border};border-radius:12px;'>"
            f"<span style='color:{fg};font-weight:900;letter-spacing:.5px'>{escape(who)}</span>"
            f"<div style='margin-top:5px;color:#dbe8f7;line-height:1.55'>{safe}</div></div>"
        )

    def clear_chat(self):
        self.chat.clear()
        self.engine.history.clear()
        self.engine.memory.update({"last_target": None, "last_result": None, "last_topic": None, "last_answer": None})
        self.write_intro()

    def pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "CyberShield — Fayl tanlang", options=QFileDialog.Option.DontUseNativeDialog)
        if path:
            self.input.setText(f"Faylni tahlil qil: {path}")
            self.ask()

    def ask(self):
        query = self.input.text().strip()
        if not query:
            return
        self.add("SIZ", query, "user")
        self.input.clear()
        response = self.engine.ask(query)
        body = response.answer
        self.ai_state["reasoning"].setText(response.intent.name.upper().replace("_", " "))
        self.ai_state["evidence"].setText(f"{len(response.evidence)} SIGNALS")
        self.ai_state["memory"].setText(f"{len(self.engine.history)} TURNS")
        self.ai_state["actions"].setText("SAFE-GATED" if response.actions else "OBSERVE")
        if response.evidence:
            body += "<br><br><b>EVIDENCE</b><ul>" + "".join(f"<li>{escape(str(e))}</li>" for e in response.evidence[:10]) + "</ul>"
        if response.actions:
            body += "<b>SAFE ACTIONS:</b> " + " • ".join(escape(a) for a in response.actions[:6])
        if response.warnings:
            body += "<br><br><span style='color:#ffc247'><b>SAFETY:</b> " + " • ".join(escape(str(w)) for w in response.warnings) + "</span>"
        if response.suggestions:
            body += "<br><br><span style='color:#7ca7d8'><b>TRY:</b> " + " • ".join(escape(s) for s in response.suggestions[:4]) + "</span>"
        self.add(response.title, body, "ai")
        self.context_label.setText(f"Context: {len(self.engine.history)} turns • focus={self.engine.session_profile.get('focus','general')} • evidence-first")

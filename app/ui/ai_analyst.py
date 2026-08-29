from html import escape
from PySide6.QtWidgets import QWidget,QVBoxLayout,QHBoxLayout,QLabel,QTextEdit,QLineEdit,QPushButton,QFrame
from PySide6.QtCore import Qt
from app.ai.copilot_engine import CopilotEngine

class AIAnalyst(QWidget):
    """Primary conversational AI surface. Uses the same copilot as the security backend."""
    def __init__(self):
        super().__init__()
        self.engine=CopilotEngine()
        root=QVBoxLayout(self); root.setContentsMargins(10,10,10,10); root.setSpacing(10)
        title=QLabel("AI SECURITY ANALYST"); title.setObjectName("pageTitle"); root.addWidget(title)
        sub=QLabel("Natural language • Uzbek / English / Russian • Local AI • Web Intelligence • Evidence-grounded security")
        sub.setObjectName("pageSubtitle"); root.addWidget(sub)
        panel=QFrame(); panel.setObjectName("panel"); pl=QVBoxLayout(panel); pl.setContentsMargins(12,12,12,12)
        head=QHBoxLayout(); head.addWidget(QLabel("CYBERSHIELD AI", objectName="panelTitle")); head.addStretch()
        badge=QLabel("LOCAL AI • WEB RESEARCH • SAFE"); badge.setObjectName("statusBadge"); head.addWidget(badge); pl.addLayout(head)
        self.chat=QTextEdit(); self.chat.setReadOnly(True); self.chat.setObjectName("analysisBox"); pl.addWidget(self.chat,1)
        root.addWidget(panel,1)
        hint=QLabel("Masalan: “Virus nima?” • “Nega bu fayl xavfli?” • “Oldingisini tushuntir” • “Internetdan oxirgi yangilikni top” • “EDR bilan antivirus farqi nima?”")
        hint.setObjectName("pageSubtitle"); root.addWidget(hint)
        row=QHBoxLayout(); row.setSpacing(8)
        self.input=QLineEdit(); self.input.setPlaceholderText("Savolingizni yozing… / Ask anything about CyberShield security…"); self.input.returnPressed.connect(self.ask); row.addWidget(self.input,1)
        btn=QPushButton("UNDERSTAND"); btn.setObjectName("primaryButton"); btn.clicked.connect(self.ask); row.addWidget(btn)
        root.addLayout(row)
        self.write_intro()

    def write_intro(self):
        self.add_message("CyberShield AI", "Salom! Men CyberShield AI yordamchisiman. Oddiy savollarga javob beraman, real tahlil natijalarini tushuntiraman va suhbat kontekstini eslab qolaman.", "ai")

    def add_message(self, who, text, tone="normal"):
        colors={"normal":"#dceaff","ai":"#6fc2ff","user":"#ffffff","warn":"#ffc247"}
        # AI responses intentionally contain trusted, generated markup; user/evidence text is escaped below.
        safe = text if tone=="ai" else escape(str(text)).replace("\n","<br>")
        self.chat.append(f"<div style='margin:9px 0'><b style='color:{colors.get(tone,'#dceaff')}'>{escape(who)}</b><br><span style='color:#dbe8f7'>{safe}</span></div>")

    def ask(self):
        query=self.input.text().strip()
        if not query:return
        self.add_message("SIZ", query, "user"); self.input.clear()
        response=self.engine.ask(query)
        body=response.answer
        if response.evidence:
            body += "<br><br><b>EVIDENCE</b><ul>" + "".join(f"<li>{escape(str(e))}</li>" for e in response.evidence[:10]) + "</ul>"
        if response.actions: body += "<b>SAFE ACTIONS:</b> " + " • ".join(escape(a) for a in response.actions[:6])
        if response.warnings: body += "<br><br><span style='color:#ffc247'><b>SAFETY:</b> " + " • ".join(escape(str(w)) for w in response.warnings) + "</span>"
        if response.suggestions: body += "<br><br><span style='color:#7ca7d8'><b>TRY:</b> " + " • ".join(escape(s) for s in response.suggestions[:4]) + "</span>"
        self.add_message(response.title, body, "ai")

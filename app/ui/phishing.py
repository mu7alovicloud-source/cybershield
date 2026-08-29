from __future__ import annotations
from PySide6.QtWidgets import QWidget,QVBoxLayout,QLabel,QLineEdit,QTextEdit,QHBoxLayout,QFrame
from app.ai.analyst import analyze_phishing_url
from app.database.database import add_incident
from app.ui.dialogs import error
from app.ui.widgets import ActionButton,StatusBadge

class Phishing(QWidget):
    def __init__(self): super().__init__(); self.build()
    def build(self):
        l=QVBoxLayout(self); l.setContentsMargins(28,22,28,18); l.setSpacing(12)
        t=QLabel('PHISHING ANALYZER'); t.setObjectName('pageTitle'); l.addWidget(t)
        s=QLabel('8-step style offline heuristic pipeline • URL ochilmaydi • typosquatting • credential lure • punycode'); s.setObjectName('pageSubtitle'); l.addWidget(s)
        top=QFrame(); top.setObjectName('panel'); tl=QHBoxLayout(top); tl.setContentsMargins(12,12,12,12); self.url=QLineEdit(); self.url.setPlaceholderText('https://example.com/login'); self.url.returnPressed.connect(self.analyze); tl.addWidget(self.url,1); b=ActionButton('URL TAHLIL','link',True); b.clicked.connect(self.analyze); tl.addWidget(b); l.addWidget(top)
        self.badge=StatusBadge('READY','info'); l.addWidget(self.badge)
        self.out=QTextEdit(); self.out.setReadOnly(True); self.out.setObjectName('analysisBox'); l.addWidget(self.out,1)
    def analyze(self):
        u=self.url.text().strip()
        if not u: self.out.setHtml('<span style="color:#ffc247">URL kiriting.</span>'); return
        try:
            r=analyze_phishing_url(u); level=r.get('level','UNKNOWN'); score=r.get('score',0); conf=r.get('confidence',0); decision=r.get('decision','MONITOR')
            state='safe' if score<35 else 'warn' if score<60 else 'danger'; self.badge.setText(f'{level} • {score}/100 • {conf:.0%}'); self.badge.set_state(state)
            reasons=r.get('reasons') or ['Kuchli phishing heuristic topilmadi.']; report=r.get('report',{})
            self.out.setHtml(f'<h2 style="color:{"#38f58d" if score<35 else "#ffc247" if score<60 else "#ff6f89"}">{level} • {score}/100</h2><p><b>Decision:</b> {decision}<br><b>Confidence:</b> {conf:.0%}</p><p><b>WHAT HAPPENED</b><br>{report.get("what_happened","—")}</p><p><b>WHY SUSPICIOUS</b><br>{report.get("why_suspicious","—")}</p><p><b>EVIDENCE</b></p><ul>{"".join(f"<li>{x}</li>" for x in reasons)}</ul><p><b>SAFE ACTION</b><br>{report.get("what_can_be_safely_done","—")}</p><p style="color:#72bfff">URL ochilmadi va unga network request yuborilmadi.</p>')
            if level in ('HIGH','CRITICAL'): add_incident(f'Potential phishing URL: {u}',level,'AI Phishing Analyzer')
        except Exception as e: error(self,'PHISHING TAHLIL XATOSI',str(e))

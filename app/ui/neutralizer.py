from __future__ import annotations

from html import escape
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton, QTextEdit, QVBoxLayout, QWidget

from app.ai.analyst import analyze_file_result
from app.security.scanner import analyze_file
from app.security.quarantine import quarantine_file
from app.ui.dialogs import confirm, error, success


class AIVirusNeutralizer(QWidget):
    """Evidence-first AI containment workspace.

    It never executes a suspicious sample and never attempts to modify malware
    bytes. High-confidence/high-risk samples can be moved to the reversible
    CyberShield quarantine vault after explicit user confirmation.
    """
    def __init__(self):
        super().__init__()
        self.path = None
        self.result = None
        self.ai = None
        self.build()

    def build(self):
        root = QVBoxLayout(self); root.setContentsMargins(28, 22, 28, 18); root.setSpacing(12)
        title = QLabel("AI VIRUS NEUTRALIZER"); title.setObjectName("pageTitle"); root.addWidget(title)
        sub = QLabel("AI evidence analysis → risk decision → safe containment. Suspicious files are never executed."); sub.setObjectName("pageSubtitle"); root.addWidget(sub)

        actions = QHBoxLayout(); actions.setSpacing(8)
        self.pick = QPushButton("FAYL TANLASH"); self.pick.setObjectName("primaryButton"); self.pick.clicked.connect(self.choose); actions.addWidget(self.pick)
        self.scan = QPushButton("AI + STATIC SCAN"); self.scan.setEnabled(False); self.scan.clicked.connect(self.analyze); actions.addWidget(self.scan)
        self.contain = QPushButton("ZARARSIZLANTIRISH / KARANTIN"); self.contain.setEnabled(False); self.contain.clicked.connect(self.contain_file); actions.addWidget(self.contain)
        actions.addStretch()
        self.status = QLabel("READY"); self.status.setObjectName("statusBadge"); actions.addWidget(self.status)
        root.addLayout(actions)

        info = QFrame(); info.setObjectName("panel"); il = QHBoxLayout(info)
        self.file_label = QLabel("Fayl tanlanmagan"); self.file_label.setObjectName("panelTitle"); il.addWidget(self.file_label, 1)
        self.score = QLabel("RISK: —"); self.score.setObjectName("panelTitle"); il.addWidget(self.score)
        root.addWidget(info)

        body = QHBoxLayout(); body.setSpacing(10)
        left = QFrame(); left.setObjectName("panel"); ll = QVBoxLayout(left)
        ll.addWidget(QLabel("AI DECISION", objectName="panelTitle"))
        self.report = QTextEdit(); self.report.setReadOnly(True); self.report.setObjectName("analysisBox"); ll.addWidget(self.report, 1)
        body.addWidget(left, 3)

        right = QFrame(); right.setObjectName("panel"); rl = QVBoxLayout(right)
        rl.addWidget(QLabel("CONTAINMENT PIPELINE", objectName="panelTitle"))
        for text in ("1  Static evidence collection", "2  AI risk + confidence", "3  User-confirmed quarantine", "4  SHA-256 integrity verification", "5  Reversible vault storage"):
            lab = QLabel(text); lab.setWordWrap(True); rl.addWidget(lab)
        rl.addStretch()
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setValue(0); rl.addWidget(self.progress)
        self.warning = QLabel("Host execution: BLOCKED"); self.warning.setStyleSheet("color:#27f28a;font-weight:900"); rl.addWidget(self.warning)
        body.addWidget(right, 2)
        root.addLayout(body, 1)

    def choose(self):
        path, _ = QFileDialog.getOpenFileName(self, "CyberShield — Fayl tanlang", options=QFileDialog.Option.DontUseNativeDialog)
        if not path: return
        self.path = path; self.result = None; self.ai = None
        self.file_label.setText(path); self.score.setText("RISK: —"); self.status.setText("READY"); self.scan.setEnabled(True); self.contain.setEnabled(False); self.progress.setValue(0)
        self.report.setHtml("<b style='color:#55b8ff'>Tayyor.</b><br>AI + STATIC SCAN tugmasini bosing. Namuna ishga tushirilmaydi.")

    def analyze(self):
        if not self.path: return
        try:
            self.status.setText("ANALYZING…"); self.progress.setValue(20)
            self.result = analyze_file(self.path); self.progress.setValue(60)
            self.ai = analyze_file_result(self.result); self.progress.setValue(100)
            score = int(self.ai.get("score", 0)); level = str(self.ai.get("level", "UNKNOWN"))
            self.score.setText(f"RISK: {score}/100 • {level}")
            self.status.setText(f"{level} • {self.ai.get('confidence', 0):.0%}")
            self.contain.setEnabled(score >= 70 and float(self.ai.get("confidence", 0)) >= .90)
            r = self.ai.get("report", {})
            reasons = self.ai.get("reasons", []) or self.result.get("indicators", [])
            color = "#27f28a" if score < 40 else "#ffc247" if score < 70 else "#ff4f6d"
            self.report.setHtml(f"""
            <h2 style='color:{color}'>{escape(level)} • {score}/100</h2>
            <p><b>Confidence:</b> {float(self.ai.get('confidence',0)):.0%}<br><b>SHA-256:</b> <code>{escape(str(self.result.get('sha256','—')))}</code></p>
            <p><b>AI DECISION</b><br>{escape(str(self.ai.get('decision','REVIEW')))}</p>
            <p><b>WHY</b><br>{escape(str(r.get('why_suspicious','No strong indicator.')))}</p>
            <p><b>SAFE RESPONSE</b><br>{escape(str(r.get('what_can_be_safely_done','Monitor and review.')))}</p>
            <ul>{''.join('<li>'+escape(str(x))+'</li>' for x in reasons[:12])}</ul>
            <p style='color:#7ca7d8'>Execution performed: FALSE • Generic malware byte modification: NEVER • Quarantine: reversible</p>
            """)
        except Exception as exc:
            self.status.setText("ERROR"); self.contain.setEnabled(False); error(self, "AI TAHLIL XATOSI", str(exc))

    def contain_file(self):
        if not self.path or not self.ai: return
        score = int(self.ai.get("score", 0)); confidence = float(self.ai.get("confidence", 0))
        if score < 70 or confidence < .90: return
        if not confirm(self, "AI ZARARSIZLANTIRISHNI TASDIQLASH", "Fayl bajarilmaydi. CyberShield uni original joyidan qaytariladigan quarantine vault'iga ko‘chiradi va SHA-256 bilan tekshiradi. Davom etilsinmi?"):
            return
        try:
            self.status.setText("CONTAINING…"); self.progress.setValue(70)
            dst = quarantine_file(self.path); self.progress.setValue(100)
            self.contain.setEnabled(False); self.status.setText("CONTAINED • VERIFIED")
            success(self, "AI ZARARSIZLANTIRISH YAKUNLANDI", f"Fayl xavfsiz izolyatsiya qilindi.<br><br><b>Vault:</b> {escape(str(dst))}<br><b>SHA-256:</b> {escape(str(self.result.get('sha256','—')))}<br><br>Asl fayl bytes o‘zgartirilmagan va amal qaytarilishi mumkin.")
        except Exception as exc:
            self.status.setText("CONTAINMENT FAILED"); error(self, "KARANTIN XATOSI", str(exc))

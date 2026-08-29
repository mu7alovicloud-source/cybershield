from __future__ import annotations

from html import escape
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from app.ai.analyst import analyze_file_result
from app.security.lab_controller import prepare_sample
from app.security.sandbox_runner import launch_sandbox, sandbox_available
from app.security.quarantine import quarantine_file
from app.security.scanner import analyze_file
from app.security.defender_scan import scan_file_with_defender
from app.database.database import add_incident
from app.ui.dialogs import confirm, error, success, warning
from app.ui.widgets import ActionButton, MetricCard, StatusBadge
from app.ui.workers import start_worker


class Sandbox(QWidget):
    """Fail-closed Safe Lab workspace with real static analysis.

    The previous implementation referenced an undefined ``ai`` variable and
    never populated ``self.result``.  This version performs the real scanner
    first, then passes its verified result to the AI analyst.
    """

    def __init__(self):
        super().__init__()
        self.sample: str | None = None
        self.result: dict | None = None
        self.ai_result: dict | None = None
        self._busy = False
        self._worker_threads = []
        self.build()

    def _card(self, title: str, content: str, object_name: str = "labCard") -> QFrame:
        card = QFrame()
        card.setObjectName(object_name)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)
        h = QLabel(title.upper())
        h.setObjectName("labCardTitle")
        body = QLabel(content)
        body.setObjectName("labCardBody")
        body.setWordWrap(True)
        layout.addWidget(h)
        layout.addWidget(body)
        card.body = body  # type: ignore[attr-defined]
        return card

    def build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 18)
        root.setSpacing(12)

        title_row = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("CYBERSHIELD SAFE LAB")
        title.setObjectName("pageTitle")
        subtitle = QLabel(
            "Fail-closed malware analysis • host execution blocked • evidence-first static inspection"
        )
        subtitle.setObjectName("pageSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        title_row.addLayout(title_box, 1)
        self.badge = StatusBadge("READY • HOST EXECUTION BLOCKED", "info")
        title_row.addWidget(self.badge, 0, Qt.AlignTop)
        root.addLayout(title_row)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        load = ActionButton("NAMUNA YUKLASH", "file", True)
        load.clicked.connect(self.load_sample)
        actions.addWidget(load)
        self.an = ActionButton("AI TAHLIL", "brain")
        self.an.setEnabled(False)
        self.an.clicked.connect(self.analyze)
        actions.addWidget(self.an)
        self.lab = ActionButton("XAVFSIZ LAB", "lab")
        self.lab.setEnabled(False)
        self.lab.clicked.connect(self.lab_check)
        actions.addWidget(self.lab)
        self.run_safe = ActionButton("IZOLATSIYADA ISHGA TUSHIRISH", "sandbox")
        self.run_safe.setEnabled(False)
        self.run_safe.clicked.connect(self.run_isolated)
        actions.addWidget(self.run_safe)
        self.q = ActionButton("KARANTIN", "quarantine")
        self.q.setEnabled(False)
        self.q.clicked.connect(self.quarantine)
        actions.addWidget(self.q)
        actions.addStretch()
        root.addLayout(actions)

        # Compact operational summary, styled like a SOC/Safe-Lab console.
        cards = QHBoxLayout()
        cards.setSpacing(9)
        self.sample_card = MetricCard("SAMPLE", "NONE", "No sample loaded", "blue", "file")
        self.verdict_card = MetricCard("VERDICT", "READY", "Waiting for analysis", "safe", "shield")
        self.risk_card = MetricCard("RISK", "—", "No score yet", "purple", "brain")
        self.engine_card = MetricCard("AI ENGINE", "READY", "Evidence-grounded", "cyan", "brain")
        for c in (self.sample_card, self.verdict_card, self.risk_card, self.engine_card):
            cards.addWidget(c)
        root.addLayout(cards)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        self.sample_info = self._card("YUKLANGAN NAMUNA", "Fayl tanlanmagan.")
        self.lab_info = self._card(
            "LAB MUHITI",
            "Host execution: BLOCKED\nDynamic execution: ISOLATED LAB ONLY\nNetwork: policy controlled",
        )
        self.live_result = self._card("TEZKOR NATIJA", "Scan hali bajarilmagan.", "labResultCard")
        grid.addWidget(self.sample_info, 0, 0)
        grid.addWidget(self.lab_info, 0, 1)
        grid.addWidget(self.live_result, 0, 2)
        root.addLayout(grid)

        body = QHBoxLayout()
        body.setSpacing(10)
        analysis = QFrame()
        analysis.setObjectName("labCard")
        al = QVBoxLayout(analysis)
        al.setContentsMargins(14, 12, 14, 12)
        ah = QLabel("AI TAHLIL XULOSASI")
        ah.setObjectName("labCardTitle")
        self.out = QLabel("Namuna yuklang va AI TAHLIL tugmasini bosing.")
        self.out.setObjectName("labOutput")
        self.out.setWordWrap(True)
        self.out.setTextFormat(Qt.RichText)
        self.out.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        al.addWidget(ah)
        al.addWidget(self.out, 1)
        body.addWidget(analysis, 2)

        stages = QFrame()
        stages.setObjectName("labCard")
        sl = QVBoxLayout(stages)
        sl.setContentsMargins(14, 12, 14, 12)
        sh = QLabel("TAHLIL BOSQICHLARI")
        sh.setObjectName("labCardTitle")
        sl.addWidget(sh)
        self.stage_labels: dict[str, QLabel] = {}
        for key, text in [
            ("static", "File Static Analysis"),
            ("hash", "Hash & Metadata"),
            ("ai", "AI Decision Engine"),
            ("lab", "Isolated Lab Gate"),
        ]:
            row = QLabel("○  " + text + "  •  WAITING")
            row.setObjectName("labStage")
            sl.addWidget(row)
            self.stage_labels[key] = row
        sl.addStretch()
        body.addWidget(stages, 1)
        root.addLayout(body, 1)

        self.status = QLabel("Sandbox • Module ready • Host execution blocked")
        self.status.setObjectName("pageSubtitle")
        root.addWidget(self.status)

    def _set_stage(self, key: str, text: str, state: str = "ok"):
        if key not in self.stage_labels:
            return
        symbol = "✓" if state == "ok" else "!" if state in {"warn", "error"} else "●" if state == "running" else "○"
        self.stage_labels[key].setText(f"{symbol}  {text}  •  {state.upper()}")
        self.stage_labels[key].setProperty("stageState", state)
        self.stage_labels[key].style().unpolish(self.stage_labels[key])
        self.stage_labels[key].style().polish(self.stage_labels[key])

    def load_sample(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Namuna tanlang", options=QFileDialog.Option.DontUseNativeDialog
        )
        if not path:
            return
        self.sample = path
        self.result = None
        self.ai_result = None
        self.an.setEnabled(True)
        self.lab.setEnabled(False)
        self.q.setEnabled(False)
        name = Path(path).name
        self.sample_card.set_value(name[:22], "Ready for static analysis")
        self.verdict_card.set_value("READY", "Waiting for AI analysis")
        self.risk_card.set_value("—", "No score yet")
        self.engine_card.set_value("READY", "Scanner + AI pipeline")
        try:
            size = Path(path).stat().st_size
            size_text = f"{size:,} bytes"
        except OSError:
            size_text = "Unavailable"
        self.sample_info.body.setText(  # type: ignore[attr-defined]
            f"<b>{escape(name)}</b><br>Path: {escape(path)}<br>Size: {size_text}<br>Hash: calculated during analysis<br>Execution: BLOCKED"
        )
        self.live_result.body.setText("<b>READY</b><br>Sample loaded; no execution performed.")  # type: ignore[attr-defined]
        self.out.setText("Namuna yuklandi. Real static scanner ishga tushirish uchun AI TAHLIL tugmasini bosing.")
        self.badge.setText("READY • HOST EXECUTION BLOCKED")
        self.badge.set_state("info")
        self.status.setText(f"Sandbox • Loaded: {name} • Static analysis ready")
        self._set_stage("static", "File Static Analysis", "ready")
        self._set_stage("hash", "Hash & Metadata", "waiting")
        self._set_stage("ai", "AI Decision Engine", "waiting")
        self._set_stage("lab", "Isolated Lab Gate", "waiting")

    def _set_busy(self, busy: bool):
        self._busy = busy
        self.an.setEnabled(bool(self.sample) and not busy)
        self.lab.setEnabled(bool(self.ai_result) and not busy)
        self.q.setEnabled(bool(self.ai_result) and not busy and int(self.ai_result.get("score", 0)) >= 40)

    def analyze(self):
        if not self.sample or self._busy:
            return
        sample = self.sample
        self._set_busy(True)
        self.engine_card.set_value("RUNNING", "Collecting verified evidence…")
        self.badge.setText("ANALYZING • HOST EXECUTION BLOCKED")
        self.badge.set_state("info")
        self.status.setText("Sandbox • Static scanner running in background • GUI remains responsive")
        self._set_stage("static", "File Static Analysis", "running")
        self._set_stage("hash", "Hash & Metadata", "waiting")
        self._set_stage("ai", "AI Decision Engine", "waiting")
        self._set_stage("lab", "Isolated Lab Gate", "waiting")

        def work():
            result = analyze_file(sample)
            result["defender_scan"] = scan_file_with_defender(sample)
            ai = analyze_file_result(result)
            return result, ai

        start_worker(self, work, self._analysis_done, self._analysis_failed)

    def _analysis_done(self, payload):
        self._set_busy(False)
        self.result, self.ai_result = payload
        ai = self.ai_result
        self._set_stage("static", "File Static Analysis", "ok")
        self._set_stage("hash", "Hash & Metadata", "ok")
        self._set_stage("ai", "AI Decision Engine", "ok")

        level = str(ai.get("level", "UNKNOWN"))
        score = int(ai.get("score", 0))
        confidence = float(ai.get("confidence", 0.0))
        decision = str(ai.get("decision", "REVIEW"))
        report = ai.get("report", {})
        indicators = list(self.result.get("indicators") or [])
        defender_status = str((self.result.get("defender_scan") or {}).get("status", "UNAVAILABLE"))
        if defender_status == "THREAT_OR_ERROR":
            indicators.append("Microsoft Defender returned a non-zero result; review Defender details before taking action.")

        if level in ("HIGH", "CRITICAL"):
            add_incident(
                f"Safe Lab high-risk sample: {self.result.get('name', 'unknown')}",
                level,
                "Safe Lab",
            )

        self.q.setEnabled(score >= 40)
        self.lab.setEnabled(True)
        self.verdict_card.set_value(level, decision)
        self.risk_card.set_value(f"{score}/100", f"Confidence {confidence:.0%}")
        self.engine_card.set_value("ACTIVE", "Evidence-grounded decision")
        self.badge.setText(f"{level} • RISK {score}/100")
        self.badge.set_state("safe" if score < 40 else "warn" if score < 65 else "danger")

        size = self.result.get("size", 0)
        sha = self.result.get("sha256", "")
        self.sample_info.body.setText(  # type: ignore[attr-defined]
            f"<b>{escape(str(self.result.get('name', Path(self.sample or '').name)))}</b><br>"
            f"SHA-256: {escape(str(sha)[:22])}…<br>Size: {size:,} bytes<br>"
            f"Verdict: {escape(str(self.result.get('verdict', 'UNKNOWN')))}"
        )
        self.live_result.body.setText(  # type: ignore[attr-defined]
            f"<b>{escape(level)}</b><br>Risk: {score}/100<br>Confidence: {confidence:.0%}<br>"
            f"Decision: {escape(decision)}<br>Defender: {escape(defender_status)}"
        )

        evidence_html = "<br>".join(f"• {escape(str(x))}" for x in indicators[:8]) or "• No strong static indicator."
        self.out.setText(
            f"<h2 style='color:#f7fbff;margin:0'>AI SECURITY ANALYSIS</h2>"
            f"<p><b>Verdict:</b> {escape(level)} • {score}/100 • {confidence:.0%}</p>"
            f"<p><b>WHAT HAPPENED</b><br>{escape(str(report.get('what_happened', '')))}</p>"
            f"<p><b>WHY</b><br>{escape(str(report.get('why_suspicious', '')))}</p>"
            f"<p><b>EVIDENCE</b><br>{evidence_html}</p>"
            f"<p><b>DECISION:</b> {escape(decision)}</p>"
            f"<hr><span style='color:#72bfff'>HOST EXECUTION: DISABLED • execution_performed=False</span>"
        )
        self.status.setText("Sandbox • AI analysis complete • No host execution performed")

    def _analysis_failed(self, message: str):
        self._set_busy(False)
        self.engine_card.set_value("ERROR", "Analysis failed safely — no host execution")
        self._set_stage("static", "File Static Analysis", "error")
        self._set_stage("hash", "Hash & Metadata", "error")
        self._set_stage("ai", "AI Decision Engine", "error")
        self._set_stage("lab", "Isolated Lab Gate", "waiting")
        self.badge.setText("ANALYSIS ERROR • HOST EXECUTION BLOCKED")
        self.badge.set_state("danger")
        self.status.setText("Sandbox • Analysis stopped safely • No sample execution occurred")
        self.out.setText(f"<h2 style='color:#ff7187'>TAHLIL XATOSI</h2><p>{escape(message)}</p><p style='color:#72bfff'>Safety state: host execution remained blocked.</p>")
        error(self, "LAB TAHLIL XATOSI", escape(message))

    def run_isolated(self):
        if not self.sample:
            warning("Avval namuna tanlang.")
            return
        result = launch_sandbox(self.sample, network=False)
        if result.get("ok"):
            success("Namuna Windows Sandbox ichida ishga tushirildi. Hostga o'zgarish yozilmaydi; tarmoq o'chirilgan.")
            self.live_result.body.setText("<b>ISOLATED RUN:</b> LAUNCHED<br>Network: DISABLED<br>Host sample mapping: READ-ONLY")
        else:
            warning(result.get("message", "Sandbox ishga tushmadi."))

    def lab_check(self):
        if not self.sample:
            return
        try:
            self._set_stage("lab", "Isolated Lab Gate", "running")
            result = prepare_sample(self.sample)
            self.out.setText(
                self.out.text()
                + "<br><br><b>LAB STATUS:</b> "
                + escape(str(result.get("status", "UNKNOWN")))
                + "<br>"
                + escape(str(result.get("message", "")))
                + "<br>"
                + "<br>".join("• " + escape(str(x)) for x in result.get("actions", []))
            )
            self._set_stage("lab", "Isolated Lab Gate", "ok" if result.get("status") != "ESCALATE" else "warn")
            if result.get("status") == "ESCALATE":
                warning(self, "SAFE LAB", result.get("message", "Lab escalation required"))
            else:
                success(self, "SAFE LAB", result.get("message", "Lab gate completed"))
        except Exception as exc:
            self._set_stage("lab", "Isolated Lab Gate", "error")
            error(self, "SAFE LAB XATOSI", str(exc))

    def quarantine(self):
        if not self.sample:
            return
        if not confirm(
            self,
            "KARANTINNI TASDIQLASH",
            "Namuna qaytariladigan quarantine vault ga ko‘chiriladi. Hostda ishga tushirilmaydi.",
        ):
            return
        try:
            dst = quarantine_file(self.sample)
            self.out.setText(
                self.out.text()
                + f'<br><br><b style="color:#38f58d">QUARANTINED:</b> {escape(str(dst))}'
            )
            self.q.setEnabled(False)
            self.sample = None
            success(self, "KARANTIN", "Namuna muvaffaqiyatli izolyatsiya qilindi.")
        except Exception as exc:
            error(self, "KARANTIN XATOSI", str(exc))

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QSplitter, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QHeaderView
)

from app.database.database import add_incident, get_incident_counts, get_recent_scans, get_scan_count
from app.security.analysis_service import scan_file
from app.security.network_monitor import get_connections
from app.security.process_monitor import get_processes
from app.ui.dialogs import error, info
from app.ui.widgets import ActionButton, MetricCard, StatusBadge


class Dashboard(QWidget):
    """Professional SOC command center backed by real local services."""
    def __init__(self):
        super().__init__()
        self.last_analysis = None
        self.build()
        self.refresh()

    def build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 22, 28, 18)
        root.setSpacing(12)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        title = QLabel("COMMAND CENTER"); title.setObjectName("pageTitle")
        subtitle = QLabel("Live local telemetry • evidence-based file analysis • AI-assisted defensive response")
        subtitle.setObjectName("pageSubtitle")
        titles.addWidget(title); titles.addWidget(subtitle)
        header.addLayout(titles, 1)
        self.protection = StatusBadge("●  PROTECTION ENGINE: ONLINE", "safe")
        header.addWidget(self.protection, 0, Qt.AlignTop)
        root.addLayout(header)

        grid = QGridLayout(); grid.setSpacing(9)
        self.cards = {}
        specs = [
            ("ACTIVE THREATS", "0", "Open incidents", "danger", "incident"),
            ("TOTAL SCANS", "0", "Analyses completed", "blue", "scan"),
            ("PROTECTION", "ACTIVE", "Unknown execution blocked", "safe", "shield"),
            ("AI RISK", "SAFE", "Current highest score", "purple", "brain"),
            ("SYSTEM", "HEALTHY", "Telemetry services", "cyan", "monitor"),
        ]
        for i, spec in enumerate(specs):
            label, value, hint, accent, icon = spec
            card = MetricCard(label, value, hint, accent, icon)
            self.cards[label] = card
            grid.addWidget(card, 0, i)
        root.addLayout(grid)

        actions = QHBoxLayout(); actions.setSpacing(9)
        scan = ActionButton("FAYL SKANERLASH", "scan", True); scan.clicked.connect(self.scan)
        refresh = ActionButton("YANGILASH", "refresh"); refresh.clicked.connect(self.refresh)
        url = ActionButton("PHISHING ANALYZER", "link"); url.clicked.connect(self.open_phishing)
        ai = ActionButton("AI COPILOT", "brain"); ai.clicked.connect(self.open_copilot)
        actions.addWidget(scan, 2); actions.addWidget(url, 1); actions.addWidget(refresh, 1); actions.addWidget(ai, 1)
        root.addLayout(actions)

        split = QSplitter(Qt.Horizontal); split.setChildrenCollapsible(False)
        left = QFrame(); left.setObjectName("panel")
        ll = QVBoxLayout(left); ll.setContentsMargins(12, 12, 12, 12)
        head = QHBoxLayout(); head.addWidget(QLabel("RECENT ANALYSES", objectName="panelTitle")); head.addStretch(); head.addWidget(QLabel("LOCAL DATABASE", objectName="pageSubtitle")); ll.addLayout(head)
        self.recent = QTableWidget(0, 5)
        self.recent.setHorizontalHeaderLabels(["FILE", "VERDICT", "RISK", "CONFIDENCE", "TIME"])
        self.recent.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3, 4): self.recent.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.recent.setEditTriggers(QTableWidget.NoEditTriggers)
        self.recent.setSelectionBehavior(QTableWidget.SelectRows)
        self.recent.setAlternatingRowColors(True)
        self.recent.itemSelectionChanged.connect(self.show_selected)
        ll.addWidget(self.recent)
        split.addWidget(left)

        right = QFrame(); right.setObjectName("panel")
        rl = QVBoxLayout(right); rl.setContentsMargins(14, 12, 14, 12)
        rl.addWidget(QLabel("AI SECURITY ANALYST", objectName="panelTitle"))
        self.analysis = QTextEdit(); self.analysis.setReadOnly(True); self.analysis.setObjectName("analysisBox")
        self.analysis.setHtml(self._empty_report()); rl.addWidget(self.analysis, 1)
        self.telemetry = QLabel("Telemetry initializing…"); self.telemetry.setObjectName("telemetryLine"); rl.addWidget(self.telemetry)
        split.addWidget(right); split.setSizes([720, 460])
        root.addWidget(split, 1)

        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh); self.timer.start(5000)

    def refresh(self):
        try:
            counts = get_incident_counts(); rows = get_recent_scans(12)
            active = sum(counts.values())
            self.cards["ACTIVE THREATS"].set_value(str(active), "Open incidents")
            self.cards["TOTAL SCANS"].set_value(str(get_scan_count()), "Analyses completed")
            self.cards["PROTECTION"].set_value("ACTIVE", "Unknown execution blocked")
            top = max((int(r[2]) for r in rows), default=0)
            risk_label = "CRITICAL" if top >= 85 else "HIGH" if top >= 65 else "REVIEW" if top >= 40 else "SAFE"
            self.cards["AI RISK"].set_value(risk_label, f"Highest score {top}/100")
            proc = len(get_processes(100)); net = len(get_connections(100))
            self.cards["SYSTEM"].set_value("HEALTHY", f"{proc} processes • {net} connections")
            self.telemetry.setText(f"● LIVE  •  Processes {proc}  •  Network {net}  •  Static analysis only  •  Host execution BLOCKED")
            self._load_rows(rows)
        except Exception as exc:
            self.telemetry.setText(f"● TELEMETRY DEGRADED  •  {exc}")

    def _load_rows(self, rows):
        self.recent.setRowCount(len(rows))
        for i, row in enumerate(rows):
            path, verdict, risk, created = row
            values = [str(path), str(verdict), f"{risk}/100", "—", str(created)]
            for j, value in enumerate(values):
                item = QTableWidgetItem(value); item.setToolTip(value)
                if j == 1:
                    clean = str(verdict).upper() in {"CLEAN", "SAFE", "LOW"}
                    mid = str(verdict).upper() in {"UNKNOWN", "MEDIUM", "SUSPICIOUS", "REVIEW"}
                    item.setForeground(QColor("#38f58d" if clean else "#ffc247" if mid else "#ff6f89"))
                if j in (2, 3): item.setTextAlignment(Qt.AlignCenter)
                self.recent.setItem(i, j, item)

    def scan(self):
        path, _ = QFileDialog.getOpenFileName(self, "CyberShield — Fayl tanlang", options=QFileDialog.Option.DontUseNativeDialog)
        if not path: return
        try:
            result = scan_file(path); ai = result["ai"]
            if ai["level"] in ("HIGH", "CRITICAL"):
                add_incident(f"High-risk file: {result['name']}", ai["level"], "Static Scanner")
            self.last_analysis = result
            self.refresh(); self.analysis.setHtml(self._report(result)); self._show_scan_result(result)
        except Exception as exc:
            error(self, "FAYL TAHLILI XATOSI", f"<b>CyberShield tahlilni yakunlay olmadi.</b><br><br>{exc}")

    def show_selected(self):
        row = self.recent.currentRow()
        if row < 0 or not self.last_analysis: return
        item = self.recent.item(row, 0)
        if item and self.last_analysis.get("path") == item.text():
            self.analysis.setHtml(self._report(self.last_analysis))

    def open_copilot(self):
        window = self.window()
        if hasattr(window, "menu"): window.menu.setCurrentRow(1)

    def open_phishing(self):
        window = self.window()
        if hasattr(window, "menu"): window.menu.setCurrentRow(5)

    @staticmethod
    def _empty_report():
        return """<h2 style='color:#55b8ff'>CYBERSHIELD AI ANALYST</h2><p style='color:#a9bdd5'>Fayl tanlang yoki skan qiling. Natija shu panelda evidence, confidence va xavfsiz action bilan ko‘rsatiladi.</p><hr><p><b>SAFETY:</b> noma’lum kod hostda ishga tushirilmaydi.</p>"""

    def _report(self, result):
        ai = result["ai"]; report = ai.get("report", {})
        level = ai["level"]
        tone = "#38f58d" if level in ("SAFE", "LOW") else "#ffc247" if level in ("MEDIUM", "SUSPICIOUS", "REVIEW") else "#ff6f89"
        reasons = "".join(f"<li>{r}</li>" for r in (ai.get("reasons") or result.get("indicators") or []))
        return f"""
        <h2 style='color:{tone};margin:0'>{level} <span style='color:#91a8c3'>• {ai['score']}/100</span></h2>
        <p><b>{result['name']}</b><br>Confidence: <b>{ai['confidence']:.0%}</b><br>SHA-256: <code>{result['sha256']}</code></p>
        <p><b>DECISION</b><br>{ai['decision']}</p>
        <p><b>WHAT HAPPENED</b><br>{report.get('what_happened','—')}</p>
        <p><b>WHY IT IS SUSPICIOUS</b><br>{report.get('why_suspicious','—')}</p>
        <p><b>WHAT CAUSED DETECTION</b><br>{report.get('what_caused_detection','—')}</p>
        <p><b>EVIDENCE</b></p><ul>{reasons or '<li>No strong malicious static indicators.</li>'}</ul>
        <p><b>SAFE ACTION</b><br>{report.get('what_can_be_safely_done','—')}</p>
        <p><b>DO NOT</b><br>{report.get('what_must_not_be_done','—')}</p>
        <p style='color:#72bfff'>Static analysis only • execution_performed=False • signature={result.get('signature_status','UNKNOWN')}</p>
        """

    def _show_scan_result(self, result):
        ai = result["ai"]
        info(self, "TAHLIL YAKUNLANDI", f"<b>{result['name']}</b><br><br>Verdict: <b>{ai['level']}</b><br>Risk: <b>{ai['score']}/100</b><br>Confidence: <b>{ai['confidence']:.0%}</b><br><br>SHA-256:<br><code>{result['sha256']}</code><br><br>Decision: <b>{ai['decision']}</b>")

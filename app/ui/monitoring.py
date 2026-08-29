from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QHeaderView
)
from PySide6.QtCore import QTimer, Qt
from app.security.process_monitor import get_processes
from app.security.network_monitor import get_connections


class Monitoring(QWidget):
    def __init__(self):
        super().__init__()
        self.build()
        self.refresh()

    def build(self):
        l = QVBoxLayout(self)
        l.setContentsMargins(30, 30, 30, 30)
        l.setSpacing(14)

        t = QLabel("LIVE MONITORING")
        t.setObjectName("pageTitle")
        l.addWidget(t)
        subtitle = QLabel("Read-only telemetry from the local machine.")
        subtitle.setObjectName("pageSubtitle")
        l.addWidget(subtitle)

        row = QHBoxLayout()
        b = QPushButton("↻  REFRESH NOW")
        b.setObjectName("primaryButton")
        b.clicked.connect(self.refresh)
        row.addWidget(b)
        self.state = QLabel()
        self.state.setObjectName("liveState")
        row.addWidget(self.state)
        row.addStretch()
        l.addLayout(row)

        tabs = QTabWidget()
        tabs.setObjectName("monitorTabs")
        self.proc = QTableWidget(0, 6)
        self.proc.setHorizontalHeaderLabels(["PID", "Name", "Status", "CPU %", "RAM %", "Executable"])
        self.net = QTableWidget(0, 6)
        self.net.setHorizontalHeaderLabels(["PID", "Family", "Type", "Local", "Remote", "Status"])
        for table in (self.proc, self.net):
            table.setAlternatingRowColors(True)
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.verticalHeader().setVisible(False)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
            table.setShowGrid(False)
        tabs.addTab(self.proc, "Processes")
        tabs.addTab(self.net, "Network Connections")
        l.addWidget(tabs, 1)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(4000)

    @staticmethod
    def _item(value):
        item = QTableWidgetItem(str(value))
        item.setForeground(Qt.GlobalColor.white)
        return item

    def refresh(self):
        ps = get_processes(100)
        self.proc.setRowCount(len(ps))
        for i, p in enumerate(ps):
            values = [p["pid"], p["name"], p["status"], p["cpu"], p["memory"], p["exe"]]
            for j, v in enumerate(values):
                self.proc.setItem(i, j, self._item(v))

        cs = get_connections(100)
        self.net.setRowCount(len(cs))
        for i, c in enumerate(cs):
            values = [c["pid"], c["family"], c["type"], c["local"], c["remote"], c["status"]]
            for j, v in enumerate(values):
                self.net.setItem(i, j, self._item(v))

        self.state.setText(f"● LIVE  •  {len(ps)} processes  •  {len(cs)} connections")

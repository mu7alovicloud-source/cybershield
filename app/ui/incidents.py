from __future__ import annotations
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QWidget,QVBoxLayout,QLabel,QTableWidget,QTableWidgetItem,QPushButton,QHBoxLayout,QComboBox
from app.database.database import get_incidents

class Incidents(QWidget):
    def __init__(self): super().__init__(); self.build(); self.load()
    def build(self):
        l=QVBoxLayout(self); l.setContentsMargins(28,22,28,18); l.setSpacing(12); t=QLabel('INCIDENT RESPONSE'); t.setObjectName('pageTitle'); l.addWidget(t)
        l.addWidget(QLabel('Evidence, severity, source and lifecycle status.',objectName='pageSubtitle'))
        row=QHBoxLayout(); self.filter=QComboBox(); self.filter.addItems(['All','CRITICAL','HIGH','MEDIUM','LOW']); row.addWidget(self.filter); b=QPushButton('↻ REFRESH'); b.clicked.connect(self.load); row.addWidget(b); row.addStretch(); l.addLayout(row)
        self.table=QTableWidget(0,6); self.table.setHorizontalHeaderLabels(['ID','TITLE','SEVERITY','SOURCE','STATUS','CREATED']); self.table.setAlternatingRowColors(True); self.table.setSelectionBehavior(QTableWidget.SelectRows); self.table.setEditTriggers(QTableWidget.NoEditTriggers); l.addWidget(self.table,1)
    def load(self):
        rows=get_incidents(); wanted=self.filter.currentText(); rows=[r for r in rows if wanted=='All' or r[2]==wanted]; self.table.setRowCount(len(rows))
        for i,row in enumerate(rows):
            for j,v in enumerate(row):
                item=QTableWidgetItem(str(v));
                if j==2: item.setForeground(QColor('#ff6f89' if str(v) in ('CRITICAL','HIGH') else '#ffc247' if str(v)=='MEDIUM' else '#38f58d'))
                self.table.setItem(i,j,item)
        self.table.resizeColumnsToContents()

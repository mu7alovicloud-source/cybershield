from PySide6.QtWidgets import QWidget,QVBoxLayout,QLabel,QPushButton,QTableWidget,QTableWidgetItem,QTabWidget
from app.security.process_monitor import get_processes
from app.security.network_monitor import get_local_network_info,get_connections
class Forensics(QWidget):
    def __init__(self): super().__init__(); self.build(); self.refresh()
    def build(self):
        l=QVBoxLayout(self); l.setContentsMargins(30,30,30,30); t=QLabel('DIGITAL FORENSICS'); t.setObjectName('pageTitle'); l.addWidget(t)
        self.info=QLabel(); l.addWidget(self.info); b=QPushButton('↻ REFRESH SNAPSHOT'); b.clicked.connect(self.refresh); l.addWidget(b)
        tabs=QTabWidget(); self.proc=QTableWidget(0,7); self.proc.setHorizontalHeaderLabels(['PID','Name','User','Status','CPU%','RAM%','Executable']); self.net=QTableWidget(0,6); self.net.setHorizontalHeaderLabels(['PID','Family','Type','Local','Remote','Status']); tabs.addTab(self.proc,'Processes'); tabs.addTab(self.net,'Network'); l.addWidget(tabs)
    def refresh(self):
        n=get_local_network_info(); self.info.setText(f"Hostname: {n['hostname']}   •   Local IP: {n['ip']}   •   Interfaces: {len(n['interfaces'])}")
        ps=get_processes(150); self.proc.setRowCount(len(ps))
        for i,p in enumerate(ps):
            vals=[p['pid'],p['name'],p['user'],p['status'],p['cpu'],p['memory'],p['exe']]
            for j,v in enumerate(vals): self.proc.setItem(i,j,QTableWidgetItem(str(v)))
        cs=get_connections(150); self.net.setRowCount(len(cs))
        for i,c in enumerate(cs):
            for j,v in enumerate([c['pid'],c['family'],c['type'],c['local'],c['remote'],c['status']]): self.net.setItem(i,j,QTableWidgetItem(str(v)))

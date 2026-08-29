"""CyberShield desktop application entry point."""
from __future__ import annotations

import sys
import os
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QFrame, QHBoxLayout, QLabel, QListWidget, QMainWindow, QStackedWidget, QStatusBar, QVBoxLayout, QWidget, QSystemTrayIcon, QMenu

from app.config import APP_NAME, APP_VERSION, APP_DESCRIPTION, APP_RELEASE_CHANNEL, ensure_runtime_ready
from app.database.database import initialize_database
from app.ui.ai_copilot import AICopilot
from app.ui.dashboard import Dashboard
from app.ui.forensic import Forensics
from app.ui.incidents import Incidents
from app.ui.malware import Malware
from app.ui.neutralizer import AIVirusNeutralizer
from app.ui.monitoring import Monitoring
from app.ui.phishing import Phishing
from app.ui.sandbox import Sandbox
from app.ui.settings import Settings
from app.ui.theme import app_stylesheet, icon_path
from app.i18n import get_language, tr, translate_tree
from app.security.background_guard import BackgroundProtection


class CyberShield(QMainWindow):
    """Premium SOC shell with a responsive icon-first navigation rail."""
    MENU = [
        ("Command Center", "home"),
        ("AI Security Copilot", "brain"),
        ("Live Monitoring", "monitor"),
        ("Incidents", "incident"),
        ("Malware Lab", "lab"),
        ("AI Virus Neutralizer", "shield"),
        ("Phishing Analyzer", "phishing"),
        ("Sandbox", "sandbox"),
        ("Forensics", "forensic"),
        ("Settings", "settings"),
    ]

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — Security Operations Center")
        self.setWindowIcon(QIcon(str(icon_path("shield"))))
        self.resize(1600, 960)
        self.setMinimumSize(1000, 680)
        self._expanded_sidebar = True
        self._build()
        self._start_background_protection()
        self.setStyleSheet(app_stylesheet())
        self._set_responsive(self.width())

    def _build(self):
        root = QWidget(); self.setCentralWidget(root)
        layout = QHBoxLayout(root); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)

        self.sidebar = QFrame(); self.sidebar.setObjectName("sidebar"); self.sidebar.setFixedWidth(250)
        sl = QVBoxLayout(self.sidebar); sl.setContentsMargins(13, 16, 13, 13); sl.setSpacing(5)
        logo = QLabel("🛡  CYBERSHIELD"); logo.setObjectName("logo"); sl.addWidget(logo)
        tag = QLabel("SECURITY OPERATIONS CENTER"); tag.setObjectName("sideTag"); sl.addWidget(tag)

        self.menu = QListWidget(); self.menu.setObjectName("menu")
        for text, icon in self.MENU:
            from PySide6.QtWidgets import QListWidgetItem
            item = QListWidgetItem(QIcon(icon_path(icon)), tr(text, get_language()))
            item.setData(Qt.UserRole, text)
            item.setToolTip(tr(text, get_language()))
            self.menu.addItem(item)
        self.menu.currentRowChanged.connect(self._navigate)
        sl.addWidget(self.menu, 1)

        online = QLabel("●  PROTECTION ENGINE ONLINE"); online.setObjectName("online"); sl.addWidget(online)
        version = QLabel(f"{APP_NAME} {APP_VERSION} • {APP_RELEASE_CHANNEL.upper()} MODE • {APP_DESCRIPTION}"); version.setObjectName("pageSubtitle"); sl.addWidget(version)
        layout.addWidget(self.sidebar)

        self.pages = QStackedWidget()
        self.page_objects = [
            Dashboard(), AICopilot(), Monitoring(), Incidents(), Malware(), AIVirusNeutralizer(),
            Phishing(), Sandbox(), Forensics(), Settings()
        ]
        for page in self.page_objects: self.pages.addWidget(page)
        layout.addWidget(self.pages, 1)
        self.settings_page = self.page_objects[-1]
        self.page_objects[1].engine.set_desktop_controller(self)
        self.settings_page.languageChanged.connect(self._on_language_changed)

        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage(tr("CyberShield protection engine online • host execution of unknown samples blocked"))
        self.menu.setCurrentRow(0)
        self._apply_language(get_language())

    def open_panel(self, name: str) -> bool:
        """Navigate only to a known CyberShield panel."""
        wanted = str(name).strip().lower()
        for i, (label, _icon) in enumerate(self.MENU):
            if label.lower() == wanted:
                self.menu.setCurrentRow(i)
                self.pages.setCurrentIndex(i)
                self.raise_(); self.activateWindow()
                return True
        return False

    def set_setting(self, name: str, value: bool) -> bool:
        """Change only reversible, allowlisted Settings controls."""
        settings = getattr(self, "settings_page", None)
        if settings is None:
            return False
        key = str(name).strip().lower()
        if key == "protection":
            settings.protect.setChecked(bool(value))
        elif key == "auto_incident":
            settings.autoincident.setChecked(bool(value))
        else:
            return False
        self.open_panel("Settings")
        return True

    def open_safe_path(self, path: str) -> bool:
        """Open a user-named folder/document without invoking a shell or executable."""
        p = Path(path).expanduser().resolve()
        if not p.exists():
            return False
        blocked = {".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr", ".dll"}
        if p.is_file() and p.suffix.lower() in blocked:
            return False
        if os.name != "nt":
            return False
        os.startfile(str(p))
        return True

    def _start_background_protection(self):
        self.protection = BackgroundProtection(interval=2.5)
        self.protection.start()
        self.tray = QSystemTrayIcon(self)
        tray_icon = QIcon(str(icon_path("shield")))
        if not tray_icon.isNull():
            self.tray.setIcon(tray_icon)
        self.tray.setToolTip("CyberShield — Quiet Protection Active")
        menu = QMenu()
        menu.addAction("Open CyberShield").triggered.connect(self.showNormal)
        menu.addAction("Protection: ON").setEnabled(False)
        menu.addAction("Exit").triggered.connect(self._safe_exit)
        self.tray.setContextMenu(menu)
        if QSystemTrayIcon.isSystemTrayAvailable(): self.tray.show()

    def closeEvent(self, event):
        if getattr(self, "_allow_exit", False):
            self.protection.stop(); event.accept(); return
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.hide(); self.tray.showMessage("CyberShield", "Protection continues in the background.", QSystemTrayIcon.Information, 2500); event.ignore()
        else:
            self._allow_exit=True; self.protection.stop(); event.accept()

    def _safe_exit(self):
        self._allow_exit=True
        self.protection.stop()
        QApplication.quit()

    def _navigate(self, index: int):
        if index >= 0:
            self.pages.setCurrentIndex(index)
            title = self.MENU[index][0]
            self.statusBar().showMessage(f"{tr(title)} • {tr('Module ready')}")

    def _on_language_changed(self, code: str):
        self._apply_language(code)

    def _apply_language(self, code: str):
        for i, (text, _icon) in enumerate(self.MENU):
            item = self.menu.item(i)
            if item is not None:
                item.setText("" if self.sidebar.width() < 120 else tr(text, code))
                item.setToolTip(tr(text, code))
        translate_tree(self, code)
        if hasattr(self, "page_objects") and len(self.page_objects) > 1:
            try: self.page_objects[1].set_language(code)
            except Exception: pass
        self.setWindowTitle(f"CyberShield — {tr('SECURITY OPERATIONS CENTER', code)}")
        self.statusBar().showMessage(tr("CyberShield protection engine online • host execution of unknown samples blocked", code))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._set_responsive(event.size().width())

    def _set_responsive(self, width: int):
        compact = width < 1180
        self.sidebar.setFixedWidth(82 if compact else 250)
        for i in range(self.menu.count()):
            item = self.menu.item(i)
            text = item.data(Qt.UserRole)
            item.setText("") if compact else item.setText(tr(text, get_language()))


def main(initial_panel: str | None = None):
    try:
        ensure_runtime_ready()
    except RuntimeError as exc:
        print(f"[CyberShield] {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    initialize_database()
    app = QApplication(sys.argv)
    app.setOrganizationName("CyberShield Security")
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(f"{APP_NAME} {APP_VERSION}")
    app.setApplicationVersion(APP_VERSION)
    app.setStyle("Fusion")
    window = CyberShield()
    window.show()
    if initial_panel:
        panel_map = {
            "settings": "Settings", "home": "Command Center", "dashboard": "Command Center",
            "ai": "AI Security Copilot", "monitoring": "Live Monitoring", "incidents": "Incidents",
            "malware": "Malware Lab", "phishing": "Phishing Analyzer", "sandbox": "Sandbox",
            "forensics": "Forensics",
        }
        target = panel_map.get(str(initial_panel).lower())
        if target:
            window.open_panel(target)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

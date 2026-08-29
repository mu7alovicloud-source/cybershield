"""Dark, accessible CyberShield dialogs.

Qt's native QMessageBox can ignore parts of a custom dark stylesheet on some
Windows themes. These dialogs are fully owned by CyberShield, so no white
system dialog leaks into the dark SOC interface.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout
from app.ui.theme import COLORS


class CyberDialog(QDialog):
    def __init__(self, title: str, message: str, kind: str = "info", confirm: bool = False, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(520)
        self._confirmed = False
        self._kind = kind
        self._build(title, message, confirm)

    def _build(self, title: str, message: str, confirm: bool):
        color = {"info": COLORS["blue_bright"], "success": COLORS["green"],
                 "warning": COLORS["yellow"], "error": COLORS["red"]}.get(self._kind, COLORS["blue"])
        self.setStyleSheet(f"""
            QDialog {{ background:#08111e; color:#f8fbff; border:1px solid #2a4664; }}
            QLabel#icon {{ color:{color}; font-size:26px; font-weight:950; }}
            QLabel#title {{ color:#ffffff; font-size:16px; font-weight:950; }}
            QLabel#message {{ color:#dceaff; font-size:13px; line-height:1.5; }}
            QPushButton {{ background:#101d30; color:#ffffff; border:1px solid #3c5b7c;
                border-radius:8px; padding:9px 18px; font-weight:900; min-width:86px; }}
            QPushButton:hover {{ background:#12365f; border-color:#42a8ff; }}
            QPushButton#primary {{ background:#0b67ff; border-color:#4caeff; }}
            QPushButton#danger {{ background:#3a1420; border-color:#b63a55; color:#ffb3bf; }}
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 18)
        root.setSpacing(14)
        head = QHBoxLayout()
        icon = QLabel({"info":"●", "success":"✓", "warning":"!", "error":"×"}.get(self._kind, "●"))
        icon.setObjectName("icon")
        icon.setAlignment(Qt.AlignCenter)
        icon.setFixedWidth(38)
        head.addWidget(icon)
        title_label = QLabel(title)
        title_label.setObjectName("title")
        head.addWidget(title_label, 1)
        root.addLayout(head)
        body = QLabel(message)
        body.setObjectName("message")
        body.setTextFormat(Qt.RichText)
        body.setWordWrap(True)
        root.addWidget(body)
        buttons = QHBoxLayout()
        buttons.addStretch()
        if confirm:
            no = QPushButton("BEKOR QILISH")
            no.clicked.connect(self.reject)
            buttons.addWidget(no)
            yes = QPushButton("TASDIQLASH")
            yes.setObjectName("danger" if self._kind in ("warning", "error") else "primary")
            yes.clicked.connect(self._accept_confirm)
            buttons.addWidget(yes)
        else:
            ok = QPushButton("TUSHUNDIM")
            ok.setObjectName("primary")
            ok.clicked.connect(self.accept)
            buttons.addWidget(ok)
        root.addLayout(buttons)

    def _accept_confirm(self):
        self._confirmed = True
        self.accept()

    @property
    def confirmed(self) -> bool:
        return self._confirmed


def info(parent, title: str, message: str):
    CyberDialog(title, message, "info", False, parent).exec()


def success(parent, title: str, message: str):
    CyberDialog(title, message, "success", False, parent).exec()


def warning(parent, title: str, message: str):
    CyberDialog(title, message, "warning", False, parent).exec()


def error(parent, title: str, message: str):
    CyberDialog(title, message, "error", False, parent).exec()


def confirm(parent, title: str, message: str, danger: bool = True) -> bool:
    kind = "warning" if danger else "info"
    d = CyberDialog(title, message, kind, True, parent)
    d.exec()
    return d.confirmed

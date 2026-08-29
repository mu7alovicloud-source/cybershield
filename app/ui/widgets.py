"""Reusable CyberShield premium widgets."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout
from app.ui.theme import COLORS, icon_path


class SectionHeader(QHBoxLayout):
    def __init__(self, title: str, subtitle: str = "", icon: str | None = None):
        super().__init__()
        self.setSpacing(10)
        if icon:
            label = QLabel()
            label.setPixmap(QIcon(icon_path(icon)).pixmap(22, 22))
            self.addWidget(label)
        box = QVBoxLayout()
        t = QLabel(title)
        t.setObjectName("panelTitle")
        box.addWidget(t)
        if subtitle:
            s = QLabel(subtitle)
            s.setObjectName("pageSubtitle")
            box.addWidget(s)
        self.addLayout(box, 1)


class MetricCard(QFrame):
    def __init__(self, label: str, value: str, hint: str, accent: str = "blue", icon: str | None = None):
        super().__init__()
        self.setObjectName(f"metric_{accent}")
        root = QHBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(11)
        if icon:
            ico = QLabel()
            ico.setPixmap(QIcon(icon_path(icon)).pixmap(30, 30))
            root.addWidget(ico, 0, Qt.AlignTop)
        box = QVBoxLayout()
        a = QLabel(label.upper()); a.setObjectName("metricLabel")
        v = QLabel(value); v.setObjectName("metricValue")
        h = QLabel(hint); h.setObjectName("metricHint")
        box.addWidget(a); box.addWidget(v); box.addWidget(h)
        root.addLayout(box, 1)
        self.value_label = v
        self.hint_label = h

    def set_value(self, value: str, hint: str | None = None):
        self.value_label.setText(value)
        if hint is not None:
            self.hint_label.setText(hint)


class ActionButton(QPushButton):
    def __init__(self, text: str, icon: str | None = None, primary: bool = False, parent=None):
        super().__init__(text, parent)
        if icon:
            self.setIcon(QIcon(icon_path(icon)))
        if primary:
            self.setObjectName("primaryButton")


class StatusBadge(QLabel):
    def __init__(self, text: str = "READY", state: str = "safe"):
        super().__init__(text)
        self.setAlignment(Qt.AlignCenter)
        self.set_state(state)

    def set_state(self, state: str):
        styles = {
            "safe": (COLORS["green"], "#061d14", "#17613e"),
            "warn": (COLORS["yellow"], "#211a08", "#6d5416"),
            "danger": (COLORS["red"], "#24101a", "#793047"),
            "info": (COLORS["blue_bright"], "#071a2c", "#1e5b8c"),
        }
        fg, bg, border = styles.get(state, styles["info"])
        self.setStyleSheet(f"color:{fg}; background:{bg}; border:1px solid {border}; border-radius:12px; padding:6px 10px; font-weight:950;")

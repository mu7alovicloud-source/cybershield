"""CyberShield premium UI theme and reusable widgets.

The theme is intentionally centralized so every page uses the same contrast,
spacing, focus, disabled-state and dialog rules. No native white dialogs are
used by the application.
"""
from __future__ import annotations

from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
ICON_DIR = APP_ROOT / "assets" / "icons"

COLORS = {
    "bg": "#040912",
    "sidebar": "#07101c",
    "panel": "#091522",
    "panel_alt": "#0c1929",
    "panel_hover": "#10223a",
    "line": "#1e3855",
    "line_bright": "#315779",
    "text": "#f7fbff",
    "text_soft": "#d9e8f8",
    "muted": "#91a8c3",
    "muted_2": "#6f87a4",
    "blue": "#147cff",
    "blue_bright": "#42a8ff",
    "cyan": "#20d9ff",
    "green": "#27f28a",
    "yellow": "#ffc247",
    "red": "#ff4f6d",
    "purple": "#b36cff",
}


def app_stylesheet() -> str:
    """Return the complete high-contrast application stylesheet."""
    c = COLORS
    return f"""
    * {{ font-family: 'Segoe UI', 'Inter', sans-serif; }}
    QMainWindow, QWidget {{ background:{c['bg']}; color:{c['text']}; font-size:14px; }}
    QFrame#sidebar {{ background:{c['sidebar']}; border-right:1px solid {c['line']}; }}
    QLabel {{ color:{c['text_soft']}; }}
    QLabel#logo {{ color:{c['text']}; font-size:25px; font-weight:950; padding:5px 8px 0; }}
    QLabel#sideTag {{ color:{c['muted']}; font-size:9px; font-weight:900; letter-spacing:1.5px; padding:0 10px 12px; }}
    QLabel#pageTitle {{ color:{c['text']}; font-size:30px; font-weight:950; letter-spacing:.2px; }}
    QLabel#pageSubtitle {{ color:{c['muted']}; font-size:13px; }}
    QLabel#pageSubtitle {{ color:{c['muted']}; font-size:13px; }}
    QLabel#panelTitle {{ color:{c['text']}; font-size:12px; font-weight:950; letter-spacing:1px; }}
    QFrame#aiHero {{ background:linear-gradient(110deg,#0b1e35,#0a1525); border:1px solid #28567e; border-radius:16px; }}
    QLabel#aiOrb {{ color:#6fd2ff; background:#06223a; border:1px solid #2e9bff; border-radius:18px; min-width:36px; min-height:36px; max-width:36px; max-height:36px; font-size:22px; font-weight:950; qproperty-alignment: AlignCenter; }}
    QLabel#aiHeroTitle {{ color:#f7fbff; font-size:15px; font-weight:950; letter-spacing:1.4px; }}
    QLabel#aiHeroSub {{ color:#8fb0cf; font-size:11px; }}
    QFrame#aiTelemetry {{ background:#07111e; border:1px solid #193653; border-radius:11px; }}
    QLabel#aiTelemetryLabel {{ color:#6f89a5; font-size:9px; font-weight:950; letter-spacing:1.1px; }}
    QLabel#aiTelemetryValue {{ color:#dff3ff; font-size:12px; font-weight:950; }}
    QTextEdit#aiChat {{ background:#050d17; border:1px solid #28435f; border-radius:12px; padding:12px; selection-background-color:#1268ff; }}
    QLabel#online {{ color:{c['green']}; font-weight:950; padding:13px 10px; }}
    QLabel#statusPill {{ color:{c['green']}; background:#061d14; border:1px solid #17613e; border-radius:14px; padding:8px 13px; font-weight:900; }}
    QLabel#metricLabel {{ color:#9db4cf; font-size:10px; font-weight:950; letter-spacing:1px; }}
    QLabel#metricValue {{ color:#ffffff; font-size:23px; font-weight:950; }}
    QLabel#metricHint {{ color:#8ca5c0; font-size:11px; }}
    QFrame#panel, QFrame#card, QFrame#metric_danger, QFrame#metric_blue,
    QFrame#metric_safe, QFrame#metric_purple, QFrame#metric_cyan,
    QFrame#metric_system {{ background:linear-gradient(180deg,{c['panel_alt']},{c['panel']});
        border:1px solid {c['line']}; border-radius:14px; }}
    QFrame#panel:hover, QFrame#metric_blue:hover, QFrame#metric_safe:hover, QFrame#metric_purple:hover, QFrame#metric_cyan:hover {{ border-color:#315b80; }}
    QFrame#metric_danger {{ border-top:2px solid {c['red']}; }}
    QFrame#metric_blue {{ border-top:2px solid {c['blue']}; }}
    QFrame#metric_safe {{ border-top:2px solid {c['green']}; }}
    QFrame#metric_purple {{ border-top:2px solid {c['purple']}; }}
    QFrame#metric_cyan {{ border-top:2px solid {c['cyan']}; }}
    QFrame#metric_system {{ border-top:2px solid #6ca8ff; }}

    QListWidget#menu {{ background:transparent; border:0; outline:0; padding:5px 0; }}
    QListWidget#menu::item {{ color:#e4effb; padding:12px 13px; margin:2px 0; border-radius:9px; min-height:22px; }}
    QListWidget#menu::item:hover {{ background:#102039; color:#ffffff; }}
    QListWidget#menu::item:selected {{ background:#0d63ef; color:#ffffff; font-weight:950;
        border:1px solid #3c9dff; }}

    QPushButton {{ background:#0f1b2c; color:#f7fbff; border:1px solid #3b5776;
        border-radius:9px; padding:10px 14px; min-height:20px; font-weight:900; }}
    QPushButton:hover {{ background:#12325a; color:#ffffff; border:1px solid {c['blue_bright']}; }}
    QPushButton:pressed {{ background:#084bb5; color:#ffffff; border:1px solid #73c3ff; }}
    QPushButton:focus {{ border:2px solid #43a5ff; padding:9px 13px; }}
    QPushButton:disabled {{ background:#101a29; color:#70859f; border:1px solid #273a51; }}
    QPushButton#primaryButton {{ background:#0b67ff; color:#ffffff; border:1px solid #42a8ff;
        font-weight:950; }}
    QPushButton#primaryButton:hover {{ background:#1580ff; border:1px solid #8bd0ff; }}
    QPushButton#dangerButton {{ background:#3a1220; color:#ff9bad; border:1px solid #9c304b; }}
    QPushButton#dangerButton:hover {{ background:#551526; color:#ffffff; border:1px solid #ff5e7a; }}
    QPushButton#successButton {{ background:#08291d; color:#62f7a7; border:1px solid #1b8050; }}
    QPushButton#successButton:hover {{ background:#0b3c29; color:#ffffff; border:1px solid #37f58c; }}

    QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {{ background:#060f1b; color:#f7fbff;
        border:1px solid #3b5675; border-radius:9px; padding:9px; selection-background-color:#1268ff;
        selection-color:#ffffff; }}
    QLineEdit::placeholder, QTextEdit::placeholder {{ color:#647d99; }}
    QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border:2px solid #238dff; padding:8px; }}
    QComboBox QAbstractItemView {{ background:#0b1727; color:#f8fbff; selection-background-color:#1268ff;
        selection-color:#ffffff; border:1px solid #315779; }}

    QTableWidget {{ background:#060f1b; color:#f8fbff; alternate-background-color:#0a1625;
        border:1px solid #294462; border-radius:10px; gridline-color:#162a42;
        selection-background-color:#1158bd; selection-color:#ffffff; }}
    QTableWidget::item {{ color:#f8fbff; padding:8px; }}
    QTableWidget::item:selected {{ background:#1158bd; color:#ffffff; }}
    QHeaderView::section {{ background:#0d1929; color:#dceaff; font-weight:950; padding:10px;
        border:0; border-bottom:1px solid #34506f; }}

    QTabWidget::pane {{ background:{c['panel']}; border:1px solid {c['line']}; border-radius:10px; }}
    QTabBar::tab {{ background:#0b1727; color:#9fb3ca; padding:9px 14px; border:1px solid #1e3855; }}
    QTabBar::tab:selected {{ background:#0e3f86; color:#ffffff; border-color:#2e9bff; }}

    QScrollBar:vertical {{ background:#07101b; width:12px; margin:2px; }}
    QScrollBar::handle:vertical {{ background:#2c4562; border-radius:5px; min-height:30px; }}
    QScrollBar::handle:vertical:hover {{ background:#3f638a; }}
    QScrollBar:horizontal {{ background:#07101b; height:12px; margin:2px; }}
    QScrollBar::handle:horizontal {{ background:#2c4562; border-radius:5px; min-width:30px; }}

    QFileDialog {{ background:#08111e; color:#f7fbff; border:1px solid #2a4664; }}
    QFileDialog QLabel {{ color:#dceaff; }}
    QFileDialog QLineEdit {{ background:#060f1b; color:#f7fbff; border:1px solid #3b5675; }}
    QFileDialog QListView, QFileDialog QTreeView, QFileDialog QTableView {{ background:#060f1b; color:#f7fbff; border:1px solid #294462; }}
    QFileDialog QListView::item:selected, QFileDialog QTreeView::item:selected, QFileDialog QTableView::item:selected {{ background:#1158bd; color:#ffffff; }}
    QMessageBox {{ background:#08111e; color:#f7fbff; }}
    QMessageBox QLabel {{ color:#f7fbff; }}
    QMessageBox QPushButton {{ background:#101d30; color:#ffffff; border:1px solid #3c5b7c; border-radius:8px; padding:8px 16px; min-width:82px; }}
    QMessageBox QPushButton:hover {{ background:#12365f; border-color:#42a8ff; }}
    QToolTip {{ background:#07101c; color:#ffffff; border:1px solid #2e91ff; padding:7px; }}
    QFrame#labCard, QFrame#labResultCard {{
        background:linear-gradient(180deg,#0b1828,#08131f);
        border:1px solid #1f3b59; border-radius:14px;
    }}
    QLabel#labCardTitle {{ color:#7f9bb8; font-size:10px; font-weight:950; letter-spacing:1.2px; }}
    QLabel#labCardBody {{ color:#d9e8f8; font-size:12px; line-height:1.4; }}
    QLabel#labOutput {{ color:#dceaff; background:#06101a; border:1px solid #1d3854; border-radius:10px; padding:12px; }}
    QLabel#labStage {{ color:#8fa9c3; background:#07111c; border:1px solid #162d45; border-radius:8px; padding:9px 10px; font-size:11px; font-weight:800; }}
    QLabel#labStage[stageState="ok"] {{ color:#5cf5a5; border-color:#185d40; background:#071a13; }}
    QLabel#labStage[stageState="ready"] {{ color:#72c8ff; border-color:#1f5b8a; background:#071827; }}
    QLabel#labStage[stageState="waiting"] {{ color:#91a8c3; border-color:#21374f; background:#07111c; }}
    QLabel#labStage[stageState="running"] {{ color:#ffffff; border-color:#2e91ff; background:#0a2038; }}
    QLabel#labStage[stageState="warn"] {{ color:#ffd166; border-color:#6b5319; background:#1d1809; }}
    QLabel#labStage[stageState="error"] {{ color:#ff7187; border-color:#733044; background:#21101a; }}
    QStatusBar {{ background:{c['sidebar']}; color:#a8bdd6; border-top:1px solid {c['line']}; }}
    QCheckBox {{ color:#e9f3ff; spacing:8px; }}
    QCheckBox::indicator {{ width:18px; height:18px; border-radius:5px; border:1px solid #46627f; background:#07101b; }}
    QCheckBox::indicator:checked {{ background:#0b67ff; border-color:#54b4ff; }}
    QProgressBar {{ background:#07101b; border:1px solid #294462; border-radius:6px; text-align:center; color:#ffffff; }}
    QProgressBar::chunk {{ background:#0b67ff; border-radius:5px; }}
    QSplitter::handle {{ background:#162b43; }}
    """


def icon_path(name: str) -> str:
    return str(ICON_DIR / f"{name}.svg")

from __future__ import annotations
from PySide6.QtCore import Signal
from PySide6.QtWidgets import QWidget,QVBoxLayout,QLabel,QComboBox,QCheckBox,QFrame,QHBoxLayout
from app.database.database import get_setting,set_setting
from app.ui.widgets import StatusBadge
from app.i18n import LANGUAGES, get_language, set_language, tr

class Settings(QWidget):
    languageChanged = Signal(str)
    def __init__(self):
        super().__init__()
        self.build()

    def _label(self, key: str, object_name: str | None = None):
        w = QLabel(tr(key))
        w.setProperty('cs_i18n_source', key)
        if object_name: w.setObjectName(object_name)
        return w

    def build(self):
        l=QVBoxLayout(self); l.setContentsMargins(28,22,28,18); l.setSpacing(12)
        self.title=self._label('SETTINGS','pageTitle'); l.addWidget(self.title)
        self.subtitle=self._label('CyberShield behavior, localization and safety policy.','pageSubtitle'); l.addWidget(self.subtitle)
        card=QFrame(); card.setObjectName('panel'); cl=QVBoxLayout(card); cl.setContentsMargins(16,16,16,16)
        self.interface_title=self._label('INTERFACE','panelTitle'); cl.addWidget(self.interface_title)
        row=QHBoxLayout(); self.language_label=self._label('Language'); row.addWidget(self.language_label)
        self.lang=QComboBox()
        self.lang.addItem(LANGUAGES['uz'], 'uz'); self.lang.addItem(LANGUAGES['en'], 'en'); self.lang.addItem(LANGUAGES['ru'], 'ru')
        self.lang.setCurrentIndex({'uz':0,'en':1,'ru':2}.get(get_language(),0))
        self.lang.currentIndexChanged.connect(self._language_changed)
        row.addWidget(self.lang,1)
        self.badge=StatusBadge(tr('UZBEK-FIRST'),'info'); self.badge.setProperty('cs_i18n_source','UZBEK-FIRST'); row.addWidget(self.badge)
        cl.addLayout(row)
        self.protect=QCheckBox(tr('Protection engine enabled')); self.protect.setProperty('cs_i18n_source','Protection engine enabled'); self.protect.setChecked(get_setting('protection','1')=='1'); self.protect.toggled.connect(lambda x:set_setting('protection','1' if x else '0')); cl.addWidget(self.protect)
        self.autoincident=QCheckBox(tr('HIGH/CRITICAL aniqlansa incident yaratish')); self.autoincident.setProperty('cs_i18n_source','HIGH/CRITICAL aniqlansa incident yaratish'); self.autoincident.setChecked(get_setting('auto_incident','1')=='1'); self.autoincident.toggled.connect(lambda x:set_setting('auto_incident','1' if x else '0')); cl.addWidget(self.autoincident)
        l.addWidget(card)
        safe=QFrame(); safe.setObjectName('panel'); sl=QVBoxLayout(safe); sl.setContentsMargins(16,16,16,16)
        self.policy_title=self._label('SAFETY POLICY','panelTitle'); sl.addWidget(self.policy_title)
        policy_key='• Unknown samples hostda ishga tushirilmaydi.\n• Default remediation: containment/quarantine.\n• Evidence saqlanadi.\n• Verificationsiz “resolved” deb ko‘rsatilmaydi.\n• Qaytarib bo‘lmaydigan harakatlar confirmation talab qiladi.'
        self.policy=self._label(policy_key); self.policy.setWordWrap(True); sl.addWidget(self.policy); l.addWidget(safe)
        l.addStretch()

    def _language_changed(self, index: int):
        code = self.lang.itemData(index) or 'uz'
        set_language(code)
        self.retranslate(code)
        self.languageChanged.emit(code)

    def retranslate(self, code: str):
        self.title.setText(tr('SETTINGS',code))
        self.subtitle.setText(tr('CyberShield behavior, localization and safety policy.',code))
        self.interface_title.setText(tr('INTERFACE',code))
        self.language_label.setText(tr('Language',code))
        self.badge.setText(tr('UZBEK-FIRST',code))
        self.protect.setText(tr('Protection engine enabled',code))
        self.autoincident.setText(tr('HIGH/CRITICAL aniqlansa incident yaratish',code))
        self.policy_title.setText(tr('SAFETY POLICY',code))
        self.policy.setText(tr('• Unknown samples hostda ishga tushirilmaydi.\n• Default remediation: containment/quarantine.\n• Evidence saqlanadi.\n• Verificationsiz “resolved” deb ko‘rsatilmaydi.\n• Qaytarib bo‘lmaydigan harakatlar confirmation talab qiladi.',code))

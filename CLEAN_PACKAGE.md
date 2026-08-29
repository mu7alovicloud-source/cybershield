# CyberShield Clean Desktop Package

Bu paket CyberShield'ning asosiy Windows Desktop/SOC variantini ajratib beradi.

## Kiritilgan
- `main.py` — asosiy launcher (desktop/background/terminal)
- `app/` — asosiy GUI, AI, scanner, phishing, sandbox, monitoring, quarantine va security modullari
- `launch_cybershield.py` — desktop launcher
- EXE build fayllari va icon
- dependency fayllari
- `data/` — faqat bo'sh runtime kataloglari

## Ataylab chiqarib tashlangan
- `.git/`, `__pycache__/`, `.pytest_cache/`
- `build/`, `dist/` — eski build qoldiqlari
- `cybershield_core/`, `cybershield_ai/`, `cybershield_autonomous/` — asosiy Desktop entrypoint tomonidan import qilinmaydigan alohida/legacy parallel subsystemlar
- `server/`, `api/`, `web/` — Web/Vercel backend
- eski root `terminal.py`, `terminal_gui.py`, `disarmer.py`, `fishing_guarrd.py`, `pixel_scaner.py`
- eski test/QA paketlari va development dokumentatsiyalarining katta to'plami
- mavjud `data/cybershield.db` va sample fayllar

## Asosiy ishga tushirish
`python -m app.main`

## EXE
`BUILD_EXE_ONEFILE.ps1` yoki `BUILD_EXE.bat`

# CyberShield — Professional Real Setup

## 1. Terminal

```powershell
python -m pip install -r requirements.txt
python main.py terminal
```

Yoki Windows'da `START_CIBER.bat`.

## 2. Desktop

Desktop uchun:

```powershell
python -m pip install -r requirements-desktop.txt
python main.py desktop
```

## 3. Help

Terminal ichida:

```text
help
commands
ciber
ciber help
```

`help` — asosiy yordam. `commands` — to‘liq allowlist. `ciber help` — natural-language operator.

## 4. Real operator

`ciber` quyidagilarni xavfsiz tarzda boshqaradi:

- project/security status
- diagnostics
- deep audit
- CyberShield desktop panel navigation (GUI controller ulanganida)
- GitHub publish
- Vercel deploy
- PyInstaller EXE build

GitHub/Vercel uchun mos CLI va autentifikatsiya foydalanuvchi kompyuterida mavjud bo‘lishi kerak. Agar vosita o‘rnatilmagan yoki autentifikatsiya yo‘q bo‘lsa, CyberShield buni FAIL sifatida ko‘rsatadi; soxta PASS bermaydi.

## 5. Fallback policy

Publish/deploy amallarida 5 tagacha strategiya ketma-ket sinovdan o‘tadi. Birinchi **verified success** `passed_strategy=N` sifatida qaytariladi. Muvaffaqiyat bo‘lmasa `passed_strategy=null` va aniq sabab qaytariladi.

## 6. Safety

Free-form CMD/PowerShell/Bash/eval bajarilmaydi. Operator external tools'ni allowlist + `shell=False` + timeout + captured output bilan chaqiradi. Security namunalari hostda bevosita ishga tushirilmaydi; dynamic analysis alohida disposable sandbox/VM uchun.

## 7. Verification

Windows'da `VERIFY_CYBERSHIELD.bat` ishlating. U compile va testlarni bajaradi.

@echo off
setlocal
cd /d "%~dp0"

python -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 (
  echo API dependencies o'rnatilmadi.
  pause
  exit /b 1
)

echo CyberShield API: http://127.0.0.1:8765
python -m uvicorn api.index:app --host 127.0.0.1 --port 8765

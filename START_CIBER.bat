@echo off
setlocal
cd /d "%~dp0"
python main.py terminal
if errorlevel 1 (
  echo.
  echo CyberShield terminal stopped with an error.
  pause
)

@echo off
setlocal
cd /d "%~dp0"
python "%~dp0ensure_dependencies.py"
if errorlevel 1 (
  echo.
  echo [ERROR] Required CyberShield terminal dependencies could not be installed.
  echo [INFO] CIBER does not require yara-python.
  endlocal & exit /b 1
)
python "%~dp0main.py" ciber %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%

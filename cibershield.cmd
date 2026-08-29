@echo off
setlocal
cd /d "%~dp0"
python "%~dp0ensure_dependencies.py" --desktop
if errorlevel 1 (
  echo.
  echo [ERROR] Required CyberShield Desktop dependencies could not be installed.
  endlocal & exit /b 1
)
python "%~dp0main.py" desktop %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%

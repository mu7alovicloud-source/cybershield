@echo off
setlocal
cd /d "%~dp0"

echo ========================================
echo CyberShield - Windows EXE Builder
echo ========================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python topilmadi.
  echo Python 3.11+ o'rnating va qayta urinib ko'ring.
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0BUILD_EXE_ONEFILE.ps1"
if errorlevel 1 (
  echo.
  echo ========================================
  echo BUILD FAILED
  echo ========================================
  pause
  exit /b 1
)

echo.
echo ========================================
echo BUILD SUCCESSFUL
 echo EXE: %~dp0dist\CyberShield.exe
 echo ========================================
pause

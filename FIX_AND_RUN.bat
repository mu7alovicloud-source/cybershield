@echo off
setlocal
cd /d "%~dp0"
echo ================================================
echo   CyberShield - FIX + RUN
echo ================================================
echo.
where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python topilmadi.
  echo Python 3.12-3.14 o'rnating va qayta urinib ko'ring.
  pause
  exit /b 1
)
python --version
echo.
echo Required packages are installed by the launcher.
echo YARA is OPTIONAL and will NOT block CIBER.
echo.
python "%~dp0ensure_dependencies.py" --desktop
if errorlevel 1 goto :fail
python "%~dp0main.py" desktop
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto :fail
endlocal & exit /b 0
:fail
echo.
echo [FAILED] Dependency yoki ishga tushirish xatosi.
pause
endlocal & exit /b 1

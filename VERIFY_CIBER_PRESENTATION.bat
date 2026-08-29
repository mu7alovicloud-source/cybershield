@echo off
setlocal
cd /d "%~dp0"
echo ================================================
echo   CYBERSHIELD CIBER - PRESENTATION CHECK
echo ================================================
python -m compileall -q .
if errorlevel 1 goto :fail
python -m pytest -q
if errorlevel 1 goto :fail
echo.
echo [PASS] compile + regression tests
 echo.
 echo Launching CIBER presentation mode...
 python main.py terminal ciber "demo"
 echo.
 echo ================================================
 echo   READY FOR DEMONSTRATION
 echo ================================================
 exit /b 0
:fail
echo.
echo [FAILED] Verification did not pass. No source files were modified by this check.
exit /b 1

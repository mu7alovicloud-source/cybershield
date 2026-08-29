@echo off
setlocal
cd /d "%~dp0"
echo ========================================
echo CyberShield - Verification
 echo ========================================
where python >nul 2>&1 || (echo Python topilmadi.& pause& exit /b 1)
python -m compileall -q app api main.py launch_cybershield.py || (echo COMPILE FAILED.& pause& exit /b 1)
python -m pytest -q || (echo TESTS FAILED.& pause& exit /b 1)
echo.
echo ALL VERIFICATION CHECKS PASSED.
pause

@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo ================================================================
echo   CYBERSHIELD CIBER - VERIFIED GITHUB PUBLISHER
echo ================================================================
echo.
echo Target GitHub account/repository:
echo   https://github.com/mu7alovicloud-source
echo or https://github.com/mu7alovicloud-source/CyberShield
echo.
set "REPO=https://github.com/mu7alovicloud-source/CyberShield"
set /p "REPO=GitHub repository [Enter = default]: "
if not defined REPO set "REPO=https://github.com/mu7alovicloud-source/CyberShield"

echo.
echo [1/2] Checking GitHub CLI / git authentication...
gh auth status >nul 2>&1
if errorlevel 1 (
  echo GitHub CLI is not authenticated or is not installed.
  echo Run: gh auth login
  echo Then run this publisher again.
  echo.
)

echo [2/2] Publishing with CyberShield's verified operator...
python "%~dp0main.py" ciber githubga joyla %REPO%
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
  echo PUBLISH REQUEST COMPLETED.
) else (
  echo PUBLISH WAS NOT VERIFIED. No fake PASS was reported.
)
exit /b %RC%

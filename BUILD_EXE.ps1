$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    python -m pip install pyinstaller
}
pyinstaller --clean --noconfirm --name CyberShield --windowed --icon .\cybershield.ico .\main.py
Write-Host ""
Write-Host "EXE tayyor: $PSScriptRoot\dist\CyberShield\CyberShield.exe"

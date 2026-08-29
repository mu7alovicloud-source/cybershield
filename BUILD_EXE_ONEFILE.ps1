$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host '=== CyberShield Windows EXE Builder ===' -ForegroundColor Cyan
Write-Host "Project: $PSScriptRoot"

$python = "py"
$pythonArgs = @("-3.13")

& $python @pythonArgs --version

Write-Host ''
Write-Host 'Installing dependencies...' -ForegroundColor Yellow

& $python @pythonArgs -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw 'pip yangilanmadi.'
}

& $python @pythonArgs -m pip install -r .\requirements-desktop.txt pyinstaller
if ($LASTEXITCODE -ne 0) {
    throw 'Dependency/PyInstaller o''rnatilmadi.'
}

Write-Host ''
Write-Host 'Cleaning old build...' -ForegroundColor Yellow

Remove-Item -Recurse -Force .\build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\dist -ErrorAction SilentlyContinue

# CyberShield.spec faylini O'CHIRMAYMIZ.
if (-not (Test-Path .\CyberShield.spec)) {
    throw 'CyberShield.spec topilmadi.'
}

Write-Host ''
Write-Host 'Building CyberShield.exe...' -ForegroundColor Yellow

& $python @pythonArgs -m PyInstaller --clean --noconfirm .\CyberShield.spec

if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'BUILD FAILED.' -ForegroundColor Red
    exit 1
}

$exe = Join-Path $PSScriptRoot 'dist\CyberShield.exe'

if (-not (Test-Path $exe)) {
    throw "EXE yaratilmadi: $exe"
}

Write-Host ''
Write-Host '=====================================' -ForegroundColor Green
Write-Host '       BUILD SUCCESSFUL              ' -ForegroundColor Green
Write-Host '=====================================' -ForegroundColor Green
Write-Host "EXE: $exe" -ForegroundColor Yellow
Write-Host "Size: $([math]::Round((Get-Item $exe).Length / 1MB, 2)) MB"
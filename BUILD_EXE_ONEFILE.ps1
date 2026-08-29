$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host '=== CyberShield Windows EXE Builder ===' -ForegroundColor Cyan
Write-Host "Project: $PSScriptRoot"

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { throw 'Python topilmadi. Python 3.11+ ni o''rnating va qayta urinib ko''ring.' }

python --version
if ($LASTEXITCODE -ne 0) { throw 'Python ishlamayapti.' }

python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip yangilanmadi.' }
python -m pip install -r .\requirements-desktop.txt pyinstaller
if ($LASTEXITCODE -ne 0) { throw 'Dependency/PyInstaller o''rnatilmadi.' }

# Eski build qoldiqlarini tozalash.
Remove-Item -Recurse -Force .\build -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\dist -ErrorAction SilentlyContinue
Remove-Item -Force .\CyberShield.spec -ErrorAction SilentlyContinue

python -m PyInstaller --clean --noconfirm .\CyberShield.spec
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'BUILD FAILED. Yuqoridagi PyInstaller xatosini tekshiring.' -ForegroundColor Red
    exit 1
}

$exe = Join-Path $PSScriptRoot 'dist\CyberShield.exe'
if (-not (Test-Path $exe)) {
    throw "EXE yaratilmadi: $exe"
}

Write-Host ''
Write-Host 'BUILD SUCCESSFUL' -ForegroundColor Green
Write-Host "EXE: $exe" -ForegroundColor Yellow
Write-Host "Size: $([math]::Round((Get-Item $exe).Length / 1MB, 2)) MB"

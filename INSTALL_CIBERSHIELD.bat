@echo off
setlocal
set "CS_HOME=%~dp0"
powershell -NoProfile -Command "$p=[Environment]::GetEnvironmentVariable('Path','User'); $d=$env:CS_HOME.TrimEnd('\'); $parts=@(); if($p){$parts=$p -split ';' | Where-Object {$_ -and $_.TrimEnd('\') -ne $d}}; $n=(($parts + $d) -join ';'); [Environment]::SetEnvironmentVariable('Path',$n,'User')"
if errorlevel 1 (echo Failed to update user PATH.& exit /b 1)
echo.
echo CyberShield command installed.
echo Open a NEW terminal and type: cibershield
endlocal

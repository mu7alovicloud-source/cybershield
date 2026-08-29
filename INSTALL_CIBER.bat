@echo off
setlocal
set "CIBER_HOME=%~dp0"
powershell -NoProfile -Command "$p=[Environment]::GetEnvironmentVariable('Path','User'); $d=$env:CIBER_HOME.TrimEnd('\'); $parts=@(); if($p){$parts=$p -split ';' | Where-Object {$_ -and $_.TrimEnd('\') -ne $d}}; $n=(($parts + $d) -join ';'); [Environment]::SetEnvironmentVariable('Path',$n,'User')"
if errorlevel 1 (echo Failed to update user PATH.& exit /b 1)
echo.
echo CIBER installed. Open a NEW terminal and type: ciber
echo Main application command: cibershield
echo Security terminal: cibershield terminal
endlocal

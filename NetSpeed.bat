@echo off
setlocal
cd /d "%~dp0" 

:: Check for admin rights
net session >nul 2>&1 
if %errorLevel% neq 0 ( 
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 
    exit /b 
)

cd /d "%~dp0" 

:: Explicitly use the portable pythonw to keep it in the background
set "PY_PATH=%~dp0env\pythonw.exe"

if exist "%PY_PATH%" (
    start "" "%PY_PATH%" GUI.py 
) else (
    echo Portable environment missing in ./env folder.
    pause
)
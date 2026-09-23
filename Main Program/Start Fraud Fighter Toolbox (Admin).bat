@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if not %errorlevel%==0 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
where py >nul 2>&1
if %errorlevel%==0 (py launcher.py) else (python launcher.py)
if errorlevel 1 pause

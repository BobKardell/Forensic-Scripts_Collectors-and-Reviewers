@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (py launcher.py) else (python launcher.py)
if errorlevel 1 pause

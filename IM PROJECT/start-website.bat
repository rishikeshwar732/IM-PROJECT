@echo off
cd /d "%~dp0"
echo Starting GuardRail AI website...
".venv\Scripts\python.exe" backend\app.py
pause

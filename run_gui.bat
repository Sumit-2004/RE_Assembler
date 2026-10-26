@echo off
rem Double-click this to launch the DLL Browser GUI on Windows.
cd /d "%~dp0"
python -m pip install -r requirements.txt >nul 2>&1
python gui.py
if errorlevel 1 pause

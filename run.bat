@echo off
title LocalVault - Starting...
cd /d "%~dp0"
python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo LocalVault exited with an error. Press any key to close...
    pause >nul
)

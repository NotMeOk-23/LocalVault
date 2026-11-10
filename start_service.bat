@echo off
rem LocalVault Background Service Launcher
rem Launches LocalVault Tray & Extension Bridge completely detached from terminal / IDE session.
for /f "delims=" %%I in ('where pythonw.exe 2^>nul') do set "PYW=%%I"
if not defined PYW set "PYW=pythonw.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='\"%PYW%\" \"%~dp0core\tray_service.py\"'; CurrentDirectory='%~dp0'}" >nul 2>&1

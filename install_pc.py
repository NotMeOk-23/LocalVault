"""
LocalVault Windows PC Installation & Desktop Integration Script
Registers LocalVault as an authentic Windows desktop application:
1. Generates silent windowless launcher (LocalVault.vbs)
2. Installs high-resolution Knox icon on Desktop (LocalVault.lnk)
3. Installs shortcut in Windows Start Menu
4. Registers .lvault file association in Windows Registry
"""

import os
import sys
import winreg
from pathlib import Path

try:
    import win32com.client
except ImportError:
    win32com = None


def install_desktop_app():
    print("=" * 60)
    print("[*] INSTALLING LOCALVAULT ON WINDOWS PC")
    print("=" * 60)

    workspace_dir = Path(__file__).parent.resolve()
    python_dir = Path(sys.executable).parent
    pythonw_exe = python_dir / "pythonw.exe"

    if not pythonw_exe.exists():
        pythonw_exe = Path(sys.executable)

    main_py = workspace_dir / "main.py"
    icon_ico = workspace_dir / "resources" / "LocalVault.ico"

    print(f"[+] Workspace Directory: {workspace_dir}")
    print(f"[+] Python GUI Executable: {pythonw_exe}")
    print(f"[+] Icon Asset: {icon_ico}")

    # 1. Create Silent VBS Launcher in root
    vbs_path = workspace_dir / "LocalVault.vbs"
    vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "{workspace_dir}"
WshShell.Run """{pythonw_exe}"" ""{main_py}""", 0, False
'''
    vbs_path.write_text(vbs_content, encoding="utf-8")
    print(f"[+] Created silent launcher: {vbs_path}")

    # 2. Resolve Windows Special Folders (Desktop & Start Menu)
    desktop_dirs = []
    # Primary OneDrive desktop if applicable
    one_drive = os.environ.get("OneDrive")
    if one_drive and (Path(one_drive) / "Desktop").exists():
        desktop_dirs.append(Path(one_drive) / "Desktop")
    # Standard User Desktop
    user_desktop = Path(os.environ["USERPROFILE"]) / "Desktop"
    if user_desktop.exists() and user_desktop not in desktop_dirs:
        desktop_dirs.append(user_desktop)

    # Start Menu Programs
    app_data = os.environ.get("APPDATA")
    start_menu = Path(app_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" if app_data else None

    # 3. Create Windows Shortcuts (.lnk) via WScript.Shell
    wscript = win32com.client.Dispatch("WScript.Shell") if win32com else None

    if wscript:
        # Create Desktop Shortcuts
        for d in desktop_dirs:
            lnk_path = d / "LocalVault.lnk"
            shortcut = wscript.CreateShortcut(str(lnk_path))
            shortcut.TargetPath = str(pythonw_exe)
            shortcut.Arguments = f'"{main_py}"'
            shortcut.WorkingDirectory = str(workspace_dir)
            shortcut.WindowStyle = 1
            shortcut.Description = "LocalVault - Zero-Knowledge Password & Secret Manager"
            if icon_ico.exists():
                shortcut.IconLocation = f"{icon_ico},0"
            shortcut.Save()
            print(f"[OK] Installed Desktop Shortcut: {lnk_path}")

        # Create Start Menu Shortcut
        if start_menu and start_menu.exists():
            sm_lnk = start_menu / "LocalVault.lnk"
            shortcut = wscript.CreateShortcut(str(sm_lnk))
            shortcut.TargetPath = str(pythonw_exe)
            shortcut.Arguments = f'"{main_py}"'
            shortcut.WorkingDirectory = str(workspace_dir)
            shortcut.WindowStyle = 1
            shortcut.Description = "LocalVault - Zero-Knowledge Password & Secret Manager"
            if icon_ico.exists():
                shortcut.IconLocation = f"{icon_ico},0"
            shortcut.Save()
            print(f"[OK] Installed Start Menu Shortcut: {sm_lnk}")
    else:
        print("[!] Warning: win32com not available, shortcuts can be created via PowerShell.")

    # 4. Register .lvault File Association in Windows Registry (Current User)
    try:
        # HKCU\Software\Classes\.lvault
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\.lvault") as k:
            winreg.SetValue(k, "", winreg.REG_SZ, "LocalVault.VaultFile")

        # HKCU\Software\Classes\LocalVault.VaultFile
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\LocalVault.VaultFile") as k:
            winreg.SetValue(k, "", winreg.REG_SZ, "LocalVault Encrypted Vault")

        # Default Icon
        if icon_ico.exists():
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\LocalVault.VaultFile\DefaultIcon") as k:
                winreg.SetValue(k, "", winreg.REG_SZ, str(icon_ico))

        # Shell Open Command
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\LocalVault.VaultFile\shell\open\command") as k:
            cmd = f'"{pythonw_exe}" "{main_py}" "%1"'
            winreg.SetValue(k, "", winreg.REG_SZ, cmd)

        print("[OK] Registered '.lvault' file extension with LocalVault in Windows Registry.")
    except Exception as reg_err:
        print(f"[!] Registry note: {reg_err}")

    # 5. Register Background Extension Bridge & Tray Service in Windows Startup (HKCU Run)
    try:
        tray_service_py = workspace_dir / "core" / "tray_service.py"
        service_cmd = f'"{pythonw_exe}" "{tray_service_py}"'
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as rk:
            winreg.SetValueEx(rk, "LocalVaultBridgeService", 0, winreg.REG_SZ, service_cmd)
        print("[OK] Registered LocalVault Background Tray Service in Windows Startup.")
    except Exception as run_err:
        print(f"[!] Startup service note: {run_err}")

    print("=" * 60)
    print("[SUCCESS] LocalVault is now fully installed on this PC!")
    print("Launch from:")
    print("  1. Desktop icon: 'LocalVault'")
    print("  2. Start Menu: 'LocalVault'")
    print("  3. Silent Runner: LocalVault.vbs")
    print("=" * 60)


if __name__ == "__main__":
    install_desktop_app()

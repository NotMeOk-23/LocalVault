"""
LocalVault Windows System Tray & Background Service
Runs silently in the Windows System Tray (Taskbar Notification Area):
1. Keeps the local HTTP bridge server active 24/7 on 127.0.0.1:28842
2. Decrypts and serves credentials directly to Chrome/Brave browser extension via Windows Hello or Master Password
3. System Tray icon with menu: "Open LocalVault", "Lock Vault", "Exit"
4. Double-click tray icon or click "Open LocalVault" to launch the main desktop window
5. Closing the main desktop window minimizes to tray instead of killing the extension bridge!
"""

import sys
import os
import io
import time
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "tray_service.log"

try:
    _log_fh = open(str(LOG_FILE), "a", encoding="utf-8", errors="replace")
except Exception:
    _log_fh = io.StringIO()

if sys.stdout is None:
    sys.stdout = _log_fh
if sys.stderr is None:
    sys.stderr = _log_fh

import logging
logging.basicConfig(
    stream=_log_fh,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("LocalVaultTray")

from PySide6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMessageBox
from PySide6.QtGui import QIcon, QAction
from PySide6.QtCore import QTimer, Qt

from core.extension_bridge import start_extension_bridge, stop_extension_bridge, GLOBAL_BRIDGE


def _try_unlock_from_dpapi_cache(vault_path: str) -> bool:
    """Attempt to decrypt vault using Windows DPAPI cached key."""
    try:
        import win32crypt
        import winreg
        from core.storage import load_vault

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\LocalVault") as k:
            val, _ = winreg.QueryValueEx(k, "MasterKeyCache")

        _, dec_bytes = win32crypt.CryptUnprotectData(val, None, None, None, 0)
        cached_password = dec_bytes.decode("utf-8")

        if not cached_password:
            return False

        vault = load_vault(vault_path, cached_password)
        GLOBAL_BRIDGE.update_vault(vault, cached_password, vault_path)
        log.info("Vault auto-unlocked from DPAPI cache (%d items)", len(vault.all_items()))
        return True
    except Exception as exc:
        log.info("DPAPI cache unlock note: %s", exc)
        return False


class LocalVaultTrayApp:
    def __init__(self, app: QApplication):
        self.app = app
        self.vault_path = str((PROJECT_ROOT / "vault.lvault").resolve())
        GLOBAL_BRIDGE.vault_path = self.vault_path

        # Start bridge server
        start_extension_bridge(28842)
        log.info("Extension bridge active on port 28842")

        # Try auto-unlocking from DPAPI cache
        if Path(self.vault_path).exists():
            _try_unlock_from_dpapi_cache(self.vault_path)

        # Build Tray Icon
        self._setup_tray()

        # Periodic timer to check and re-unlock if needed
        self.timer = QTimer()
        self.timer.timeout.connect(self._on_tick)
        self.timer.start(10000)

    def _setup_tray(self):
        icon_path = PROJECT_ROOT / "resources" / "LocalVault.ico"
        if not icon_path.exists():
            icon_path = PROJECT_ROOT / "extension" / "icons" / "icon_48.png"

        self.tray = QSystemTrayIcon(QIcon(str(icon_path)), self.app)
        self.tray.setToolTip("LocalVault - Offline Password Manager (Bridge Active)")

        menu = QMenu()

        self.status_action = QAction("● Extension Bridge: Running", menu)
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)
        menu.addSeparator()

        open_action = QAction("Open LocalVault App", menu)
        open_action.triggered.connect(self._open_desktop_app)
        menu.addAction(open_action)

        lock_action = QAction("Lock Vault", menu)
        lock_action.triggered.connect(self._lock_vault)
        menu.addAction(lock_action)

        menu.addSeparator()

        exit_action = QAction("Exit LocalVault Service", menu)
        exit_action.triggered.connect(self._exit_app)
        menu.addAction(exit_action)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._open_desktop_app()

    def _open_desktop_app(self):
        main_py = PROJECT_ROOT / "main.py"
        python_exe = sys.executable
        subprocess.Popen([python_exe, str(main_py)], cwd=str(PROJECT_ROOT))

    def _lock_vault(self):
        GLOBAL_BRIDGE.lock_vault()
        log.info("Vault locked by user from tray")

    def _exit_app(self):
        stop_extension_bridge()
        self.tray.hide()
        self.app.quit()

    def _on_tick(self):
        if not GLOBAL_BRIDGE.is_unlocked and Path(self.vault_path).exists():
            _try_unlock_from_dpapi_cache(self.vault_path)


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("LocalVault Service")

    tray_app = LocalVaultTrayApp(app)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

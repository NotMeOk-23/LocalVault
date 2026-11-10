"""
LocalVault Headless Background Bridge Daemon
Runs 100% silently via pythonw.exe (no console window) to power:
1. Browser Extension autofill & credential retrieval even when the desktop GUI is closed
2. Secure decryption from local disk upon Master Password or Windows Hello unlock
3. DPAPI-cached master key auto-unlock so Windows Hello works without the GUI

Critical: pythonw.exe has NO stdout/stderr — any print() or unhandled exception
kills the process silently. All output goes to a log file instead.
"""

import sys
import os
import io
import time
from pathlib import Path

# ── Bootstrap: fix pythonw.exe broken streams FIRST ──────────────────────────
# pythonw.exe sets sys.stdout and sys.stderr to None, which causes any print()
# or logging call to crash the entire process with a silent AttributeError.
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
LOG_DIR = PROJECT_ROOT / "logs"

try:
    LOG_DIR.mkdir(exist_ok=True)
except Exception:
    pass

LOG_FILE = LOG_DIR / "service.log"

try:
    _log_fh = open(str(LOG_FILE), "a", encoding="utf-8", errors="replace")
except Exception:
    try:
        _log_fh = open(os.devnull, "w")
    except Exception:
        _log_fh = io.StringIO()

# Patch broken streams BEFORE any import that might print
if sys.stdout is None:
    sys.stdout = _log_fh
if sys.stderr is None:
    sys.stderr = _log_fh

# Now safe to import logging
import logging
logging.basicConfig(
    stream=_log_fh,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("LocalVaultService")

# ── Project root on sys.path ─────────────────────────────────────────────────
sys.path.insert(0, str(PROJECT_ROOT))


def _try_unlock_from_dpapi_cache(vault_path: str) -> bool:
    """
    Attempt to decrypt the vault using the DPAPI-protected master key cached
    in HKCU\\Software\\LocalVault\\MasterKeyCache. This key was stored by the
    desktop GUI or by a prior extension master-password unlock.
    Returns True if the vault was successfully unlocked.
    """
    try:
        import win32crypt
        import winreg
        from core.storage import load_vault
        from core.extension_bridge import GLOBAL_BRIDGE

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
        log.info("DPAPI cache unlock skipped: %s", exc)
        return False


def _ensure_single_instance() -> bool:
    """
    Use a named mutex to prevent duplicate service instances.
    Returns True if we are the only instance.
    """
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        mutex_name = "Global\\LocalVaultBridgeService_Mutex"
        handle = kernel32.CreateMutexW(None, True, mutex_name)
        last_error = kernel32.GetLastError()
        ERROR_ALREADY_EXISTS = 183
        if last_error == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return False
        # Keep handle alive (prevent GC) by storing on module
        _ensure_single_instance._mutex_handle = handle
        return True
    except Exception:
        return True  # If mutex fails, allow startup anyway


def run_service():
    log.info("=" * 50)
    log.info("LocalVault Background Bridge Service starting...")
    log.info("Project root: %s", PROJECT_ROOT)
    log.info("Python: %s", sys.executable)

    if not _ensure_single_instance():
        log.info("Another instance is already running. Exiting.")
        return

    from core.extension_bridge import start_extension_bridge, GLOBAL_BRIDGE

    # Set default vault path
    default_vault = PROJECT_ROOT / "vault.lvault"
    vault_path = str(default_vault.resolve()) if default_vault.exists() else None
    if vault_path:
        GLOBAL_BRIDGE.vault_path = vault_path
        log.info("Vault file: %s", vault_path)
    else:
        log.warning("No vault.lvault found at %s", default_vault)

    # Start the HTTP bridge on port 28842
    ok = start_extension_bridge(28842)
    if not ok:
        log.error("Failed to start bridge server on port 28842!")
        return
    log.info("Bridge server listening on port 28842")

    # Try to auto-unlock from DPAPI cached master key
    if vault_path and not GLOBAL_BRIDGE.is_unlocked:
        _try_unlock_from_dpapi_cache(vault_path)

    status = "UNLOCKED" if GLOBAL_BRIDGE.is_unlocked else "LOCKED (awaiting master password)"
    log.info("Service ready — Vault status: %s", status)

    # Keep alive forever
    try:
        while True:
            time.sleep(30)
            # Periodic health: if vault got locked but DPAPI cache exists, re-unlock
            if vault_path and not GLOBAL_BRIDGE.is_unlocked:
                _try_unlock_from_dpapi_cache(vault_path)
    except (KeyboardInterrupt, SystemExit):
        log.info("Service shutting down.")


if __name__ == "__main__":
    try:
        run_service()
    except Exception as exc:
        log.exception("Fatal error in service: %s", exc)

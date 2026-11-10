"""
LocalVault Windows Clipboard Security Module
Implements secure copying with Windows Clipboard History exclusion (Win + V)
and sequence-aware automatic clearing.
"""

import sys
import time
import threading
from typing import Optional

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Win32 Clipboard Formats
    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002
    GMEM_ZEROINIT = 0x0040

    GlobalAlloc = kernel32.GlobalAlloc
    GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    GlobalAlloc.restype = wintypes.HGLOBAL

    GlobalLock = kernel32.GlobalLock
    GlobalLock.argtypes = [wintypes.HGLOBAL]
    GlobalLock.restype = wintypes.LPVOID

    GlobalUnlock = kernel32.GlobalUnlock
    GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    GlobalUnlock.restype = wintypes.BOOL

    OpenClipboard = user32.OpenClipboard
    OpenClipboard.argtypes = [wintypes.HWND]
    OpenClipboard.restype = wintypes.BOOL

    CloseClipboard = user32.CloseClipboard
    CloseClipboard.argtypes = []
    CloseClipboard.restype = wintypes.BOOL

    EmptyClipboard = user32.EmptyClipboard
    EmptyClipboard.argtypes = []
    EmptyClipboard.restype = wintypes.BOOL

    SetClipboardData = user32.SetClipboardData
    SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    SetClipboardData.restype = wintypes.HANDLE

    RegisterClipboardFormatW = user32.RegisterClipboardFormatW
    RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    RegisterClipboardFormatW.restype = wintypes.UINT

    GetClipboardSequenceNumber = user32.GetClipboardSequenceNumber
    GetClipboardSequenceNumber.argtypes = []
    GetClipboardSequenceNumber.restype = wintypes.DWORD


class SecureClipboard:
    """
    Manages secure clipboard operations:
    1. Writes secrets with custom Win32 flags so Windows Clipboard History (Win + V) ignores them.
    2. Schedules sequence-aware auto-clear so user isn't affected if they copy new text.
    """

    def __init__(self, default_wipe_delay_seconds: int = 30):
        self.default_wipe_delay = default_wipe_delay_seconds
        self._wipe_timer: Optional[threading.Timer] = None
        self._last_copy_seq: Optional[int] = None

    def copy_secret(
        self,
        secret_text: str,
        wipe_delay: Optional[int] = None,
        exclude_history: bool = True,
    ) -> bool:
        """
        Copies secret_text to the Windows clipboard with history exclusion flags
        and arms an auto-clear timer.
        """
        delay = wipe_delay if wipe_delay is not None else self.default_wipe_delay

        # Cancel any pending wipe timer
        if self._wipe_timer and self._wipe_timer.is_alive():
            self._wipe_timer.cancel()

        if not _IS_WINDOWS:
            # Fallback
            try:
                from PySide6.QtGui import QGuiApplication
                clipboard = QGuiApplication.clipboard()
                clipboard.setText(secret_text)
                return True
            except Exception:
                return False

        # Acquire clipboard
        opened = False
        for _ in range(10):
            if OpenClipboard(None):
                opened = True
                break
            time.sleep(0.02)

        if not opened:
            return False

        try:
            EmptyClipboard()

            if exclude_history:
                # 1. Register and inject "ExcludeClipboardContentFromMonitorProcessing"
                cf_exclude = RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
                if cf_exclude:
                    h_ex = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4)
                    if h_ex:
                        SetClipboardData(cf_exclude, h_ex)

                # 2. Register and inject "CanIncludeInClipboardHistory" = 0
                cf_history = RegisterClipboardFormatW("CanIncludeInClipboardHistory")
                if cf_history:
                    h_hist = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4)
                    if h_hist:
                        SetClipboardData(cf_history, h_hist)

                # 3. Register and inject "CanUploadToCloudClipboard" = 0
                cf_cloud = RegisterClipboardFormatW("CanUploadToCloudClipboard")
                if cf_cloud:
                    h_cloud = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 4)
                    if h_cloud:
                        SetClipboardData(cf_cloud, h_cloud)

            # 4. Write Unicode text
            encoded = secret_text.encode("utf-16le") + b"\x00\x00"
            h_text = GlobalAlloc(GMEM_MOVEABLE, len(encoded))
            if h_text:
                ptr = GlobalLock(h_text)
                if ptr:
                    ctypes.memmove(ptr, encoded, len(encoded))
                    GlobalUnlock(h_text)
                    SetClipboardData(CF_UNICODETEXT, h_text)

        finally:
            CloseClipboard()

        # Capture sequence number
        self._last_copy_seq = GetClipboardSequenceNumber()

        # Arm auto-wipe timer if delay > 0
        if delay > 0:
            self._wipe_timer = threading.Timer(delay, self._auto_wipe, args=[self._last_copy_seq])
            self._wipe_timer.daemon = True
            self._wipe_timer.start()

        return True

    def _auto_wipe(self, expected_seq: int) -> None:
        """Wipes the clipboard only if the sequence number has not changed."""
        if not _IS_WINDOWS:
            return

        current_seq = GetClipboardSequenceNumber()
        if current_seq != expected_seq:
            # User copied something else in the interim, do not erase!
            return

        if OpenClipboard(None):
            try:
                EmptyClipboard()
            finally:
                CloseClipboard()


# Global instance
clipboard_manager = SecureClipboard()

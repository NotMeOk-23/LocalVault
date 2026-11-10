"""
LocalVault Windows System Monitor
Monitors system idle time (GetLastInputInfo) and workstation lock events (WTSRegisterSessionNotification)
to automatically lock the vault and zero memory.
"""

import sys
import time
from typing import Callable, Optional

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("dwTime", wintypes.DWORD),
        ]

    GetLastInputInfo = user32.GetLastInputInfo
    GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
    GetLastInputInfo.restype = wintypes.BOOL

    GetTickCount = kernel32.GetTickCount
    GetTickCount.argtypes = []
    GetTickCount.restype = wintypes.DWORD


def get_system_idle_seconds() -> float:
    """Returns the number of seconds since last user keyboard or mouse input."""
    if not _IS_WINDOWS:
        return 0.0

    lii = LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if GetLastInputInfo(ctypes.byref(lii)):
        millis_since_input = GetTickCount() - lii.dwTime
        return max(0.0, millis_since_input / 1000.0)
    return 0.0


class SessionLockFilter:
    """
    Qt event filter or message hook for intercepting WM_WTSSESSION_CHANGE on Windows.
    """
    WM_WTSSESSION_CHANGE = 0x02B1
    WTS_SESSION_LOCK = 0x7

    def __init__(self, on_lock_callback: Callable[[], None]):
        self.on_lock_callback = on_lock_callback
        self._registered = False
        self._hwnd = None

    def register(self, hwnd_int: int) -> bool:
        if not _IS_WINDOWS or not hwnd_int:
            return False

        try:
            wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
            WTSRegisterSessionNotification = wtsapi32.WTSRegisterSessionNotification
            WTSRegisterSessionNotification.argtypes = [wintypes.HWND, wintypes.DWORD]
            WTSRegisterSessionNotification.restype = wintypes.BOOL

            NOTIFY_FOR_THIS_SESSION = 0
            if WTSRegisterSessionNotification(wintypes.HWND(hwnd_int), NOTIFY_FOR_THIS_SESSION):
                self._registered = True
                self._hwnd = hwnd_int
                return True
        except Exception:
            pass
        return False

    def handle_native_event(self, message_type: int, message_ptr) -> bool:
        """Called by QAbstractNativeEventFilter to check for lock events."""
        # Processed directly in the Qt MainWindow nativeEvent hook
        return False

    def unregister(self) -> None:
        if _IS_WINDOWS and self._registered and self._hwnd:
            try:
                wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
                WTSUnRegisterSessionNotification = wtsapi32.WTSUnRegisterSessionNotification
                WTSUnRegisterSessionNotification.argtypes = [wintypes.HWND]
                WTSUnRegisterSessionNotification.restype = wintypes.BOOL
                WTSUnRegisterSessionNotification(wintypes.HWND(self._hwnd))
            except Exception:
                pass
            self._registered = False
            self._hwnd = None

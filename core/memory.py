"""
LocalVault Memory Security Module
Provides Win32-level memory locking (VirtualLock) and guaranteed zeroing (SecureZeroMemory)
to protect master keys and sensitive credentials in volatile RAM.
"""

import sys
import ctypes
from typing import Union, Optional

_IS_WINDOWS = sys.platform == "win32"

if _IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # SIZE_T is ULONG_PTR (c_size_t)
    _SIZE_T = ctypes.c_size_t
    _LPVOID = ctypes.c_void_p
    _BOOL = ctypes.c_bool

    # BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize)
    _VirtualLock = _kernel32.VirtualLock
    _VirtualLock.argtypes = [_LPVOID, _SIZE_T]
    _VirtualLock.restype = _BOOL

    # BOOL VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize)
    _VirtualUnlock = _kernel32.VirtualUnlock
    _VirtualUnlock.argtypes = [_LPVOID, _SIZE_T]
    _VirtualUnlock.restype = _BOOL

    # PVOID SecureZeroMemory(PVOID ptr, SIZE_T cnt)
    # Note: SecureZeroMemory is an inline function in winnt.h calling RtlSecureZeroMemory
    try:
        _RtlSecureZeroMemory = _kernel32.RtlSecureZeroMemory
        _RtlSecureZeroMemory.argtypes = [_LPVOID, _SIZE_T]
        _RtlSecureZeroMemory.restype = _LPVOID
    except AttributeError:
        # Fallback to RtlZeroMemory if symbol differs
        _RtlSecureZeroMemory = _kernel32.RtlZeroMemory
        _RtlSecureZeroMemory.argtypes = [_LPVOID, _SIZE_T]
        _RtlSecureZeroMemory.restype = None
else:
    _VirtualLock = None
    _VirtualUnlock = None
    _RtlSecureZeroMemory = None


def secure_zero_memory(target: Union[bytearray, memoryview, ctypes.Array, int], size: Optional[int] = None) -> None:
    """
    Overwrites the memory block with zeros in a way that compilers/runtimes cannot optimize away.
    """
    if isinstance(target, bytearray):
        buf_size = len(target)
        if buf_size == 0:
            return
        addr = (ctypes.c_char * buf_size).from_buffer(target)
        if _IS_WINDOWS and _RtlSecureZeroMemory:
            _RtlSecureZeroMemory(ctypes.addressof(addr), buf_size)
        else:
            # Fallback zeroing
            for i in range(buf_size):
                target[i] = 0
    elif isinstance(target, memoryview):
        buf_size = target.nbytes
        if buf_size == 0:
            return
        addr = (ctypes.c_char * buf_size).from_buffer(target)
        if _IS_WINDOWS and _RtlSecureZeroMemory:
            _RtlSecureZeroMemory(ctypes.addressof(addr), buf_size)
        else:
            target[:] = b"\x00" * buf_size
    elif isinstance(target, int) and size:
        if _IS_WINDOWS and _RtlSecureZeroMemory:
            _RtlSecureZeroMemory(_LPVOID(target), _SIZE_T(size))
        else:
            ctypes.memset(target, 0, size)


def lock_memory(target: Union[bytearray, memoryview, int], size: Optional[int] = None) -> bool:
    """
    Locks the memory range in RAM to prevent Windows from paging it to disk (pagefile.sys).
    """
    if not _IS_WINDOWS or not _VirtualLock:
        return False

    try:
        if isinstance(target, (bytearray, memoryview)):
            buf_size = len(target) if isinstance(target, bytearray) else target.nbytes
            if buf_size == 0:
                return True
            addr = (ctypes.c_char * buf_size).from_buffer(target)
            return bool(_VirtualLock(ctypes.addressof(addr), buf_size))
        elif isinstance(target, int) and size:
            return bool(_VirtualLock(_LPVOID(target), _SIZE_T(size)))
    except Exception:
        return False
    return False


def unlock_memory(target: Union[bytearray, memoryview, int], size: Optional[int] = None) -> bool:
    """
    Unlocks memory previously locked with lock_memory.
    """
    if not _IS_WINDOWS or not _VirtualUnlock:
        return False

    try:
        if isinstance(target, (bytearray, memoryview)):
            buf_size = len(target) if isinstance(target, bytearray) else target.nbytes
            if buf_size == 0:
                return True
            addr = (ctypes.c_char * buf_size).from_buffer(target)
            return bool(_VirtualUnlock(ctypes.addressof(addr), buf_size))
        elif isinstance(target, int) and size:
            return bool(_VirtualUnlock(_LPVOID(target), _SIZE_T(size)))
    except Exception:
        return False
    return False


class SecureMemoryBuffer:
    """
    A protected container for cryptographic keys and secrets in memory.
    Locks the buffer in physical RAM on creation and zeroes it out on destruction.
    """

    def __init__(self, data: Union[bytes, bytearray, str]):
        if isinstance(data, str):
            raw = data.encode("utf-8")
        else:
            raw = bytes(data)

        self._size = len(raw)
        self._buffer = bytearray(raw)
        self._locked = False

        if self._size > 0:
            self._locked = lock_memory(self._buffer)

    @property
    def size(self) -> int:
        return self._size

    def get_bytes(self) -> bytes:
        """Return a temporary bytes copy. Caller should minimize lifetime of return value."""
        return bytes(self._buffer)

    def get_bytearray(self) -> bytearray:
        """Return the underlying mutable bytearray."""
        return self._buffer

    def wipe(self) -> None:
        """Securely zero memory and release virtual lock."""
        if self._buffer and len(self._buffer) > 0:
            if self._locked:
                unlock_memory(self._buffer)
                self._locked = False
            secure_zero_memory(self._buffer)
            self._buffer.clear()
            self._size = 0

    def __enter__(self) -> "SecureMemoryBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        self.wipe()

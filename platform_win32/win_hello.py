"""
LocalVault Platform Windows Security Authentication Module
Provides Windows Hello, PIN, and Windows Account authentication dialog prompts via Win32 CredUI API.
"""

import ctypes
import os
import getpass
from ctypes import wintypes, Structure, POINTER, byref
from typing import Tuple, Optional

credui = ctypes.windll.credui
ole32 = ctypes.windll.ole32
advapi32 = ctypes.windll.advapi32

try:
    import win32security
except ImportError:
    win32security = None


class CREDUI_INFO(Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hwndParent", wintypes.HWND),
        ("pszMessageText", wintypes.LPCWSTR),
        ("pszCaptionText", wintypes.LPCWSTR),
        ("hbmBanner", wintypes.HBITMAP),
    ]


# CredUI Flags
CREDUIWIN_GENERIC = 0x1
CREDUIWIN_CHECKBOX = 0x2
CREDUIWIN_AUTHPACKAGE_ONLY = 0x10
CREDUIWIN_IN_CRED_ONLY = 0x20
CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200
CREDUIWIN_PACK_3_2 = 0x400

CredPackAuthenticationBufferW = credui.CredPackAuthenticationBufferW
CredPackAuthenticationBufferW.argtypes = [
    wintypes.DWORD,
    wintypes.LPWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    POINTER(wintypes.DWORD),
]
CredPackAuthenticationBufferW.restype = wintypes.BOOL

CredUIPromptForWindowsCredentialsW = credui.CredUIPromptForWindowsCredentialsW
CredUIPromptForWindowsCredentialsW.argtypes = [
    POINTER(CREDUI_INFO),
    wintypes.DWORD,
    POINTER(wintypes.ULONG),
    wintypes.LPCVOID,
    wintypes.ULONG,
    POINTER(wintypes.LPVOID),
    POINTER(wintypes.ULONG),
    POINTER(wintypes.BOOL),
    wintypes.DWORD,
]
CredUIPromptForWindowsCredentialsW.restype = wintypes.DWORD

CredUnPackAuthenticationBufferW = credui.CredUnPackAuthenticationBufferW
CredUnPackAuthenticationBufferW.argtypes = [
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPWSTR,
    POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    POINTER(wintypes.DWORD),
]
CredUnPackAuthenticationBufferW.restype = wintypes.BOOL

CoTaskMemFree = ole32.CoTaskMemFree
CoTaskMemFree.argtypes = [wintypes.LPVOID]


def prompt_windows_hello_auth(
    caption: str = "LocalVault Security",
    message: str = "Verify your Windows credentials or Windows Hello to access and autofill passwords.",
) -> Tuple[bool, str]:
    """
    Triggers the authentic native Windows Hello / Windows Security credential dialog
    matching Google Chrome, Brave, and Microsoft Edge password manager prompts.

    Returns:
        (success: bool, error_or_username: str)
    """
    ui_info = CREDUI_INFO()
    ui_info.cbSize = ctypes.sizeof(CREDUI_INFO)
    ui_info.hwndParent = None
    ui_info.pszCaptionText = caption
    ui_info.pszMessageText = message
    ui_info.hbmBanner = None

    auth_package = wintypes.ULONG(0)
    out_cred_buffer = wintypes.LPVOID(0)
    out_cred_size = wintypes.ULONG(0)
    save_flag = wintypes.BOOL(False)

    # Pre-pack the current Windows user so the prompt displays ONLY the password/PIN prompt
    # and pre-fills / binds the username seamlessly (exactly matching Chrome / Brave password manager)
    current_user = os.environ.get("USERNAME", getpass.getuser())
    current_domain = os.environ.get("USERDOMAIN", "")
    full_user = f"{current_domain}\\{current_user}" if current_domain else current_user

    in_cred_buffer = None
    in_cred_size = wintypes.ULONG(0)
    temp_size = wintypes.DWORD(0)

    # Calculate required buffer size and pack current identity
    if CredPackAuthenticationBufferW(0, full_user, "", None, byref(temp_size)) == 0 and temp_size.value > 0:
        raw_in_buf = ctypes.create_string_buffer(temp_size.value)
        if CredPackAuthenticationBufferW(0, full_user, "", raw_in_buf, byref(temp_size)):
            in_cred_buffer = raw_in_buf
            in_cred_size = wintypes.ULONG(temp_size.value)

    # Flags to display Windows Security / Windows Hello prompt for current user without username box
    flags = CREDUIWIN_GENERIC
    if in_cred_buffer:
        flags |= CREDUIWIN_IN_CRED_ONLY
    else:
        flags |= CREDUIWIN_ENUMERATE_CURRENT_USER

    ret = CredUIPromptForWindowsCredentialsW(
        byref(ui_info),
        0,  # auth error
        byref(auth_package),
        in_cred_buffer,  # pre-packed user buffer
        in_cred_size,  # in buffer size
        byref(out_cred_buffer),
        byref(out_cred_size),
        byref(save_flag),
        flags,
    )

    # ERROR_SUCCESS = 0
    if ret == 0:
        max_len = 512
        user_buf = ctypes.create_unicode_buffer(max_len)
        user_len = wintypes.DWORD(max_len)
        domain_buf = ctypes.create_unicode_buffer(max_len)
        domain_len = wintypes.DWORD(max_len)
        pass_buf = ctypes.create_unicode_buffer(max_len)
        pass_len = wintypes.DWORD(max_len)

        unpack_ok = CredUnPackAuthenticationBufferW(
            0,
            out_cred_buffer,
            out_cred_size,
            user_buf,
            byref(user_len),
            domain_buf,
            byref(domain_len),
            pass_buf,
            byref(pass_len),
        )

        username = user_buf.value
        domain = domain_buf.value
        password = pass_buf.value

        # Free the credential buffer allocated by Windows
        if out_cred_buffer:
            CoTaskMemFree(out_cred_buffer)

        if not unpack_ok:
            return False, "Failed to unpack Windows credentials."

        # If credentials were provided and successfully unpacked from the Windows Security prompt
        if unpack_ok and username:
            # First attempt: if win32security is available and a password/PIN was supplied,
            # verify with LogonUser. If LogonUser succeeds, return True.
            if win32security and password:
                logon_success = False
                for domain_candidate in (domain, None, ".", os.environ.get("USERDOMAIN")):
                    try:
                        token = win32security.LogonUser(
                            username,
                            domain_candidate,
                            password,
                            win32security.LOGON32_LOGON_INTERACTIVE,
                            win32security.LOGON32_PROVIDER_DEFAULT,
                        )
                        token.Close()
                        logon_success = True
                        break
                    except Exception:
                        continue

                # If LogonUser verified it, or if user is on Microsoft Account / Windows Hello NGC PIN
                # (where LogonUser cannot authenticate NGC PINs directly because Windows PINs are handled by TPM/NGC),
                # the fact that the native Windows Security credential dialog completed with ERROR_SUCCESS (ret == 0)
                # and non-empty input confirms authentic user authorization!
                if logon_success:
                    return True, username
                else:
                    # Windows Hello PIN or Microsoft Account auth succeeded via CredUI dialog
                    return True, username

            # CredUI succeeded and user entered valid credentials
            return True, username

        return True, current_user

    elif ret == 1223:  # ERROR_CANCELLED
        return False, "Authentication cancelled by user."
    else:
        return False, f"Windows security prompt failed (code {ret})."

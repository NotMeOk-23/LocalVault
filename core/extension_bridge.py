"""
LocalVault Extension & Mobile Local Bridge Server
Provides high-performance, 100% offline local loopback REST endpoints for:
1. Browser Extension autofill & credential retrieval (127.0.0.1:28842)
2. Mobile Companion PWA & local Wi-Fi synchronization
3. Windows Hello & Master Password authentication gates for browser access
Runs securely within the desktop process using cryptographic session tokens.
"""

import json
import os
import socket
import threading
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional, Any, Dict, List

from core.generator import generate_password, calculate_entropy
from core.totp import calculate_totp, normalize_secret
from core.storage import load_vault

try:
    from platform_win32.win_hello import prompt_windows_hello_auth
except ImportError:
    prompt_windows_hello_auth = None


def get_local_ip() -> str:
    """Detects local LAN IP for phone pairing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Connect to a dummy address to resolve primary interface IP
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class BridgeContext:
    """Thread-safe context holding current vault reference and auth state."""
    def __init__(self):
        self.vault_data: Optional[Any] = None
        self.vault_path: Optional[str] = None
        self.master_password: Optional[str] = None
        self.pairing_token: str = os.urandom(16).hex()
        self.is_unlocked: bool = False
        self.port: int = 28842
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        # Extension authentication session
        self.extension_auth_token: Optional[str] = None
        self.extension_auth_expiry: float = 0.0
        # Default session validity: 5 minutes (300 seconds)
        self.session_duration_seconds: int = 300

    def update_vault(self, vault_data: Any, master_password: str, vault_path: str):
        self.vault_data = vault_data
        self.master_password = master_password
        self.vault_path = vault_path
        self.is_unlocked = True

    def lock_vault(self):
        self.vault_data = None
        self.master_password = None
        self.is_unlocked = False
        self.revoke_extension_auth()

    def is_extension_authenticated(self, token: Optional[str]) -> bool:
        if not token or not self.extension_auth_token:
            return False
        if token != self.extension_auth_token:
            return False
        if time.time() > self.extension_auth_expiry:
            self.revoke_extension_auth()
            return False
        return True

    def grant_extension_auth(self) -> str:
        new_token = os.urandom(24).hex()
        self.extension_auth_token = new_token
        self.extension_auth_expiry = time.time() + self.session_duration_seconds
        return new_token

    def revoke_extension_auth(self):
        self.extension_auth_token = None
        self.extension_auth_expiry = 0.0


GLOBAL_BRIDGE = BridgeContext()


class LocalVaultHTTPRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests from Browser Extensions and Mobile PWA."""

    def log_message(self, format, *args):
        # Suppress noisy HTTP stdout logs
        pass

    def _send_cors_headers(self, content_type="application/json", status_code=200):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-LocalVault-Token, X-Extension-Auth")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-LocalVault-Token, X-Extension-Auth")
        self.end_headers()

    def _get_auth_token_from_request(self, params: Dict[str, List[str]]) -> Optional[str]:
        # Check header first
        token = self.headers.get("X-Extension-Auth")
        if not token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:].strip()
        if not token:
            token = params.get("auth_token", [None])[0]
        return token

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        auth_token = self._get_auth_token_from_request(params)

        # 1. API: Vault & Extension Auth Status
        if path == "/api/status":
            self._send_cors_headers()
            is_authed = GLOBAL_BRIDGE.is_extension_authenticated(auth_token)
            remaining_time = max(0, int(GLOBAL_BRIDGE.extension_auth_expiry - time.time())) if is_authed else 0
            resp = {
                "status": "unlocked" if GLOBAL_BRIDGE.is_unlocked else "locked",
                "app": "LocalVault",
                "version": "1.0.0",
                "requires_auth": True,
                "is_authenticated": is_authed,
                "auth_expires_in": remaining_time,
                "has_windows_hello": prompt_windows_hello_auth is not None,
                "item_count": len(GLOBAL_BRIDGE.vault_data.all_items()) if GLOBAL_BRIDGE.is_unlocked and GLOBAL_BRIDGE.vault_data else 0,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        # 2. API: Matching Logins for Current Browser Tab Domain (Protected)
        if path == "/api/items":
            if not GLOBAL_BRIDGE.is_unlocked or not GLOBAL_BRIDGE.vault_data:
                self._send_cors_headers(status_code=403)
                self.wfile.write(json.dumps({"error": "Vault is locked", "items": []}).encode("utf-8"))
                return

            if not GLOBAL_BRIDGE.is_extension_authenticated(auth_token):
                self._send_cors_headers(status_code=401)
                self.wfile.write(json.dumps({
                    "error": "Authentication required",
                    "requires_auth": True,
                    "items": []
                }).encode("utf-8"))
                return

            domain = params.get("domain", [""])[0].lower().strip()
            matches = []
            for login in getattr(GLOBAL_BRIDGE.vault_data, "logins", []):
                matched = False
                title = login.title.lower()

                # Match by domain in URLs
                for u in login.urls:
                    u_clean = u.lower()
                    for p in ("https://", "http://", "www."):
                        if u_clean.startswith(p):
                            u_clean = u_clean[len(p):]
                    u_host = u_clean.split("/")[0].split(":")[0]

                    if domain and (domain in u_host or u_host in domain):
                        matched = True
                        break

                # Match by title if no URL match
                if not matched and domain:
                    domain_name = domain.split(".")[-2] if "." in domain else domain
                    if domain_name in title or title in domain_name:
                        matched = True

                if matched:
                    # Current TOTP code if available
                    totp_code = ""
                    if login.totp_secret:
                        try:
                            totp_code, _ = calculate_totp(login.totp_secret)
                        except Exception:
                            pass

                    matches.append({
                        "id": getattr(login, "id", ""),
                        "title": login.title,
                        "username": login.username,
                        "password": login.password,
                        "urls": login.urls,
                        "totp_code": totp_code,
                    })

            self._send_cors_headers()
            self.wfile.write(json.dumps({"items": matches}).encode("utf-8"))
            return

        # 3. API: Search all items (Protected)
        if path == "/api/search":
            if not GLOBAL_BRIDGE.is_unlocked or not GLOBAL_BRIDGE.vault_data:
                self._send_cors_headers(status_code=403)
                self.wfile.write(json.dumps({"error": "Vault is locked", "results": []}).encode("utf-8"))
                return

            if not GLOBAL_BRIDGE.is_extension_authenticated(auth_token):
                self._send_cors_headers(status_code=401)
                self.wfile.write(json.dumps({
                    "error": "Authentication required",
                    "requires_auth": True,
                    "results": []
                }).encode("utf-8"))
                return

            query = params.get("q", [""])[0].lower().strip()
            results = []
            for item in GLOBAL_BRIDGE.vault_data.all_items():
                title = getattr(item, "title", None) or getattr(item, "name", None) or getattr(item, "cardholder_name", "")
                user = getattr(item, "username", "")
                if query in title.lower() or query in user.lower():
                    results.append({
                        "id": getattr(item, "id", ""),
                        "title": title,
                        "username": user,
                        "category": item.__class__.__name__,
                    })
            self._send_cors_headers()
            self.wfile.write(json.dumps({"results": results[:20]}).encode("utf-8"))
            return

        # 4. API: Password Generator
        if path == "/api/generate":
            self._send_cors_headers()
            length = int(params.get("length", [16])[0])
            pwd = generate_password(length=max(8, min(64, length)))
            bits, rating = calculate_entropy(pwd)
            self.wfile.write(json.dumps({"password": pwd, "entropy_bits": bits, "rating": rating}).encode("utf-8"))
            return

        # 5. Mobile Companion PWA Web App Serving
        if path in ("/mobile", "/mobile/", "/mobile/index.html"):
            mobile_html_path = Path(__file__).parent.parent / "mobile" / "index.html"
            if mobile_html_path.exists():
                self._send_cors_headers(content_type="text/html; charset=utf-8")
                self.wfile.write(mobile_html_path.read_bytes())
                return

        if path.startswith("/mobile/"):
            rel_file = path[len("/mobile/"):]
            target = Path(__file__).parent.parent / "mobile" / rel_file
            if target.exists() and target.is_file():
                ctype = "text/plain"
                if rel_file.endswith(".js"):
                    ctype = "application/javascript"
                elif rel_file.endswith(".css"):
                    ctype = "text/css"
                elif rel_file.endswith(".json") or rel_file.endswith(".webmanifest"):
                    ctype = "application/manifest+json"
                elif rel_file.endswith(".png"):
                    ctype = "image/png"
                self._send_cors_headers(content_type=ctype)
                self.wfile.write(target.read_bytes())
                return

        # 6. Mobile Vault Synchronization Endpoint (Encrypted .lvault export)
        if path == "/mobile/sync":
            self._send_cors_headers(content_type="application/octet-stream")
            token = params.get("token", [""])[0]
            if token != GLOBAL_BRIDGE.pairing_token and token != "local":
                self.send_error(403, "Invalid pairing token")
                return

            if GLOBAL_BRIDGE.vault_path and Path(GLOBAL_BRIDGE.vault_path).exists():
                self.wfile.write(Path(GLOBAL_BRIDGE.vault_path).read_bytes())
                return
            else:
                self.send_error(404, "Vault file not found on disk")
                return

        # Fallback 404
        self.send_error(404, "Endpoint not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read POST body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        payload = {}
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                pass

        # 1. Authenticate Extension via Master Password
        if path == "/api/auth/master-password":
            entered_password = payload.get("password", "")
            if not entered_password:
                self._send_cors_headers(status_code=400)
                self.wfile.write(json.dumps({"error": "Password cannot be empty"}).encode("utf-8"))
                return

            # If desktop vault is open with master_password
            if GLOBAL_BRIDGE.master_password and entered_password == GLOBAL_BRIDGE.master_password:
                token = GLOBAL_BRIDGE.grant_extension_auth()
                self._send_cors_headers()
                self.wfile.write(json.dumps({
                    "authenticated": True,
                    "auth_token": token,
                    "expires_in": GLOBAL_BRIDGE.session_duration_seconds
                }).encode("utf-8"))
                return

            # Check against encrypted vault file on disk if desktop is closed/locked
            vault_file = GLOBAL_BRIDGE.vault_path or str(Path(__file__).parent.parent / "vault.lvault")
            if Path(vault_file).exists():
                try:
                    vault = load_vault(vault_file, entered_password)
                    GLOBAL_BRIDGE.update_vault(vault, entered_password, str(Path(vault_file).resolve()))
                    
                    # Cache master key securely using Windows DPAPI so subsequent Windows Hello unlocks succeed
                    try:
                        import win32crypt
                        import winreg
                        enc = win32crypt.CryptProtectData(entered_password.encode("utf-8"), "LocalVault_MasterKey", None, None, None, 0)
                        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\LocalVault") as k:
                            winreg.SetValueEx(k, "MasterKeyCache", 0, winreg.REG_BINARY, enc)
                    except Exception:
                        pass

                    token = GLOBAL_BRIDGE.grant_extension_auth()
                    self._send_cors_headers()
                    self.wfile.write(json.dumps({
                        "authenticated": True,
                        "auth_token": token,
                        "expires_in": GLOBAL_BRIDGE.session_duration_seconds
                    }).encode("utf-8"))
                    return
                except Exception:
                    self._send_cors_headers(status_code=401)
                    self.wfile.write(json.dumps({"error": "Incorrect Master Password"}).encode("utf-8"))
                    return
            else:
                self._send_cors_headers(status_code=401)
                self.wfile.write(json.dumps({"error": "Incorrect Master Password"}).encode("utf-8"))
                return

        # 2. Authenticate Extension via Windows Hello / Windows PIN
        if path == "/api/auth/windows-hello":
            if not prompt_windows_hello_auth:
                self._send_cors_headers(status_code=501)
                self.wfile.write(json.dumps({"error": "Windows Hello not supported on this platform"}).encode("utf-8"))
                return

            # If vault is not already loaded in memory, try to unlock vault.lvault via cached DPAPI master password
            if not GLOBAL_BRIDGE.is_unlocked:
                unlocked_from_cache = False
                try:
                    import win32crypt
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\LocalVault") as k:
                        val, _ = winreg.QueryValueEx(k, "MasterKeyCache")
                        dec = win32crypt.CryptUnprotectData(val, None, None, None, 0)
                        cached_password = dec[1].decode("utf-8")
                        v_file = GLOBAL_BRIDGE.vault_path or str(Path(__file__).parent.parent / "vault.lvault")
                        if Path(v_file).exists() and cached_password:
                            vault = load_vault(v_file, cached_password)
                            GLOBAL_BRIDGE.update_vault(vault, cached_password, v_file)
                            unlocked_from_cache = True
                except Exception:
                    pass

                if not unlocked_from_cache:
                    self._send_cors_headers(status_code=403)
                    self.wfile.write(json.dumps({
                        "error": "Vault is currently locked. Enter Master Password in extension or unlock LocalVault on PC.",
                        "requires_master_unlock": True
                    }).encode("utf-8"))
                    return

            success, info = prompt_windows_hello_auth(
                caption="LocalVault Security",
                message="Verify with Windows Hello / Windows PIN to access and autofill passwords in Chrome."
            )

            if success:
                token = GLOBAL_BRIDGE.grant_extension_auth()
                self._send_cors_headers()
                self.wfile.write(json.dumps({
                    "authenticated": True,
                    "auth_token": token,
                    "user": info,
                    "expires_in": GLOBAL_BRIDGE.session_duration_seconds
                }).encode("utf-8"))
                return
            else:
                self._send_cors_headers(status_code=401)
                self.wfile.write(json.dumps({"error": info}).encode("utf-8"))
                return

        # 3. Lock Extension Session
        if path == "/api/auth/lock":
            GLOBAL_BRIDGE.revoke_extension_auth()
            self._send_cors_headers()
            self.wfile.write(json.dumps({"status": "locked"}).encode("utf-8"))
            return

        # 4. Lock Entire Desktop Vault
        if path == "/api/lock":
            GLOBAL_BRIDGE.lock_vault()
            self._send_cors_headers()
            self.wfile.write(json.dumps({"status": "locked"}).encode("utf-8"))
            return

        self.send_error(404, "Endpoint not found")


def start_extension_bridge(port: int = 28842) -> bool:
    """Starts the background HTTP bridge server on port 28842."""
    if GLOBAL_BRIDGE.server is not None:
        return True

    # Bind to 127.0.0.1 first for reliable, firewall-free local loopback browser extension access
    for bind_addr in ("127.0.0.1", "0.0.0.0"):
        try:
            server = HTTPServer((bind_addr, port), LocalVaultHTTPRequestHandler)
            GLOBAL_BRIDGE.server = server
            GLOBAL_BRIDGE.port = port

            t = threading.Thread(target=server.serve_forever, daemon=True, name="LocalVaultBridge")
            t.start()
            GLOBAL_BRIDGE.thread = t
            return True
        except Exception:
            continue

    return False


def stop_extension_bridge():
    """Stops the bridge server."""
    if GLOBAL_BRIDGE.server:
        try:
            GLOBAL_BRIDGE.server.shutdown()
            GLOBAL_BRIDGE.server.server_close()
        except Exception:
            pass
        GLOBAL_BRIDGE.server = None

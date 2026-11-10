# 🛡️ LocalVault

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/GUI-PySide6%20(Qt6)-41CD52.svg?logo=qt&logoColor=white)](https://pypi.org/project/PySide6/)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM%20%2B%20Argon2id-critical.svg)](#security-architecture)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Chrome%20%7C%20Brave%20%7C%20Edge%20%7C%20Android-informational.svg)](#platforms)

> **LocalVault** is a 100% offline, zero-knowledge password and secret manager. It gives you the refined, multi-pane experience of premium password managers, native **Windows Hello biometrics/PIN**, and real-time browser autofill — completely without telemetry, subscription fees, or cloud dependencies.

---

## 📑 Table of Contents

- [Key Highlights](#-key-highlights)
- [Security Architecture](#-security-architecture)
- [Project Layout](#-project-layout)
- [Installation & Setup](#-installation--setup)
- [Desktop Application Usage](#-desktop-application-usage)
- [Browser Extension Usage](#-browser-extension-usage)
- [Background Service & System Tray](#-background-service--system-tray)
- [Mobile Companion & Local Sync](#-mobile-companion--local-sync)
- [CLI & Secret Injection](#-cli--secret-injection)
- [Running Automated Tests](#-running-automated-tests)
- [License](#-license)

---

## ✨ Key Highlights

- **100% Offline & Zero-Knowledge:** Your encrypted vault file (`*.lvault`) never leaves your local machine. No external servers, no analytics, no accounts required.
- **Hardware & OS Biometrics:** Unlock your passwords inside Chrome, Brave, and Edge using authentic **Windows Hello** (Fingerprint, Facial Recognition, or Windows PIN).
- **Modern 3-Pane Knox Interface:** Clean category filters, search pill (`Ctrl+K`), fast item inspection, and instant quick-copy actions.
- **Browser Autofill Extension:** Detects current web domains and fills matching usernames, passwords, and TOTP two-factor codes in 1 click.
- **Silent Tray & Background Bridge:** The extension communicates with a lightweight local loopback daemon (`127.0.0.1:28842`), so browser autofill works seamlessly even when the desktop window is closed.
- **Watchtower Security Audit:** Evaluates overall password hygiene, flags weak/reused passwords, missing 2FA seeds, and expired developer tokens.
- **Developer Hub & Process Secret Injection:** Inject secrets directly from vault references (`lvault://...`) into environment variables at runtime without writing plaintext `.env` files to disk.

---

## 🔒 Security Architecture

| Layer | Standard / Implementation |
| :--- | :--- |
| **Cipher** | **AES-256-GCM** Authenticated Encryption with Associated Data (AEAD) |
| **Key Derivation** | **Argon2id** (RFC 9106): 64 MiB RAM, 3 iterations, 4 parallel threads, 256-bit CSPRNG salt |
| **Memory Protection** | Cryptographic key zeroing (`ctypes.memset`) on vault lock; secrets held in secure memory buffers |
| **Biometric Store** | Windows Data Protection API (**DPAPI**) hardware-backed envelope keys |
| **2FA / Authenticator** | RFC 6238 Time-based One-Time Password (**TOTP**) algorithm with live countdown dials |
| **Clipboard Defense** | Excluded from Windows Cloud Clipboard (`Win+V`) and auto-cleared after 30 seconds |

---

## 📂 Project Layout

```text
LocalVault/
├── core/                        # Cryptographic & storage core
│   ├── crypto.py                # Argon2id KDF & AES-256-GCM encryption engine
│   ├── storage.py               # LVKM atomic binary envelope serialization
│   ├── models.py                # Typed credential models (Logins, Cards, Keys, etc.)
│   ├── generator.py             # Cryptographic password generator & entropy scoring
│   ├── totp.py                  # RFC 6238 TOTP computation & verification
│   ├── audit.py                 # Watchtower password health scanner
│   ├── references.py           # Process secret injection engine
│   ├── extension_bridge.py      # Loopback HTTP server (127.0.0.1:28842)
│   ├── service.py               # Headless background daemon
│   └── tray_service.py          # Windows System Tray companion process
├── ui/                          # PySide6 desktop Knox interface
│   ├── main_window.py           # 3-Pane desktop application window
│   ├── unlock_dialog.py         # Master password & 2FA unlock modal
│   ├── entry_dialog.py          # Credential editor dialog
│   ├── api_key_view.py          # Developer API token inspector
│   ├── audit_view.py            # Watchtower circular score dial & reports
│   └── styles.py                # Knox dark theme QSS stylesheet
├── platform_win32/              # Windows OS integrations
│   ├── win_hello.py             # Native Windows Hello / CredUI authentication bridge
│   ├── clipboard.py             # Protected clipboard & auto-flush
│   └── monitor.py               # Session lock & workstation idle monitor
├── extension/                   # Chromium MV3 Browser Extension
│   ├── manifest.json            # Manifest V3 configuration
│   ├── popup/                   # Extension UI with Windows Hello trigger
│   ├── content/                 # Web page input field autofill script
│   └── background/              # Service worker
├── mobile/                      # Companion Web App (offline PWA)
├── android/                     # Native Android project wrapper
├── install_pc.py                # Windows desktop & startup installer
├── start_service.bat            # Detached service launcher
├── start_service.vbs            # Silent background WMI runner
└── requirements.txt             # Python package dependencies
```

---

## 🚀 Installation & Setup

### Prerequisites

- **OS:** Windows 10 or Windows 11 (64-bit)
- **Python:** Python 3.10, 3.11, 3.12, or 3.13

### 1. Clone & Set Up Environment

```powershell
# Clone the repository
git clone https://github.com/<your-username>/LocalVault.git
cd LocalVault

# (Optional) Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### 2. Install Desktop Integration & Startup Service

Run the installer to configure desktop shortcuts, Start Menu entries, the `.lvault` file association, and Windows Startup:

```powershell
python install_pc.py
```

---

## 🖥️ Desktop Application Usage

### Launching

Launch the application using any of the following:
- Double-click the **LocalVault** shortcut on your Desktop or in your Start Menu.
- Or run via terminal:
  ```powershell
  python main.py
  ```

### First-Time Initialization
1. If no vault exists, the app prompts you to create a **Master Password**.
2. An entropy meter evaluates password strength in real time.
3. *(Optional)* Toggle **Two-Factor Authentication (2FA)** to bind your favorite authenticator app (Google Authenticator, Aegis, Ente, etc.).
4. Click **Create Encrypted Vault**. Your container is encrypted and saved locally as `vault.lvault`.

### Day-to-Day Navigation
- **3-Pane Layout:** Filter by category (Logins, Cards, Notes, Developer Keys), select items in the middle pane, and inspect details in the right pane.
- **Quick Actions:** Click **Copy** next to usernames or passwords, or click **Peek (10s)** to reveal hidden passwords with an automatic countdown.
- **Keyboard Shortcuts:**
  - `Ctrl + K`: Jump to and focus the search bar.
  - `Ctrl + N`: Open the New Item category dialog.
  - `Esc`: Close open credential inspector and return to the main list.

---

## 🌐 Browser Extension Usage

The extension works on **Google Chrome**, **Brave Browser**, **Microsoft Edge**, and other Chromium-based browsers.

### Installing the Extension

1. Open your browser and navigate to the extensions management page:
   - **Chrome / Brave / Edge:** `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked**.
4. Select the `extension/` folder inside the `LocalVault` directory.
5. Pin the **LocalVault** icon to your browser toolbar.

### Unlocking & Autofill Workflow
1. Click the LocalVault icon in your toolbar.
2. Click **Use Windows Hello / PIN** (or enter your master password).
3. Complete the native Windows biometric or PIN prompt.
4. When you visit a website (e.g., `github.com` or `spotify.com`), the extension automatically filters and displays matching accounts:
   - Click **Autofill** to inject your credentials into the login form.
   - Click **Copy TOTP** to copy the current 6-digit 2FA token.

---

## ⚙️ Background Service & System Tray

LocalVault includes a background service (`core/tray_service.py`) that lives in your Windows Taskbar System Tray:

- **Always Available:** Keeps loopback port `28842` running in the background so the browser extension can autofill passwords even when the main desktop app window is closed.
- **Hardware-Protected DPAPI Auto-Unlock:** Decrypts your vault on demand when you verify Windows Hello in the extension.
- **Tray Menu Actions:**
  - Double-click the tray icon to launch the desktop interface.
  - Right-click to lock the vault or cleanly stop the service.
- **Manual Launch:** If ever stopped, double-click `start_service.bat` to restart it detached.

---

## 📱 Mobile Companion & Local Sync

LocalVault supports local Wi-Fi pairing with your mobile device without third-party cloud intermediaries:

1. Inside the desktop app, click **Developer** or your profile menu and select **Mobile Companion**.
2. A QR code is generated using your computer's local network IP address (`http://192.168.x.x:28842/mobile`).
3. Scan the QR code with your phone camera on the same Wi-Fi network.
4. The companion web application loads in your mobile browser. Tap **Add to Home Screen** to install it as an offline Progressive Web App (PWA).

---

## 💻 CLI & Secret Injection

LocalVault includes a developer CLI for injecting production secrets directly into process memory without writing sensitive `.env` files to disk:

```powershell
# 1. Inspect a specific secret reference
python main.py get lvault://api_keys/OpenAI/secret_key

# 2. Inject environment variables directly into a child command
python main.py run --env .env.template -- python server.py

# 3. Run a security health audit in terminal
python main.py audit
```

Example `.env.template`:
```env
DATABASE_URL=lvault://databases/Prod/connection_uri
STRIPE_SECRET=lvault://api_keys/Stripe/secret_key
```

---

## 🧪 Running Automated Tests

Run the full test suite with `pytest`:

```powershell
pytest test_vault.py test_app_flow.py -v
```

All tests verify:
- Argon2id key derivation & AES-256-GCM AEAD encryption integrity.
- Binary header packing & version handling.
- Anti-tampering and authentication failure protections.
- Secret reference resolution & template injection.
- TOTP token generation against RFC 6238 test vectors.

---

## 📄 License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

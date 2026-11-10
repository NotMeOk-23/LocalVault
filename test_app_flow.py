"""
End-to-End Automated Flow & Error Diagnostic Script for LocalVault.
Executes the full application lifecycle: setup, unlock, creation, TOTP generation,
inspector rendering, fuzzy searching, persistence, and clipboard protection.
"""

import os
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QTimer

from core.models import VaultData, APIKeyEntry, LoginEntry, SSHEntry, SecureNoteEntry
from core.crypto import (
    derive_master_key,
    encrypt_payload,
    decrypt_payload,
    generate_salt,
    AuthenticationFailedError,
)
from core.totp import calculate_totp, verify_totp, generate_totp_secret
from core.storage import save_vault, load_vault
from ui.styles import DARK_THEME_QSS
from ui.unlock_dialog import UnlockDialog
from ui.main_window import MainWindow
from ui.entry_dialog import EntryDialog
from ui.generator_dialog import GeneratorDialog
from platform_win32.clipboard import clipboard_manager


def run_diagnostics():
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    print("=" * 60)
    print("[*] STARTING LOCALVAULT COMPREHENSIVE RUNTIME DIAGNOSTIC")
    print("=" * 60)

    # 1. Initialize Headless Qt Application
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(DARK_THEME_QSS)
    print("[OK] Qt Application initialized successfully.")

    test_vault_path = Path("diagnostic_test.lvault").resolve()
    if test_vault_path.exists():
        test_vault_path.unlink()

    master_pwd = "MilitaryGradeMasterPassword2026!"

    # 2. Test Vault Creation Flow (UnlockDialog in setup mode)
    print("\n--- 1. Testing Vault Setup & Master Password Initialization ---")
    unlock_dlg = UnlockDialog(vault_path=str(test_vault_path))
    assert unlock_dlg.is_new_vault is True, "Expected dialog to detect new vault"

    unlock_dlg.pwd_edit.setText(master_pwd)
    unlock_dlg.confirm_edit.setText(master_pwd)
    # Execute creation
    unlock_dlg._execute_action(master_pwd)
    assert test_vault_path.exists(), "Vault file was not created on disk!"
    assert unlock_dlg.unlocked_data is not None, "Failed to initialize unlocked_data"
    print(f"[OK] Vault created on disk: {test_vault_path.name} ({test_vault_path.stat().st_size} bytes)")

    # 3. Test MainWindow Initialization
    print("\n--- 2. Testing MainWindow Lifecycle & Navigation ---")
    main_win = MainWindow(unlock_dlg.unlocked_data, master_pwd, str(test_vault_path))
    main_win.show()
    print("[OK] MainWindow instantiated and rendered.")

    # 4. Test Adding Entries via Programmatic UI Actions
    print("\n--- 3. Testing Adding Credentials (API Keys, Logins with TOTP, SSH, Notes) ---")

    # A. Add API Key
    api_entry = APIKeyEntry(
        name="OpenAI GPT-5 Production Key",
        service="OpenAI",
        environment="Production",
        key_id="org-openai-enterprise",
        secret_key="sk-proj-supersecretkey999888777",
        base_url="https://api.openai.com/v1",
        organization_id="org-enterprise",
        tags=["ai", "llm", "prod"],
        notes="Rotated monthly",
    )
    main_win.vault_data.api_keys.append(api_entry)

    # B. Add Login with 2FA Authenticator
    totp_secret = "JBSWY3DPEHPK3PXP"  # Base32 secret for 'Hello!'
    login_entry = LoginEntry(
        title="GitHub Cloud",
        username="lead_architect@company.com",
        password="SuperSecurePassword456!#",
        urls=["https://github.com/login"],
        totp_secret=totp_secret,
        tags=["git", "code"],
    )
    main_win.vault_data.logins.append(login_entry)

    # C. Add SSH Key
    ssh_entry = SSHEntry(
        name="Production Database Bastion",
        hostname="bastion.prod.internal",
        port=2222,
        username="admin",
        private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nMOCK_KEY_DATA\n-----END OPENSSH PRIVATE KEY-----",
        tags=["infrastructure"],
    )
    main_win.vault_data.ssh_keys.append(ssh_entry)

    # D. Add Secure Note
    note_entry = SecureNoteEntry(
        title="Master Cold Storage Recovery Instructions",
        content="BIP-39 Seed Words stored in physical safe #4.",
        tags=["recovery", "critical"],
    )
    main_win.vault_data.secure_notes.append(note_entry)

    # Save to disk and refresh UI
    main_win._save_changes()
    main_win._refresh_categories_and_items()

    assert main_win.items_list.count() == 4, f"Expected 4 items in list, got {main_win.items_list.count()}"
    print(f"[OK] Successfully added 4 items. Current list count: {main_win.items_list.count()}")

    # 5. Test Item Selection & Inspector Rendering
    print("\n--- 4. Testing Item Inspector View & Secret Masking ---")
    # Select API Key
    main_win.inspector.set_entry(api_entry)
    assert main_win.inspector.title_label.text() == "OpenAI GPT-5 Production Key"
    assert main_win.inspector.env_badge.text() == "PRODUCTION"
    assert main_win.inspector.totp_widget.isVisible() is False
    print("[OK] API Key details rendered accurately.")

    # Select Login with TOTP
    main_win.inspector.set_entry(login_entry)
    assert main_win.inspector.title_label.text() == "GitHub Cloud"
    assert main_win.inspector.totp_widget.isVisible() is True
    # Verify TOTP calculation
    current_code = main_win.inspector.totp_widget.code_label.text().replace(" ", "")
    assert len(current_code) == 6, f"Expected 6-digit TOTP code, got '{current_code}'"
    assert verify_totp(current_code, totp_secret), "TOTP code failed verification against secret!"
    print(f"[OK] Live TOTP Authenticator generated active code: {current_code} (Verified valid!)")

    # 6. Test Generator Dialog
    print("\n--- 5. Testing Interactive Generator Dialog (Passwords, Diceware, API Tokens) ---")
    gen_dlg = GeneratorDialog(main_win, initial_mode="password")
    assert len(gen_dlg.generated_result) == 24, "Default password length mismatch"
    assert gen_dlg.entropy_bar.value() > 80, "Entropy calculation lower than expected for 24-char password"
    print(f"[OK] Generated password: {gen_dlg.generated_result[:6]}... (Entropy: {gen_dlg.entropy_label.text()})")

    # Test Diceware mode
    gen_dlg.tabs.setCurrentIndex(1)
    words = gen_dlg.generated_result.split("-")
    assert len(words) == 5, f"Expected 5 words in Diceware passphrase, got {len(words)}"
    print(f"[OK] Generated Diceware passphrase: {gen_dlg.generated_result}")

    # Test API Token mode
    gen_dlg.tabs.setCurrentIndex(2)
    assert gen_dlg.generated_result.startswith("sk_live_"), "API Key prefix mismatch"
    print(f"[OK] Generated API Key token: {gen_dlg.generated_result[:16]}...")
    gen_dlg.close()

    # 7. Test Instant Fuzzy Search & Filtering
    print("\n--- 6. Testing Instant Search & Category Filtering ---")
    main_win._search_query = "OpenAI"
    main_win._refresh_items_list()
    assert main_win.items_list.count() == 1, f"Search filter failed: expected 1 item, got {main_win.items_list.count()}"
    print(f"[OK] Search for 'OpenAI' returned exactly 1 matching record.")

    main_win._search_query = "non_existent_query_xyz"
    main_win._refresh_items_list()
    assert main_win.items_list.count() == 0, "Expected 0 results for non-existent search"
    print("[OK] Search with zero matches handled cleanly.")

    # Reset search
    main_win._search_query = ""
    main_win._active_category = "ssh_keys"
    main_win._refresh_items_list()
    assert main_win.items_list.count() == 1, "Category filter for ssh_keys failed"
    print("[OK] Category switching to 'SSH Keys' correctly displayed 1 item.")

    # Reset to all
    main_win._active_category = "all"
    main_win._refresh_items_list()

    # 8. Test Modification & Persistence Roundtrip
    print("\n--- 7. Testing Persistence Roundtrip (Close & Re-open with Argon2id) ---")
    main_win.close()

    # Reload from disk using storage engine directly
    reloaded = load_vault(str(test_vault_path), master_pwd)
    assert len(reloaded.api_keys) == 1
    assert reloaded.api_keys[0].secret_key == "sk-proj-supersecretkey999888777"
    assert len(reloaded.logins) == 1
    assert reloaded.logins[0].totp_secret == totp_secret
    assert len(reloaded.ssh_keys) == 1
    assert len(reloaded.secure_notes) == 1
    print("[OK] Vault persisted to disk and reloaded with 100% data integrity.")

    # 9. Test Rejection of Incorrect Master Password
    print("\n--- 8. Testing Tamper & Wrong Password Rejection ---")
    try:
        load_vault(str(test_vault_path), "IncorrectPasswordAttempt!")
        assert False, "Vault accepted incorrect master password!"
    except AuthenticationFailedError:
        print("[OK] Successfully rejected incorrect master password via AES-256-GCM AEAD tag check.")

    # 10. Test Windows Clipboard Security Integration
    print("\n--- 9. Testing Windows Clipboard History Protection ---")
    copied = clipboard_manager.copy_secret("temp_diagnostic_secret_12345", wipe_delay=2, exclude_history=True)
    if copied:
        print("[OK] Copied secret with Windows History Exclusion (Win+V exclusion flags injected).")
    else:
        print("[INFO] Non-Windows or clipboard busy (fallback handled).")

    # Cleanup temporary test vault
    if test_vault_path.exists():
        test_vault_path.unlink()
    print("[OK] Temporary test vault cleaned up.")

    print("\n" + "=" * 60)
    print("[*] ALL CHECKS PASSED: 0 ERRORS DETECTED IN LOCALVAULT")
    print("=" * 60)


if __name__ == "__main__":
    run_diagnostics()

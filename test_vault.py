"""
Comprehensive Test Suite for LocalVault Core Engine
Tests Argon2id, AES-256-GCM AEAD, Bit-Flipping resistance, TOTP Authenticator,
Memory Zeroing, Generator, and Atomic Storage.
"""

import os
import time
import pytest
from pathlib import Path

from core.models import VaultData, APIKeyEntry, LoginEntry, SSHEntry, SecureNoteEntry, VaultSettings
from core.crypto import (
    derive_master_key,
    encrypt_payload,
    decrypt_payload,
    generate_salt,
    generate_nonce,
    AuthenticationFailedError,
    SALT_LENGTH,
)
from core.memory import SecureMemoryBuffer, secure_zero_memory
from core.totp import (
    calculate_totp,
    verify_totp,
    generate_totp_secret,
    parse_otpauth_uri,
    normalize_secret,
)
from core.generator import (
    generate_password,
    generate_passphrase,
    generate_api_key,
    calculate_entropy,
    evaluate_password_strength,
)
from core.jwt_decoder import is_jwt_token, decode_jwt
from core.references import resolve_reference, inject_env, format_reference
from core.audit import run_vault_audit
from core.storage import save_vault, load_vault, pack_header, unpack_header


def test_crypto_roundtrip():
    salt = generate_salt(SALT_LENGTH)
    password = "SuperStrongMasterPassword!2026"
    key_buf = derive_master_key(password, salt, memory_cost=16384, time_cost=2, parallelism=2)

    plaintext = b"Sensitive API Key: sk_live_9999888877776666"
    nonce, ciphertext_and_tag = encrypt_payload(plaintext, key_buf, compress=True)

    # Valid decrypt
    decrypted = decrypt_payload(nonce, ciphertext_and_tag, key_buf, decompress=True)
    assert decrypted == plaintext

    # Wrong password test
    wrong_key = derive_master_key("WrongPassword123!", salt, memory_cost=16384, time_cost=2, parallelism=2)
    with pytest.raises(AuthenticationFailedError):
        decrypt_payload(nonce, ciphertext_and_tag, wrong_key, decompress=True)

    wrong_key.wipe()
    key_buf.wipe()


def test_crypto_bit_flipping_tamper_detection():
    """Verify AES-256-GCM immediately catches tampered ciphertext or nonce."""
    salt = generate_salt(SALT_LENGTH)
    key_buf = derive_master_key("TestMasterPwd!", salt, memory_cost=16384, time_cost=2, parallelism=2)

    plaintext = b"Role: admin=0, user=1"
    nonce, ciphertext_and_tag = encrypt_payload(plaintext, key_buf, compress=False)

    # Flip a single bit in the ciphertext
    tampered_bytes = bytearray(ciphertext_and_tag)
    tampered_bytes[5] ^= 0x01  # Flip bit

    with pytest.raises(AuthenticationFailedError):
        decrypt_payload(nonce, bytes(tampered_bytes), key_buf, decompress=False)

    # Flip a bit in the nonce
    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0x01
    with pytest.raises(AuthenticationFailedError):
        decrypt_payload(bytes(tampered_nonce), ciphertext_and_tag, key_buf, decompress=False)

    key_buf.wipe()


def test_memory_security_zeroing():
    sensitive = bytearray(b"super_secret_master_token_data")
    assert any(b != 0 for b in sensitive)
    secure_zero_memory(sensitive)
    assert all(b == 0 for b in sensitive)

    with SecureMemoryBuffer(b"crypto_key_bytes_1234567890") as buf:
        assert buf.size > 0
        raw = buf.get_bytes()
        assert raw == b"crypto_key_bytes_1234567890"
    # When exited, buffer is wiped
    assert buf.size == 0


def test_totp_authenticator():
    # RFC 6238 standard test vector
    # Secret: '12345678901234567890' (in Base32: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
    rfc_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    # At T=59s, step=1, RFC 6238 code with SHA1 is 287082
    code, rem, prog = calculate_totp(rfc_secret, for_time=59, period=30, digits=6, algorithm="SHA1")
    assert code == "287082"
    assert rem == 1  # 59 % 30 = 29, 30 - 29 = 1s left

    # Current time verification
    curr_code, _, _ = calculate_totp(rfc_secret)
    assert len(curr_code) == 6
    assert verify_totp(curr_code, rfc_secret)
    assert not verify_totp("000000", rfc_secret)

    # New secret generation
    new_sec = generate_totp_secret()
    assert len(new_sec) >= 16

    # OTPAuth URI parsing
    uri = "otpauth://totp/LocalVault:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=LocalVault&period=30&digits=6"
    parsed = parse_otpauth_uri(uri)
    assert parsed["secret"] == "JBSWY3DPEHPK3PXP"
    assert parsed["issuer"] == "LocalVault"
    assert parsed["digits"] == 6


def test_password_strength_rules():
    """Verify rule-based evaluation: 10+ chars with all 4 types for Strong, 12-14+ for Military-Grade."""
    # 1. Long password with ONLY lowercase -> Must be Very Weak (missing 3 types)
    _, rating_lower, score, hint = evaluate_password_strength("abcdefghijklmnopqrst")
    assert rating_lower == "Very Weak"
    assert "uppercase" in hint and "numbers" in hint and "symbols" in hint

    # 2. 12+ chars with upper, lower, numbers, but NO special symbols -> Must be Moderate (NOT Strong or Military-Grade)
    _, rating_no_sym, _, hint_no_sym = evaluate_password_strength("Password123456")
    assert rating_no_sym == "Moderate"
    assert "symbols" in hint_no_sym

    # 3. 8 chars with ALL 4 types -> Must be Moderate (too short for Strong)
    _, rating_short_4, _, hint_short_4 = evaluate_password_strength("Aa1!Bb2@")
    assert rating_short_4 == "Moderate"
    assert "10 more" in hint_short_4 or "Need 2 more" in hint_short_4

    # 4. Exactly 10 chars with ALL 4 types -> Must be Strong
    _, rating_10, score_10, _ = evaluate_password_strength("Abcde!1234")
    assert rating_10 == "Strong"
    assert score_10 >= 75

    # 5. Exactly 12 chars with ALL 4 types -> Must be Military-Grade
    _, rating_12, score_12, _ = evaluate_password_strength("Abcd!1234567")
    assert rating_12 == "Military-Grade"
    assert score_12 >= 90

    # 6. 14+ chars with ALL 4 types -> Must be Military-Grade (100%)
    _, rating_14, score_14, _ = evaluate_password_strength("Abcdefgh!12345")
    assert rating_14 == "Military-Grade"
    assert score_14 == 100


def test_generator_entropy():
    pwd = generate_password(length=24, use_upper=True, use_lower=True, use_digits=True, use_special=True)
    assert len(pwd) == 24
    entropy, rating = calculate_entropy(pwd)
    assert entropy > 80.0
    assert rating in ["Strong", "Very Strong", "Military-Grade"]

    passphrase = generate_passphrase(num_words=6, separator="-")
    words = passphrase.split("-")
    assert len(words) == 6

    api_key = generate_api_key(prefix="sk_live_", length=32, mode="hex")
    assert api_key.startswith("sk_live_")
    assert len(api_key) == 8 + 32  # prefix + 32 hex chars


def test_storage_atomic_save_and_load(tmp_path: Path):
    vault_file = str(tmp_path / "test_vault.lvault")
    master_pwd = "VaultSecretPassword123!"

    vault = VaultData()
    vault.settings.auto_lock_minutes = 10
    vault.api_keys.append(
        APIKeyEntry(
            name="OpenAI API Key",
            service="OpenAI",
            environment="Production",
            key_id="org-localvault",
            secret_key="sk-proj-test1234567890",
            tags=["ai", "prod"],
        )
    )
    vault.logins.append(
        LoginEntry(
            title="GitHub",
            username="dev_user",
            password="UltraPassword456!",
            totp_secret="JBSWY3DPEHPK3PXP",
        )
    )

    save_vault(vault, vault_file, master_pwd)
    assert os.path.exists(vault_file)

    # Load back
    loaded = load_vault(vault_file, master_pwd)
    assert loaded.settings.auto_lock_minutes == 10
    assert len(loaded.api_keys) == 1
    assert loaded.api_keys[0].name == "OpenAI API Key"
    assert loaded.api_keys[0].secret_key == "sk-proj-test1234567890"
    assert len(loaded.logins) == 1
    assert loaded.logins[0].totp_secret == "JBSWY3DPEHPK3PXP"

    # Wrong password raises error
    with pytest.raises(AuthenticationFailedError):
        load_vault(vault_file, "WrongMasterPassword!")


def test_jwt_decoder():
    # Valid mock JWT token:
    # Header: {"alg": "HS256", "typ": "JWT"} -> eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCL9
    # Payload: {"sub": "1234567890", "name": "Alice", "iat": 1516239022, "exp": 1999999999}
    header_b64 = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
    payload_b64 = "eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkFsaWNlIiwgImV4cCI6IDE5OTk5OTk5OTksICJpYXQiOiAxNTE2MjM5MDIyfQ"
    sig_b64 = "mock_signature_bytes_12345"
    mock_jwt = f"{header_b64}.{payload_b64}.{sig_b64}"

    assert is_jwt_token(mock_jwt) is True
    assert is_jwt_token("sk-proj-not-a-jwt") is False

    decoded = decode_jwt(mock_jwt)
    assert decoded is not None
    assert decoded["algorithm"] == "HS256"
    assert decoded["subject"] == "1234567890"
    assert decoded["payload"]["name"] == "Alice"
    assert decoded["is_expired"] is False


def test_secret_references():
    vault = VaultData()
    vault.api_keys.append(
        APIKeyEntry(
            name="Stripe Live API",
            service="Stripe",
            key_id="pk_live_12345",
            secret_key="sk_live_999888777",
        )
    )
    vault.logins.append(
        LoginEntry(
            title="GitHub",
            username="alice@company.com",
            password="UltraSecretPassword!99",
            totp_secret="JBSWY3DPEHPK3PXP",
        )
    )

    # Resolve direct fields
    assert resolve_reference("lvault://api_keys/Stripe Live API/secret_key", vault) == "sk_live_999888777"
    assert resolve_reference("lvault://api_keys/Stripe Live API/key_id", vault) == "pk_live_12345"
    assert resolve_reference("lvault://logins/GitHub/password", vault) == "UltraSecretPassword!99"
    assert resolve_reference("lvault://logins/GitHub/username", vault) == "alice@company.com"

    # Resolve dynamic TOTP rolling code
    totp_code = resolve_reference("lvault://logins/GitHub/totp_code", vault)
    assert len(totp_code) == 6
    assert totp_code.isdigit()

    # Template env injection
    template = """
    # Local Development Environment
    STRIPE_KEY=lvault://api_keys/Stripe Live API/secret_key
    PUBLIC_KEY=lvault://api_keys/Stripe Live API/key_id
    DB_PASSWORD=lvault://logins/GitHub/password
    STATIC_VAR=hello_world
    """
    injected = inject_env(template, vault)
    assert injected["STRIPE_KEY"] == "sk_live_999888777"
    assert injected["PUBLIC_KEY"] == "pk_live_12345"
    assert injected["DB_PASSWORD"] == "UltraSecretPassword!99"
    assert injected["STATIC_VAR"] == "hello_world"


def test_security_audit_watchtower():
    vault = VaultData()

    # 1. Weak Login
    vault.logins.append(
        LoginEntry(
            title="Old Forum",
            username="user1",
            password="password123",  # Weak (no symbols, no upper)
            totp_secret="",          # Missing 2FA
        )
    )

    # 2. Reused Password Login
    vault.logins.append(
        LoginEntry(
            title="Shopping Site",
            username="user2",
            password="password123",  # Reused identical password
            totp_secret="",
        )
    )

    # 3. Expired API Key
    vault.api_keys.append(
        APIKeyEntry(
            name="Deprecated Cloud Key",
            secret_key="sk-old-key",
            expires_at="2020-01-01T00:00:00Z",  # Expired
        )
    )

    report = run_vault_audit(vault)
    assert report.total_items_scanned == 3
    assert report.weak_passwords_count >= 1
    assert report.reused_passwords_count >= 2
    assert report.missing_2fa_count >= 2
    assert report.expired_keys_count >= 1
    assert report.score < 70
    assert report.grade in ["C", "F"]
    assert len(report.issues) >= 4


def test_multiple_similar_sites_and_home_privacy():
    """
    Tests:
    1. Multiple similar sites for the same credentials (e.g. static.formula1.com and id.formula1.com).
    2. Secret references for multi-site URLs.
    3. Home page card does NOT show user ID / username, and shows only linked sites.
    4. Home page card height optimization (78px sizeHint, no clipped text).
    """
    import os
    from PySide6.QtWidgets import QApplication, QLabel
    from PySide6.QtCore import Qt
    from ui.main_window import MainWindow

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication([])

    vault = VaultData()
    f1_login = LoginEntry(
        title="Formula 1 Fan Pass",
        username="private_user_42@domain.com",
        password="SuperStrongPass!2026",
        urls=["https://static.formula1.com", "https://id.formula1.com"],
        totp_secret="JBSWY3DPEHPK3PXP",
    )
    vault.logins.append(f1_login)

    # 1. Verify Secret References for multiple sites
    assert resolve_reference("lvault://logins/Formula 1 Fan Pass/url", vault) == "https://static.formula1.com"
    assert resolve_reference("lvault://logins/Formula 1 Fan Pass/urls", vault) == "https://static.formula1.com, https://id.formula1.com"
    assert resolve_reference("lvault://logins/Formula 1 Fan Pass/url_1", vault) == "https://static.formula1.com"
    assert resolve_reference("lvault://logins/Formula 1 Fan Pass/url_2", vault) == "https://id.formula1.com"

    # 2. Verify Home Page UI Rendering
    win = MainWindow(vault, "TestMasterPassword123!", "test.lvault")
    assert win.items_list.count() == 1

    item = win.items_list.item(0)
    assert item.sizeHint().height() == 78  # Optimized height accommodates full word size

    card = win.items_list.itemWidget(item)
    labels = card.findChildren(QLabel)
    texts = [lbl.text() for lbl in labels]

    # Verify Title
    assert "Formula 1 Fan Pass" in texts

    # Verify Privacy: username ("private_user_42@domain.com") MUST NOT appear on home page
    for t in texts:
        assert "private_user_42@domain.com" not in t

    # Verify linked sites are displayed in subtitle
    subtitle_found = any("static.formula1.com" in t and "id.formula1.com" in t for t in texts)
    assert subtitle_found, f"Expected linked sites in subtitle, got: {texts}"

    # 3. Verify Search matches multiple linked sites
    win.search_edit.setText("static.formula1")
    assert win.items_list.count() == 1

    win.search_edit.setText("id.formula1")
    assert win.items_list.count() == 1

    win.search_edit.setText("nonexistent.site")
    assert win.items_list.count() == 0

    # 4. Verify Inspector displays Username / Email right where the password is seen so user can log in
    win.search_edit.setText("")
    win._on_item_selected(win.items_list.item(0))
    assert win.inspector.current_entry is not None

    # Inspect all widgets in the inspector: Username / Email MUST be present so user knows what to enter
    from PySide6.QtWidgets import QLineEdit
    inspector_labels = [lbl.text() for lbl in win.inspector.findChildren(QLabel)]
    inspector_edits = [ed.text() for ed in win.inspector.findChildren(QLineEdit)]
    all_inspector_texts = inspector_labels + inspector_edits

    assert "private_user_42@domain.com" in all_inspector_texts, "User ID / email must be rendered in the inspector where password is seen"
    assert "USERNAME / EMAIL" in inspector_labels, "'USERNAME / EMAIL' field must appear in inspector"

    # Verify sort button is properly sized and toggles
    assert win.sort_btn.text() == "↓ A"
    assert win.sort_btn.width() >= 50
    win._toggle_sort()
    assert win.sort_btn.text() == "↑ Z"
    win._toggle_sort()
    assert win.sort_btn.text() == "↓ A"

    # Verify clicking 'All Items' in sidebar resets inspector and returns to full list
    win._on_item_selected(win.items_list.item(0))
    assert win.inspector.current_entry is not None
    # Simulate clicking All Items in sidebar
    for i in range(win.sidebar_list.count()):
        it = win.sidebar_list.item(i)
        if it.data(Qt.ItemDataRole.UserRole) == "all_items":
            win._on_sidebar_item_clicked(it)
            break
    assert win.inspector.current_entry is None
    assert win.cat_filter_combo.currentIndex() == 0

    # Verify badge style is flat (no button border to prevent fake clickable button appearance)
    from ui.styles import get_category_badge_style, DARK_THEME_QSS
    assert "border: none" in get_category_badge_style("login")
    assert "border-color: #38bdf8" not in DARK_THEME_QSS.split("itemsList::item:hover")[1].split("}")[0], "No blinking light border on hover"

    # Open Watchtower
    win._open_audit_view()
    assert win.main_stack.currentIndex() == 1

    # Trigger ESC key reset
    win._close_open_credentials_and_jump_home()

    assert win.inspector.current_entry is None
    assert len(win.items_list.selectedItems()) == 0
    assert win.main_stack.currentIndex() == 0
    assert win._active_category == "all"
    assert win.search_edit.text() == ""


def test_1password_knox_categories_and_views():
    """
    Verifies:
    1. Serialization and deserialization of all 1Password item categories.
    2. VaultData.all_items() aggregation across all 12 categories.
    3. Storage persistence roundtrip with new categories.
    4. Headless rendering of 1Password CategoryPickerDialog, ProfileView,
       DeveloperHubView, and Watchtower CircularGaugeWidget.
    """
    import os
    import tempfile
    from PySide6.QtWidgets import QApplication
    from core.models import (
        CreditCardEntry,
        IdentityEntry,
        BankAccountEntry,
        DatabaseEntry,
        CryptoWalletEntry,
        ServerEntry,
        SoftwareLicenseEntry,
        PasswordItemEntry,
    )
    from ui.category_picker_dialog import CategoryPickerDialog
    from ui.profile_view import ProfileView
    from ui.developer_view import DeveloperHubView
    from ui.audit_view import CircularGaugeWidget
    from ui.main_window import MainWindow

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication([])

    # 1. Create items
    card = CreditCardEntry(cardholder_name="Alex Mercer", card_number="4111111111111234", expiry_month="05", expiry_year="2029", cvv="789")
    identity = IdentityEntry(title="Primary Passport", first_name="Alex", last_name="Mercer", email="alex@mercer.internal")
    bank = BankAccountEntry(title="Chase Operations", bank_name="JPMorgan Chase", account_number="9876543210", routing_number="021000021")
    db = DatabaseEntry(title="RDS Master", db_type="PostgreSQL", hostname="rds.aws.internal", port=5432, password="DbPassword!2026")
    crypto = CryptoWalletEntry(title="Cold Ledger", network="Ethereum", address="0x1234567890abcdef1234567890abcdef12345678")
    server = ServerEntry(title="Edge Gateway", ip_address="192.168.1.1", server_type="Linux")
    license_item = SoftwareLicenseEntry(title="CLion License", software_name="CLion", license_key="CL-1234-5678-ABCD")
    pwd_item = PasswordItemEntry(title="Master Safe Key", password="UltraSecureSafeCombination!999")

    # 2. Test to_dict and from_dict roundtrip
    for item_cls, item_obj in [
        (CreditCardEntry, card),
        (IdentityEntry, identity),
        (BankAccountEntry, bank),
        (DatabaseEntry, db),
        (CryptoWalletEntry, crypto),
        (ServerEntry, server),
        (SoftwareLicenseEntry, license_item),
        (PasswordItemEntry, pwd_item),
    ]:
        d = item_obj.to_dict()
        recreated = item_cls.from_dict(d)
        assert recreated.id == item_obj.id
        assert recreated.vault_name == "Personal"

    # 3. Add to VaultData and test persistence
    vault = VaultData()
    vault.credit_cards.append(card)
    vault.identities.append(identity)
    vault.bank_accounts.append(bank)
    vault.databases.append(db)
    vault.crypto_wallets.append(crypto)
    vault.servers.append(server)
    vault.software_licenses.append(license_item)
    vault.passwords.append(pwd_item)

    all_items = vault.all_items()
    assert len(all_items) == 8

    with tempfile.NamedTemporaryFile(suffix=".lvault", delete=False) as tf:
        temp_path = tf.name

    try:
        save_vault(vault, temp_path, "VaultSecretKey2026!")
        reloaded = load_vault(temp_path, "VaultSecretKey2026!")
        assert len(reloaded.credit_cards) == 1
        assert reloaded.credit_cards[0].cardholder_name == "Alex Mercer"
        assert len(reloaded.bank_accounts) == 1
        assert reloaded.bank_accounts[0].account_number == "9876543210"
        assert len(reloaded.databases) == 1
        assert reloaded.databases[0].password == "DbPassword!2026"
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    # 4. Headless UI Component Verification
    picker = CategoryPickerDialog()
    picker.search_edit.setText("credit")
    credit_card_tuple = next(t for t in picker.category_widgets if t[0] == "credit_cards")
    login_tuple = next(t for t in picker.category_widgets if t[0] == "login")
    assert credit_card_tuple[2].isHidden() is False
    assert login_tuple[2].isHidden() is True

    profile = ProfileView(vault_data=vault)
    assert profile.avatar_label.text() != ""

    dev_hub = DeveloperHubView()
    assert dev_hub is not None

    gauge = CircularGaugeWidget(score=988)
    assert gauge.score == 988

    # 5. MainWindow integration with all categories
    win = MainWindow(vault, "VaultSecretKey2026!", "test_categories.lvault")
    assert win.items_list.count() == 8
    # Switch to credit cards category filter
    win.cat_filter_combo.setCurrentIndex(2)  # Credit Cards
    assert win.items_list.count() == 1
    win._on_item_selected(win.items_list.item(0))
    assert win.inspector.current_entry is not None
    assert win.inspector.title_label.text() == "Alex Mercer"


if __name__ == "__main__":
    pytest.main(["-v", __file__])

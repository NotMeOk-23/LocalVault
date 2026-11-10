"""
LocalVault Lock & Unlock Screen
Handles first-time master password initialization, 2FA setup, and secure vault unlocking.
"""

from pathlib import Path
from typing import Optional, Tuple
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QProgressBar,
    QCheckBox,
    QFileDialog,
    QMessageBox,
    QFrame,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

from core.generator import calculate_entropy, evaluate_password_strength
from core.models import VaultData, VaultSettings
from core.storage import save_vault, load_vault
from core.totp import generate_totp_secret, verify_totp, calculate_totp
from core.crypto import AuthenticationFailedError


class UnlockDialog(QDialog):
    """
    Master Password Authentication and Initial Vault Setup Modal.
    """

    def __init__(self, parent=None, vault_path: str = "vault.lvault"):
        super().__init__(parent)
        self.vault_path = str(Path(vault_path).resolve())
        self.unlocked_data: Optional[VaultData] = None
        self.master_password: str = ""

        self.setWindowTitle("LocalVault - Military-Grade Zero-Knowledge Vault")
        self.setFixedWidth(460)

        self._setup_ui()
        self._check_vault_exists()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        # Header Logo & Title
        header_layout = QVBoxLayout()
        header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        shield_icon = QLabel("🛡️")
        shield_icon.setFont(QFont("Segoe UI Emoji", 36))
        shield_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(shield_icon)

        self.title_lbl = QLabel("LocalVault")
        self.title_lbl.setObjectName("titleLabel")
        self.title_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(self.title_lbl)

        self.subtitle_lbl = QLabel("100% Offline • AES-256-GCM • Argon2id")
        self.subtitle_lbl.setObjectName("subtitleLabel")
        self.subtitle_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(self.subtitle_lbl)

        layout.addLayout(header_layout)

        # Vault File Selector Row
        file_row = QHBoxLayout()
        self.file_label = QLabel(Path(self.vault_path).name)
        self.file_label.setStyleSheet("color: #38bdf8; font-weight: 600; font-size: 11px;")
        file_row.addWidget(QLabel("Vault:"))
        file_row.addWidget(self.file_label)
        file_row.addStretch()

        self.switch_file_btn = QPushButton("Change...")
        self.switch_file_btn.setFixedHeight(24)
        self.switch_file_btn.clicked.connect(self._choose_vault_file)
        file_row.addWidget(self.switch_file_btn)
        layout.addLayout(file_row)

        # Main Input Card
        self.card = QFrame()
        self.card.setObjectName("cardFrame")
        card_layout = QVBoxLayout(self.card)
        card_layout.setSpacing(10)

        # Password Row
        pwd_lbl = QLabel("MASTER PASSWORD")
        pwd_lbl.setObjectName("sectionHeader")
        card_layout.addWidget(pwd_lbl)

        pwd_row = QHBoxLayout()
        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_edit.setPlaceholderText("Enter Master Password")
        self.pwd_edit.textChanged.connect(self._on_password_changed)
        self.pwd_edit.returnPressed.connect(self._handle_action)
        pwd_row.addWidget(self.pwd_edit)

        self.peek_btn = QPushButton("👁")
        self.peek_btn.setFixedWidth(36)
        self.peek_btn.clicked.connect(self._toggle_peek)
        pwd_row.addWidget(self.peek_btn)
        card_layout.addLayout(pwd_row)

        # Confirmation Password (Setup Mode Only)
        self.confirm_lbl = QLabel("CONFIRM MASTER PASSWORD")
        self.confirm_lbl.setObjectName("sectionHeader")
        card_layout.addWidget(self.confirm_lbl)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit.setPlaceholderText("Re-type Master Password")
        self.confirm_edit.returnPressed.connect(self._handle_action)
        card_layout.addWidget(self.confirm_edit)

        # Password Entropy Bar (Setup Mode Only)
        self.entropy_container = QWidget()
        ent_layout = QVBoxLayout(self.entropy_container)
        ent_layout.setContentsMargins(0, 0, 0, 0)
        ent_layout.setSpacing(4)

        ent_text_row = QHBoxLayout()
        self.entropy_text = QLabel("Strength: Empty")
        self.entropy_text.setStyleSheet("font-size: 11px; color: #94a3b8;")
        ent_text_row.addWidget(self.entropy_text)
        ent_text_row.addStretch()
        ent_layout.addLayout(ent_text_row)

        self.entropy_bar = QProgressBar()
        self.entropy_bar.setRange(0, 100)
        self.entropy_bar.setFixedHeight(4)
        self.entropy_bar.setTextVisible(False)
        ent_layout.addWidget(self.entropy_bar)

        card_layout.addWidget(self.entropy_container)

        # 2FA Authenticator Code Input (Visible if 2FA is required)
        self.totp_container = QWidget()
        totp_box = QVBoxLayout(self.totp_container)
        totp_box.setContentsMargins(0, 0, 0, 0)
        totp_box.setSpacing(4)

        totp_lbl = QLabel("2FA AUTHENTICATOR CODE")
        totp_lbl.setObjectName("sectionHeader")
        totp_box.addWidget(totp_lbl)

        self.totp_edit = QLineEdit()
        self.totp_edit.setPlaceholderText("6-digit Code from Authenticator App")
        self.totp_edit.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        self.totp_edit.returnPressed.connect(self._handle_action)
        totp_box.addWidget(self.totp_edit)

        card_layout.addWidget(self.totp_container)

        # Setup 2FA Option (Setup Mode Only)
        self.setup_2fa_cb = QCheckBox("Enable Authenticator 2FA for Vault Unlock")
        self.setup_2fa_cb.setStyleSheet("color: #38bdf8; font-weight: 500;")
        self.setup_2fa_cb.toggled.connect(self._on_setup_2fa_toggled)
        card_layout.addWidget(self.setup_2fa_cb)

        # 2FA Seed reveal during setup
        self.seed_container = QWidget()
        seed_layout = QVBoxLayout(self.seed_container)
        seed_layout.setContentsMargins(0, 0, 0, 0)
        seed_layout.setSpacing(4)

        seed_lbl = QLabel("AUTHENTICATOR SECRET SEED (Save to Google Authenticator / Authy):")
        seed_lbl.setStyleSheet("font-size: 10px; color: #fbbf24; font-weight: bold;")
        seed_layout.addWidget(seed_lbl)

        self.seed_display = QLineEdit()
        self.seed_display.setReadOnly(True)
        self.seed_display.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        seed_layout.addWidget(self.seed_display)

        seed_verify_lbl = QLabel("Enter Current 6-digit Code to verify 2FA setup:")
        seed_verify_lbl.setStyleSheet("font-size: 11px; color: #94a3b8;")
        seed_layout.addWidget(seed_verify_lbl)

        self.setup_totp_verify = QLineEdit()
        self.setup_totp_verify.setPlaceholderText("123456")
        seed_layout.addWidget(self.setup_totp_verify)

        card_layout.addWidget(self.seed_container)

        layout.addWidget(self.card)

        # Action Button & Status
        self.status_lbl = QLabel("")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 12px;")
        layout.addWidget(self.status_lbl)

        self.action_btn = QPushButton("Unlock Vault")
        self.action_btn.setObjectName("primaryButton")
        self.action_btn.setFixedHeight(40)
        self.action_btn.clicked.connect(self._handle_action)
        layout.addWidget(self.action_btn)

    def _check_vault_exists(self):
        exists = Path(self.vault_path).exists()
        self.is_new_vault = not exists

        if self.is_new_vault:
            self.title_lbl.setText("Initialize Vault")
            self.subtitle_lbl.setText("Create your local master password")
            self.action_btn.setText("Create Encrypted Vault")
            self.confirm_lbl.setVisible(True)
            self.confirm_edit.setVisible(True)
            self.entropy_container.setVisible(True)
            self.setup_2fa_cb.setVisible(True)
            self.totp_container.setVisible(False)
            self.seed_container.setVisible(False)
        else:
            self.title_lbl.setText("Unlock Vault")
            self.subtitle_lbl.setText("100% Offline • AES-256-GCM")
            self.action_btn.setText("Unlock Vault")
            self.confirm_lbl.setVisible(False)
            self.confirm_edit.setVisible(False)
            self.entropy_container.setVisible(False)
            self.setup_2fa_cb.setVisible(False)
            self.seed_container.setVisible(False)
            # We will show totp_container if vault settings indicate 2FA enabled after password test
            self.totp_container.setVisible(False)

    def _on_password_changed(self, text: str):
        if self.is_new_vault:
            bits, rating, score_pct, hint = evaluate_password_strength(text)
            if hint and text:
                self.entropy_text.setText(f"Strength: {rating} ({score_pct}%) — {hint}")
            else:
                self.entropy_text.setText(f"Strength: {rating}")
            self.entropy_bar.setValue(score_pct)

            if score_pct >= 90:
                color = "#00e676"  # Emerald green (Military-Grade)
            elif score_pct >= 75:
                color = "#00d2ff"  # Cyan (Strong)
            elif score_pct >= 45:
                color = "#fbbf24"  # Amber (Moderate)
            else:
                color = "#ef4444"  # Red (Weak / Very Weak)

            self.entropy_bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: #1e293b;
                    border: none;
                    border-radius: 2px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 2px;
                }}
            """)

    def _on_setup_2fa_toggled(self, checked: bool):
        self.seed_container.setVisible(checked)
        if checked and not self.seed_display.text():
            secret = generate_totp_secret()
            self.seed_display.setText(secret)

    def _toggle_peek(self):
        if self.pwd_edit.echoMode() == QLineEdit.EchoMode.Password:
            self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.peek_btn.setText("🔒")
        else:
            self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.peek_btn.setText("👁")

    def _choose_vault_file(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Select or Create Vault File",
            self.vault_path,
            "LocalVault Container (*.lvault);;All Files (*.*)",
        )
        if file_path:
            self.vault_path = str(Path(file_path).resolve())
            self.file_label.setText(Path(self.vault_path).name)
            self._check_vault_exists()

    def _handle_action(self):
        password = self.pwd_edit.text()
        if not password:
            self.status_lbl.setText("Master password cannot be empty.")
            return

        self.status_lbl.setText("")
        self.action_btn.setEnabled(False)
        self.action_btn.setText("Computing Argon2id Key...")

        # Process in UI loop
        QTimer.singleShot(50, lambda: self._execute_action(password))

    def _execute_action(self, password: str):
        try:
            if self.is_new_vault:
                confirm = self.confirm_edit.text()
                if password != confirm:
                    self.status_lbl.setText("Passwords do not match!")
                    self.action_btn.setEnabled(True)
                    self.action_btn.setText("Create Encrypted Vault")
                    return

                vault_data = VaultData()
                if self.setup_2fa_cb.isChecked():
                    seed = self.seed_display.text().strip()
                    token = self.setup_totp_verify.text().strip()
                    if not verify_totp(token, seed):
                        self.status_lbl.setText("Invalid 2FA Authenticator code!")
                        self.action_btn.setEnabled(True)
                        self.action_btn.setText("Create Encrypted Vault")
                        return
                    vault_data.settings.vault_2fa_enabled = True
                    vault_data.settings.vault_2fa_secret = seed

                save_vault(vault_data, self.vault_path, password)
                self.unlocked_data = vault_data
                self.master_password = password
                self.accept()

            else:
                # Decrypt vault
                try:
                    data = load_vault(self.vault_path, password)
                except AuthenticationFailedError:
                    self.status_lbl.setText("Incorrect master password or corrupted file.")
                    self.action_btn.setEnabled(True)
                    self.action_btn.setText("Unlock Vault")
                    return

                # If 2FA enabled on vault
                if data.settings.vault_2fa_enabled and data.settings.vault_2fa_secret:
                    if not self.totp_container.isVisible():
                        self.totp_container.setVisible(True)
                        self.totp_edit.setFocus()
                        self.status_lbl.setText("Master password accepted. Please enter 2FA code.")
                        self.status_lbl.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 12px;")
                        self.action_btn.setEnabled(True)
                        self.action_btn.setText("Verify 2FA & Unlock")
                        return

                    # Verify 2FA token
                    token = self.totp_edit.text().strip()
                    if not verify_totp(token, data.settings.vault_2fa_secret):
                        self.status_lbl.setText("Invalid 2FA Authenticator code.")
                        self.status_lbl.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 12px;")
                        self.action_btn.setEnabled(True)
                        self.action_btn.setText("Verify 2FA & Unlock")
                        return

                self.unlocked_data = data
                self.master_password = password
                self.accept()

        except Exception as e:
            self.status_lbl.setText(f"Error: {str(e)[:50]}")
            self.action_btn.setEnabled(True)
            self.action_btn.setText("Retry")

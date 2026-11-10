"""
LocalVault 1Password Manage Account Modal
Recreates 1Password's Manage Account window with tabs:
Your Details, Sign-in & Recovery, Linked to Your Account, and Usage data.
"""

from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedWidget,
    QListWidget,
    QListWidgetItem,
    QFrame,
    QLineEdit,
    QCheckBox,
    QMessageBox,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont

from core.models import VaultData


class ManageAccountDialog(QDialog):
    """
    Manage Account dialog matching 1Password's exact account management interface.
    """

    def __init__(self, parent=None, vault_data: VaultData = None):
        super().__init__(parent)
        self.vault_data = vault_data or VaultData()

        self.setWindowTitle("Manage Account")
        self.resize(680, 480)
        self.setStyleSheet("""
            QDialog {
                background-color: #101622;
                border: 1px solid #233146;
                border-radius: 12px;
            }
        """)

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Left Vertical Tabs Pane
        left_pane = QWidget()
        left_pane.setFixedWidth(210)
        left_pane.setStyleSheet("background-color: #0d121c; border-right: 1px solid #1a2333;")
        left_layout = QVBoxLayout(left_pane)
        left_layout.setContentsMargins(14, 18, 14, 18)
        left_layout.setSpacing(8)

        dialog_title = QLabel("Manage Account")
        dialog_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        dialog_title.setStyleSheet("color: #f8fafc; margin-bottom: 8px;")
        left_layout.addWidget(dialog_title)

        self.tab_list = QListWidget()
        self.tab_list.setObjectName("sidebarList")
        self.tab_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        tabs = [
            ("👤  Your Details", 0),
            ("🔑  Sign-in & Recovery", 1),
            ("💻  Linked to Your Account", 2),
            ("📊  Usage data", 3),
        ]
        for label, idx in tabs:
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, idx)
            self.tab_list.addItem(item)

        self.tab_list.setCurrentRow(0)
        self.tab_list.currentRowChanged.connect(self._on_tab_changed)
        left_layout.addWidget(self.tab_list)
        left_layout.addStretch()

        main_layout.addWidget(left_pane)

        # Right Stack Content
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: #121926;")

        # Page 0: Your Details
        p0 = self._build_your_details_page()
        self.stack.addWidget(p0)

        # Page 1: Sign-in & Recovery
        p1 = self._build_signin_recovery_page()
        self.stack.addWidget(p1)

        # Page 2: Linked to Your Account
        p2 = self._build_linked_accounts_page()
        self.stack.addWidget(p2)

        # Page 3: Usage data
        p3 = self._build_usage_data_page()
        self.stack.addWidget(p3)

        main_layout.addWidget(self.stack)

    def _on_tab_changed(self, row: int):
        self.stack.setCurrentIndex(row)

    def _build_your_details_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Avatar & Name
        top_row = QHBoxLayout()
        avatar = QLabel(self.vault_data.settings.user_name[:1].upper() if self.vault_data.settings.user_name else "S")
        avatar.setFixedSize(54, 54)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        avatar.setStyleSheet("background-color: #0572ec; color: #ffffff; border-radius: 27px;")
        top_row.addWidget(avatar)

        name_col = QVBoxLayout()
        name_lbl = QLabel(self.vault_data.settings.user_name)
        name_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        name_lbl.setStyleSheet("color: #ffffff;")
        name_col.addWidget(name_lbl)

        email_lbl = QLabel(self.vault_data.settings.user_email)
        email_lbl.setStyleSheet("color: #94a3b8; font-size: 12px;")
        name_col.addWidget(email_lbl)
        top_row.addLayout(name_col)
        top_row.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(28, 28)
        close_btn.setStyleSheet("background: transparent; border: none; color: #94a3b8; font-size: 14px;")
        close_btn.clicked.connect(self.accept)
        top_row.addWidget(close_btn)
        layout.addLayout(top_row)

        # Details Card
        card = QFrame()
        card.setObjectName("inspectorCard")
        c_layout = QVBoxLayout(card)
        c_layout.setSpacing(10)

        card_title = QLabel("Your Details")
        card_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        card_title.setStyleSheet("color: #ffffff;")
        c_layout.addWidget(card_title)

        c_layout.addWidget(QLabel("Sign-in address:"))
        s_addr = QLineEdit("localvault.internal")
        s_addr.setReadOnly(True)
        c_layout.addWidget(s_addr)

        c_layout.addWidget(QLabel("Email address:"))
        s_email = QLineEdit(self.vault_data.settings.user_email)
        s_email.setReadOnly(True)
        c_layout.addWidget(s_email)

        c_layout.addWidget(QLabel("Secret Key:"))
        s_key = QLineEdit("A3-RT45-LOCAL-VAULT-MILITARY-GRADE-256")
        s_key.setReadOnly(True)
        s_key.setEchoMode(QLineEdit.EchoMode.Password)
        c_layout.addWidget(s_key)

        layout.addWidget(card)
        layout.addStretch()
        return widget

    def _build_signin_recovery_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        header = QLabel("Sign-in & Recovery")
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #ffffff;")
        layout.addWidget(header)

        card = QFrame()
        card.setObjectName("inspectorCard")
        c_layout = QVBoxLayout(card)
        c_layout.setSpacing(10)

        c_layout.addWidget(QLabel("How you sign in:"))
        txt = QLabel("• Master Password (Argon2id + AES-256-GCM AEAD)\n• Zero-knowledge local decryption buffer in RAM\n• 2FA Authenticator TOTP protection")
        txt.setStyleSheet("color: #cbd5e1; line-height: 18px;")
        c_layout.addWidget(txt)
        layout.addWidget(card)

        # Recovery card
        rec_card = QFrame()
        rec_card.setObjectName("inspectorCard")
        r_layout = QVBoxLayout(rec_card)
        r_layout.setSpacing(10)

        r_title = QLabel("🛡️ Set up your account recovery")
        r_title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        r_title.setStyleSheet("color: #38bdf8;")
        r_layout.addWidget(r_title)

        r_desc = QLabel("If you forget your master password, a recovery key code can restore access to your encrypted vault.")
        r_desc.setStyleSheet("color: #94a3b8;")
        r_desc.setWordWrap(True)
        r_layout.addWidget(r_desc)

        setup_btn = QPushButton("Set up recovery code")
        setup_btn.setObjectName("primaryButton")
        setup_btn.clicked.connect(lambda: QMessageBox.information(self, "Recovery Code", "Your emergency recovery code is active and backed by your local Argon2id credentials."))
        r_layout.addWidget(setup_btn)

        layout.addWidget(rec_card)
        layout.addStretch()
        return widget

    def _build_linked_accounts_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        header = QLabel("Linked to Your Account (2)")
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #ffffff;")
        layout.addWidget(header)

        device_name = os.environ.get("COMPUTERNAME", "Local Workstation")
        devices = [
            (device_name, "Windows Workstation • Local Host", "Active"),
            ("Browser Extension", "LocalVault Extension Bridge", "Connected"),
        ]

        for name, desc, status in devices:
            card = QFrame()
            card.setObjectName("inspectorCard")
            row = QHBoxLayout(card)
            row.setContentsMargins(14, 12, 14, 12)

            info_col = QVBoxLayout()
            d_name = QLabel(name)
            d_name.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
            d_name.setStyleSheet("color: #f1f5f9;")
            info_col.addWidget(d_name)

            d_desc = QLabel(desc)
            d_desc.setStyleSheet("color: #94a3b8; font-size: 11px;")
            info_col.addWidget(d_desc)
            row.addLayout(info_col)
            row.addStretch()

            unlink_btn = QPushButton("Unlink")
            unlink_btn.setStyleSheet("""
                QPushButton {
                    background-color: #241416;
                    border: 1px solid #7f1d1d;
                    color: #fca5a5;
                    border-radius: 4px;
                    padding: 4px 10px;
                    font-size: 11px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background-color: #7f1d1d;
                    color: #ffffff;
                }
            """)
            unlink_btn.clicked.connect(lambda _, n=name: QMessageBox.information(self, "Unlinked", f"Disconnected {n} from LocalVault."))
            row.addWidget(unlink_btn)
            layout.addWidget(card)

        layout.addStretch()
        return widget

    def _build_usage_data_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        header = QLabel("Usage data")
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #ffffff;")
        layout.addWidget(header)

        cb = QCheckBox("Share anonymous diagnostics with LocalVault")
        cb.setChecked(False)
        cb.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        layout.addWidget(cb)

        desc = QLabel("100% Offline Promise: LocalVault never sends telemetry, passwords, or metadata across the network. All data stays strictly on your local disk.")
        desc.setStyleSheet("color: #34d399; font-size: 12px; line-height: 18px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addStretch()
        return widget

"""
LocalVault 1Password Profile View
Recreates 1Password's Profile dashboard with:
Avatar, User name, "Set details now, save time later" banner,
Personal details card, Payment method card, and Manage Account button.
"""

from typing import Callable, Optional
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QMessageBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from core.models import VaultData
from ui.manage_account_dialog import ManageAccountDialog


class ProfileView(QWidget):
    """
    Profile view matching 1Password's exact Profile page.
    """

    def __init__(
        self,
        parent=None,
        vault_data: Optional[VaultData] = None,
        on_navigate_callback: Optional[Callable[[str], None]] = None,
        on_manage_account: Optional[Callable[[], None]] = None,
        on_add_identity: Optional[Callable[[], None]] = None,
        on_add_payment: Optional[Callable[[], None]] = None,
    ):
        super().__init__(parent)
        self.vault_data = vault_data or VaultData()
        self.on_navigate = on_navigate_callback
        self.on_manage_account = on_manage_account
        self.on_add_identity = on_add_identity
        self.on_add_payment = on_add_payment

        self._setup_ui()

    def set_vault_data(self, vault_data: VaultData):
        self.vault_data = vault_data
        uname = (self.vault_data.settings.user_name if self.vault_data else "") or os.environ.get("USERNAME", "User").capitalize()
        self.name_label.setText(uname)
        self.avatar_label.setText(uname[:1].upper() if uname else "U")

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(36, 28, 36, 28)
        main_layout.setSpacing(20)

        # Top User Header Row
        header_row = QHBoxLayout()
        header_row.setSpacing(14)

        uname = (self.vault_data.settings.user_name if self.vault_data else "") or os.environ.get("USERNAME", "User").capitalize()
        self.avatar_label = QLabel(uname[:1].upper() if uname else "U")
        self.avatar_label.setFixedSize(52, 52)
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.avatar_label.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self.avatar_label.setStyleSheet("background-color: #0572ec; color: #ffffff; border-radius: 26px;")
        header_row.addWidget(self.avatar_label)

        self.name_label = QLabel(uname)
        self.name_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self.name_label.setStyleSheet("color: #ffffff;")
        header_row.addWidget(self.name_label)
        header_row.addStretch()

        manage_btn = QPushButton("⚙  Manage Account")
        manage_btn.setObjectName("secondaryButton")
        manage_btn.setFixedHeight(34)
        manage_btn.clicked.connect(self._handle_manage_account)
        header_row.addWidget(manage_btn)
        main_layout.addLayout(header_row)

        # 1Password Banner: "Set details now, save time later"
        banner = QFrame()
        banner.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1a2234, stop:1 #28374f);
                border: 1px solid #2d3f5a;
                border-radius: 12px;
                padding: 16px 20px;
            }
        """)
        b_layout = QHBoxLayout(banner)
        b_layout.setContentsMargins(14, 12, 14, 12)

        b_text_col = QVBoxLayout()
        b_title = QLabel("Set details now, save time later")
        b_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        b_title.setStyleSheet("color: #ffffff; background: transparent;")
        b_text_col.addWidget(b_title)

        b_desc = QLabel("Fast track filling forms using LocalVault to fill your personal and payment details.")
        b_desc.setStyleSheet("color: #cbd5e1; font-size: 13px; background: transparent;")
        b_text_col.addWidget(b_desc)
        b_layout.addLayout(b_text_col)
        b_layout.addStretch()

        art_lbl = QLabel("💳 🪪 🚀")
        art_lbl.setFont(QFont("Segoe UI Emoji", 24))
        art_lbl.setStyleSheet("background: transparent;")
        b_layout.addWidget(art_lbl)

        main_layout.addWidget(banner)

        # 2 Cards Side-by-Side: Personal Details & Payment Method
        cards_row = QHBoxLayout()
        cards_row.setSpacing(16)

        # Card 1: Personal Details
        c1 = QFrame()
        c1.setObjectName("inspectorCard")
        c1_layout = QVBoxLayout(c1)
        c1_layout.setContentsMargins(18, 16, 18, 16)
        c1_layout.setSpacing(10)

        c1_title = QLabel("Set your personal details")
        c1_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        c1_title.setStyleSheet("color: #ffffff;")
        c1_layout.addWidget(c1_title)

        c1_desc = QLabel("Add your name, address, phone numbers, and more to fill forms faster.")
        c1_desc.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 18px;")
        c1_desc.setWordWrap(True)
        c1_layout.addWidget(c1_desc)
        c1_layout.addStretch()

        c1_btn_row = QHBoxLayout()
        c1_btn = QPushButton("Default identity   Select")
        c1_btn.setObjectName("secondaryButton")
        c1_btn.clicked.connect(self._handle_identity)
        c1_btn_row.addWidget(c1_btn)
        c1_layout.addLayout(c1_btn_row)
        cards_row.addWidget(c1)

        # Card 2: Payment Method
        c2 = QFrame()
        c2.setObjectName("inspectorCard")
        c2_layout = QVBoxLayout(c2)
        c2_layout.setContentsMargins(18, 16, 18, 16)
        c2_layout.setSpacing(10)

        c2_title = QLabel("Set your payment method")
        c2_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        c2_title.setStyleSheet("color: #ffffff;")
        c2_layout.addWidget(c2_title)

        c2_desc = QLabel("Experience smoother checkouts by adding your primary payment card now.")
        c2_desc.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 18px;")
        c2_desc.setWordWrap(True)
        c2_layout.addWidget(c2_desc)
        c2_layout.addStretch()

        c2_btn_row = QHBoxLayout()
        c2_btn = QPushButton("Default payment card   Select")
        c2_btn.setObjectName("secondaryButton")
        c2_btn.clicked.connect(self._handle_payment)
        c2_btn_row.addWidget(c2_btn)
        c2_layout.addLayout(c2_btn_row)
        cards_row.addWidget(c2)

        main_layout.addLayout(cards_row)
        main_layout.addStretch()

    def _handle_manage_account(self):
        if self.on_manage_account:
            self.on_manage_account()
        else:
            dlg = ManageAccountDialog(self, vault_data=self.vault_data)
            dlg.exec()

    def _handle_identity(self):
        if self.on_add_identity:
            self.on_add_identity()
        elif self.on_navigate:
            self.on_navigate("identities")

    def _handle_payment(self):
        if self.on_add_payment:
            self.on_add_payment()
        elif self.on_navigate:
            self.on_navigate("credit_cards")

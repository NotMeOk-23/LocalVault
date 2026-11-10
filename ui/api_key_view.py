"""
LocalVault Detailed Item Inspector View
1Password-authentic right-side inspector pane for viewing credential details:
- Masked secrets with auto-hiding peek timer
- Live embedded TOTP authenticator with live countdown
- One-click clipboard copy with Windows Win+V privacy exclusion
- Dynamic Secret References (lvault://)
- Built-in offline JWT Inspector
- Support for all 12 1Password categories
- Authentic 1Password vault dial empty state
"""

import json
from typing import Optional, Union, Callable, Any
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QLineEdit,
    QTextEdit,
    QMessageBox,
)
from PySide6.QtCore import Qt, QTimer, QPointF
from PySide6.QtGui import QFont, QPainter, QColor, QPen, QRadialGradient, QLinearGradient, QPolygonF

from core.models import (
    APIKeyEntry,
    LoginEntry,
    SSHEntry,
    SecureNoteEntry,
    CreditCardEntry,
    IdentityEntry,
    BankAccountEntry,
    DatabaseEntry,
    CryptoWalletEntry,
    ServerEntry,
    SoftwareLicenseEntry,
    PasswordItemEntry,
)
from core.jwt_decoder import is_jwt_token, decode_jwt
from ui.styles import get_environment_badge_style, get_category_badge_style, get_category_icon_glyph
from ui.totp_widget import TOTPAuthenticatorWidget
from platform_win32.clipboard import clipboard_manager


class VaultDialGraphic(QWidget):
    """Realistic painted 1Password Vault Dial with metallic rings and tick marks."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 140)

    def paintEvent(self, event):
        import math
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        center = self.rect().center()
        radius = min(w, h) / 2 - 6

        # Outer metallic rim with subtle linear gradient
        grad_outer = QLinearGradient(0, 0, w, h)
        grad_outer.setColorAt(0.0, QColor("#2a3e5c"))
        grad_outer.setColorAt(0.5, QColor("#162334"))
        grad_outer.setColorAt(1.0, QColor("#0d1522"))
        painter.setBrush(grad_outer)
        painter.setPen(QPen(QColor("#354d70"), 2))
        painter.drawEllipse(center, radius, radius)

        # Dial track
        track_r = radius - 10
        painter.setBrush(QColor("#0e1522"))
        painter.setPen(QPen(QColor("#1f2e44"), 1))
        painter.drawEllipse(center, track_r, track_r)

        # Radial tick marks (like a safe combination dial)
        painter.setPen(QPen(QColor("#48658a"), 1.5))
        for deg in range(0, 360, 15):
            rad = math.radians(deg)
            is_major = (deg % 30 == 0)
            inner_dist = track_r - (8 if is_major else 4)
            outer_dist = track_r - 2
            x1 = center.x() + inner_dist * math.cos(rad)
            y1 = center.y() + inner_dist * math.sin(rad)
            x2 = center.x() + outer_dist * math.cos(rad)
            y2 = center.y() + outer_dist * math.sin(rad)
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))

        # Inner combination knob
        knob_r = track_r - 18
        grad_knob = QRadialGradient(center.x(), center.y() - 10, knob_r)
        grad_knob.setColorAt(0.0, QColor("#22334a"))
        grad_knob.setColorAt(0.7, QColor("#141f2e"))
        grad_knob.setColorAt(1.0, QColor("#0c131e"))
        painter.setBrush(grad_knob)
        painter.setPen(QPen(QColor("#2d4362"), 1.5))
        painter.drawEllipse(center, knob_r, knob_r)

        # Center 1Password Brand Keyhole Badge
        badge_r = 18
        grad_badge = QLinearGradient(center.x() - badge_r, center.y() - badge_r, center.x() + badge_r, center.y() + badge_r)
        grad_badge.setColorAt(0.0, QColor("#0a84ff"))
        grad_badge.setColorAt(1.0, QColor("#0572ec"))
        painter.setBrush(grad_badge)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(center, badge_r, badge_r)

        # White Padlock / Keyhole Emblem
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(center.x() - 4, center.y() - 5, 8, 8)
        poly = QPolygonF([
            QPointF(center.x() - 3, center.y() - 1),
            QPointF(center.x() + 3, center.y() - 1),
            QPointF(center.x() + 4, center.y() + 6),
            QPointF(center.x() - 4, center.y() + 6),
        ])
        painter.drawPolygon(poly)


class ItemInspectorView(QWidget):
    """
    Right-side inspector pane for viewing credential details in 1Password layout.
    """

    def __init__(
        self,
        parent=None,
        on_edit_callback: Optional[Callable] = None,
        on_delete_callback: Optional[Callable] = None,
        on_favorite_callback: Optional[Callable] = None,
        on_new_item_callback: Optional[Callable] = None,
    ):
        super().__init__(parent)
        self.on_edit = on_edit_callback
        self.on_delete = on_delete_callback
        self.on_favorite = on_favorite_callback
        self.on_new_item = on_new_item_callback
        self.current_entry = None
        self._peek_timer = QTimer(self)
        self._peek_timer.setSingleShot(True)
        self._peek_timer.timeout.connect(self._auto_hide_secret)

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        # 1Password Vault Dial Empty State Placeholder
        self.placeholder = QWidget()
        ph_layout = QVBoxLayout(self.placeholder)
        ph_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph_layout.setSpacing(14)

        # Painted Metallic Vault Dial Graphic
        self.dial_graphic = VaultDialGraphic()
        ph_layout.addWidget(self.dial_graphic, alignment=Qt.AlignmentFlag.AlignCenter)

        ph_title = QLabel("Select an item to view its details")
        ph_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph_title.setStyleSheet("color: #f1f5f9; font-size: 16px; font-weight: 700; background: transparent;")
        ph_layout.addWidget(ph_title)

        ph_sub = QLabel("Choose an item from the list or press Ctrl+N to add a new credential.")
        ph_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph_sub.setStyleSheet("color: #64748b; font-size: 13px; background: transparent;")
        ph_layout.addWidget(ph_sub)

        new_item_btn = QPushButton("+ New Item")
        new_item_btn.setObjectName("primaryButton")
        new_item_btn.setFixedSize(120, 34)
        new_item_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        new_item_btn.clicked.connect(self._trigger_new_item)
        ph_layout.addSpacing(6)
        ph_layout.addWidget(new_item_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        main_layout.addWidget(self.placeholder)

        # Scroll area for details
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setVisible(False)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(14)

        # Header card
        self.header_card = QFrame()
        self.header_card.setObjectName("inspectorCard")
        header_layout = QVBoxLayout(self.header_card)
        header_layout.setSpacing(8)

        # Top badges & actions row
        badge_row = QHBoxLayout()
        self.category_badge = QLabel("LOGIN")
        self.category_badge.setStyleSheet(get_category_badge_style("login"))
        self.category_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        badge_row.addWidget(self.category_badge)

        self.env_badge = QLabel("PRODUCTION")
        self.env_badge.setStyleSheet(get_environment_badge_style("Production"))
        self.env_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.env_badge.setVisible(False)
        badge_row.addWidget(self.env_badge)

        self.vault_badge = QLabel("Personal")
        self.vault_badge.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 600; padding-left: 4px;")
        self.vault_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        badge_row.addWidget(self.vault_badge)

        badge_row.addStretch()

        # Favorite Star Toggle
        self.fav_btn = QPushButton("☆")
        self.fav_btn.setFixedSize(28, 28)
        self.fav_btn.setToolTip("Toggle Favorite")
        self.fav_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #233146;
                border-radius: 6px;
                color: #94a3b8;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #1a2537;
                color: #fbbf24;
                border-color: #f59e0b;
            }
        """)
        self.fav_btn.clicked.connect(self._toggle_favorite)
        badge_row.addWidget(self.fav_btn)

        # Edit button
        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setFixedHeight(28)
        self.edit_btn.setObjectName("secondaryButton")
        self.edit_btn.clicked.connect(self._trigger_edit)
        badge_row.addWidget(self.edit_btn)

        # Delete button
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setObjectName("dangerButton")
        self.delete_btn.setFixedHeight(28)
        self.delete_btn.clicked.connect(self._trigger_delete)
        badge_row.addWidget(self.delete_btn)

        header_layout.addLayout(badge_row)

        # Main Title & Category Glyph
        title_row = QHBoxLayout()
        self.glyph_label = QLabel("🔑")
        self.glyph_label.setFont(QFont("Segoe UI Emoji", 20))
        title_row.addWidget(self.glyph_label)

        self.title_label = QLabel("Item Name")
        self.title_label.setObjectName("titleLabel")
        self.title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.title_label.setStyleSheet("color: #f8fafc;")
        title_row.addWidget(self.title_label, stretch=1)
        header_layout.addLayout(title_row)

        self.content_layout.addWidget(self.header_card)

        # Embedded TOTP Authenticator (Visible for logins with 2FA)
        self.totp_widget = TOTPAuthenticatorWidget()
        self.totp_widget.setVisible(False)
        self.content_layout.addWidget(self.totp_widget)

        # Credentials Fields Container
        self.fields_card = QFrame()
        self.fields_card.setObjectName("inspectorCard")
        self.fields_layout = QVBoxLayout(self.fields_card)
        self.fields_layout.setSpacing(12)
        self.content_layout.addWidget(self.fields_card)

        # Notes Card
        self.notes_card = QFrame()
        self.notes_card.setObjectName("inspectorCard")
        notes_layout = QVBoxLayout(self.notes_card)
        notes_title = QLabel("NOTES")
        notes_title.setObjectName("sectionHeader")
        notes_layout.addWidget(notes_title)

        self.notes_text = QTextEdit()
        self.notes_text.setReadOnly(True)
        self.notes_text.setMaximumHeight(90)
        notes_layout.addWidget(self.notes_text)
        self.content_layout.addWidget(self.notes_card)

        self.content_layout.addStretch()
        self.scroll_area.setWidget(self.content_widget)
        main_layout.addWidget(self.scroll_area)

    def set_entry(self, entry: Optional[Any]):
        self.current_entry = entry
        self._peek_timer.stop()

        if entry is None:
            self.placeholder.setVisible(True)
            self.scroll_area.setVisible(False)
            return

        self.placeholder.setVisible(False)
        self.scroll_area.setVisible(True)

        # Update Favorite Button
        is_fav = getattr(entry, "is_favorite", False)
        self.fav_btn.setText("⭐" if is_fav else "☆")
        self.fav_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {'#3b2f15' if is_fav else 'transparent'};
                border: 1px solid {'#f59e0b' if is_fav else '#233146'};
                border-radius: 6px;
                color: {'#fbbf24' if is_fav else '#94a3b8'};
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: #1a2537;
                color: #fbbf24;
            }}
        """)

        # Clear old dynamic fields
        while self.fields_layout.count() > 0:
            item = self.fields_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                while item.layout().count() > 0:
                    sub = item.layout().takeAt(0)
                    if sub.widget():
                        sub.widget().deleteLater()

        # Render category-specific views
        if isinstance(entry, LoginEntry):
            self._render_login(entry)
        elif isinstance(entry, CreditCardEntry):
            self._render_credit_card(entry)
        elif isinstance(entry, IdentityEntry):
            self._render_identity(entry)
        elif isinstance(entry, APIKeyEntry):
            self._render_api_key(entry)
        elif isinstance(entry, SSHEntry):
            self._render_ssh(entry)
        elif isinstance(entry, SecureNoteEntry):
            self._render_note(entry)
        elif isinstance(entry, BankAccountEntry):
            self._render_bank_account(entry)
        elif isinstance(entry, DatabaseEntry):
            self._render_database(entry)
        elif isinstance(entry, CryptoWalletEntry):
            self._render_crypto_wallet(entry)
        elif isinstance(entry, ServerEntry):
            self._render_server(entry)
        elif isinstance(entry, SoftwareLicenseEntry):
            self._render_software_license(entry)
        elif isinstance(entry, PasswordItemEntry):
            self._render_password_item(entry)
        else:
            self._render_generic(entry)

    # ------------------ Category Renderers ------------------
    def _render_login(self, entry: LoginEntry):
        self.category_badge.setText("LOGIN")
        self.category_badge.setStyleSheet(get_category_badge_style("login"))
        self.glyph_label.setText("🔑")
        self.env_badge.setVisible(False)
        self.title_label.setText(entry.title)

        # Linked Sites
        if entry.urls:
            valid_urls = [u.strip() for u in entry.urls if u.strip()]
            if len(valid_urls) == 1:
                self._add_url_field("WEBSITE URL", valid_urls[0], ref_uri=f"lvault://logins/{entry.title}/url")
            elif len(valid_urls) > 1:
                for idx, url in enumerate(valid_urls, 1):
                    self._add_url_field(f"LINKED SITE {idx}", url, ref_uri=f"lvault://logins/{entry.title}/url_{idx}")

        # Username / Email (Displayed here in inspector so the user can see and copy it to log in)
        if entry.username:
            self._add_copyable_field(
                "USERNAME / EMAIL",
                entry.username,
                is_secret=False,
                ref_uri=f"lvault://logins/{entry.title}/username",
            )

        # Password
        self._add_copyable_field("PASSWORD", entry.password, is_secret=True, ref_uri=f"lvault://logins/{entry.title}/password")

        # TOTP Authenticator
        if entry.totp_secret:
            self.totp_widget.set_config(
                secret=entry.totp_secret,
                period=entry.totp_period,
                digits=entry.totp_digits,
                algorithm=entry.totp_algorithm,
            )
            self.totp_widget.setVisible(True)
        else:
            self.totp_widget.setVisible(False)

        self._render_notes(entry.notes)

    def _render_credit_card(self, entry: CreditCardEntry):
        self.category_badge.setText("CREDIT CARD")
        self.category_badge.setStyleSheet(get_category_badge_style("credit_card"))
        self.glyph_label.setText("💳")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)

        display_title = entry.cardholder_name or f"{entry.card_type} •••• {entry.card_number[-4:] if len(entry.card_number)>=4 else ''}"
        self.title_label.setText(display_title)

        self._add_copyable_field("CARDHOLDER NAME", entry.cardholder_name, is_secret=False)
        self._add_copyable_field("CARD TYPE", entry.card_type, is_secret=False)
        self._add_copyable_field("CARD NUMBER", entry.card_number, is_secret=True, ref_uri=f"lvault://cards/{entry.cardholder_name}/number")

        exp_str = f"{entry.expiry_month} / {entry.expiry_year}" if entry.expiry_month and entry.expiry_year else ""
        if exp_str:
            self._add_copyable_field("EXPIRY DATE", exp_str, is_secret=False)

        if entry.cvv:
            self._add_copyable_field("VERIFICATION NUMBER (CVV)", entry.cvv, is_secret=True, ref_uri=f"lvault://cards/{entry.cardholder_name}/cvv")
        if entry.pin:
            self._add_copyable_field("PIN", entry.pin, is_secret=True)

        self._render_notes(entry.notes)

    def _render_identity(self, entry: IdentityEntry):
        self.category_badge.setText("IDENTITY")
        self.category_badge.setStyleSheet(get_category_badge_style("identity"))
        self.glyph_label.setText("🪪")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title or f"{entry.first_name} {entry.last_name}")

        full_name = f"{entry.first_name} {entry.last_name}".strip()
        if full_name:
            self._add_copyable_field("FULL NAME", full_name, is_secret=False)
        if entry.email:
            self._add_copyable_field("EMAIL ADDRESS", entry.email, is_secret=False)
        if entry.phone:
            self._add_copyable_field("PHONE NUMBER", entry.phone, is_secret=False)
        if entry.company or entry.job_title:
            work = f"{entry.job_title} at {entry.company}".strip(" at ")
            self._add_copyable_field("COMPANY & ROLE", work, is_secret=False)
        if entry.address:
            self._add_copyable_field("MAILING ADDRESS", entry.address, is_secret=False)

        self._render_notes(entry.notes)

    def _render_api_key(self, entry: APIKeyEntry):
        self.category_badge.setText("API CREDENTIALS")
        self.category_badge.setStyleSheet(get_category_badge_style("api_key"))
        self.glyph_label.setText("⚡")

        self.env_badge.setText(entry.environment.upper())
        self.env_badge.setStyleSheet(get_environment_badge_style(entry.environment))
        self.env_badge.setVisible(True)

        self.title_label.setText(entry.name)
        self.totp_widget.setVisible(False)

        if entry.key_id:
            self._add_copyable_field("CLIENT ID / PUBLIC KEY", entry.key_id, is_secret=False, ref_uri=f"lvault://api_keys/{entry.name}/key_id")

        self._add_copyable_field("SECRET KEY / TOKEN", entry.secret_key, is_secret=True, ref_uri=f"lvault://api_keys/{entry.name}/secret_key")

        if is_jwt_token(entry.secret_key):
            self._render_jwt_inspector(entry.secret_key)

        if entry.base_url:
            self._add_copyable_field("BASE URL", entry.base_url, is_secret=False, ref_uri=f"lvault://api_keys/{entry.name}/base_url")
        if entry.organization_id:
            self._add_copyable_field("ORGANIZATION ID", entry.organization_id, is_secret=False)

        self._render_notes(entry.notes)

    def _render_ssh(self, entry: SSHEntry):
        self.category_badge.setText("SSH KEY")
        self.category_badge.setStyleSheet(get_category_badge_style("ssh_key"))
        self.glyph_label.setText("💻")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.name)

        if entry.hostname:
            host_str = f"{entry.hostname}:{entry.port}" if entry.port != 22 else entry.hostname
            self._add_copyable_field("HOSTNAME", host_str, is_secret=False)
        if entry.username:
            self._add_copyable_field("SSH USERNAME", entry.username, is_secret=False)

        self._add_copyable_field("PRIVATE KEY", entry.private_key, is_secret=True, ref_uri=f"lvault://ssh/{entry.name}/private_key")

        if entry.passphrase:
            self._add_copyable_field("PASSPHRASE", entry.passphrase, is_secret=True)

        self._render_notes(entry.notes)

    def _render_note(self, entry: SecureNoteEntry):
        self.category_badge.setText("SECURE NOTE")
        self.category_badge.setStyleSheet(get_category_badge_style("secure_note"))
        self.glyph_label.setText("📝")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        self._render_notes(entry.content, title="CONTENT")

    def _render_bank_account(self, entry: BankAccountEntry):
        self.category_badge.setText("BANK ACCOUNT")
        self.category_badge.setStyleSheet(get_category_badge_style("bank_account"))
        self.glyph_label.setText("🏦")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        if entry.bank_name:
            self._add_copyable_field("BANK NAME", entry.bank_name, is_secret=False)
        self._add_copyable_field("ACCOUNT NUMBER", entry.account_number, is_secret=True)
        if entry.routing_number:
            self._add_copyable_field("ROUTING NUMBER", entry.routing_number, is_secret=False)
        if entry.account_type:
            self._add_copyable_field("ACCOUNT TYPE", entry.account_type, is_secret=False)
        if entry.swift_code:
            self._add_copyable_field("SWIFT / BIC", entry.swift_code, is_secret=False)
        if entry.iban:
            self._add_copyable_field("IBAN", entry.iban, is_secret=False)
        if entry.pin:
            self._add_copyable_field("ATM PIN", entry.pin, is_secret=True)

        self._render_notes(entry.notes)

    def _render_database(self, entry: DatabaseEntry):
        self.category_badge.setText("DATABASE")
        self.category_badge.setStyleSheet(get_category_badge_style("database"))
        self.glyph_label.setText("🗄️")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        self._add_copyable_field("DATABASE TYPE", entry.db_type, is_secret=False)
        if entry.hostname:
            self._add_copyable_field("HOST / PORT", f"{entry.hostname}:{entry.port}", is_secret=False)
        if entry.database:
            self._add_copyable_field("DATABASE NAME", entry.database, is_secret=False)
        if entry.username:
            self._add_copyable_field("USERNAME", entry.username, is_secret=False)
        self._add_copyable_field("PASSWORD", entry.password, is_secret=True)

        self._render_notes(entry.notes)

    def _render_crypto_wallet(self, entry: CryptoWalletEntry):
        self.category_badge.setText("CRYPTO WALLET")
        self.category_badge.setStyleSheet(get_category_badge_style("crypto_wallet"))
        self.glyph_label.setText("🪙")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        self._add_copyable_field("NETWORK / CHAIN", entry.network, is_secret=False)
        self._add_copyable_field("WALLET ADDRESS", entry.address, is_secret=False)

        if entry.recovery_phrase:
            self._add_copyable_field("RECOVERY SEED PHRASE", entry.recovery_phrase, is_secret=True)
        if entry.private_key:
            self._add_copyable_field("PRIVATE KEY", entry.private_key, is_secret=True)

        self._render_notes(entry.notes)

    def _render_server(self, entry: ServerEntry):
        self.category_badge.setText("SERVER")
        self.category_badge.setStyleSheet(get_category_badge_style("server"))
        self.glyph_label.setText("🖥️")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        self._add_copyable_field("OS / TYPE", entry.server_type, is_secret=False)
        if entry.ip_address:
            self._add_copyable_field("IP ADDRESS", entry.ip_address, is_secret=False)
        if entry.hostname:
            self._add_copyable_field("HOSTNAME", entry.hostname, is_secret=False)
        if entry.admin_user:
            self._add_copyable_field("ADMIN USER", entry.admin_user, is_secret=False)
        if entry.admin_password:
            self._add_copyable_field("ADMIN PASSWORD", entry.admin_password, is_secret=True)

        self._render_notes(entry.notes)

    def _render_software_license(self, entry: SoftwareLicenseEntry):
        self.category_badge.setText("SOFTWARE LICENSE")
        self.category_badge.setStyleSheet(get_category_badge_style("software_license"))
        self.glyph_label.setText("📜")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        if entry.software_name:
            self._add_copyable_field("SOFTWARE", entry.software_name, is_secret=False)
        self._add_copyable_field("LICENSE KEY", entry.license_key, is_secret=False)
        if entry.licensed_to:
            self._add_copyable_field("LICENSED TO", entry.licensed_to, is_secret=False)
        if entry.license_email:
            self._add_copyable_field("REGISTERED EMAIL", entry.license_email, is_secret=False)
        if entry.version:
            self._add_copyable_field("VERSION", entry.version, is_secret=False)

        self._render_notes(entry.notes)

    def _render_password_item(self, entry: PasswordItemEntry):
        self.category_badge.setText("PASSWORD")
        self.category_badge.setStyleSheet(get_category_badge_style("password"))
        self.glyph_label.setText("🔒")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(entry.title)

        self._add_copyable_field("PASSWORD", entry.password, is_secret=True)
        self._render_notes(entry.notes)

    def _render_generic(self, entry):
        self.category_badge.setText("ITEM")
        self.glyph_label.setText("🔑")
        self.env_badge.setVisible(False)
        self.totp_widget.setVisible(False)
        self.title_label.setText(getattr(entry, "title", None) or getattr(entry, "name", "Item"))
        self._render_notes(getattr(entry, "notes", ""))

    # ------------------ JWT Inspector ------------------
    def _render_jwt_inspector(self, token: str):
        jwt_data = decode_jwt(token)
        if not jwt_data:
            return

        jwt_card = QFrame()
        jwt_card.setStyleSheet("""
            QFrame {
                background-color: #0b111a;
                border: 1px solid #0572ec;
                border-radius: 8px;
                padding: 12px;
                margin-top: 8px;
            }
        """)
        jwt_layout = QVBoxLayout(jwt_card)
        jwt_layout.setSpacing(8)

        top_row = QHBoxLayout()
        jwt_title = QLabel("🔍 JSON WEB TOKEN (JWT) INSPECTED")
        jwt_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8; letter-spacing: 0.5px;")
        top_row.addWidget(jwt_title)

        alg_badge = QLabel(f"ALG: {jwt_data['algorithm']}")
        alg_badge.setStyleSheet("background-color: #172554; color: #60a5fa; border: 1px solid #3b82f6; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: bold;")
        top_row.addWidget(alg_badge)

        top_row.addStretch()

        if jwt_data.get("is_expired"):
            status_badge = QLabel("EXPIRED")
            status_badge.setStyleSheet("background-color: #450a0a; color: #f87171; border: 1px solid #b91c1c; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: bold;")
        else:
            status_badge = QLabel("ACTIVE")
            status_badge.setStyleSheet("background-color: #064e3b; color: #34d399; border: 1px solid #059669; border-radius: 4px; padding: 2px 6px; font-size: 10px; font-weight: bold;")
        top_row.addWidget(status_badge)

        jwt_layout.addLayout(top_row)

        claims_text = []
        if jwt_data.get("issuer") != "None":
            claims_text.append(f"<b>Issuer (iss):</b> {jwt_data['issuer']}")
        if jwt_data.get("subject") != "None":
            claims_text.append(f"<b>Subject (sub):</b> {jwt_data['subject']}")
        if jwt_data.get("expires_at_formatted"):
            claims_text.append(f"<b>Expires At (exp):</b> {jwt_data['expires_at_formatted']}")

        if claims_text:
            claims_lbl = QLabel("<br>".join(claims_text))
            claims_lbl.setStyleSheet("color: #cbd5e1; font-size: 11px;")
            jwt_layout.addWidget(claims_lbl)

        payload_edit = QTextEdit()
        payload_edit.setReadOnly(True)
        payload_edit.setFont(QFont("Consolas", 10))
        payload_edit.setPlainText(json.dumps(jwt_data.get("payload", {}), indent=2))
        payload_edit.setMaximumHeight(90)
        payload_edit.setStyleSheet("background-color: #080c14; border: 1px solid #1e293b; color: #38bdf8;")
        jwt_layout.addWidget(payload_edit)

        self.fields_layout.addWidget(jwt_card)

    # ------------------ Field Construction Helpers ------------------
    def _add_copyable_field(
        self,
        label_text: str,
        value: str,
        is_secret: bool = False,
        ref_uri: Optional[str] = None,
    ):
        field_layout = QVBoxLayout()
        field_layout.setSpacing(4)

        lbl = QLabel(label_text)
        lbl.setObjectName("sectionHeader")
        lbl.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 700; letter-spacing: 0.5px;")
        field_layout.addWidget(lbl)

        row = QHBoxLayout()
        line_edit = QLineEdit()
        line_edit.setText(value)
        line_edit.setReadOnly(True)
        line_edit.setFont(QFont("Consolas", 11))
        line_edit.setStyleSheet("background-color: #121926; border: 1px solid #1e2a3c; border-radius: 6px; padding: 6px 10px; color: #f8fafc;")

        if is_secret:
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            peek_btn = QPushButton("👁 Peek (10s)")
            peek_btn.setStyleSheet("""
                QPushButton {
                    background-color: #182232;
                    border: 1px solid #283950;
                    border-radius: 6px;
                    color: #94a3b8;
                    font-size: 11px;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #223249;
                    color: #ffffff;
                }
            """)
            peek_btn.clicked.connect(lambda: self._peek_secret(line_edit, peek_btn))
            row.addWidget(line_edit, stretch=1)
            row.addWidget(peek_btn)
        else:
            row.addWidget(line_edit, stretch=1)

        copy_btn = QPushButton("Copy")
        copy_btn.setObjectName("copyButton")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #182232;
                border: 1px solid #283950;
                border-radius: 6px;
                color: #cbd5e1;
                font-weight: 600;
                font-size: 11px;
                padding: 5px 12px;
            }
            QPushButton:hover {
                background-color: #223249;
                color: #ffffff;
            }
        """)
        copy_btn.clicked.connect(lambda: self._copy_value(value, copy_btn, is_secret))
        row.addWidget(copy_btn)

        if ref_uri:
            ref_btn = QPushButton("🔗 Ref")
            ref_btn.setToolTip(f"Copy Secret Reference ({ref_uri})")
            ref_btn.setStyleSheet("""
                QPushButton {
                    background-color: #172554;
                    color: #60a5fa;
                    border: 1px solid #1e40af;
                    border-radius: 6px;
                    padding: 5px 10px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #1e3a8a;
                    border-color: #3b82f6;
                }
            """)
            ref_btn.clicked.connect(lambda: self._copy_ref(ref_uri, ref_btn))
            row.addWidget(ref_btn)

        field_layout.addLayout(row)
        self.fields_layout.addLayout(field_layout)

    def _add_url_field(self, label: str, url: str, ref_uri: Optional[str] = None):
        field_layout = QVBoxLayout()
        field_layout.setSpacing(4)

        lbl = QLabel(label)
        lbl.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 700; letter-spacing: 0.5px;")
        field_layout.addWidget(lbl)

        row = QHBoxLayout()
        row.setSpacing(8)

        line_edit = QLineEdit(url)
        line_edit.setReadOnly(True)
        line_edit.setStyleSheet("background-color: #121926; border: 1px solid #1e2a3c; border-radius: 6px; padding: 6px 10px; color: #38bdf8;")
        row.addWidget(line_edit, stretch=1)

        open_btn = QPushButton("↗ Open")
        open_btn.setToolTip(f"Open {url} in default browser")
        open_btn.setStyleSheet("""
            QPushButton {
                background-color: #0f2e22;
                color: #34d399;
                border: 1px solid #059669;
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #064e3b;
                border-color: #10b981;
            }
        """)
        open_btn.clicked.connect(lambda: self._open_external_url(url))
        row.addWidget(open_btn)

        copy_btn = QPushButton("Copy")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #182232;
                border: 1px solid #283950;
                border-radius: 6px;
                color: #cbd5e1;
                font-weight: 600;
                font-size: 11px;
                padding: 5px 12px;
            }
            QPushButton:hover {
                background-color: #223249;
                color: #ffffff;
            }
        """)
        copy_btn.clicked.connect(lambda: self._copy_value(url, copy_btn, False))
        row.addWidget(copy_btn)

        if ref_uri:
            ref_btn = QPushButton("🔗 Ref")
            ref_btn.setToolTip(f"Copy Secret Reference ({ref_uri})")
            ref_btn.setStyleSheet("""
                QPushButton {
                    background-color: #172554;
                    color: #60a5fa;
                    border: 1px solid #1e40af;
                    border-radius: 6px;
                    padding: 5px 10px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #1e3a8a;
                    border-color: #3b82f6;
                }
            """)
            ref_btn.clicked.connect(lambda: self._copy_ref(ref_uri, ref_btn))
            row.addWidget(ref_btn)

        field_layout.addLayout(row)
        self.fields_layout.addLayout(field_layout)

    def _open_external_url(self, url: str):
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl
        clean_url = url.strip()
        if clean_url and not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            clean_url = "https://" + clean_url
        QDesktopServices.openUrl(QUrl(clean_url))

    def _peek_secret(self, edit_widget: QLineEdit, btn: QPushButton):
        if edit_widget.echoMode() == QLineEdit.EchoMode.Password:
            edit_widget.setEchoMode(QLineEdit.EchoMode.Normal)
            btn.setText("🔒 Hide")
            self._peek_timer.stop()
            self._peek_timer.start(10000)
            self._active_peek_widget = edit_widget
            self._active_peek_btn = btn
        else:
            self._auto_hide_secret()

    def _auto_hide_secret(self):
        if hasattr(self, "_active_peek_widget") and self._active_peek_widget:
            self._active_peek_widget.setEchoMode(QLineEdit.EchoMode.Password)
            if hasattr(self, "_active_peek_btn") and self._active_peek_btn:
                self._active_peek_btn.setText("👁 Peek (10s)")

    def _copy_value(self, val: str, btn: QPushButton, is_secret: bool):
        clipboard_manager.copy_secret(val, wipe_delay=30 if is_secret else 0, exclude_history=is_secret)
        btn.setText("Copied!")
        QTimer.singleShot(2000, lambda: btn.setText("Copy"))

    def _copy_ref(self, ref_uri: str, btn: QPushButton):
        clipboard_manager.copy_secret(ref_uri, wipe_delay=0, exclude_history=False)
        btn.setText("Ref Copied!")
        QTimer.singleShot(2000, lambda: btn.setText("🔗 Ref"))

    def _render_notes(self, notes_content: str, title: str = "NOTES"):
        if notes_content:
            self.notes_card.setVisible(True)
            self.notes_text.setPlainText(notes_content)
        else:
            self.notes_card.setVisible(False)

    def _toggle_favorite(self):
        if self.current_entry:
            new_fav = not getattr(self.current_entry, "is_favorite", False)
            self.current_entry.is_favorite = new_fav
            self.fav_btn.setText("⭐" if new_fav else "☆")
            if self.on_favorite:
                self.on_favorite(self.current_entry)

    def _trigger_edit(self):
        if self.on_edit and self.current_entry:
            self.on_edit(self.current_entry)

    def _trigger_delete(self):
        if self.on_delete and self.current_entry:
            resp = QMessageBox.question(
                self,
                "Confirm Deletion",
                "Are you sure you want to permanently delete this item from your encrypted vault?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp == QMessageBox.StandardButton.Yes:
                self.on_delete(self.current_entry)

    def _trigger_new_item(self):
        if self.on_new_item:
            self.on_new_item()

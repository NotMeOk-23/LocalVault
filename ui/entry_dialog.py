"""
LocalVault Entry Add / Edit Dialog
Comprehensive modal for creating and updating all 1Password categories:
Logins, Credit Cards, Identities, API Credentials, SSH Keys, Secure Notes,
Bank Accounts, Databases, Crypto Wallets, Servers, Software Licenses, and Passwords.
"""

from typing import Optional, Union, Dict, Any, List
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QTextEdit,
    QComboBox,
    QStackedWidget,
    QWidget,
    QFormLayout,
    QMessageBox,
    QSpinBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

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
from ui.generator_dialog import GeneratorDialog
from core.totp import normalize_secret, parse_otpauth_uri

CATEGORY_TYPES = [
    ("login", "🔑 Login"),
    ("credit_card", "💳 Credit Card"),
    ("identity", "🪪 Identity"),
    ("api_key", "⚡ API Credentials"),
    ("ssh_key", "💻 SSH Key"),
    ("secure_note", "📝 Secure Note"),
    ("bank_account", "🏦 Bank Account"),
    ("database", "🗄️ Database"),
    ("crypto_wallet", "🪙 Crypto Wallet"),
    ("server", "🖥️ Server"),
    ("software_license", "📜 Software License"),
    ("password", "🔒 Password"),
]


class EntryDialog(QDialog):
    """
    Dialog for adding or editing vault items across all 1Password categories.
    """

    def __init__(
        self,
        parent=None,
        entry: Optional[Any] = None,
        default_category: str = "login",
    ):
        super().__init__(parent)
        self.entry = entry
        self.result_entry = None
        self.is_edit_mode = entry is not None

        title = "Edit Entry" if self.is_edit_mode else "New Vault Entry"
        self.setWindowTitle(title)
        self.setMinimumWidth(620)
        self.setMinimumHeight(520)

        self._setup_ui(default_category)
        if self.is_edit_mode:
            self._populate_fields(entry)

    def _setup_ui(self, default_category: str):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # Category Selector
        cat_row = QHBoxLayout()
        cat_label = QLabel("Item Category:")
        cat_label.setStyleSheet("font-weight: 600; color: #94a3b8;")
        cat_row.addWidget(cat_label)

        self.cat_combo = QComboBox()
        self.cat_combo.setObjectName("categoryFilterCombo")
        for key, display in CATEGORY_TYPES:
            self.cat_combo.addItem(display, key)

        if self.is_edit_mode:
            self.cat_combo.setEnabled(False)
        cat_row.addWidget(self.cat_combo, stretch=1)
        layout.addLayout(cat_row)

        # Form Stack
        self.stack = QStackedWidget()

        # 0. Login Form
        self.login_widget = self._create_login_form()
        self.stack.addWidget(self.login_widget)

        # 1. Credit Card Form
        self.card_widget = self._create_credit_card_form()
        self.stack.addWidget(self.card_widget)

        # 2. Identity Form
        self.id_widget = self._create_identity_form()
        self.stack.addWidget(self.id_widget)

        # 3. API Key Form
        self.api_widget = self._create_api_form()
        self.stack.addWidget(self.api_widget)

        # 4. SSH Key Form
        self.ssh_widget = self._create_ssh_form()
        self.stack.addWidget(self.ssh_widget)

        # 5. Secure Note Form
        self.note_widget = self._create_note_form()
        self.stack.addWidget(self.note_widget)

        # 6. Bank Account Form
        self.bank_widget = self._create_bank_form()
        self.stack.addWidget(self.bank_widget)

        # 7. Database Form
        self.db_widget = self._create_db_form()
        self.stack.addWidget(self.db_widget)

        # 8. Crypto Wallet Form
        self.crypto_widget = self._create_crypto_form()
        self.stack.addWidget(self.crypto_widget)

        # 9. Server Form
        self.server_widget = self._create_server_form()
        self.stack.addWidget(self.server_widget)

        # 10. Software License Form
        self.lic_widget = self._create_license_form()
        self.stack.addWidget(self.lic_widget)

        # 11. Password Item Form
        self.pwd_widget = self._create_pwd_form()
        self.stack.addWidget(self.pwd_widget)

        layout.addWidget(self.stack, stretch=1)

        # Connect combo
        self.cat_combo.currentIndexChanged.connect(self.stack.setCurrentIndex)
        self._select_initial_category(default_category)

        # Dialog Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        self.save_btn = QPushButton("Save Item")
        self.save_btn.setObjectName("primaryButton")
        self.save_btn.clicked.connect(self._save_entry)
        btn_layout.addWidget(self.save_btn)

        layout.addLayout(btn_layout)

    def _select_initial_category(self, cat_key: str):
        c = cat_key.lower().strip()
        cat_map = {
            "login": "login",
            "logins": "login",
            "email": "login",
            "emails": "login",
            "credit_card": "credit_card",
            "credit_cards": "credit_card",
            "identity": "identity",
            "identities": "identity",
            "driver_license": "identity",
            "driver_licenses": "identity",
            "passport": "identity",
            "passports": "identity",
            "ssn": "identity",
            "api_key": "api_key",
            "api_keys": "api_key",
            "ssh_key": "ssh_key",
            "ssh_keys": "ssh_key",
            "secure_note": "secure_note",
            "secure_notes": "secure_note",
            "document": "secure_note",
            "documents": "secure_note",
            "medical_record": "secure_note",
            "medical_records": "secure_note",
            "membership": "secure_note",
            "memberships": "secure_note",
            "reward": "secure_note",
            "rewards": "secure_note",
            "outdoor_license": "secure_note",
            "outdoor_licenses": "secure_note",
            "bank_account": "bank_account",
            "bank_accounts": "bank_account",
            "database": "database",
            "databases": "database",
            "crypto_wallet": "crypto_wallet",
            "crypto_wallets": "crypto_wallet",
            "server": "server",
            "servers": "server",
            "wireless_router": "server",
            "wireless_routers": "server",
            "software_license": "software_license",
            "software_licenses": "software_license",
            "password": "password",
            "passwords": "password",
        }
        target = cat_map.get(c, c.rstrip("s"))
        for i in range(self.cat_combo.count()):
            key = self.cat_combo.itemData(i)
            if key == target or (target in key) or (key in target):
                self.cat_combo.setCurrentIndex(i)
                return
        self.cat_combo.setCurrentIndex(0)

    # ------------------ Form Builders ------------------
    def _create_login_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.login_title = QLineEdit()
        self.login_title.setPlaceholderText("e.g. GitHub, Google, Amazon...")
        form.addRow("Title *:", self.login_title)

        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("Email, username, or phone")
        form.addRow("Username / Email:", self.login_user)

        pwd_row = QHBoxLayout()
        self.login_pwd = QLineEdit()
        self.login_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_pwd.setPlaceholderText("Password *")
        pwd_row.addWidget(self.login_pwd)

        self.login_peek = QPushButton("👁")
        self.login_peek.setFixedWidth(36)
        self.login_peek.clicked.connect(lambda: self._toggle_echo(self.login_pwd, self.login_peek))
        pwd_row.addWidget(self.login_peek)

        self.login_gen = QPushButton("Generate")
        self.login_gen.setObjectName("copyButton")
        self.login_gen.clicked.connect(lambda: self._open_generator("password", self.login_pwd))
        pwd_row.addWidget(self.login_gen)
        form.addRow("Password *:", pwd_row)

        # Multi-Website container
        self.url_rows: List[tuple] = []
        self.url_container = QWidget()
        self.url_container_layout = QVBoxLayout(self.url_container)
        self.url_container_layout.setContentsMargins(0, 0, 0, 0)
        self.url_container_layout.setSpacing(6)

        self.url_rows_widget = QWidget()
        self.url_rows_layout = QVBoxLayout(self.url_rows_widget)
        self.url_rows_layout.setContentsMargins(0, 0, 0, 0)
        self.url_rows_layout.setSpacing(6)
        self.url_container_layout.addWidget(self.url_rows_widget)

        self.add_url_btn = QPushButton("+ Add Another Linked Site")
        self.add_url_btn.setStyleSheet("""
            QPushButton {
                background-color: #172554;
                color: #60a5fa;
                border: 1px dashed #2563eb;
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #1e3a8a;
                border-color: #3b82f6;
            }
        """)
        self.add_url_btn.clicked.connect(lambda: self._add_url_row())
        self.url_container_layout.addWidget(self.add_url_btn)

        form.addRow("Linked Sites:", self.url_container)
        self._add_url_row()

        # TOTP row
        totp_row = QHBoxLayout()
        self.login_totp = QLineEdit()
        self.login_totp.setPlaceholderText("Base32 Key or otpauth://totp/ URI")
        totp_row.addWidget(self.login_totp)

        self.login_parse_btn = QPushButton("Import URI")
        self.login_parse_btn.clicked.connect(self._parse_totp_uri_field)
        totp_row.addWidget(self.login_parse_btn)
        form.addRow("2FA TOTP Key:", totp_row)

        self.login_tags = QLineEdit()
        self.login_tags.setPlaceholderText("comma-separated (e.g. social, work)")
        form.addRow("Tags:", self.login_tags)

        self.login_notes = QTextEdit()
        self.login_notes.setMaximumHeight(65)
        form.addRow("Notes:", self.login_notes)

        return widget

    def _create_credit_card_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.card_holder = QLineEdit()
        self.card_holder.setPlaceholderText("Cardholder Name as shown on card *")
        form.addRow("Cardholder *:", self.card_holder)

        self.card_type = QComboBox()
        self.card_type.addItems(["Visa", "Mastercard", "American Express", "Discover", "UnionPay", "Other"])
        form.addRow("Card Type:", self.card_type)

        self.card_number = QLineEdit()
        self.card_number.setPlaceholderText("16-digit card number *")
        form.addRow("Card Number *:", self.card_number)

        exp_row = QHBoxLayout()
        self.card_exp_month = QComboBox()
        self.card_exp_month.addItems([f"{m:02d}" for m in range(1, 13)])
        exp_row.addWidget(QLabel("Month:"))
        exp_row.addWidget(self.card_exp_month)

        self.card_exp_year = QComboBox()
        self.card_exp_year.addItems([str(y) for y in range(2025, 2045)])
        exp_row.addWidget(QLabel("Year:"))
        exp_row.addWidget(self.card_exp_year)
        exp_row.addStretch()
        form.addRow("Expiry Date:", exp_row)

        sec_row = QHBoxLayout()
        self.card_cvv = QLineEdit()
        self.card_cvv.setEchoMode(QLineEdit.EchoMode.Password)
        self.card_cvv.setPlaceholderText("CVV / CVC (3-4 digits)")
        sec_row.addWidget(self.card_cvv)

        cvv_peek = QPushButton("👁")
        cvv_peek.setFixedWidth(36)
        cvv_peek.clicked.connect(lambda: self._toggle_echo(self.card_cvv, cvv_peek))
        sec_row.addWidget(cvv_peek)

        self.card_pin = QLineEdit()
        self.card_pin.setEchoMode(QLineEdit.EchoMode.Password)
        self.card_pin.setPlaceholderText("ATM PIN (optional)")
        sec_row.addWidget(QLabel("PIN:"))
        sec_row.addWidget(self.card_pin)

        pin_peek = QPushButton("👁")
        pin_peek.setFixedWidth(36)
        pin_peek.clicked.connect(lambda: self._toggle_echo(self.card_pin, pin_peek))
        sec_row.addWidget(pin_peek)
        form.addRow("Security Code:", sec_row)

        self.card_tags = QLineEdit()
        self.card_tags.setPlaceholderText("comma-separated")
        form.addRow("Tags:", self.card_tags)

        self.card_notes = QTextEdit()
        self.card_notes.setMaximumHeight(65)
        form.addRow("Notes:", self.card_notes)

        return widget

    def _create_identity_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.id_label = QLineEdit()
        self.id_label.setPlaceholderText("e.g. Personal Profile, Work Persona *")
        form.addRow("Profile Label *:", self.id_label)

        name_row = QHBoxLayout()
        self.id_first = QLineEdit()
        self.id_first.setPlaceholderText("First Name")
        name_row.addWidget(self.id_first)

        self.id_last = QLineEdit()
        self.id_last.setPlaceholderText("Last Name")
        name_row.addWidget(self.id_last)
        form.addRow("Full Name:", name_row)

        self.id_email = QLineEdit()
        self.id_email.setPlaceholderText("Primary email address")
        form.addRow("Email:", self.id_email)

        self.id_phone = QLineEdit()
        self.id_phone.setPlaceholderText("+1 (555) 000-0000")
        form.addRow("Phone Number:", self.id_phone)

        self.id_company = QLineEdit()
        self.id_company.setPlaceholderText("Company / Organization")
        form.addRow("Company:", self.id_company)

        self.id_job = QLineEdit()
        self.id_job.setPlaceholderText("Job Title")
        form.addRow("Job Title:", self.id_job)

        self.id_address = QTextEdit()
        self.id_address.setMaximumHeight(55)
        self.id_address.setPlaceholderText("Full Street Address, City, State, ZIP, Country")
        form.addRow("Address:", self.id_address)

        self.id_tags = QLineEdit()
        form.addRow("Tags:", self.id_tags)

        self.id_notes = QTextEdit()
        self.id_notes.setMaximumHeight(55)
        form.addRow("Notes:", self.id_notes)

        return widget

    def _create_api_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.api_name = QLineEdit()
        self.api_name.setPlaceholderText("e.g. OpenAI Production Key *")
        form.addRow("Name / Label *:", self.api_name)

        self.api_service = QComboBox()
        self.api_service.setEditable(True)
        self.api_service.addItems(["OpenAI", "Anthropic", "Stripe", "AWS", "GitHub", "Google Cloud", "Supabase", "HuggingFace", "Custom"])
        form.addRow("Service / Provider:", self.api_service)

        self.api_env = QComboBox()
        self.api_env.addItems(["Production", "Staging", "Development", "Test"])
        form.addRow("Environment:", self.api_env)

        self.api_key_id = QLineEdit()
        self.api_key_id.setPlaceholderText("Client ID or Public Key (e.g. pk_live_...)")
        form.addRow("Key ID / Public:", self.api_key_id)

        sec_layout = QHBoxLayout()
        self.api_secret = QLineEdit()
        self.api_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_secret.setPlaceholderText("Private API Key / Secret Token *")
        sec_layout.addWidget(self.api_secret)

        self.api_peek_btn = QPushButton("👁")
        self.api_peek_btn.setFixedWidth(36)
        self.api_peek_btn.clicked.connect(lambda: self._toggle_echo(self.api_secret, self.api_peek_btn))
        sec_layout.addWidget(self.api_peek_btn)

        self.api_gen_btn = QPushButton("Generate")
        self.api_gen_btn.setObjectName("copyButton")
        self.api_gen_btn.clicked.connect(lambda: self._open_generator("api", self.api_secret))
        sec_layout.addWidget(self.api_gen_btn)
        form.addRow("Secret Key *:", sec_layout)

        self.api_base_url = QLineEdit()
        self.api_base_url.setPlaceholderText("e.g. https://api.openai.com/v1")
        form.addRow("Base URL:", self.api_base_url)

        self.api_org_id = QLineEdit()
        self.api_org_id.setPlaceholderText("e.g. org-1234567890")
        form.addRow("Org / Project ID:", self.api_org_id)

        self.api_tags = QLineEdit()
        form.addRow("Tags:", self.api_tags)

        self.api_notes = QTextEdit()
        self.api_notes.setMaximumHeight(65)
        form.addRow("Notes:", self.api_notes)

        return widget

    def _create_ssh_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.ssh_name = QLineEdit()
        self.ssh_name.setPlaceholderText("e.g. Production Bastion *")
        form.addRow("Host Label *:", self.ssh_name)

        self.ssh_host = QLineEdit()
        self.ssh_host.setPlaceholderText("e.g. bastion.internal.net")
        form.addRow("Hostname / IP:", self.ssh_host)

        self.ssh_user = QLineEdit()
        self.ssh_user.setPlaceholderText("e.g. ubuntu, root, ec2-user")
        form.addRow("SSH User:", self.ssh_user)

        self.ssh_priv = QTextEdit()
        self.ssh_priv.setPlaceholderText("-----BEGIN OPENSSH PRIVATE KEY----- ... *")
        self.ssh_priv.setMaximumHeight(85)
        form.addRow("Private Key *:", self.ssh_priv)

        self.ssh_pass = QLineEdit()
        self.ssh_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssh_pass.setPlaceholderText("Key Passphrase (if encrypted)")
        form.addRow("Passphrase:", self.ssh_pass)

        self.ssh_tags = QLineEdit()
        form.addRow("Tags:", self.ssh_tags)

        return widget

    def _create_note_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.note_title = QLineEdit()
        self.note_title.setPlaceholderText("Note Title *")
        form.addRow("Title *:", self.note_title)

        self.note_content = QTextEdit()
        self.note_content.setPlaceholderText("Secure markdown notes, recovery codes, seed phrases...")
        self.note_content.setMinimumHeight(160)
        form.addRow("Content *:", self.note_content)

        self.note_tags = QLineEdit()
        form.addRow("Tags:", self.note_tags)

        return widget

    def _create_bank_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.bank_title = QLineEdit()
        self.bank_title.setPlaceholderText("e.g. Chase Main Checking *")
        form.addRow("Title *:", self.bank_title)

        self.bank_name = QLineEdit()
        self.bank_name.setPlaceholderText("e.g. JPMorgan Chase")
        form.addRow("Bank Name:", self.bank_name)

        self.bank_acc_num = QLineEdit()
        self.bank_acc_num.setEchoMode(QLineEdit.EchoMode.Password)
        self.bank_acc_num.setPlaceholderText("Account Number *")
        acc_row = QHBoxLayout()
        acc_row.addWidget(self.bank_acc_num)
        acc_peek = QPushButton("👁")
        acc_peek.setFixedWidth(36)
        acc_peek.clicked.connect(lambda: self._toggle_echo(self.bank_acc_num, acc_peek))
        acc_row.addWidget(acc_peek)
        form.addRow("Account # *:", acc_row)

        self.bank_routing = QLineEdit()
        self.bank_routing.setPlaceholderText("Routing Number (9 digits)")
        form.addRow("Routing #:", self.bank_routing)

        self.bank_type = QComboBox()
        self.bank_type.addItems(["Checking", "Savings", "Business", "Money Market", "Investment"])
        form.addRow("Account Type:", self.bank_type)

        self.bank_swift = QLineEdit()
        self.bank_swift.setPlaceholderText("SWIFT / BIC Code")
        form.addRow("SWIFT Code:", self.bank_swift)

        self.bank_iban = QLineEdit()
        self.bank_iban.setPlaceholderText("IBAN (International)")
        form.addRow("IBAN:", self.bank_iban)

        self.bank_tags = QLineEdit()
        form.addRow("Tags:", self.bank_tags)

        self.bank_notes = QTextEdit()
        self.bank_notes.setMaximumHeight(60)
        form.addRow("Notes:", self.bank_notes)

        return widget

    def _create_db_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.db_title = QLineEdit()
        self.db_title.setPlaceholderText("e.g. Production RDS Postgres *")
        form.addRow("Title *:", self.db_title)

        self.db_type = QComboBox()
        self.db_type.addItems(["PostgreSQL", "MySQL", "MongoDB", "Redis", "SQLite", "Oracle", "SQL Server"])
        form.addRow("Database Type:", self.db_type)

        self.db_host = QLineEdit()
        self.db_host.setPlaceholderText("e.g. db.prod.internal")
        form.addRow("Hostname / Host:", self.db_host)

        self.db_port = QSpinBox()
        self.db_port.setRange(1, 65535)
        self.db_port.setValue(5432)
        form.addRow("Port:", self.db_port)

        self.db_name = QLineEdit()
        self.db_name.setPlaceholderText("Database Name (e.g. app_production)")
        form.addRow("Database Name:", self.db_name)

        self.db_user = QLineEdit()
        self.db_user.setPlaceholderText("DB Username")
        form.addRow("Username:", self.db_user)

        db_pwd_row = QHBoxLayout()
        self.db_pwd = QLineEdit()
        self.db_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.db_pwd.setPlaceholderText("DB Password *")
        db_pwd_row.addWidget(self.db_pwd)

        db_peek = QPushButton("👁")
        db_peek.setFixedWidth(36)
        db_peek.clicked.connect(lambda: self._toggle_echo(self.db_pwd, db_peek))
        db_pwd_row.addWidget(db_peek)

        db_gen = QPushButton("Generate")
        db_gen.setObjectName("copyButton")
        db_gen.clicked.connect(lambda: self._open_generator("password", self.db_pwd))
        db_pwd_row.addWidget(db_gen)
        form.addRow("Password *:", db_pwd_row)

        self.db_tags = QLineEdit()
        form.addRow("Tags:", self.db_tags)

        self.db_notes = QTextEdit()
        self.db_notes.setMaximumHeight(55)
        form.addRow("Notes:", self.db_notes)

        return widget

    def _create_crypto_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.crypto_title = QLineEdit()
        self.crypto_title.setPlaceholderText("e.g. Ledger Cold Storage *")
        form.addRow("Title *:", self.crypto_title)

        self.crypto_network = QComboBox()
        self.crypto_network.addItems(["Ethereum", "Bitcoin", "Solana", "Polygon", "Avalanche", "Cosmos", "Cardano", "Other"])
        form.addRow("Network / Chain:", self.crypto_network)

        self.crypto_address = QLineEdit()
        self.crypto_address.setPlaceholderText("Public Wallet Address (0x...) *")
        form.addRow("Public Address *:", self.crypto_address)

        self.crypto_phrase = QTextEdit()
        self.crypto_phrase.setPlaceholderText("12 or 24-word Secret Recovery Seed Phrase...")
        self.crypto_phrase.setMaximumHeight(65)
        form.addRow("Recovery Phrase:", self.crypto_phrase)

        self.crypto_priv = QLineEdit()
        self.crypto_priv.setEchoMode(QLineEdit.EchoMode.Password)
        self.crypto_priv.setPlaceholderText("Private Key (hex)")
        priv_row = QHBoxLayout()
        priv_row.addWidget(self.crypto_priv)
        priv_peek = QPushButton("👁")
        priv_peek.setFixedWidth(36)
        priv_peek.clicked.connect(lambda: self._toggle_echo(self.crypto_priv, priv_peek))
        priv_row.addWidget(priv_peek)
        form.addRow("Private Key:", priv_row)

        self.crypto_tags = QLineEdit()
        form.addRow("Tags:", self.crypto_tags)

        self.crypto_notes = QTextEdit()
        self.crypto_notes.setMaximumHeight(55)
        form.addRow("Notes:", self.crypto_notes)

        return widget

    def _create_server_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.server_title = QLineEdit()
        self.server_title.setPlaceholderText("e.g. Dedicated Web Node 1 *")
        form.addRow("Server Title *:", self.server_title)

        self.server_type = QComboBox()
        self.server_type.addItems(["Linux", "Windows Server", "macOS", "FreeBSD", "VMware ESXi"])
        form.addRow("OS / Type:", self.server_type)

        self.server_ip = QLineEdit()
        self.server_ip.setPlaceholderText("Public or Private IP (e.g. 192.168.1.100)")
        form.addRow("IP Address:", self.server_ip)

        self.server_host = QLineEdit()
        self.server_host.setPlaceholderText("FQDN (e.g. node1.cluster.local)")
        form.addRow("Hostname:", self.server_host)

        self.server_user = QLineEdit()
        self.server_user.setPlaceholderText("Admin Username (e.g. Administrator, root)")
        form.addRow("Admin User:", self.server_user)

        srv_pwd_row = QHBoxLayout()
        self.server_pwd = QLineEdit()
        self.server_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.server_pwd.setPlaceholderText("Admin Password")
        srv_pwd_row.addWidget(self.server_pwd)

        srv_peek = QPushButton("👁")
        srv_peek.setFixedWidth(36)
        srv_peek.clicked.connect(lambda: self._toggle_echo(self.server_pwd, srv_peek))
        srv_pwd_row.addWidget(srv_peek)

        srv_gen = QPushButton("Generate")
        srv_gen.setObjectName("copyButton")
        srv_gen.clicked.connect(lambda: self._open_generator("password", self.server_pwd))
        srv_pwd_row.addWidget(srv_gen)
        form.addRow("Admin Password:", srv_pwd_row)

        self.server_tags = QLineEdit()
        form.addRow("Tags:", self.server_tags)

        self.server_notes = QTextEdit()
        self.server_notes.setMaximumHeight(55)
        form.addRow("Notes:", self.server_notes)

        return widget

    def _create_license_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.lic_title = QLineEdit()
        self.lic_title.setPlaceholderText("e.g. JetBrains All Products Pack *")
        form.addRow("Title *:", self.lic_title)

        self.lic_sw = QLineEdit()
        self.lic_sw.setPlaceholderText("Software / Application Name")
        form.addRow("Software:", self.lic_sw)

        self.lic_key = QLineEdit()
        self.lic_key.setPlaceholderText("License Key / Serial Number *")
        form.addRow("License Key *:", self.lic_key)

        self.lic_user = QLineEdit()
        self.lic_user.setPlaceholderText("Licensed To (Full Name)")
        form.addRow("Licensed To:", self.lic_user)

        self.lic_email = QLineEdit()
        self.lic_email.setPlaceholderText("Registered Email Address")
        form.addRow("Email:", self.lic_email)

        self.lic_pub = QLineEdit()
        self.lic_pub.setPlaceholderText("Publisher / Vendor")
        form.addRow("Publisher:", self.lic_pub)

        self.lic_ver = QLineEdit()
        self.lic_ver.setPlaceholderText("Version (e.g. 2026.1)")
        form.addRow("Version:", self.lic_ver)

        self.lic_tags = QLineEdit()
        form.addRow("Tags:", self.lic_tags)

        self.lic_notes = QTextEdit()
        self.lic_notes.setMaximumHeight(55)
        form.addRow("Notes:", self.lic_notes)

        return widget

    def _create_pwd_form(self) -> QWidget:
        widget = QWidget()
        form = QFormLayout(widget)
        form.setSpacing(10)

        self.pwd_title = QLineEdit()
        self.pwd_title.setPlaceholderText("e.g. Router Master Key, Safe Combination *")
        form.addRow("Title *:", self.pwd_title)

        p_row = QHBoxLayout()
        self.pwd_value = QLineEdit()
        self.pwd_value.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_value.setPlaceholderText("Password *")
        p_row.addWidget(self.pwd_value)

        p_peek = QPushButton("👁")
        p_peek.setFixedWidth(36)
        p_peek.clicked.connect(lambda: self._toggle_echo(self.pwd_value, p_peek))
        p_row.addWidget(p_peek)

        p_gen = QPushButton("Generate")
        p_gen.setObjectName("copyButton")
        p_gen.clicked.connect(lambda: self._open_generator("password", self.pwd_value))
        p_row.addWidget(p_gen)
        form.addRow("Password *:", p_row)

        self.pwd_tags = QLineEdit()
        form.addRow("Tags:", self.pwd_tags)

        self.pwd_notes = QTextEdit()
        self.pwd_notes.setMaximumHeight(70)
        form.addRow("Notes:", self.pwd_notes)

        return widget

    # ------------------ Multi-URL Helpers ------------------
    def _add_url_row(self, url: str = ""):
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(6)

        site_icon = QLabel("🌐")
        site_icon.setFixedWidth(20)
        row_layout.addWidget(site_icon)

        line_edit = QLineEdit()
        line_edit.setPlaceholderText("e.g. https://id.formula1.com or static.formula1.com")
        if url:
            line_edit.setText(url)
        row_layout.addWidget(line_edit, stretch=1)

        del_btn = QPushButton("✕")
        del_btn.setFixedSize(26, 26)
        del_btn.setToolTip("Remove this linked site")
        del_btn.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #94a3b8;
                border: 1px solid #334155;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                padding: 0px;
            }
            QPushButton:hover {
                background-color: #7f1d1d;
                color: #fca5a5;
                border-color: #dc2626;
            }
        """)
        del_btn.clicked.connect(lambda: self._remove_url_row(row_widget, line_edit))
        row_layout.addWidget(del_btn)

        self.url_rows_layout.addWidget(row_widget)
        self.url_rows.append((row_widget, line_edit))

    def _remove_url_row(self, row_widget: QWidget, line_edit: QLineEdit):
        if len(self.url_rows) > 1:
            self.url_rows = [pair for pair in self.url_rows if pair[0] != row_widget]
            self.url_rows_layout.removeWidget(row_widget)
            row_widget.deleteLater()
        else:
            line_edit.clear()

    def _clear_url_rows(self):
        for row_widget, _ in self.url_rows:
            self.url_rows_layout.removeWidget(row_widget)
            row_widget.deleteLater()
        self.url_rows.clear()

    def _toggle_echo(self, edit_field: QLineEdit, btn: QPushButton):
        if edit_field.echoMode() == QLineEdit.EchoMode.Password:
            edit_field.setEchoMode(QLineEdit.EchoMode.Normal)
            btn.setText("🔒")
        else:
            edit_field.setEchoMode(QLineEdit.EchoMode.Password)
            btn.setText("👁")

    def _open_generator(self, mode: str, target_field: QLineEdit):
        gen = GeneratorDialog(self, initial_mode=mode)
        if gen.exec():
            target_field.setText(gen.generated_result)

    def _parse_totp_uri_field(self):
        text = self.login_totp.text().strip()
        if text.startswith("otpauth://"):
            try:
                parsed = parse_otpauth_uri(text)
                self.login_totp.setText(parsed["secret"])
                if not self.login_user.text() and parsed["label"]:
                    self.login_user.setText(parsed["label"])
                QMessageBox.information(self, "2FA Imported", f"Successfully extracted TOTP secret for {parsed['issuer'] or parsed['label']}!")
            except Exception as e:
                QMessageBox.warning(self, "Invalid URI", f"Failed to parse otpauth URI: {e}")

    # ------------------ Populate Fields ------------------
    def _populate_fields(self, entry):
        if isinstance(entry, LoginEntry):
            self._select_initial_category("login")
            self.login_title.setText(entry.title)
            self.login_user.setText(entry.username)
            self.login_pwd.setText(entry.password)
            self._clear_url_rows()
            if entry.urls:
                for u in entry.urls:
                    if u.strip():
                        self._add_url_row(u.strip())
            if not self.url_rows:
                self._add_url_row("")
            self.login_totp.setText(entry.totp_secret)
            self.login_tags.setText(", ".join(entry.tags))
            self.login_notes.setPlainText(entry.notes)

        elif isinstance(entry, CreditCardEntry):
            self._select_initial_category("credit_card")
            self.card_holder.setText(entry.cardholder_name)
            self.card_type.setCurrentText(entry.card_type)
            self.card_number.setText(entry.card_number)
            self.card_exp_month.setCurrentText(entry.expiry_month)
            self.card_exp_year.setCurrentText(entry.expiry_year)
            self.card_cvv.setText(entry.cvv)
            self.card_pin.setText(entry.pin)
            self.card_tags.setText(", ".join(entry.tags))
            self.card_notes.setPlainText(entry.notes)

        elif isinstance(entry, IdentityEntry):
            self._select_initial_category("identity")
            self.id_label.setText(entry.title)
            self.id_first.setText(entry.first_name)
            self.id_last.setText(entry.last_name)
            self.id_email.setText(entry.email)
            self.id_phone.setText(entry.phone)
            self.id_company.setText(entry.company)
            self.id_job.setText(entry.job_title)
            self.id_address.setPlainText(entry.address)
            self.id_tags.setText(", ".join(entry.tags))
            self.id_notes.setPlainText(entry.notes)

        elif isinstance(entry, APIKeyEntry):
            self._select_initial_category("api_key")
            self.api_name.setText(entry.name)
            self.api_service.setCurrentText(entry.service)
            self.api_env.setCurrentText(entry.environment)
            self.api_key_id.setText(entry.key_id)
            self.api_secret.setText(entry.secret_key)
            self.api_base_url.setText(entry.base_url)
            self.api_org_id.setText(entry.organization_id)
            self.api_tags.setText(", ".join(entry.tags))
            self.api_notes.setPlainText(entry.notes)

        elif isinstance(entry, SSHEntry):
            self._select_initial_category("ssh_key")
            self.ssh_name.setText(entry.name)
            self.ssh_host.setText(entry.hostname)
            self.ssh_user.setText(entry.username)
            self.ssh_priv.setPlainText(entry.private_key)
            self.ssh_pass.setText(entry.passphrase)
            self.ssh_tags.setText(", ".join(entry.tags))

        elif isinstance(entry, SecureNoteEntry):
            self._select_initial_category("secure_note")
            self.note_title.setText(entry.title)
            self.note_content.setPlainText(entry.content)
            self.note_tags.setText(", ".join(entry.tags))

        elif isinstance(entry, BankAccountEntry):
            self._select_initial_category("bank_account")
            self.bank_title.setText(entry.title)
            self.bank_name.setText(entry.bank_name)
            self.bank_acc_num.setText(entry.account_number)
            self.bank_routing.setText(entry.routing_number)
            self.bank_type.setCurrentText(entry.account_type)
            self.bank_swift.setText(entry.swift_code)
            self.bank_iban.setText(entry.iban)
            self.bank_tags.setText(", ".join(entry.tags))
            self.bank_notes.setPlainText(entry.notes)

        elif isinstance(entry, DatabaseEntry):
            self._select_initial_category("database")
            self.db_title.setText(entry.title)
            self.db_type.setCurrentText(entry.db_type)
            self.db_host.setText(entry.hostname)
            self.db_port.setValue(entry.port)
            self.db_name.setText(entry.database)
            self.db_user.setText(entry.username)
            self.db_pwd.setText(entry.password)
            self.db_tags.setText(", ".join(entry.tags))
            self.db_notes.setPlainText(entry.notes)

        elif isinstance(entry, CryptoWalletEntry):
            self._select_initial_category("crypto_wallet")
            self.crypto_title.setText(entry.title)
            self.crypto_network.setCurrentText(entry.network)
            self.crypto_address.setText(entry.address)
            self.crypto_phrase.setPlainText(entry.recovery_phrase)
            self.crypto_priv.setText(entry.private_key)
            self.crypto_tags.setText(", ".join(entry.tags))
            self.crypto_notes.setPlainText(entry.notes)

        elif isinstance(entry, ServerEntry):
            self._select_initial_category("server")
            self.server_title.setText(entry.title)
            self.server_type.setCurrentText(entry.server_type)
            self.server_ip.setText(entry.ip_address)
            self.server_host.setText(entry.hostname)
            self.server_user.setText(entry.admin_user)
            self.server_pwd.setText(entry.admin_password)
            self.server_tags.setText(", ".join(entry.tags))
            self.server_notes.setPlainText(entry.notes)

        elif isinstance(entry, SoftwareLicenseEntry):
            self._select_initial_category("software_license")
            self.lic_title.setText(entry.title)
            self.lic_sw.setText(entry.software_name)
            self.lic_key.setText(entry.license_key)
            self.lic_user.setText(entry.licensed_to)
            self.lic_email.setText(entry.license_email)
            self.lic_pub.setText(entry.publisher)
            self.lic_ver.setText(entry.version)
            self.lic_tags.setText(", ".join(entry.tags))
            self.lic_notes.setPlainText(entry.notes)

        elif isinstance(entry, PasswordItemEntry):
            self._select_initial_category("password")
            self.pwd_title.setText(entry.title)
            self.pwd_value.setText(entry.password)
            self.pwd_tags.setText(", ".join(entry.tags))
            self.pwd_notes.setPlainText(entry.notes)

    # ------------------ Save Entry ------------------
    def _save_entry(self):
        cat_key = self.cat_combo.currentData()
        entry_id = self.entry.id if self.is_edit_mode and hasattr(self.entry, "id") else None

        if cat_key == "login":
            title = self.login_title.text().strip()
            pwd = self.login_pwd.text().strip()
            if not title or not pwd:
                QMessageBox.warning(self, "Missing Fields", "Please provide both Title and Password.")
                return

            urls = [edit.text().strip() for _, edit in self.url_rows if edit.text().strip()]
            tags = [t.strip() for t in self.login_tags.text().split(",") if t.strip()]
            totp = normalize_secret(self.login_totp.text().strip())

            item = LoginEntry(
                title=title,
                username=self.login_user.text().strip(),
                password=pwd,
                urls=urls,
                totp_secret=totp,
                tags=tags,
                notes=self.login_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "credit_card":
            holder = self.card_holder.text().strip()
            num = self.card_number.text().strip()
            if not holder or not num:
                QMessageBox.warning(self, "Missing Fields", "Please provide Cardholder Name and Card Number.")
                return

            tags = [t.strip() for t in self.card_tags.text().split(",") if t.strip()]
            item = CreditCardEntry(
                cardholder_name=holder,
                card_number=num,
                expiry_month=self.card_exp_month.currentText(),
                expiry_year=self.card_exp_year.currentText(),
                cvv=self.card_cvv.text().strip(),
                pin=self.card_pin.text().strip(),
                card_type=self.card_type.currentText(),
                tags=tags,
                notes=self.card_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "identity":
            lbl = self.id_label.text().strip()
            if not lbl:
                QMessageBox.warning(self, "Missing Fields", "Please provide a Profile Label.")
                return

            tags = [t.strip() for t in self.id_tags.text().split(",") if t.strip()]
            item = IdentityEntry(
                title=lbl,
                first_name=self.id_first.text().strip(),
                last_name=self.id_last.text().strip(),
                email=self.id_email.text().strip(),
                phone=self.id_phone.text().strip(),
                address=self.id_address.toPlainText().strip(),
                company=self.id_company.text().strip(),
                job_title=self.id_job.text().strip(),
                tags=tags,
                notes=self.id_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "api_key":
            name = self.api_name.text().strip()
            sec = self.api_secret.text().strip()
            if not name or not sec:
                QMessageBox.warning(self, "Missing Fields", "Please provide both Name and Secret Key.")
                return

            tags = [t.strip() for t in self.api_tags.text().split(",") if t.strip()]
            item = APIKeyEntry(
                name=name,
                service=self.api_service.currentText().strip(),
                environment=self.api_env.currentText(),
                key_id=self.api_key_id.text().strip(),
                secret_key=sec,
                base_url=self.api_base_url.text().strip(),
                organization_id=self.api_org_id.text().strip(),
                tags=tags,
                notes=self.api_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "ssh_key":
            name = self.ssh_name.text().strip()
            priv = self.ssh_priv.toPlainText().strip()
            if not name or not priv:
                QMessageBox.warning(self, "Missing Fields", "Please provide Host Label and Private Key.")
                return

            tags = [t.strip() for t in self.ssh_tags.text().split(",") if t.strip()]
            item = SSHEntry(
                name=name,
                hostname=self.ssh_host.text().strip(),
                username=self.ssh_user.text().strip(),
                private_key=priv,
                passphrase=self.ssh_pass.text().strip(),
                tags=tags,
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "secure_note":
            title = self.note_title.text().strip()
            content = self.note_content.toPlainText().strip()
            if not title or not content:
                QMessageBox.warning(self, "Missing Fields", "Please provide Note Title and Content.")
                return

            tags = [t.strip() for t in self.note_tags.text().split(",") if t.strip()]
            item = SecureNoteEntry(
                title=title,
                content=content,
                tags=tags,
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "bank_account":
            title = self.bank_title.text().strip()
            acc = self.bank_acc_num.text().strip()
            if not title or not acc:
                QMessageBox.warning(self, "Missing Fields", "Please provide Title and Account Number.")
                return

            tags = [t.strip() for t in self.bank_tags.text().split(",") if t.strip()]
            item = BankAccountEntry(
                title=title,
                bank_name=self.bank_name.text().strip(),
                account_number=acc,
                routing_number=self.bank_routing.text().strip(),
                account_type=self.bank_type.currentText(),
                swift_code=self.bank_swift.text().strip(),
                iban=self.bank_iban.text().strip(),
                tags=tags,
                notes=self.bank_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "database":
            title = self.db_title.text().strip()
            pwd = self.db_pwd.text().strip()
            if not title or not pwd:
                QMessageBox.warning(self, "Missing Fields", "Please provide Title and Database Password.")
                return

            tags = [t.strip() for t in self.db_tags.text().split(",") if t.strip()]
            item = DatabaseEntry(
                title=title,
                db_type=self.db_type.currentText(),
                hostname=self.db_host.text().strip(),
                port=self.db_port.value(),
                database=self.db_name.text().strip(),
                username=self.db_user.text().strip(),
                password=pwd,
                tags=tags,
                notes=self.db_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "crypto_wallet":
            title = self.crypto_title.text().strip()
            addr = self.crypto_address.text().strip()
            if not title or not addr:
                QMessageBox.warning(self, "Missing Fields", "Please provide Wallet Title and Public Address.")
                return

            tags = [t.strip() for t in self.crypto_tags.text().split(",") if t.strip()]
            item = CryptoWalletEntry(
                title=title,
                wallet_name=title,
                address=addr,
                network=self.crypto_network.currentText(),
                recovery_phrase=self.crypto_phrase.toPlainText().strip(),
                private_key=self.crypto_priv.text().strip(),
                tags=tags,
                notes=self.crypto_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "server":
            title = self.server_title.text().strip()
            if not title:
                QMessageBox.warning(self, "Missing Fields", "Please provide a Server Title.")
                return

            tags = [t.strip() for t in self.server_tags.text().split(",") if t.strip()]
            item = ServerEntry(
                title=title,
                hostname=self.server_host.text().strip(),
                ip_address=self.server_ip.text().strip(),
                admin_user=self.server_user.text().strip(),
                admin_password=self.server_pwd.text().strip(),
                server_type=self.server_type.currentText(),
                tags=tags,
                notes=self.server_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "software_license":
            title = self.lic_title.text().strip()
            key = self.lic_key.text().strip()
            if not title or not key:
                QMessageBox.warning(self, "Missing Fields", "Please provide Title and License Key.")
                return

            tags = [t.strip() for t in self.lic_tags.text().split(",") if t.strip()]
            item = SoftwareLicenseEntry(
                title=title,
                software_name=self.lic_sw.text().strip() or title,
                license_key=key,
                licensed_to=self.lic_user.text().strip(),
                license_email=self.lic_email.text().strip(),
                publisher=self.lic_pub.text().strip(),
                version=self.lic_ver.text().strip(),
                tags=tags,
                notes=self.lic_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        elif cat_key == "password":
            title = self.pwd_title.text().strip()
            pwd = self.pwd_value.text().strip()
            if not title or not pwd:
                QMessageBox.warning(self, "Missing Fields", "Please provide Title and Password.")
                return

            tags = [t.strip() for t in self.pwd_tags.text().split(",") if t.strip()]
            item = PasswordItemEntry(
                title=title,
                password=pwd,
                tags=tags,
                notes=self.pwd_notes.toPlainText().strip(),
            )
            if entry_id:
                item.id = entry_id
            self.result_entry = item

        self.accept()

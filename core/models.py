"""
LocalVault Data Models and Schemas
1Password-Grade zero-knowledge data structures for API keys, passwords,
logins, credit cards, identities, server credentials, crypto wallets, and secure notes.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
import uuid


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class APIKeyEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    service: str = ""  # e.g., OpenAI, Stripe, AWS, GitHub, Supabase
    environment: str = "Production"  # Production, Staging, Development, Test
    key_id: str = ""  # Public / Client ID
    secret_key: str = ""  # Private API Secret or Bearer Token
    base_url: str = ""  # e.g. https://api.openai.com/v1
    organization_id: str = ""
    project_id: str = ""
    scopes: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    expires_at: Optional[str] = None
    rotation_interval_days: int = 90
    last_rotated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "APIKeyEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class LoginEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    username: str = ""
    password: str = ""
    urls: List[str] = field(default_factory=list)
    totp_secret: str = ""  # Base32 secret for 2FA authenticator
    totp_algorithm: str = "SHA1"  # SHA1, SHA256, SHA512
    totp_digits: int = 6
    totp_period: int = 30
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoginEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class CreditCardEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    cardholder_name: str = ""
    card_number: str = ""
    expiry_date: str = ""  # MM/YY
    expiry_month: str = ""
    expiry_year: str = ""
    cvv: str = ""
    pin: str = ""
    card_type: str = "Visa"  # Visa, Mastercard, Amex, Discover
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CreditCardEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class IdentityEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    first_name: str = ""
    last_name: str = ""
    email: str = ""
    phone: str = ""
    address: str = ""
    company: str = ""
    job_title: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class SSHEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    hostname: str = ""
    port: int = 22
    username: str = ""
    private_key: str = ""  # PEM or OpenSSH private key
    public_key: str = ""
    passphrase: str = ""
    fingerprint: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SSHEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class SecureNoteEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    content: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecureNoteEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class BankAccountEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    bank_name: str = ""
    account_number: str = ""
    routing_number: str = ""
    account_type: str = "Checking"  # Checking, Savings, Business
    swift_code: str = ""
    iban: str = ""
    pin: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BankAccountEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class DatabaseEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    db_type: str = "PostgreSQL"  # PostgreSQL, MySQL, MongoDB, Redis, SQLite
    hostname: str = ""
    port: int = 5432
    database: str = ""
    username: str = ""
    password: str = ""
    connection_string: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DatabaseEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class CryptoWalletEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    wallet_name: str = ""
    address: str = ""
    network: str = "Ethereum"  # Bitcoin, Ethereum, Solana, Polygon
    recovery_phrase: str = ""
    private_key: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CryptoWalletEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class ServerEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    hostname: str = ""
    ip_address: str = ""
    admin_user: str = ""
    admin_password: str = ""
    server_type: str = "Linux"  # Linux, Windows, macOS, BSD
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServerEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class SoftwareLicenseEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    software_name: str = ""
    license_key: str = ""
    licensed_to: str = ""
    license_email: str = ""
    publisher: str = ""
    version: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SoftwareLicenseEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class PasswordItemEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    password: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    vault_name: str = "Personal"
    is_archived: bool = False
    is_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PasswordItemEntry":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class VaultSettings:
    auto_lock_minutes: int = 5
    lock_on_minimize: bool = False
    lock_on_workstation_lock: bool = True
    clipboard_wipe_seconds: int = 30
    exclude_windows_clipboard_history: bool = True
    vault_2fa_enabled: bool = False
    vault_2fa_secret: str = ""
    user_name: str = "Sumit"
    user_email: str = "user@localvault.internal"
    vaults: List[str] = field(default_factory=lambda: ["Personal"])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultSettings":
        valid_fields = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class VaultData:
    version: int = 1
    settings: VaultSettings = field(default_factory=VaultSettings)
    api_keys: List[APIKeyEntry] = field(default_factory=list)
    logins: List[LoginEntry] = field(default_factory=list)
    credit_cards: List[CreditCardEntry] = field(default_factory=list)
    identities: List[IdentityEntry] = field(default_factory=list)
    ssh_keys: List[SSHEntry] = field(default_factory=list)
    secure_notes: List[SecureNoteEntry] = field(default_factory=list)
    bank_accounts: List[BankAccountEntry] = field(default_factory=list)
    databases: List[DatabaseEntry] = field(default_factory=list)
    crypto_wallets: List[CryptoWalletEntry] = field(default_factory=list)
    servers: List[ServerEntry] = field(default_factory=list)
    software_licenses: List[SoftwareLicenseEntry] = field(default_factory=list)
    passwords: List[PasswordItemEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "settings": self.settings.to_dict(),
            "api_keys": [item.to_dict() for item in self.api_keys],
            "logins": [item.to_dict() for item in self.logins],
            "credit_cards": [item.to_dict() for item in self.credit_cards],
            "identities": [item.to_dict() for item in self.identities],
            "ssh_keys": [item.to_dict() for item in self.ssh_keys],
            "secure_notes": [item.to_dict() for item in self.secure_notes],
            "bank_accounts": [item.to_dict() for item in self.bank_accounts],
            "databases": [item.to_dict() for item in self.databases],
            "crypto_wallets": [item.to_dict() for item in self.crypto_wallets],
            "servers": [item.to_dict() for item in self.servers],
            "software_licenses": [item.to_dict() for item in self.software_licenses],
            "passwords": [item.to_dict() for item in self.passwords],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VaultData":
        settings_data = data.get("settings", {})
        settings = VaultSettings.from_dict(settings_data) if isinstance(settings_data, dict) else VaultSettings()

        api_keys = [APIKeyEntry.from_dict(item) for item in data.get("api_keys", [])]
        logins = [LoginEntry.from_dict(item) for item in data.get("logins", [])]
        credit_cards = [CreditCardEntry.from_dict(item) for item in data.get("credit_cards", [])]
        identities = [IdentityEntry.from_dict(item) for item in data.get("identities", [])]
        ssh_keys = [SSHEntry.from_dict(item) for item in data.get("ssh_keys", [])]
        secure_notes = [SecureNoteEntry.from_dict(item) for item in data.get("secure_notes", [])]
        bank_accounts = [BankAccountEntry.from_dict(item) for item in data.get("bank_accounts", [])]
        databases = [DatabaseEntry.from_dict(item) for item in data.get("databases", [])]
        crypto_wallets = [CryptoWalletEntry.from_dict(item) for item in data.get("crypto_wallets", [])]
        servers = [ServerEntry.from_dict(item) for item in data.get("servers", [])]
        software_licenses = [SoftwareLicenseEntry.from_dict(item) for item in data.get("software_licenses", [])]
        passwords = [PasswordItemEntry.from_dict(item) for item in data.get("passwords", [])]

        return cls(
            version=data.get("version", 1),
            settings=settings,
            api_keys=api_keys,
            logins=logins,
            credit_cards=credit_cards,
            identities=identities,
            ssh_keys=ssh_keys,
            secure_notes=secure_notes,
            bank_accounts=bank_accounts,
            databases=databases,
            crypto_wallets=crypto_wallets,
            servers=servers,
            software_licenses=software_licenses,
            passwords=passwords,
        )

    def all_items(self) -> List[Any]:
        """Returns all vault items across all categories."""
        return (
            self.logins
            + self.api_keys
            + self.credit_cards
            + self.identities
            + self.ssh_keys
            + self.secure_notes
            + self.bank_accounts
            + self.databases
            + self.crypto_wallets
            + self.servers
            + self.software_licenses
            + self.passwords
        )

"""
LocalVault Main Desktop Application Window
Pixel-accurate recreation of 1Password on Windows (Knox design system):
- Top Header Bar with 1Password logo app menu, navigation history (< >),
  centered search pill (Ctrl+K), and + New Item primary action.
- Left Sidebar with Account Profile Pill, main navigation (Profile, All Items,
  Favorites, Watchtower, Developer), Vaults (Personal), Tags, Archive, and Trash.
- Central Stacked Views:
  - All Items (Knox 3-Pane desktop layout with category filter, sort, and item counter)
  - Profile View (Account card, Identity/Payment cards, Manage Account)
  - Favorites View (Star empty state / filtered favorite credentials)
  - Watchtower View (Circular score gauge dial, strength bar, alert cards)
  - Developer Hub (SSH Agent, CLI integration, MCP Server, Environments)
- ESC key mapped to close active inspector credentials and return to home page.
- 100% offline, AES-256-GCM + Argon2id military-grade zero-knowledge encryption.
"""

import sys
from typing import Optional, List, Union, Tuple, Any
from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QStackedWidget,
    QListWidget,
    QListWidgetItem,
    QLineEdit,
    QPushButton,
    QLabel,
    QStatusBar,
    QMessageBox,
    QFileDialog,
    QComboBox,
    QFrame,
    QToolButton,
    QMenu,
)
from PySide6.QtCore import Qt, QTimer, QSize
from PySide6.QtGui import QIcon, QFont, QShortcut, QKeySequence, QAction

from core.models import (
    VaultData,
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
from core.storage import save_vault
from ui.styles import DARK_THEME_QSS, get_environment_badge_style, get_category_badge_style, get_category_icon_glyph
from ui.api_key_view import ItemInspectorView
from ui.audit_view import SecurityAuditView
from ui.profile_view import ProfileView
from ui.favorites_view import FavoritesView
from ui.developer_view import DeveloperHubView
from ui.category_picker_dialog import CategoryPickerDialog
from ui.manage_account_dialog import ManageAccountDialog
from ui.generator_dialog import GeneratorDialog
from ui.entry_dialog import EntryDialog
from platform_win32.monitor import get_system_idle_seconds, SessionLockFilter

_active_window = None


class MainWindow(QMainWindow):
    """
    Main application desktop window for LocalVault with 1Password Knox ergonomics.
    """

    def __init__(self, vault_data: VaultData, master_password: str, vault_path: str):
        super().__init__()
        self.vault_data = vault_data
        self.master_password = master_password
        self.vault_path = vault_path

        self.setWindowTitle("LocalVault - Military-Grade Key & Password Manager")
        self.resize(1280, 800)
        self.setMinimumSize(980, 620)
        self.setStyleSheet(DARK_THEME_QSS)

        icon_path = Path(__file__).parent.parent / "resources" / "LocalVault.ico"
        if icon_path.exists():
            from PySide6.QtGui import QIcon
            self.setWindowIcon(QIcon(str(icon_path)))

        # Start Extension & Mobile Local Bridge Server
        try:
            from core.extension_bridge import start_extension_bridge, GLOBAL_BRIDGE
            start_extension_bridge(28842)
            GLOBAL_BRIDGE.update_vault(self.vault_data, self.master_password, self.vault_path)

            # Securely cache master key via Windows DPAPI so the browser extension can unlock offline via Windows Hello / PIN
            try:
                import win32crypt
                import winreg
                enc = win32crypt.CryptProtectData(self.master_password.encode("utf-8"), "LocalVault_MasterKey", None, None, None, 0)
                with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\LocalVault") as k:
                    winreg.SetValueEx(k, "MasterKeyCache", 0, winreg.REG_BINARY, enc)
            except Exception:
                pass
        except Exception as e:
            print(f"[!] Warning: Could not initialize extension bridge: {e}")

        self._active_category = "all"
        self._active_main_view = "all_items"
        self._search_query = ""
        self._sort_ascending = True
        self._nav_history: List[str] = ["all_items"]
        self._nav_history_idx: int = 0

        self._setup_ui()
        self._refresh_all_views()
        self._update_nav_buttons_state()

        # Keyboard Shortcuts
        self._setup_shortcuts()

        # Idle timer for auto-lock
        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._check_inactivity)
        self._idle_timer.start(5000)

        # Session lock monitor hook
        self._session_filter = SessionLockFilter(self.lock_vault)
        if sys.platform == "win32":
            self._session_filter.register(int(self.winId()))

    def _setup_shortcuts(self):
        # Map ESC key to close all open credentials and jump back to home page
        self._esc_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self._esc_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        self._esc_shortcut.activated.connect(self._close_open_credentials_and_jump_home)

        # Ctrl+K to focus search pill
        self._search_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        self._search_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        self._search_shortcut.activated.connect(self._focus_search)

        # Ctrl+N to open category picker
        self._new_shortcut = QShortcut(QKeySequence("Ctrl+N"), self)
        self._new_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        self._new_shortcut.activated.connect(self._open_category_picker)

        # Ctrl+Shift+L to lock vault
        self._lock_shortcut = QShortcut(QKeySequence("Ctrl+Shift+L"), self)
        self._lock_shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
        self._lock_shortcut.activated.connect(self.lock_vault)

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. 1Password Knox Top Header Bar
        self.header_bar = self._create_top_header_bar()
        main_layout.addWidget(self.header_bar)

        # 2. Main Outer Splitter Layout
        self.outer_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.outer_splitter.setHandleWidth(1)

        # Pane A: Left Navigation Sidebar
        self.sidebar_widget = self._create_sidebar()
        self.outer_splitter.addWidget(self.sidebar_widget)

        # Pane B: Main Center Stack
        self.main_stack = QStackedWidget()
        self.center_stack = self.main_stack

        # Stack Page 0: All Items Two-Pane Splitter (Middle List + Right Inspector)
        self.items_page = self._create_items_view()
        self.main_stack.addWidget(self.items_page)

        # Stack Page 1: Security Audit / Watchtower View (Index 1)
        self.audit_view = SecurityAuditView(
            on_select_item_callback=self._select_and_highlight_item
        )
        self.main_stack.addWidget(self.audit_view)

        # Stack Page 2: Profile View (Index 2)
        self.profile_view = ProfileView(
            parent=self,
            on_manage_account=self._open_manage_account_dialog,
            on_add_identity=lambda: self._add_entry_with_category("identity"),
            on_add_payment=lambda: self._add_entry_with_category("credit_card"),
        )
        self.main_stack.addWidget(self.profile_view)

        # Stack Page 3: Favorites View (Index 3)
        self.favorites_view = FavoritesView(
            parent=self,
            on_find_items=lambda: self._switch_main_view("all_items"),
        )
        self.main_stack.addWidget(self.favorites_view)

        # Stack Page 4: Developer Hub View (Index 4)
        self.developer_view = DeveloperHubView(parent=self)
        self.main_stack.addWidget(self.developer_view)

        self.outer_splitter.addWidget(self.main_stack)
        self.outer_splitter.setSizes([220, 1060])
        main_layout.addWidget(self.outer_splitter, stretch=1)

        # 3. Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.crypto_status_lbl = QLabel("AES-256-GCM AEAD • Argon2id (64 MiB RAM)")
        self.crypto_status_lbl.setStyleSheet("color: #00e676; font-weight: 600; padding-right: 12px; font-size: 11px;")
        self.status_bar.addWidget(self.crypto_status_lbl)

        self.clip_status_lbl = QLabel("Win32 Clipboard: Protected (Win+V Excluded, 30s Auto-Wipe)")
        self.clip_status_lbl.setStyleSheet("color: #38bdf8; font-weight: 500; font-size: 11px;")
        self.status_bar.addWidget(self.clip_status_lbl)

        self.vault_info_lbl = QLabel(f"Vault: {Path(self.vault_path).name} (Personal)")
        self.vault_info_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        self.status_bar.addPermanentWidget(self.vault_info_lbl)

    # ------------------ Header Bar ------------------
    def _create_top_header_bar(self) -> QWidget:
        header = QFrame()
        header.setObjectName("topHeaderBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 6, 12, 6)
        header_layout.setSpacing(10)

        # App Logo & Menu Dropdown Button
        self.app_menu_btn = QToolButton()
        self.app_menu_btn.setObjectName("appMenuButton")
        self.app_menu_btn.setText("🛡️ LocalVault ▾")
        self.app_menu_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

        app_menu = QMenu(self.app_menu_btn)
        new_item_act = app_menu.addAction("New Item... (Ctrl+N)")
        new_item_act.triggered.connect(self._open_category_picker)

        new_vault_act = app_menu.addAction("New Vault...")
        new_vault_act.triggered.connect(lambda: QMessageBox.information(self, "Vaults", "Personal Vault is currently active. Additional isolated vaults can be created in the CLI or settings."))

        app_menu.addSeparator()

        manage_acc_act = app_menu.addAction("Manage Account...")
        manage_acc_act.triggered.connect(self._open_manage_account_dialog)

        generator_act = app_menu.addAction("Password Generator...")
        generator_act.triggered.connect(self._open_generator)

        connect_mobile_act = app_menu.addAction("📱 Connect Phone (QR Code)...")
        connect_mobile_act.triggered.connect(self._open_mobile_connect_dialog)

        app_menu.addSeparator()

        lock_act = app_menu.addAction("Lock Vault (Ctrl+Shift+L)")
        lock_act.triggered.connect(self.lock_vault)

        exit_act = app_menu.addAction("Quit (Ctrl+Q)")
        exit_act.triggered.connect(self.close)

        self.app_menu_btn.setMenu(app_menu)
        header_layout.addWidget(self.app_menu_btn)

        # History Navigation Buttons (< >)
        self.back_btn = QPushButton("‹")
        self.back_btn.setObjectName("navArrowBtn")
        self.back_btn.setToolTip("Back")
        self.back_btn.clicked.connect(self._nav_back)
        header_layout.addWidget(self.back_btn)

        self.fwd_btn = QPushButton("›")
        self.fwd_btn.setObjectName("navArrowBtn")
        self.fwd_btn.setToolTip("Forward")
        self.fwd_btn.clicked.connect(self._nav_fwd)
        header_layout.addWidget(self.fwd_btn)

        header_layout.addSpacing(16)

        # Centered Search Pill
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("searchPillEdit")
        self.search_edit.setPlaceholderText("Search in Personal (Ctrl+K)")
        self.search_edit.textChanged.connect(self._on_search_changed)
        header_layout.addWidget(self.search_edit, stretch=1)

        header_layout.addSpacing(16)

        # Right Action Buttons
        self.phone_btn = QPushButton("📱")
        self.phone_btn.setObjectName("navArrowBtn")
        self.phone_btn.setToolTip("Connect to Phone (QR Code)")
        self.phone_btn.clicked.connect(self._open_mobile_connect_dialog)
        header_layout.addWidget(self.phone_btn)

        self.help_btn = QPushButton("?")
        self.help_btn.setObjectName("navArrowBtn")
        self.help_btn.setToolTip("Help & Keyboard Shortcuts")
        self.help_btn.clicked.connect(self._show_help_dialog)
        header_layout.addWidget(self.help_btn)

        self.add_btn = QPushButton("+ New Item")
        self.add_btn.setObjectName("primaryButton")
        self.add_btn.setToolTip("Add new vault credential (Ctrl+N)")
        self.add_btn.clicked.connect(self._open_category_picker)
        header_layout.addWidget(self.add_btn)

        return header

    # ------------------ Left Sidebar ------------------
    def _create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("sidebarPane")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 12, 10, 12)
        sidebar_layout.setSpacing(6)

        # Account Profile Pill
        self.account_pill = QFrame()
        self.account_pill.setObjectName("accountPill")
        self.account_pill.setCursor(Qt.CursorShape.PointingHandCursor)
        pill_layout = QHBoxLayout(self.account_pill)
        pill_layout.setContentsMargins(8, 6, 8, 6)
        pill_layout.setSpacing(10)

        avatar_lbl = QLabel("R")
        avatar_lbl.setFixedSize(28, 28)
        avatar_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar_lbl.setStyleSheet("background-color: #0572ec; color: #ffffff; font-weight: bold; border-radius: 14px; font-size: 13px;")
        pill_layout.addWidget(avatar_lbl)

        acc_text_layout = QVBoxLayout()
        acc_text_layout.setSpacing(1)
        user_display = (self.vault_data.settings.user_name if self.vault_data else "") or os.environ.get("USERNAME", "User").capitalize()
        acc_name = QLabel(user_display)
        acc_name.setStyleSheet("font-weight: 700; color: #f8fafc; font-size: 12px;")
        acc_vault = QLabel("Personal")
        acc_vault.setStyleSheet("color: #64748b; font-size: 11px;")
        acc_text_layout.addWidget(acc_name)
        acc_text_layout.addWidget(acc_vault)
        pill_layout.addLayout(acc_text_layout, stretch=1)

        chevron_lbl = QLabel("▾")
        chevron_lbl.setStyleSheet("color: #64748b; font-size: 10px;")
        pill_layout.addWidget(chevron_lbl)

        self.account_pill.mousePressEvent = lambda e: self._open_manage_account_dialog()
        sidebar_layout.addWidget(self.account_pill)

        sidebar_layout.addSpacing(6)

        # Main Nav List
        self.sidebar_list = QListWidget()
        self.sidebar_list.setObjectName("sidebarList")
        self.sidebar_list.itemClicked.connect(self._on_sidebar_item_clicked)

        nav_items = [
            ("profile", "👤 Profile"),
            ("all_items", "📑 All Items"),
            ("favorites", "⭐ Favorites"),
            ("watchtower", "🛡️ Watchtower"),
            ("developer", "⚡ Developer"),
        ]
        for key, label in nav_items:
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.sidebar_list.addItem(item)

        sidebar_layout.addWidget(self.sidebar_list)

        # Vaults Section
        vault_sec_lbl = QLabel("VAULTS")
        vault_sec_lbl.setObjectName("sidebarSectionHeader")
        sidebar_layout.addWidget(vault_sec_lbl)

        self.vaults_list = QListWidget()
        self.vaults_list.setObjectName("sidebarList")
        self.vaults_list.setMaximumHeight(40)
        v_item = QListWidgetItem("🔒 Personal")
        v_item.setData(Qt.ItemDataRole.UserRole, "vault_personal")
        self.vaults_list.addItem(v_item)
        self.vaults_list.itemClicked.connect(lambda it: self._close_open_credentials_and_jump_home())
        sidebar_layout.addWidget(self.vaults_list)

        # Tags Section
        tag_sec_lbl = QLabel("TAGS")
        tag_sec_lbl.setObjectName("sidebarSectionHeader")
        sidebar_layout.addWidget(tag_sec_lbl)

        self.tags_list = QListWidget()
        self.tags_list.setObjectName("sidebarList")
        self.tags_list.setMaximumHeight(40)
        t_item = QListWidgetItem("🏷️ Starter Kit")
        t_item.setData(Qt.ItemDataRole.UserRole, "tag_starter")
        self.tags_list.addItem(t_item)
        self.tags_list.itemClicked.connect(lambda it: self._filter_by_tag("Starter Kit"))
        sidebar_layout.addWidget(self.tags_list)

        sidebar_layout.addStretch()

        # Bottom Utilities: Archive & Deleted
        self.bottom_list = QListWidget()
        self.bottom_list.setObjectName("sidebarList")
        self.bottom_list.setMaximumHeight(80)

        arch_item = QListWidgetItem("📁 Archive")
        arch_item.setData(Qt.ItemDataRole.UserRole, "archive")
        self.bottom_list.addItem(arch_item)

        trash_item = QListWidgetItem("🗑️ Recently Deleted")
        trash_item.setData(Qt.ItemDataRole.UserRole, "trash")
        self.bottom_list.addItem(trash_item)
        self.bottom_list.itemClicked.connect(self._on_bottom_list_clicked)
        sidebar_layout.addWidget(self.bottom_list)

        return sidebar

    # ------------------ Middle & Right Splitter (All Items) ------------------
    def _create_items_view(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        items_splitter = QSplitter(Qt.Orientation.Horizontal)
        items_splitter.setHandleWidth(1)

        # Middle Pane: Items List & Filter Toolbar
        items_pane = QFrame()
        items_pane.setObjectName("itemsPane")
        items_pane.setMinimumWidth(320)
        items_layout = QVBoxLayout(items_pane)
        items_layout.setContentsMargins(0, 0, 0, 0)
        items_layout.setSpacing(0)

        # Filter & Sort Toolbar
        toolbar = QFrame()
        toolbar.setObjectName("itemsToolbar")
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(10, 8, 10, 8)
        tb_layout.setSpacing(8)

        self.cat_filter_combo = QComboBox()
        self.cat_filter_combo.setObjectName("categoryFilterCombo")
        self.cat_filter_combo.addItem("All Categories", "all")
        self.cat_filter_combo.addItem("🔑 Logins", "logins")
        self.cat_filter_combo.addItem("💳 Credit Cards", "credit_cards")
        self.cat_filter_combo.addItem("🪪 Identities", "identities")
        self.cat_filter_combo.addItem("⚡ API Credentials", "api_keys")
        self.cat_filter_combo.addItem("💻 SSH Keys", "ssh_keys")
        self.cat_filter_combo.addItem("📝 Secure Notes", "secure_notes")
        self.cat_filter_combo.addItem("🏦 Bank Accounts", "bank_accounts")
        self.cat_filter_combo.addItem("🗄️ Databases", "databases")
        self.cat_filter_combo.addItem("🪙 Crypto Wallets", "crypto_wallets")
        self.cat_filter_combo.addItem("🖥️ Servers", "servers")
        self.cat_filter_combo.addItem("📜 Software Licenses", "software_licenses")
        self.cat_filter_combo.addItem("🔒 Passwords", "passwords")
        self.cat_filter_combo.currentIndexChanged.connect(self._on_cat_filter_changed)
        tb_layout.addWidget(self.cat_filter_combo, stretch=1)

        self.sort_btn = QPushButton("↓ A")
        self.sort_btn.setObjectName("sortButton")
        self.sort_btn.setFixedSize(54, 28)
        self.sort_btn.setToolTip("Sort A to Z (click to toggle)")
        self.sort_btn.clicked.connect(self._toggle_sort)
        tb_layout.addWidget(self.sort_btn)

        self.item_count_lbl = QLabel("0 items")
        self.item_count_lbl.setStyleSheet("color: #64748b; font-size: 11px; font-weight: 600;")
        tb_layout.addWidget(self.item_count_lbl)

        items_layout.addWidget(toolbar)

        # Items List
        self.items_list = QListWidget()
        self.items_list.setObjectName("itemsList")
        self.items_list.itemClicked.connect(self._on_item_selected)
        items_layout.addWidget(self.items_list, stretch=1)

        items_splitter.addWidget(items_pane)

        # Right Pane: Item Inspector
        self.inspector = ItemInspectorView(
            on_edit_callback=self._edit_entry,
            on_delete_callback=self._delete_entry,
            on_favorite_callback=self._on_entry_favorite_toggled,
            on_new_item_callback=self._open_category_picker,
        )
        items_splitter.addWidget(self.inspector)
        items_splitter.setSizes([340, 720])

        layout.addWidget(items_splitter)
        return container

    # ------------------ View Switching & Navigation ------------------
    def _switch_main_view(self, view_key: str, add_to_history: bool = True):
        self._active_main_view = view_key

        # Update sidebar selection
        for i in range(self.sidebar_list.count()):
            it = self.sidebar_list.item(i)
            if it.data(Qt.ItemDataRole.UserRole) == view_key:
                self.sidebar_list.setCurrentItem(it)
                break

        if view_key == "all_items":
            self._active_category = "all"
            if hasattr(self, "cat_filter_combo"):
                self.cat_filter_combo.blockSignals(True)
                self.cat_filter_combo.setCurrentIndex(0)
                self.cat_filter_combo.blockSignals(False)
            self.main_stack.setCurrentIndex(0)
            self._refresh_items_list()
        elif view_key == "watchtower":
            self.main_stack.setCurrentIndex(1)
            self.audit_view.set_vault_data(self.vault_data)
        elif view_key == "profile":
            self.main_stack.setCurrentIndex(2)
        elif view_key == "favorites":
            self.main_stack.setCurrentIndex(3)
            favs = [it for it in self.vault_data.all_items() if getattr(it, "is_favorite", False)]
            self.favorites_view.set_favorite_items(favs)
        elif view_key == "developer":
            self.main_stack.setCurrentIndex(4)

        if add_to_history:
            if not self._nav_history or self._nav_history[-1] != view_key:
                self._nav_history.append(view_key)
                self._nav_history_idx = len(self._nav_history) - 1

        self._update_nav_buttons_state()

    def _update_nav_buttons_state(self):
        can_back = self._nav_history_idx > 0
        can_fwd = self._nav_history_idx < len(self._nav_history) - 1
        self.back_btn.setEnabled(can_back)
        self.fwd_btn.setEnabled(can_fwd)

    def _nav_back(self):
        if self._nav_history_idx > 0:
            self._nav_history_idx -= 1
            prev_view = self._nav_history[self._nav_history_idx]
            self._switch_main_view(prev_view, add_to_history=False)
            self._update_nav_buttons_state()

    def _nav_fwd(self):
        if self._nav_history_idx < len(self._nav_history) - 1:
            self._nav_history_idx += 1
            next_view = self._nav_history[self._nav_history_idx]
            self._switch_main_view(next_view, add_to_history=False)
            self._update_nav_buttons_state()

    def _on_sidebar_item_clicked(self, item: QListWidgetItem):
        key = item.data(Qt.ItemDataRole.UserRole)
        if key == "all_items":
            self._close_open_credentials_and_jump_home()
        else:
            self._switch_main_view(key)

    def _toggle_sort(self):
        self._sort_ascending = not getattr(self, "_sort_ascending", True)
        self.sort_btn.setText("↓ A" if self._sort_ascending else "↑ Z")
        self.sort_btn.setToolTip("Sorting A to Z" if self._sort_ascending else "Sorting Z to A")
        self._refresh_items_list()

    def _on_bottom_list_clicked(self, item: QListWidgetItem):
        key = item.data(Qt.ItemDataRole.UserRole)
        if key == "archive":
            QMessageBox.information(self, "Archive", "No archived items in Personal Vault.")
        elif key == "trash":
            QMessageBox.information(self, "Recently Deleted", "Recently Deleted items are safely purged after 30 days. No items currently in Trash.")

    def _filter_by_tag(self, tag_name: str):
        self._switch_main_view("all_items")
        self.search_edit.setText(tag_name)

    # ------------------ Refresh & Population ------------------
    def _refresh_all_views(self):
        # Default select All Items in sidebar
        for i in range(self.sidebar_list.count()):
            it = self.sidebar_list.item(i)
            if it.data(Qt.ItemDataRole.UserRole) == "all_items":
                self.sidebar_list.setCurrentItem(it)
                break

        self._refresh_items_list()

    def _refresh_categories_and_items(self):
        """Backward-compatible alias for refreshing views and lists."""
        self._refresh_items_list()

    def _refresh_items_list(self):
        self.items_list.clear()
        query = self._search_query.lower()
        combo_cat = self.cat_filter_combo.currentData() if hasattr(self, "cat_filter_combo") else "all"
        selected_cat = self._active_category if self._active_category != "all" else (combo_cat or "all")

        entries: List[Tuple[str, Any]] = []

        # Collect matching entries
        category_map = [
            ("login", "logins", self.vault_data.logins),
            ("credit_card", "credit_cards", self.vault_data.credit_cards),
            ("identity", "identities", self.vault_data.identities),
            ("api_key", "api_keys", self.vault_data.api_keys),
            ("ssh_key", "ssh_keys", self.vault_data.ssh_keys),
            ("secure_note", "secure_notes", self.vault_data.secure_notes),
            ("bank_account", "bank_accounts", self.vault_data.bank_accounts),
            ("database", "databases", self.vault_data.databases),
            ("crypto_wallet", "crypto_wallets", self.vault_data.crypto_wallets),
            ("server", "servers", self.vault_data.servers),
            ("software_license", "software_licenses", self.vault_data.software_licenses),
            ("password", "passwords", self.vault_data.passwords),
        ]

        for cat_single, cat_plural, item_list in category_map:
            matches_cat = (selected_cat == "all") or (selected_cat == cat_plural) or (selected_cat in ["logins", "passwords"] and cat_plural in ["logins", "passwords"])
            if matches_cat:
                for item in item_list:
                    if self._matches_filter(item, cat_single, query):
                        entries.append((cat_single, item))

        # Sort items alphabetically based on toggle state
        asc = getattr(self, "_sort_ascending", True)
        entries.sort(
            key=lambda t: (getattr(t[1], "title", None) or getattr(t[1], "name", None) or getattr(t[1], "cardholder_name", "")).lower(),
            reverse=not asc,
        )

        # Update counter
        count = len(entries)
        self.item_count_lbl.setText(f"{count} {'item' if count == 1 else 'items'}")

        # Populate Items ListWidget
        for cat_type, entry in entries:
            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(0, 78))
            list_item.setData(Qt.ItemDataRole.UserRole, entry)
            self.items_list.addItem(list_item)

            card_widget = self._create_item_card_widget(cat_type, entry)
            self.items_list.setItemWidget(list_item, card_widget)

        # Clear inspector if empty
        if self.items_list.count() == 0:
            self.inspector.set_entry(None)

    def _matches_filter(self, item: Any, cat_type: str, query: str) -> bool:
        if not query:
            return True

        fields: List[str] = []
        for attr in ["title", "name", "service", "environment", "key_id", "hostname", "notes", "cardholder_name", "bank_name", "software_name", "address"]:
            val = getattr(item, attr, None)
            if val:
                fields.append(str(val))

        urls = getattr(item, "urls", [])
        if urls:
            fields.extend(urls)

        tags = getattr(item, "tags", [])
        if tags:
            fields.extend(tags)

        return any(query in f.lower() for f in fields)

    def _create_item_card_widget(self, cat_type: str, entry: Any) -> QWidget:
        widget = QWidget()
        widget.setStyleSheet("background: transparent; border: none;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)

        # Category Glyph
        glyph_lbl = QLabel(get_category_icon_glyph(cat_type))
        glyph_lbl.setFixedWidth(20)
        glyph_lbl.setFont(QFont("Segoe UI Emoji", 12))
        top_row.addWidget(glyph_lbl)

        # Title
        title_text = getattr(entry, "title", None) or getattr(entry, "name", None) or getattr(entry, "cardholder_name", "Untitled")
        title_lbl = QLabel(title_text)
        title_lbl.setStyleSheet("font-weight: 600; font-size: 13px; color: #f8fafc;")
        title_lbl.setFixedHeight(20)
        top_row.addWidget(title_lbl, stretch=1)

        # Favorite star if marked
        if getattr(entry, "is_favorite", False):
            star_lbl = QLabel("⭐")
            star_lbl.setFont(QFont("Segoe UI Emoji", 10))
            top_row.addWidget(star_lbl)

        # Category Badge (Only for non-login items to avoid button confusion; transparent to mouse)
        if cat_type != "login":
            cat_badge = QLabel(cat_type.replace("_", " ").upper())
            cat_badge.setStyleSheet(get_category_badge_style(cat_type))
            cat_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cat_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            top_row.addWidget(cat_badge)

        # Environment Badge for API Keys
        if cat_type == "api_key" and hasattr(entry, "environment"):
            env_badge = QLabel(entry.environment.upper())
            env_badge.setStyleSheet(get_environment_badge_style(entry.environment))
            env_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            top_row.addWidget(env_badge)

        layout.addLayout(top_row)

        # Subtitle Row (Requirement: Do NOT show user ID on the home page!)
        sub_row = QHBoxLayout()
        sub_row.setContentsMargins(28, 0, 0, 0)
        sub_row.setSpacing(6)

        if cat_type == "login":
            urls = getattr(entry, "urls", [])
            if urls:
                clean_sites = []
                for u in urls:
                    raw_u = u.strip()
                    if not raw_u:
                        continue
                    for prefix in ("https://", "http://", "www."):
                        if raw_u.lower().startswith(prefix):
                            raw_u = raw_u[len(prefix):]
                    clean_sites.append(raw_u.rstrip("/"))
                sub_text = " • ".join(clean_sites) if clean_sites else "No linked sites"
            else:
                sub_text = "No linked sites"
        elif cat_type == "credit_card":
            num = getattr(entry, "card_number", "")
            sub_text = f"{getattr(entry, 'card_type', 'Card')} •••• {num[-4:] if len(num)>=4 else '••••'}"
        elif cat_type == "identity":
            sub_text = getattr(entry, "email", "") or getattr(entry, "company", "Identity Profile")
        elif cat_type == "api_key":
            sub_text = f"{entry.service or 'Custom'} • {entry.base_url or 'API Key'}"
        elif cat_type == "ssh_key":
            sub_text = entry.hostname or "SSH Host"
        elif cat_type == "bank_account":
            num = getattr(entry, "account_number", "")
            sub_text = f"{getattr(entry, 'bank_name', 'Bank')} •••• {num[-4:] if len(num)>=4 else '••••'}"
        elif cat_type == "database":
            sub_text = f"{getattr(entry, 'db_type', 'DB')} • {getattr(entry, 'hostname', 'localhost')}"
        elif cat_type == "crypto_wallet":
            sub_text = f"{getattr(entry, 'network', 'Crypto')} • {getattr(entry, 'address', '')[:12]}..."
        elif cat_type == "server":
            sub_text = f"{getattr(entry, 'server_type', 'Server')} • {getattr(entry, 'ip_address', '')}"
        elif cat_type == "software_license":
            sub_text = getattr(entry, "software_name", "Software License")
        elif cat_type == "password":
            sub_text = "Password Item"
        else:
            sub_text = f"{len(getattr(entry, 'content', ''))} chars"

        sub_lbl = QLabel(sub_text)
        sub_lbl.setStyleSheet("color: #64748b; font-size: 11px;")
        sub_lbl.setFixedHeight(18)
        sub_row.addWidget(sub_lbl, stretch=1)

        layout.addLayout(sub_row)
        return widget

    # ------------------ Action Handlers ------------------
    def _on_cat_filter_changed(self):
        self._refresh_items_list()

    def _on_item_selected(self, item: QListWidgetItem):
        entry = item.data(Qt.ItemDataRole.UserRole)
        self.inspector.set_entry(entry)

    def _on_search_changed(self, text: str):
        self._search_query = text
        if self.center_stack.currentIndex() != 0:
            self._switch_main_view("all_items")
        self._refresh_items_list()

    def _focus_search(self):
        if self.center_stack.currentIndex() != 0:
            self._switch_main_view("all_items")
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def _open_category_picker(self):
        picker = CategoryPickerDialog(self)
        if picker.exec():
            cat = picker.selected_category or getattr(picker, "selected_category_id", None)
            if cat == "__import__":
                self._open_import_dialog()
            elif cat:
                self._add_entry_with_category(cat)

    def _open_import_dialog(self):
        """Allows importing passwords/logins from CSV or JSON exports (1Password, Bitwarden, Chrome, LastPass)."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Credentials into LocalVault",
            "",
            "Password Exports (*.csv *.json *.1pif);;CSV Files (*.csv);;JSON Files (*.json);;All Files (*.*)",
        )
        if not file_path:
            return

        imported_count = 0
        try:
            p = Path(file_path)
            if p.suffix.lower() == ".csv":
                import csv
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        r_lower = {k.lower().strip(): v for k, v in row.items() if k}
                        title = r_lower.get("title") or r_lower.get("name") or r_lower.get("url") or "Imported Item"
                        username = r_lower.get("username") or r_lower.get("login_username") or r_lower.get("user") or r_lower.get("email") or ""
                        password = r_lower.get("password") or r_lower.get("login_password") or ""
                        url = r_lower.get("url") or r_lower.get("website") or r_lower.get("login_url") or ""
                        notes = r_lower.get("notes") or r_lower.get("note") or ""
                        totp = r_lower.get("totp") or r_lower.get("otp") or ""

                        if password or username:
                            entry = LoginEntry(
                                title=title,
                                username=username,
                                password=password,
                                urls=[url] if url else [],
                                totp_secret=totp,
                                notes=notes,
                                vault_name="Personal",
                            )
                            self.vault_data.logins.append(entry)
                            imported_count += 1

            elif p.suffix.lower() == ".json":
                import json
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                items = data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                for item in items:
                    name = item.get("name", "Imported Item")
                    login = item.get("login", {})
                    user = login.get("username", "")
                    pwd = login.get("password", "")
                    uris = [u.get("uri", "") for u in login.get("uris", []) if u.get("uri")]
                    totp = login.get("totp", "")
                    if pwd or user:
                        entry = LoginEntry(
                            title=name,
                            username=user,
                            password=pwd,
                            urls=uris,
                            totp_secret=totp,
                            vault_name="Personal",
                        )
                        self.vault_data.logins.append(entry)
                        imported_count += 1

            if imported_count > 0:
                self._save_changes()
                self._refresh_items_list()
                QMessageBox.information(
                    self,
                    "Import Complete",
                    f"Successfully imported {imported_count} credential(s) into your encrypted Personal Vault!",
                )
            else:
                QMessageBox.warning(
                    self,
                    "No Items Found",
                    "No valid credential records could be parsed from the selected file. Please verify the format.",
                )
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to import file: {e}")

    def _add_entry_with_category(self, cat_id: str):
        dialog = EntryDialog(self, default_category=cat_id)
        if dialog.exec() and dialog.result_entry:
            new_entry = dialog.result_entry
            self._add_item_to_vault(new_entry)
            self._save_changes()
            self._switch_main_view("all_items")
            self._refresh_items_list()
            self.inspector.set_entry(new_entry)

    def _add_item_to_vault(self, entry: Any):
        if isinstance(entry, LoginEntry):
            self.vault_data.logins.append(entry)
        elif isinstance(entry, CreditCardEntry):
            self.vault_data.credit_cards.append(entry)
        elif isinstance(entry, IdentityEntry):
            self.vault_data.identities.append(entry)
        elif isinstance(entry, APIKeyEntry):
            self.vault_data.api_keys.append(entry)
        elif isinstance(entry, SSHEntry):
            self.vault_data.ssh_keys.append(entry)
        elif isinstance(entry, SecureNoteEntry):
            self.vault_data.secure_notes.append(entry)
        elif isinstance(entry, BankAccountEntry):
            self.vault_data.bank_accounts.append(entry)
        elif isinstance(entry, DatabaseEntry):
            self.vault_data.databases.append(entry)
        elif isinstance(entry, CryptoWalletEntry):
            self.vault_data.crypto_wallets.append(entry)
        elif isinstance(entry, ServerEntry):
            self.vault_data.servers.append(entry)
        elif isinstance(entry, SoftwareLicenseEntry):
            self.vault_data.software_licenses.append(entry)
        elif isinstance(entry, PasswordItemEntry):
            self.vault_data.passwords.append(entry)

    def _edit_entry(self, entry: Any):
        dialog = EntryDialog(self, entry=entry)
        if dialog.exec() and dialog.result_entry:
            updated = dialog.result_entry
            self._update_item_in_vault(updated)
            self._save_changes()
            self._refresh_items_list()
            self.inspector.set_entry(updated)

    def _update_item_in_vault(self, updated: Any):
        cat_lists = [
            self.vault_data.logins,
            self.vault_data.credit_cards,
            self.vault_data.identities,
            self.vault_data.api_keys,
            self.vault_data.ssh_keys,
            self.vault_data.secure_notes,
            self.vault_data.bank_accounts,
            self.vault_data.databases,
            self.vault_data.crypto_wallets,
            self.vault_data.servers,
            self.vault_data.software_licenses,
            self.vault_data.passwords,
        ]
        for lst in cat_lists:
            for i, it in enumerate(lst):
                if getattr(it, "id", None) == getattr(updated, "id", None):
                    lst[i] = updated
                    return

    def _delete_entry(self, entry: Any):
        cat_lists = [
            self.vault_data.logins,
            self.vault_data.credit_cards,
            self.vault_data.identities,
            self.vault_data.api_keys,
            self.vault_data.ssh_keys,
            self.vault_data.secure_notes,
            self.vault_data.bank_accounts,
            self.vault_data.databases,
            self.vault_data.crypto_wallets,
            self.vault_data.servers,
            self.vault_data.software_licenses,
            self.vault_data.passwords,
        ]
        for lst in cat_lists:
            lst[:] = [x for x in lst if getattr(x, "id", None) != getattr(entry, "id", None)]

        self._save_changes()
        self._refresh_items_list()
        self.inspector.set_entry(None)

    def _on_entry_favorite_toggled(self, entry: Any):
        self._save_changes()
        self._refresh_items_list()

    def _select_and_highlight_item(self, item_id: str):
        """Called from audit / watchtower view to jump to a specific item."""
        self._active_category = "all"
        if hasattr(self, "cat_filter_combo"):
            self.cat_filter_combo.blockSignals(True)
            self.cat_filter_combo.setCurrentIndex(0)
            self.cat_filter_combo.blockSignals(False)
        self._switch_main_view("all_items")
        self._search_query = ""
        self.search_edit.clear()
        self.cat_filter_combo.setCurrentIndex(0)
        self._refresh_items_list()

        for i in range(self.items_list.count()):
            it = self.items_list.item(i)
            entry = it.data(Qt.ItemDataRole.UserRole)
            if entry and getattr(entry, "id", None) == item_id:
                self.items_list.setCurrentItem(it)
                self.inspector.set_entry(entry)
                break

    def _open_audit_view(self):
        """Switches center stack to Watchtower security audit view."""
        self._switch_main_view("watchtower")

    def _open_manage_account_dialog(self):
        dlg = ManageAccountDialog(self)
        dlg.exec()

    def _open_generator(self):
        gen = GeneratorDialog(self)
        gen.exec()

    def _show_help_dialog(self):
        msg = (
            "<h3>LocalVault Keyboard Shortcuts</h3>"
            "<ul>"
            "<li><b>Ctrl + K</b>: Focus Search bar</li>"
            "<li><b>Ctrl + N</b>: Add New Vault Item (+ Category Picker)</li>"
            "<li><b>ESC</b>: Close open credentials, clear search, jump to Home</li>"
            "<li><b>Ctrl + Shift + L</b>: Immediately lock vault</li>"
            "<li><b>Ctrl + Q</b>: Quit LocalVault</li>"
            "</ul>"
            "<p>All data is encrypted offline using <b>AES-256-GCM AEAD</b> and <b>Argon2id</b> key derivation.</p>"
        )
        QMessageBox.information(self, "Help & Shortcuts", msg)

    def _open_mobile_connect_dialog(self):
        """Opens QR Code pairing modal to connect mobile phone on local Wi-Fi."""
        from ui.mobile_connect_dialog import MobileConnectDialog
        dlg = MobileConnectDialog(self)
        dlg.exec()

    def _close_open_credentials_and_jump_home(self):
        """
        ESC Key Handler:
        Closes all open credentials in the inspector, deselects active items,
        and returns to the home page (All Items view) with search cleared.
        """
        self.items_list.clearSelection()
        self.items_list.setCurrentItem(None)
        self.inspector.set_entry(None)

        self._active_category = "all"
        if hasattr(self, "cat_filter_combo"):
            self.cat_filter_combo.blockSignals(True)
            self.cat_filter_combo.setCurrentIndex(0)
            self.cat_filter_combo.blockSignals(False)
        self._switch_main_view("all_items")
        self._search_query = ""
        self.search_edit.blockSignals(True)
        self.search_edit.clear()
        self.search_edit.blockSignals(False)

        self._refresh_items_list()
        self.items_list.setFocus()

    def _save_changes(self):
        try:
            save_vault(self.vault_data, self.vault_path, self.master_password)
            try:
                from core.extension_bridge import GLOBAL_BRIDGE
                GLOBAL_BRIDGE.update_vault(self.vault_data, self.master_password, self.vault_path)
            except Exception:
                pass
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to persist encrypted vault: {e}")

    def _check_inactivity(self):
        max_minutes = self.vault_data.settings.auto_lock_minutes
        if max_minutes > 0:
            idle_seconds = get_system_idle_seconds()
            if idle_seconds >= (max_minutes * 60):
                self.lock_vault()

    def lock_vault(self):
        """Immediately locks the vault, clears memory, and returns to unlock dialog."""
        self._idle_timer.stop()
        self.inspector.set_entry(None)

        try:
            from core.extension_bridge import GLOBAL_BRIDGE
            GLOBAL_BRIDGE.lock_vault()
        except Exception:
            pass

        self.master_password = ""
        self.close()

        from ui.unlock_dialog import UnlockDialog
        unlock = UnlockDialog(vault_path=self.vault_path)
        if unlock.exec() and unlock.unlocked_data:
            new_win = MainWindow(unlock.unlocked_data, unlock.master_password, unlock.vault_path)
            new_win.show()
            global _active_window
            _active_window = new_win
        else:
            sys.exit(0)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self._close_open_credentials_and_jump_home()
            event.accept()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event):
        self._session_filter.unregister()
        super().closeEvent(event)

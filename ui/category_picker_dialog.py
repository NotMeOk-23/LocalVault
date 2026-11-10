"""
LocalVault 1Password-Style "What would you like to add?" Category Picker Modal
Provides an authentic Knox grid with instant search filtering,
smoothly expandable 16-category secondary section, frameless dark aesthetics,
and 100% interactive category cards.
"""

from typing import Optional, List, Tuple
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QScrollArea,
    QWidget,
)
from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QFont

PRIMARY_CATEGORIES: List[Tuple[str, str, str, str]] = [
    ("login", "Login", "🔑", "#0572ec"),
    ("secure_notes", "Secure Note", "📝", "#d97706"),
    ("credit_cards", "Credit Card", "💳", "#2563eb"),
    ("identities", "Identity", "🪪", "#16a34a"),
    ("api_keys", "API Credentials", "⚡", "#0891b2"),
    ("documents", "Document", "📄", "#64748b"),
]

MORE_CATEGORIES: List[Tuple[str, str, str, str]] = [
    ("bank_accounts", "Bank Account", "🏦", "#059669"),
    ("crypto_wallets", "Crypto Wallet", "🪙", "#ea580c"),
    ("databases", "Database", "🗄️", "#9333ea"),
    ("driver_licenses", "Driver License", "🚗", "#0284c7"),
    ("emails", "Email", "✉️", "#0284c7"),
    ("medical_records", "Medical Record", "🩺", "#e11d48"),
    ("memberships", "Membership", "🎫", "#7c3aed"),
    ("outdoor_licenses", "Outdoor License", "🌲", "#15803d"),
    ("passports", "Passport", "🛂", "#1e40af"),
    ("passwords", "Password", "🔒", "#3b82f6"),
    ("rewards", "Rewards", "🎁", "#ca8a04"),
    ("ssh_keys", "SSH Key", "💻", "#475569"),
    ("servers", "Server", "🖥️", "#4f46e5"),
    ("ssn", "Social Security Number", "🛡️", "#0369a1"),
    ("software_licenses", "Software License", "📜", "#ca8a04"),
    ("wireless_routers", "Wireless Router", "📶", "#0891b2"),
]


class CategoryPickerDialog(QDialog):
    """
    Modal dialog matching 1Password's 'What would you like to add?' category selector.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_category: Optional[str] = None
        self._selected_category_id: Optional[str] = None
        self.is_expanded: bool = False
        self._drag_pos = QPoint()

        self.setWindowTitle("What would you like to add?")
        self.setFixedWidth(560)
        self.setMinimumHeight(500)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

        self._setup_ui()

    @property
    def selected_category_id(self) -> Optional[str]:
        return self._selected_category_id or self.selected_category

    @selected_category_id.setter
    def selected_category_id(self, val: Optional[str]):
        self._selected_category_id = val
        self.selected_category = val

    def _setup_ui(self):
        # Outermost container for clean rounded Knox border
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.container_frame = QFrame(self)
        self.container_frame.setObjectName("dialogContainer")
        self.container_frame.setStyleSheet("""
            QFrame#dialogContainer {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #141f31, stop:1 #0c1320);
                border: 1px solid #283e5c;
                border-radius: 12px;
            }
        """)
        outer_layout.addWidget(self.container_frame)

        layout = QVBoxLayout(self.container_frame)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header with Title & Close button
        header_row = QHBoxLayout()
        title_lbl = QLabel("What would you like to add?")
        title_lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color: #f8fafc; background: transparent;")
        header_row.addWidget(title_lbl)
        header_row.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                color: #94a3b8;
                font-size: 14px;
                border-radius: 14px;
            }
            QPushButton:hover {
                background-color: #1e2a3c;
                color: #ffffff;
            }
        """)
        close_btn.clicked.connect(self.reject)
        header_row.addWidget(close_btn)
        layout.addLayout(header_row)

        # Search Bar
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍  Search for a category or website")
        self.search_edit.setFixedHeight(38)
        self.search_edit.setStyleSheet("""
            QLineEdit {
                background-color: #141f30;
                border: 1px solid #23364f;
                border-radius: 8px;
                padding-left: 14px;
                color: #ffffff;
                font-size: 13px;
            }
            QLineEdit:hover {
                background-color: #172438;
                border-color: #2f4564;
            }
            QLineEdit:focus {
                border-color: #0572ec;
                background-color: #18273b;
            }
        """)
        self.search_edit.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_edit)

        # Scrollable container for Category Cards
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.scroll.setStyleSheet("background: transparent; border: none;")

        self.cards_container = QWidget()
        self.cards_container.setStyleSheet("background: transparent;")
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(12)

        # Primary 2x3 Grid
        self.primary_grid_widget = QWidget()
        self.primary_grid_widget.setStyleSheet("background: transparent;")
        self.primary_grid = QGridLayout(self.primary_grid_widget)
        self.primary_grid.setContentsMargins(0, 0, 0, 0)
        self.primary_grid.setSpacing(10)

        self.category_widgets = []

        for idx, (cat_key, cat_label, glyph, color) in enumerate(PRIMARY_CATEGORIES):
            card = self._create_category_card(cat_key, cat_label, glyph, color, is_primary=True)
            row = idx // 3
            col = idx % 3
            self.primary_grid.addWidget(card, row, col)
            self.category_widgets.append((cat_key, cat_label, card))

        self.cards_layout.addWidget(self.primary_grid_widget)

        # "More categories" Expandable Toggle Button
        self.more_toggle_btn = QPushButton("More categories  ▾")
        self.more_toggle_btn.setFixedHeight(36)
        self.more_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.more_toggle_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #152234, stop:1 #111a28);
                border: 1px solid #23344d;
                border-radius: 6px;
                color: #94a3b8;
                font-weight: 600;
                font-size: 12px;
                text-align: center;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1c2b40, stop:1 #152233);
                color: #f1f5f9;
                border-color: #354a67;
            }
        """)
        self.more_toggle_btn.clicked.connect(self._toggle_more_categories)
        self.cards_layout.addWidget(self.more_toggle_btn)

        # "More categories" 2-Column Grid
        self.more_grid_widget = QWidget()
        self.more_grid_widget.setStyleSheet("background: transparent;")
        self.more_grid = QGridLayout(self.more_grid_widget)
        self.more_grid.setContentsMargins(0, 0, 0, 0)
        self.more_grid.setSpacing(8)
        self.more_grid_widget.setVisible(False)

        for idx, (cat_key, cat_label, glyph, color) in enumerate(MORE_CATEGORIES):
            card = self._create_category_card(cat_key, cat_label, glyph, color, is_primary=False)
            row = idx // 2
            col = idx % 2
            self.more_grid.addWidget(card, row, col)
            self.category_widgets.append((cat_key, cat_label, card))

        self.cards_layout.addWidget(self.more_grid_widget)
        self.cards_layout.addStretch()

        self.scroll.setWidget(self.cards_container)
        layout.addWidget(self.scroll, stretch=1)

        # Bottom Migration / Import Footer Link
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        self.migrate_link = QPushButton("📥  Migrate or Import data into LocalVault")
        self.migrate_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.migrate_link.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                color: #38bdf8;
                font-size: 12px;
                font-weight: 500;
                padding: 4px;
            }
            QPushButton:hover {
                color: #60a5fa;
                text-decoration: underline;
            }
        """)
        self.migrate_link.clicked.connect(self._on_migrate_clicked)
        footer_layout.addWidget(self.migrate_link)
        footer_layout.addStretch()
        layout.addLayout(footer_layout)

    def _create_category_card(self, key: str, label: str, glyph: str, color: str, is_primary: bool) -> QPushButton:
        card = QPushButton()
        card.setObjectName("categoryTile")
        card.setCursor(Qt.CursorShape.PointingHandCursor)

        if is_primary:
            card.setFixedHeight(94)
            card.setStyleSheet("""
                QPushButton#categoryTile {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #172437, stop:1 #121c2c);
                    border: 1px solid #24354c;
                    border-radius: 10px;
                    padding: 8px;
                    text-align: center;
                }
                QPushButton#categoryTile:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #203149, stop:1 #162438);
                    border: 1px solid #0572ec;
                }
                QPushButton#categoryTile:pressed {
                    background: #0f1826;
                    border-color: #0461c8;
                }
            """)

            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(10, 8, 10, 8)
            c_layout.setSpacing(6)
            c_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            icon_box = QLabel(glyph)
            icon_box.setFont(QFont("Segoe UI Emoji", 24))
            icon_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_box.setStyleSheet("background: transparent;")
            icon_box.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            c_layout.addWidget(icon_box)

            text_lbl = QLabel(label)
            text_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
            text_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            text_lbl.setStyleSheet("color: #f1f5f9; background: transparent;")
            text_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            c_layout.addWidget(text_lbl)

        else:
            card.setFixedHeight(46)
            card.setStyleSheet("""
                QPushButton#categoryTile {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #152234, stop:1 #111a28);
                    border: 1px solid #213249;
                    border-radius: 8px;
                    padding: 4px 12px;
                }
                QPushButton#categoryTile:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1d2c42, stop:1 #152233);
                    border: 1px solid #0572ec;
                }
                QPushButton#categoryTile:pressed {
                    background: #0f1826;
                    border-color: #0461c8;
                }
            """)

            c_layout = QHBoxLayout(card)
            c_layout.setContentsMargins(10, 6, 10, 6)
            c_layout.setSpacing(10)

            icon_box = QLabel(glyph)
            icon_box.setFont(QFont("Segoe UI Emoji", 16))
            icon_box.setStyleSheet("background: transparent;")
            icon_box.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            c_layout.addWidget(icon_box)

            text_lbl = QLabel(label)
            text_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Medium))
            text_lbl.setStyleSheet("color: #e2e8f0; background: transparent;")
            text_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
            c_layout.addWidget(text_lbl)
            c_layout.addStretch()

        # Connect button click directly with bound key
        card.clicked.connect(lambda checked=False, k=key: self._select_category(k))
        return card

    def _toggle_more_categories(self):
        self.is_expanded = not self.is_expanded
        self.more_grid_widget.setVisible(self.is_expanded)
        self.more_toggle_btn.setText("Show less  ▴" if self.is_expanded else "More categories  ▾")

    def _on_search_changed(self, text: str):
        query = text.strip().lower()
        if query:
            self.more_grid_widget.setVisible(True)
            self.more_toggle_btn.setVisible(False)
            for _, label, card in self.category_widgets:
                card.setVisible(query in label.lower())
        else:
            self.more_grid_widget.setVisible(self.is_expanded)
            self.more_toggle_btn.setVisible(True)
            for _, _, card in self.category_widgets:
                card.setVisible(True)

    def _select_category(self, key: str):
        self.selected_category = key
        self.selected_category_id = key
        self.accept()

    def _on_migrate_clicked(self):
        self.selected_category = "__import__"
        self.selected_category_id = "__import__"
        self.accept()

    # Draggable header support for frameless window
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and not self._drag_pos.isNull():
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()
        super().mouseMoveEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)

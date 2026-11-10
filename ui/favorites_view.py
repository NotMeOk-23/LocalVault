"""
LocalVault 1Password Favorites View
Displays starred favorite items or the authentic 1Password gold star empty state.
"""

from typing import Callable, Optional, List, Any
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QListWidget,
    QListWidgetItem,
    QStackedWidget,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont

from ui.styles import get_category_icon_glyph, get_category_badge_style


class FavoritesView(QWidget):
    """
    Favorites view matching 1Password's exact Favorites dashboard.
    Shows the gold star empty state if no favorites are present, or lists favorites.
    """

    def __init__(
        self,
        parent=None,
        on_find_items: Optional[Callable[[], None]] = None,
        on_browse_callback: Optional[Callable[[], None]] = None,
    ):
        super().__init__(parent)
        self.on_find_items = on_find_items or on_browse_callback

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.stack = QStackedWidget()

        # Page 0: Empty State
        self.empty_page = self._create_empty_state()
        self.stack.addWidget(self.empty_page)

        # Page 1: Favorites List
        self.list_page = self._create_list_page()
        self.stack.addWidget(self.list_page)

        layout.addWidget(self.stack)

    def _create_empty_state(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(12)

        star = QLabel("⭐")
        star.setFont(QFont("Segoe UI Emoji", 48))
        star.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(star)

        title = QLabel("Favorites")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffffff;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        desc = QLabel("Favorite the items you use the most to make\nthem easier to find in LocalVault later.")
        desc.setFont(QFont("Segoe UI", 13))
        desc.setStyleSheet("color: #94a3b8; line-height: 20px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)

        if self.on_find_items:
            btn = QPushButton("Browse All Items")
            btn.setObjectName("primaryButton")
            btn.setFixedWidth(160)
            btn.clicked.connect(self.on_find_items)
            layout.addSpacing(8)
            layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignCenter)

        return widget

    def _create_list_page(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        title_lbl = QLabel("⭐ Favorite Items")
        title_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title_lbl.setStyleSheet("color: #ffffff;")
        layout.addWidget(title_lbl)

        self.fav_list = QListWidget()
        self.fav_list.setObjectName("itemsList")
        layout.addWidget(self.fav_list, stretch=1)

        return widget

    def set_favorite_items(self, items: List[Any]):
        if not items:
            self.stack.setCurrentIndex(0)
            return

        self.stack.setCurrentIndex(1)
        self.fav_list.clear()

        for entry in items:
            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(0, 64))
            list_item.setData(Qt.ItemDataRole.UserRole, entry)
            self.fav_list.addItem(list_item)

            card = QWidget()
            card.setStyleSheet("background: transparent; border: none;")
            c_layout = QHBoxLayout(card)
            c_layout.setContentsMargins(14, 8, 14, 8)
            c_layout.setSpacing(10)

            star = QLabel("⭐")
            star.setFont(QFont("Segoe UI Emoji", 14))
            c_layout.addWidget(star)

            title_text = getattr(entry, "title", None) or getattr(entry, "name", None) or getattr(entry, "cardholder_name", "Untitled")
            name_lbl = QLabel(title_text)
            name_lbl.setStyleSheet("font-weight: 600; font-size: 14px; color: #f8fafc;")
            c_layout.addWidget(name_lbl, stretch=1)

            cat_name = type(entry).__name__.replace("Entry", "").replace("Item", "")
            badge = QLabel(cat_name.upper())
            badge.setStyleSheet(get_category_badge_style(cat_name))
            c_layout.addWidget(badge)

            self.fav_list.setItemWidget(list_item, card)


# Backward compatibility alias
FavoritesEmptyView = FavoritesView

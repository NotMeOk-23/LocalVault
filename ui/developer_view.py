"""
LocalVault 1Password Developer Hub View
Recreates 1Password's Developer dashboard with cards for:
SSH Agent, Environments, CLI, Watchtower, and MCP Server.
"""

from typing import Callable, Optional
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
    QMessageBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

from core.models import VaultData


class DeveloperHubView(QWidget):
    """
    Developer Hub view matching 1Password's exact Developer interface.
    """

    def __init__(
        self,
        parent=None,
        on_navigate_callback: Optional[Callable[[str], None]] = None,
        vault_data: Optional[VaultData] = None,
    ):
        super().__init__(parent)
        self.on_navigate = on_navigate_callback
        self.vault_data = vault_data or VaultData()

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 28, 32, 28)
        main_layout.setSpacing(18)

        # Header Title & Subtitle
        header_col = QVBoxLayout()
        header_col.setSpacing(6)

        title = QLabel("Developer")
        title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffffff;")
        header_col.addWidget(title)

        subtitle = QLabel("Tools and integrations built to secure developer workflows. Local-only and 100% offline.")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        header_col.addWidget(subtitle)
        main_layout.addLayout(header_col)

        # 2-Column Grid of 1Password Developer Cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        grid = QGridLayout(container)
        grid.setContentsMargins(0, 8, 0, 8)
        grid.setSpacing(16)

        cards = [
            (
                "SSH Agent",
                "💻",
                "Manage your SSH keys, sign Git commits, and authorize SSH connections directly with your encrypted vault.",
                "View SSH Agent",
                lambda: self._navigate_to("ssh_keys"),
            ),
            (
                "Environments",
                "🌐",
                "Simplify secrets management across environments with Production, Staging, and Development API scopes.",
                "View Environments",
                lambda: self._navigate_to("api_keys"),
            ),
            (
                "CLI",
                "⚡",
                "Access LocalVault from the terminal with 'main.py run' to inject secrets in RAM, and 'main.py get' for references.",
                "View CLI Guide",
                self._show_cli_guide,
            ),
            (
                "Watchtower",
                "🛡️",
                "Review developer secrets, weak passwords, and expired tokens, then fix them with 1-click remediation.",
                "View Watchtower",
                lambda: self._navigate_to("audit"),
            ),
            (
                "MCP Server",
                "🤖",
                "Run a local zero-knowledge MCP server so Antigravity and AI assistants can securely access developer credentials.",
                "View MCP Server",
                self._show_mcp_guide,
            ),
        ]

        for idx, (c_title, glyph, c_desc, btn_text, action_fn) in enumerate(cards):
            card = self._create_dev_card(c_title, glyph, c_desc, btn_text, action_fn)
            r = idx // 2
            c = idx % 2
            grid.addWidget(card, r, c)

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

    def _create_dev_card(self, title: str, glyph: str, desc: str, btn_text: str, action_fn: Callable) -> QFrame:
        card = QFrame()
        card.setObjectName("inspectorCard")
        card.setMinimumHeight(140)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)

        # Title Row
        t_row = QHBoxLayout()
        icon = QLabel(glyph)
        icon.setFont(QFont("Segoe UI Emoji", 16))
        t_row.addWidget(icon)

        t_lbl = QLabel(title)
        t_lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        t_lbl.setStyleSheet("color: #f8fafc;")
        t_row.addWidget(t_lbl)
        t_row.addStretch()
        layout.addLayout(t_row)

        # Description
        desc_lbl = QLabel(desc)
        desc_lbl.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 18px;")
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)
        layout.addStretch()

        # Action Button
        btn_row = QHBoxLayout()
        btn = QPushButton(btn_text)
        btn.setObjectName("secondaryButton")
        btn.clicked.connect(action_fn)
        btn_row.addWidget(btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        return card

    def _navigate_to(self, category: str):
        if self.on_navigate:
            self.on_navigate(category)

    def _show_cli_guide(self):
        msg = (
            "LocalVault Developer CLI Commands:\n\n"
            "1. In-Memory Process Injection (No unencrypted .env on disk):\n"
            "   python main.py run --env .env.template -- npm run dev\n\n"
            "2. Extract Secret to stdout:\n"
            "   python main.py get lvault://api_keys/OpenAI/secret_key\n\n"
            "3. Extract Live Rolling 6-digit TOTP:\n"
            "   python main.py get lvault://logins/GitHub/totp_code\n\n"
            "4. Terminal Security Audit:\n"
            "   python main.py audit\n"
        )
        QMessageBox.information(self, "LocalVault CLI Integration", msg)

    def _show_mcp_guide(self):
        msg = (
            "LocalVault MCP Integration:\n\n"
            "LocalVault provides built-in Model Context Protocol tools allowing AI assistants\n"
            "to query secret references in-memory without exposing your master password.\n\n"
            "Status: Local stdio active."
        )
        QMessageBox.information(self, "LocalVault MCP Server", msg)

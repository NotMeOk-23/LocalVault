"""
LocalVault 1Password Watchtower View
Recreates 1Password's Watchtower interface with circular score dial,
overall password strength bar, and prioritized vulnerability cards.
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
    QProgressBar,
    QMessageBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPainter, QColor, QPen

from core.models import VaultData
from core.audit import run_vault_audit, AuditReport, AuditIssue


class CircularGaugeWidget(QWidget):
    """Circular progress dial matching 1Password's Watchtower score badge."""

    def __init__(self, parent=None, score: int = 988, max_score: int = 1000):
        super().__init__(parent)
        self.setFixedSize(110, 110)
        self.score = score
        self.max_score = max_score

    def set_score(self, score_0_to_100: int):
        self.score = int(score_0_to_100 * 10)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = self.width()
        height = self.height()
        radius = min(width, height) / 2 - 8
        center = self.rect().center()

        # Track background
        pen_bg = QPen(QColor("#1e293b"), 8)
        pen_bg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_bg)
        painter.drawArc(int(center.x() - radius), int(center.y() - radius), int(radius * 2), int(radius * 2), 0, 360 * 16)

        # Active progress arc
        pct = min(1.0, max(0.0, self.score / self.max_score))
        if pct >= 0.85:
            arc_color = QColor("#22c55e")  # Bright green
        elif pct >= 0.70:
            arc_color = QColor("#eab308")  # Amber
        else:
            arc_color = QColor("#ef4444")  # Red

        pen_fg = QPen(arc_color, 8)
        pen_fg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_fg)
        start_angle = 90 * 16
        span_angle = int(-pct * 360 * 16)
        painter.drawArc(int(center.x() - radius), int(center.y() - radius), int(radius * 2), int(radius * 2), start_angle, span_angle)

        # Draw Score Text
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        painter.drawText(int(center.x() - 40), int(center.y() - 14), 80, 24, Qt.AlignmentFlag.AlignCenter, str(self.score))

        rating_text = "VERY GOOD" if pct >= 0.85 else ("FAIR" if pct >= 0.70 else "AT RISK")
        painter.setPen(arc_color)
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        painter.drawText(int(center.x() - 45), int(center.y() + 8), 90, 16, Qt.AlignmentFlag.AlignCenter, rating_text)


class SecurityAuditView(QWidget):
    """
    Watchtower dashboard widget matching 1Password's exact Watchtower page.
    """

    def __init__(self, parent=None, on_select_item_callback: Optional[Callable[[str], None]] = None):
        super().__init__(parent)
        self.on_select_item = on_select_item_callback
        self.vault_data: Optional[VaultData] = None

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 24, 32, 24)
        main_layout.setSpacing(16)

        # Header Row
        header_row = QHBoxLayout()
        header_row.setSpacing(14)

        title_col = QVBoxLayout()
        title_col.setSpacing(6)

        w_title = QLabel("Watchtower")
        w_title.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        w_title.setStyleSheet("color: #ffffff;")
        title_col.addWidget(w_title)

        w_sub = QLabel("Get alerts for any security issues that affect you. Your score gives an overall idea of how safe your data is. Take action on the flagged items to level up your security.")
        w_sub.setStyleSheet("color: #94a3b8; font-size: 13px; line-height: 18px;")
        w_sub.setWordWrap(True)
        title_col.addWidget(w_sub)

        share_btn = QPushButton("↗  Share My Score")
        share_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: #38bdf8;
                font-weight: 600;
                font-size: 12px;
                text-align: left;
                padding: 0;
            }
            QPushButton:hover {
                text-decoration: underline;
                color: #7dd3fc;
            }
        """)
        share_btn.clicked.connect(self._share_score)
        title_col.addWidget(share_btn)
        header_row.addLayout(title_col, stretch=1)

        # Circular Gauge on the top right
        self.gauge = CircularGaugeWidget()
        header_row.addWidget(self.gauge)
        main_layout.addLayout(header_row)

        # Overall Password Strength Progress Bar
        str_col = QVBoxLayout()
        str_col.setSpacing(6)

        str_label = QLabel("Overall Password Strength")
        str_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        str_label.setStyleSheet("color: #f1f5f9;")
        str_col.addWidget(str_label)

        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(98)
        self.strength_bar.setFixedHeight(8)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1e293b;
                border: none;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background-color: #22c55e;
                border-radius: 4px;
            }
        """)
        str_col.addWidget(self.strength_bar)
        main_layout.addLayout(str_col)

        # Scrollable Area for Watchtower Alert Cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.issues_container = QWidget()
        self.issues_layout = QVBoxLayout(self.issues_container)
        self.issues_layout.setContentsMargins(0, 8, 0, 8)
        self.issues_layout.setSpacing(12)

        scroll.setWidget(self.issues_container)
        main_layout.addWidget(scroll)

    def set_vault_data(self, vault_data: VaultData):
        self.vault_data = vault_data
        self.refresh_audit()

    def refresh_audit(self):
        if not self.vault_data:
            return

        report: AuditReport = run_vault_audit(self.vault_data)
        self.gauge.set_score(report.score)
        self.strength_bar.setValue(report.score)

        # Clear existing cards
        while self.issues_layout.count():
            child = self.issues_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if not report.issues:
            empty_card = QFrame()
            empty_card.setObjectName("inspectorCard")
            e_layout = QVBoxLayout(empty_card)
            e_layout.setContentsMargins(20, 20, 20, 20)
            e_title = QLabel("🎉  No security issues detected!")
            e_title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
            e_title.setStyleSheet("color: #22c55e;")
            e_layout.addWidget(e_title)
            e_desc = QLabel("Your passwords, API keys, and credentials adhere to top military-grade security standards.")
            e_desc.setStyleSheet("color: #94a3b8;")
            e_layout.addWidget(e_desc)
            self.issues_layout.addWidget(empty_card)
        else:
            for idx, issue in enumerate(report.issues, 1):
                card = self._create_issue_card(idx, issue)
                self.issues_layout.addWidget(card)

        self.issues_layout.addStretch()

    def _create_issue_card(self, num: int, issue: AuditIssue) -> QFrame:
        card = QFrame()
        card.setObjectName("inspectorCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(14)

        # Number Badge (1Password Red / Amber Badge)
        badge = QLabel(str(num))
        badge.setFixedSize(30, 30)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        if issue.severity == "CRITICAL":
            badge.setStyleSheet("background-color: #e11d48; color: #ffffff; border-radius: 6px;")
        elif issue.severity == "WARNING":
            badge.setStyleSheet("background-color: #ea580c; color: #ffffff; border-radius: 6px;")
        else:
            badge.setStyleSheet("background-color: #2563eb; color: #ffffff; border-radius: 6px;")
        layout.addWidget(badge)

        # Details Column
        col = QVBoxLayout()
        col.setSpacing(4)

        t_lbl = QLabel(f"{issue.item_title} — {issue.category}")
        t_lbl.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        t_lbl.setStyleSheet("color: #ffffff;")
        col.addWidget(t_lbl)

        d_lbl = QLabel(f"{issue.description} {issue.recommendation}")
        d_lbl.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 16px;")
        d_lbl.setWordWrap(True)
        col.addWidget(d_lbl)
        layout.addLayout(col, stretch=1)

        # Action Button (1Password "Set up" / "Fix")
        btn = QPushButton("Fix Credential →" if issue.item_id else "Set up")
        btn.setObjectName("secondaryButton")
        btn.clicked.connect(lambda _, i=issue.item_id: self._trigger_fix(i))
        layout.addWidget(btn)

        return card

    def _trigger_fix(self, item_id: str):
        if self.on_select_item and item_id:
            self.on_select_item(item_id)

    def _share_score(self):
        QMessageBox.information(self, "Watchtower Score", f"Your LocalVault Watchtower Score is {self.gauge.score} / 1000.")

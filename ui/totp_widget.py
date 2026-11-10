"""
LocalVault Interactive TOTP Authenticator Widget
Visualizes live 6/8-digit Time-Based One-Time Passwords with animated countdown ring.
"""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QProgressBar,
    QFrame,
)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont

from core.totp import calculate_totp
from platform_win32.clipboard import clipboard_manager


class TOTPAuthenticatorWidget(QFrame):
    """
    Renders live rolling TOTP token with countdown timer and 1-click clipboard copy.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("cardFrame")
        self._secret = ""
        self._period = 30
        self._digits = 6
        self._algorithm = "SHA1"

        self._setup_ui()

        # 1-second update timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_token)
        self._timer.start(1000)

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        # Header
        top_layout = QHBoxLayout()
        header_label = QLabel("2FA AUTHENTICATOR CODE")
        header_label.setStyleSheet("font-size: 11px; font-weight: bold; color: #00d2ff; letter-spacing: 1px;")
        top_layout.addWidget(header_label)
        top_layout.addStretch()

        self.time_label = QLabel("30s left")
        self.time_label.setStyleSheet("font-size: 11px; color: #94a3b8; font-weight: 600;")
        top_layout.addWidget(self.time_label)
        layout.addLayout(top_layout)

        # Code row + Copy button
        code_layout = QHBoxLayout()

        self.code_label = QLabel("------")
        code_font = QFont("Consolas", 24, QFont.Weight.Bold)
        code_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 4)
        self.code_label.setFont(code_font)
        self.code_label.setStyleSheet("color: #f8fafc;")
        code_layout.addWidget(self.code_label)

        code_layout.addStretch()

        self.copy_btn = QPushButton("Copy Code")
        self.copy_btn.setObjectName("copyButton")
        self.copy_btn.clicked.connect(self._copy_code)
        code_layout.addWidget(self.copy_btn)

        layout.addLayout(code_layout)

        # Visual progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1e293b;
                border: none;
                border-radius: 2px;
            }
            QProgressBar::chunk {
                background-color: #00e676;
                border-radius: 2px;
            }
        """)
        layout.addWidget(self.progress_bar)

    def set_config(self, secret: str, period: int = 30, digits: int = 6, algorithm: str = "SHA1"):
        """Configures the secret key and refreshes immediately."""
        self._secret = secret.strip()
        self._period = period
        self._digits = digits
        self._algorithm = algorithm
        self._refresh_token()

    def _refresh_token(self):
        if not self._secret:
            self.code_label.setText("------")
            self.time_label.setText("No Secret")
            self.progress_bar.setValue(0)
            self.copy_btn.setEnabled(False)
            return

        self.copy_btn.setEnabled(True)
        try:
            code, rem_secs, ratio = calculate_totp(
                secret_base32=self._secret,
                period=self._period,
                digits=self._digits,
                algorithm=self._algorithm,
            )

            # Format with a space in the middle for readability (e.g. '123 456')
            if len(code) == 6:
                formatted_code = f"{code[:3]} {code[3:]}"
            elif len(code) == 8:
                formatted_code = f"{code[:4]} {code[4:]}"
            else:
                formatted_code = code

            self.code_label.setText(formatted_code)
            self.time_label.setText(f"{rem_secs}s left")

            pct = int((rem_secs / self._period) * 100)
            self.progress_bar.setValue(pct)

            # Dynamic color coding based on urgency
            if rem_secs > 10:
                color = "#00e676"  # Emerald green
            elif rem_secs > 5:
                color = "#ffab00"  # Amber warning
            else:
                color = "#ff1744"  # Red urgent

            self.progress_bar.setStyleSheet(f"""
                QProgressBar {{
                    background-color: #1e293b;
                    border: none;
                    border-radius: 2px;
                }}
                QProgressBar::chunk {{
                    background-color: {color};
                    border-radius: 2px;
                }}
            """)
        except Exception:
            self.code_label.setText("INVALID")
            self.time_label.setText("Error")
            self.copy_btn.setEnabled(False)

    def _copy_code(self):
        raw_code = self.code_label.text().replace(" ", "")
        if raw_code and raw_code not in ["------", "INVALID"]:
            clipboard_manager.copy_secret(raw_code, wipe_delay=30, exclude_history=True)
            self.copy_btn.setText("Copied!")
            QTimer.singleShot(2000, lambda: self.copy_btn.setText("Copy Code"))

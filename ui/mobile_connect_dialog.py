"""
LocalVault Mobile Connection & QR Code Pairing Dialog
Enables instant zero-knowledge mobile access on iPhone and Android via Wi-Fi PWA pairing.
"""

from pathlib import Path
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPixmap, QImage

import qrcode
from core.extension_bridge import get_local_ip, GLOBAL_BRIDGE


class MobileConnectDialog(QDialog):
    """
    Dialog displaying the Wi-Fi pairing QR code and instructions for mobile access.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connect LocalVault to Phone")
        self.setFixedWidth(460)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #141f31, stop:1 #0c1320);
                border: 1px solid #283e5c;
                border-radius: 12px;
            }
        """)

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header row
        header = QHBoxLayout()
        title = QLabel("📱 Connect Phone")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #f8fafc; background: transparent;")
        header.addWidget(title)
        header.addStretch()

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                color: #94a3b8;
                font-size: 14px;
                border-radius: 14px;
            }
            QPushButton:hover {
                background: #1e2a3c;
                color: #ffffff;
            }
        """)
        close_btn.clicked.connect(self.accept)
        header.addWidget(close_btn)
        layout.addLayout(header)

        # Subtitle
        sub_lbl = QLabel("Scan this QR code with your phone camera while connected to the same Wi-Fi network.")
        sub_lbl.setWordWrap(True)
        sub_lbl.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 1.4;")
        layout.addWidget(sub_lbl)

        # Generate QR Code
        local_ip = get_local_ip()
        port = GLOBAL_BRIDGE.port
        token = GLOBAL_BRIDGE.pairing_token
        url = f"http://{local_ip}:{port}/mobile?token={token}"

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="#090e17", back_color="#ffffff").convert("RGBA")

        # Convert PIL to QPixmap
        data = qr_img.tobytes("raw", "RGBA")
        qimage = QImage(data, qr_img.width, qr_img.height, QImage.Format.Format_RGBA8888)
        pixmap = QPixmap.fromImage(qimage)

        # QR Container Card
        qr_card = QFrame()
        qr_card.setStyleSheet("background: #ffffff; border-radius: 10px; padding: 10px;")
        qr_layout = QVBoxLayout(qr_card)
        qr_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        qr_lbl = QLabel()
        qr_lbl.setPixmap(pixmap)
        qr_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_layout.addWidget(qr_lbl)

        layout.addWidget(qr_card, alignment=Qt.AlignmentFlag.AlignCenter)

        # URL Box
        url_box = QFrame()
        url_box.setStyleSheet("background: #0e1624; border: 1px solid #1c2a3f; border-radius: 6px; padding: 8px 12px;")
        url_layout = QHBoxLayout(url_box)
        url_lbl = QLabel(url)
        url_lbl.setStyleSheet("color: #38bdf8; font-family: Consolas, monospace; font-size: 11px;")
        url_layout.addWidget(url_lbl)
        layout.addWidget(url_box)

        # Step-by-Step Instructions
        instr_card = QFrame()
        instr_card.setStyleSheet("background: #111a28; border: 1px solid #1c2a3f; border-radius: 8px; padding: 12px;")
        instr_layout = QVBoxLayout(instr_card)
        instr_layout.setSpacing(6)

        steps = [
            "<b>1. Scan QR Code</b> using your iPhone Camera or Android Google Lens / Chrome.",
            "<b>2. Install on Phone</b>:<br>"
            "&nbsp;&nbsp;• <b>iPhone</b>: Tap Share ➔ <i>'Add to Home Screen'</i><br>"
            "&nbsp;&nbsp;• <b>Android</b>: Tap Menu (⋮) ➔ <i>'Install App'</i>",
            "<b>3. 100% Offline Access</b>: Works anytime, anywhere. Syncs whenever on home Wi-Fi.",
        ]
        for s in steps:
            lbl = QLabel(s)
            lbl.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
            lbl.setWordWrap(True)
            instr_layout.addWidget(lbl)

        layout.addWidget(instr_card)

        # Done Button
        done_btn = QPushButton("Done")
        done_btn.setObjectName("primaryButton")
        done_btn.clicked.connect(self.accept)
        layout.addWidget(done_btn)

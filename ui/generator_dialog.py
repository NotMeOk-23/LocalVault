"""
LocalVault Interactive Generator Dialog
Generates military-grade passwords, Diceware passphrases, and API keys with real-time entropy.
"""

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QLineEdit,
    QSlider,
    QCheckBox,
    QComboBox,
    QProgressBar,
    QTabWidget,
    QWidget,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

from core.generator import (
    generate_password,
    generate_passphrase,
    generate_api_key,
    calculate_entropy,
    evaluate_password_strength,
)
from platform_win32.clipboard import clipboard_manager


class GeneratorDialog(QDialog):
    """
    Modal for generating passwords, passphrases, and API keys.
    """

    def __init__(self, parent=None, initial_mode: str = "password"):
        super().__init__(parent)
        self.setWindowTitle("Military-Grade Generator")
        self.setMinimumWidth(540)
        self.generated_result = ""

        self._setup_ui(initial_mode)
        self._regenerate()

    def _setup_ui(self, initial_mode: str):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 20, 20, 20)

        # Output Display Field
        self.output_edit = QLineEdit()
        self.output_edit.setReadOnly(True)
        out_font = QFont("Consolas", 14, QFont.Weight.Bold)
        self.output_edit.setFont(out_font)
        self.output_edit.setStyleSheet("""
            QLineEdit {
                background-color: #0b1017;
                border: 2px solid #00d2ff;
                border-radius: 8px;
                padding: 12px;
                color: #38bdf8;
            }
        """)
        layout.addWidget(self.output_edit)

        # Entropy & Strength Rating
        entropy_layout = QHBoxLayout()
        self.entropy_label = QLabel("Entropy: 0.0 bits")
        self.entropy_label.setStyleSheet("font-size: 12px; color: #94a3b8; font-weight: 600;")
        entropy_layout.addWidget(self.entropy_label)

        entropy_layout.addStretch()

        self.strength_badge = QLabel("Rating")
        self.strength_badge.setStyleSheet("""
            background-color: #064e3b;
            color: #34d399;
            border: 1px solid #059669;
            border-radius: 4px;
            padding: 2px 10px;
            font-weight: bold;
            font-size: 11px;
        """)
        entropy_layout.addWidget(self.strength_badge)
        layout.addLayout(entropy_layout)

        # Entropy Progress Bar
        self.entropy_bar = QProgressBar()
        self.entropy_bar.setRange(0, 128)
        self.entropy_bar.setFixedHeight(5)
        self.entropy_bar.setTextVisible(False)
        self.entropy_bar.setStyleSheet("""
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
        layout.addWidget(self.entropy_bar)

        # Mode Tabs
        self.tabs = QTabWidget()

        # Tab 1: Random Password
        pwd_tab = QWidget()
        pwd_layout = QVBoxLayout(pwd_tab)
        pwd_layout.setSpacing(10)

        # Length Slider
        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length:"))
        self.len_label = QLabel("24 characters")
        self.len_label.setStyleSheet("color: #00d2ff; font-weight: bold;")
        len_row.addWidget(self.len_label)
        len_row.addStretch()
        pwd_layout.addLayout(len_row)

        self.len_slider = QSlider(Qt.Orientation.Horizontal)
        self.len_slider.setRange(8, 64)
        self.len_slider.setValue(24)
        self.len_slider.valueChanged.connect(self._on_len_changed)
        pwd_layout.addWidget(self.len_slider)

        # Checkboxes
        cb_grid = QHBoxLayout()
        self.cb_upper = QCheckBox("Uppercase (A-Z)")
        self.cb_upper.setChecked(True)
        self.cb_upper.toggled.connect(self._regenerate)
        cb_grid.addWidget(self.cb_upper)

        self.cb_lower = QCheckBox("Lowercase (a-z)")
        self.cb_lower.setChecked(True)
        self.cb_lower.toggled.connect(self._regenerate)
        cb_grid.addWidget(self.cb_lower)

        self.cb_digits = QCheckBox("Numbers (0-9)")
        self.cb_digits.setChecked(True)
        self.cb_digits.toggled.connect(self._regenerate)
        cb_grid.addWidget(self.cb_digits)
        pwd_layout.addLayout(cb_grid)

        cb_grid2 = QHBoxLayout()
        self.cb_symbols = QCheckBox("Symbols (!@#$)")
        self.cb_symbols.setChecked(True)
        self.cb_symbols.toggled.connect(self._regenerate)
        cb_grid2.addWidget(self.cb_symbols)

        self.cb_avoid_ambig = QCheckBox("Avoid Ambiguous (1, l, 0, O)")
        self.cb_avoid_ambig.setChecked(True)
        self.cb_avoid_ambig.toggled.connect(self._regenerate)
        cb_grid2.addWidget(self.cb_avoid_ambig)
        pwd_layout.addLayout(cb_grid2)

        self.tabs.addTab(pwd_tab, "Password")

        # Tab 2: Diceware Passphrase
        phrase_tab = QWidget()
        phrase_layout = QVBoxLayout(phrase_tab)
        phrase_layout.setSpacing(10)

        words_row = QHBoxLayout()
        words_row.addWidget(QLabel("Word Count:"))
        self.words_label = QLabel("5 words")
        self.words_label.setStyleSheet("color: #00d2ff; font-weight: bold;")
        words_row.addWidget(self.words_label)
        words_row.addStretch()
        phrase_layout.addLayout(words_row)

        self.words_slider = QSlider(Qt.Orientation.Horizontal)
        self.words_slider.setRange(3, 8)
        self.words_slider.setValue(5)
        self.words_slider.valueChanged.connect(self._on_words_changed)
        phrase_layout.addWidget(self.words_slider)

        opt_row = QHBoxLayout()
        opt_row.addWidget(QLabel("Separator:"))
        self.sep_combo = QComboBox()
        self.sep_combo.addItems(["- (Hyphen)", "_ (Underscore)", ". (Period)", "  (Space)"])
        self.sep_combo.currentIndexChanged.connect(self._regenerate)
        opt_row.addWidget(self.sep_combo)

        self.cb_cap = QCheckBox("Capitalize Words")
        self.cb_cap.setChecked(True)
        self.cb_cap.toggled.connect(self._regenerate)
        opt_row.addWidget(self.cb_cap)
        phrase_layout.addLayout(opt_row)

        self.tabs.addTab(phrase_tab, "Diceware Passphrase")

        # Tab 3: API Key Token
        api_tab = QWidget()
        api_layout = QVBoxLayout(api_tab)
        api_layout.setSpacing(10)

        prefix_row = QHBoxLayout()
        prefix_row.addWidget(QLabel("Prefix Template:"))
        self.prefix_combo = QComboBox()
        self.prefix_combo.addItems([
            "sk_live_ (Stripe / OpenAI Secret)",
            "pk_live_ (Public / Client ID)",
            "ghp_ (GitHub Personal Token)",
            "ak_ (Cloud Access Key)",
            "sec_ (Generic Secret)",
            "None",
        ])
        self.prefix_combo.currentIndexChanged.connect(self._regenerate)
        prefix_row.addWidget(self.prefix_combo)
        api_layout.addLayout(prefix_row)

        format_row = QHBoxLayout()
        format_row.addWidget(QLabel("Encoding:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Hexadecimal (32/64 chars)", "Base64 URL-Safe", "Alphanumeric"])
        self.format_combo.currentIndexChanged.connect(self._regenerate)
        format_row.addWidget(self.format_combo)
        api_layout.addLayout(format_row)

        self.tabs.addTab(api_tab, "API Key Token")

        # Connect tab switch to regenerate
        self.tabs.currentChanged.connect(self._regenerate)
        if initial_mode == "api":
            self.tabs.setCurrentIndex(2)
        elif initial_mode == "passphrase":
            self.tabs.setCurrentIndex(1)
        else:
            self.tabs.setCurrentIndex(0)

        layout.addWidget(self.tabs)

        # Bottom Action Buttons
        btn_layout = QHBoxLayout()

        self.regen_btn = QPushButton("↻ Regenerate")
        self.regen_btn.clicked.connect(self._regenerate)
        btn_layout.addWidget(self.regen_btn)

        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.setObjectName("copyButton")
        self.copy_btn.clicked.connect(self._copy_result)
        btn_layout.addWidget(self.copy_btn)

        btn_layout.addStretch()

        self.use_btn = QPushButton("Use This Value")
        self.use_btn.setObjectName("primaryButton")
        self.use_btn.clicked.connect(self._use_result)
        btn_layout.addWidget(self.use_btn)

        layout.addLayout(btn_layout)

    def _on_len_changed(self, val: int):
        self.len_label.setText(f"{val} characters")
        self._regenerate()

    def _on_words_changed(self, val: int):
        self.words_label.setText(f"{val} words")
        self._regenerate()

    def _regenerate(self):
        tab_idx = self.tabs.currentIndex()

        if tab_idx == 0:  # Password
            length = self.len_slider.value()
            val = generate_password(
                length=length,
                use_upper=self.cb_upper.isChecked(),
                use_lower=self.cb_lower.isChecked(),
                use_digits=self.cb_digits.isChecked(),
                use_special=self.cb_symbols.isChecked(),
                avoid_ambiguous=self.cb_avoid_ambig.isChecked(),
            )
        elif tab_idx == 1:  # Passphrase
            num_words = self.words_slider.value()
            sep_choice = self.sep_combo.currentText()[0]
            val = generate_passphrase(
                num_words=num_words,
                separator=sep_choice,
                capitalize=self.cb_cap.isChecked(),
            )
        else:  # API Key
            prefix_text = self.prefix_combo.currentText().split(" ")[0]
            if prefix_text == "None":
                prefix_text = ""
            fmt_text = self.format_combo.currentText()
            mode = "hex" if "Hex" in fmt_text else ("base64" if "Base64" in fmt_text else "alphanumeric")
            val = generate_api_key(prefix=prefix_text, length=32, mode=mode)

        self.generated_result = val
        self.output_edit.setText(val)

        # Update entropy and rule-based strength
        bits, rating, score_pct, hint = evaluate_password_strength(val)
        self.entropy_label.setText(f"Entropy: {bits} bits ({score_pct}%)")
        self.strength_badge.setText(rating)
        self.entropy_bar.setValue(score_pct)

        # Badge styling based on rating
        if rating == "Military-Grade":
            style = "background-color: #064e3b; color: #34d399; border: 1px solid #059669; border-radius: 4px; padding: 2px 10px; font-weight: bold; font-size: 11px;"
        elif rating == "Strong":
            style = "background-color: #1e3a5f; color: #38bdf8; border: 1px solid #0284c7; border-radius: 4px; padding: 2px 10px; font-weight: bold; font-size: 11px;"
        elif rating == "Moderate":
            style = "background-color: #451a03; color: #fbbf24; border: 1px solid #d97706; border-radius: 4px; padding: 2px 10px; font-weight: bold; font-size: 11px;"
        else:
            style = "background-color: #450a0a; color: #f87171; border: 1px solid #b91c1c; border-radius: 4px; padding: 2px 10px; font-weight: bold; font-size: 11px;"
        self.strength_badge.setStyleSheet(style)

    def _copy_result(self):
        if self.generated_result:
            clipboard_manager.copy_secret(self.generated_result, wipe_delay=30, exclude_history=True)
            self.copy_btn.setText("Copied!")
            QTimer.singleShot(2000, lambda: self.copy_btn.setText("Copy to Clipboard"))

    def _use_result(self):
        self.accept()

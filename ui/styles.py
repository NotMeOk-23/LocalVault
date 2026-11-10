"""
LocalVault 1Password Knox Dark Theme
Pixel-accurate recreation of 1Password's Knox design system for Windows:
layered navy-black depth, refined 1px borders, signature Knox blue (#0572ec),
custom pill badges, and clean three-pane desktop ergonomics.
"""

DARK_THEME_QSS = """
/* Global Reset and Typography - NEVER set global background-color on QWidget to preserve container gradients */
QWidget {
    color: #e2e8f0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
    selection-background-color: #0572ec;
    selection-color: #ffffff;
}

/* Main Window Canvas */
QMainWindow {
    background-color: #090e17;
}

/* Splitter dividers */
QSplitter::handle {
    background-color: #162030;
}
QSplitter::handle:horizontal {
    width: 1px;
}
QSplitter::handle:vertical {
    height: 1px;
}

/* Top Header Bar */
QFrame#topHeaderBar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #121c2c, stop:1 #0c1421);
    border-bottom: 1px solid #182537;
    padding: 6px 14px;
}

/* App Logo Dropdown Button */
QToolButton#appMenuButton {
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 10px;
    color: #f8fafc;
    font-weight: 700;
    font-size: 14px;
}
QToolButton#appMenuButton:hover {
    background-color: #172437;
    border-color: #23364f;
}
QToolButton#appMenuButton:pressed {
    background-color: #101b2a;
}

/* Nav History Buttons (< >) & Help (?) */
QPushButton#navArrowBtn {
    background-color: #131c2a;
    border: 1px solid #1e2c3e;
    border-radius: 6px;
    color: #94a3b8;
    font-size: 13px;
    font-weight: bold;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
QPushButton#navArrowBtn:hover {
    background-color: #1a273b;
    border-color: #2e435d;
    color: #f1f5f9;
}
QPushButton#navArrowBtn:disabled {
    background-color: transparent;
    border: 1px solid transparent;
    color: #334155;
}

/* 1Password Knox Pill Search Bar */
QLineEdit#searchPillEdit {
    background-color: #141f2f;
    border: 1px solid #22344c;
    border-radius: 17px;
    padding: 0 16px;
    color: #f8fafc;
    font-size: 13px;
    min-height: 34px;
    max-height: 34px;
}
QLineEdit#searchPillEdit:hover {
    background-color: #172438;
    border-color: #2e4463;
}
QLineEdit#searchPillEdit:focus {
    background-color: #19273c;
    border: 1px solid #0572ec;
}

/* Primary Action Button (+ New Item) */
QPushButton#primaryButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0a7aff, stop:1 #0572ec);
    border: 1px solid #2086fc;
    border-radius: 6px;
    color: #ffffff;
    font-weight: 600;
    font-size: 13px;
    padding: 6px 16px;
    min-height: 22px;
}
QPushButton#primaryButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a88ff, stop:1 #0774ed);
    border-color: #4098ff;
}
QPushButton#primaryButton:pressed {
    background-color: #034e9f;
    border-color: #034e9f;
}

/* Secondary Button */
QPushButton#secondaryButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #162234, stop:1 #111a28);
    border: 1px solid #23344d;
    border-radius: 6px;
    color: #cbd5e1;
    font-weight: 500;
    font-size: 12px;
    padding: 5px 12px;
}
QPushButton#secondaryButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1c2b40, stop:1 #152233);
    border-color: #2f4463;
    color: #ffffff;
}
QPushButton#secondaryButton:pressed {
    background-color: #0d1522;
}

/* Sort Button */
QPushButton#sortButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #162234, stop:1 #111a28);
    border: 1px solid #23344d;
    border-radius: 6px;
    color: #cbd5e1;
    font-weight: 600;
    font-size: 12px;
    padding: 3px 6px;
    min-width: 48px;
    max-width: 56px;
    min-height: 26px;
    max-height: 28px;
    text-align: center;
}
QPushButton#sortButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1c2b40, stop:1 #152233);
    border-color: #2f4463;
    color: #ffffff;
}
QPushButton#sortButton:pressed {
    background-color: #0f4c81;
    border-color: #0572ec;
}

/* Left Navigation Sidebar */
QFrame#sidebarPane {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #090e17, stop:1 #0b111c);
    border-right: 1px solid #162030;
}

/* Account Profile Pill */
QFrame#accountPill {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #152234, stop:1 #101928);
    border: 1px solid #203148;
    border-radius: 8px;
    padding: 8px 10px;
}
QFrame#accountPill:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1b2b40, stop:1 #132032);
    border-color: #2b415e;
}

/* Sidebar List Widget */
QListWidget#sidebarList {
    background-color: transparent;
    border: none;
    padding: 6px 4px;
    outline: none;
}
QListWidget#sidebarList::item {
    height: 34px;
    border-radius: 6px;
    padding-left: 10px;
    margin-bottom: 2px;
    color: #94a3b8;
    font-weight: 500;
    font-size: 13px;
}
QListWidget#sidebarList::item:hover {
    background-color: rgba(255, 255, 255, 0.04);
    color: #f1f5f9;
}
QListWidget#sidebarList::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0f4c81, stop:1 #093c66);
    color: #ffffff;
    font-weight: 600;
    border-left: 3px solid #38bdf8;
    border-radius: 4px;
}

/* Section Header Labels in Sidebar */
QLabel#sidebarSectionHeader {
    color: #64748b;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.8px;
    padding-left: 10px;
    margin-top: 14px;
    margin-bottom: 4px;
    background: transparent;
}

/* Middle Items List Pane */
QFrame#itemsPane {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0d1421, stop:1 #0f1725);
    border-right: 1px solid #162030;
}

/* Filter & Sort Toolbar */
QFrame#itemsToolbar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #111a28, stop:1 #0e1623);
    border-bottom: 1px solid #162030;
    padding: 8px 12px;
}

QComboBox#categoryFilterCombo {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #162234, stop:1 #111a28);
    border: 1px solid #23344d;
    border-radius: 6px;
    padding: 4px 10px;
    color: #f1f5f9;
    font-size: 12px;
    font-weight: 600;
    min-height: 24px;
}
QComboBox#categoryFilterCombo:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1c2b40, stop:1 #152233);
    border-color: #2f4463;
}
QComboBox#categoryFilterCombo QAbstractItemView {
    background-color: #131d2c;
    border: 1px solid #23344d;
    selection-background-color: #0f4c81;
    selection-color: #ffffff;
    color: #f1f5f9;
    padding: 4px;
}

/* Items QListWidget */
QListWidget#itemsList {
    background-color: transparent;
    border: none;
    padding: 8px;
    outline: none;
}
QListWidget#itemsList::item {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #152132, stop:1 #111927);
    border: 1px solid #1c2a3f;
    border-radius: 8px;
    margin-bottom: 6px;
    padding: 0px;
}
QListWidget#itemsList::item:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1b2b40, stop:1 #142031);
    border-color: #283e5c;
}
QListWidget#itemsList::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0e487b, stop:1 #09365c);
    border: 1px solid #38bdf8;
}

/* Detail / Inspector Pane */
QFrame#inspectorPane {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #090e17, stop:1 #060a10);
}

/* Cards & Frames inside Inspector */
QFrame#inspectorCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #131e2e, stop:1 #0f1725);
    border: 1px solid #1d2c42;
    border-radius: 10px;
    padding: 16px;
}

/* Field Group Box */
QFrame#fieldCard {
    background-color: #0d1522;
    border: 1px solid #19273b;
    border-radius: 8px;
    padding: 10px 14px;
}

/* Input Fields */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background-color: #121c2b;
    border: 1px solid #203148;
    border-radius: 6px;
    padding: 7px 10px;
    color: #f8fafc;
    font-size: 13px;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #0572ec;
    background-color: #162438;
}
QLineEdit[readOnly="true"] {
    background-color: #0c1421;
    border: 1px solid #182639;
    color: #94a3b8;
}

/* Buttons Default */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #162234, stop:1 #111a28);
    border: 1px solid #23344d;
    border-radius: 6px;
    padding: 6px 14px;
    color: #f1f5f9;
    font-weight: 500;
}
QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1c2b40, stop:1 #152233);
    border-color: #2f4463;
}
QPushButton:pressed {
    background-color: #0f1724;
}
QPushButton:disabled, QPushButton:disabled:hover {
    background-color: #101622;
    border: 1px solid #162030;
    color: #475569;
}

/* Action Utility Buttons (Copy, Ref, Open) */
QPushButton#actionPillBtn {
    background-color: #142031;
    border: 1px solid #21334c;
    border-radius: 4px;
    color: #38bdf8;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 8px;
}
QPushButton#actionPillBtn:hover {
    background-color: #1b2c44;
    border-color: #0572ec;
    color: #ffffff;
}

QPushButton#dangerButton {
    background-color: #3c1216;
    border: 1px solid #6b181d;
    border-radius: 6px;
    color: #fca5a5;
    font-weight: 600;
}
QPushButton#dangerButton:hover {
    background-color: #6b181d;
    border-color: #991b1b;
    color: #ffffff;
}

/* Status Bar */
QStatusBar {
    background-color: #070b12;
    border-top: 1px solid #141c2a;
    color: #64748b;
    font-size: 11px;
    padding: 3px 10px;
}

/* Scrollbars - Sleek Knox Minimal */
QScrollBar:vertical {
    background: transparent;
    width: 6px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #23334c;
    min-height: 24px;
    border-radius: 3px;
}
QScrollBar::handle:vertical:hover {
    background: #364e75;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Modal Dialogs */
QDialog {
    background-color: #0d1420;
}

/* Tooltips */
QToolTip {
    background-color: #152132;
    border: 1px solid #283c58;
    color: #f8fafc;
    padding: 5px 9px;
    border-radius: 4px;
    font-size: 11px;
}
"""


def get_category_color(cat: str) -> str:
    """Returns the authentic 1Password Knox icon color for each category."""
    c = cat.lower().replace(" ", "_")
    if "login" in c or "account" in c:
        return "#0572ec"  # 1Password blue
    elif "credit" in c or "card" in c or "payment" in c:
        return "#2563eb"  # Royal blue
    elif "note" in c:
        return "#d97706"  # Amber
    elif "identity" in c:
        return "#16a34a"  # Green
    elif "api" in c or "token" in c:
        return "#0891b2"  # Cyan / Teal
    elif "ssh" in c or "terminal" in c:
        return "#475569"  # Slate dark
    elif "bank" in c:
        return "#059669"  # Emerald
    elif "crypto" in c or "wallet" in c:
        return "#ea580c"  # Orange
    elif "db" in c or "database" in c:
        return "#9333ea"  # Purple
    elif "server" in c:
        return "#4f46e5"  # Indigo
    elif "software" in c or "license" in c:
        return "#ca8a04"  # Gold
    elif "doc" in c or "file" in c:
        return "#64748b"  # Grey
    elif "password" in c:
        return "#3b82f6"  # Blue
    return "#0572ec"


def get_category_icon_glyph(cat: str) -> str:
    """Returns representative unicode glyph for each 1Password category."""
    c = cat.lower().replace(" ", "_")
    if "login" in c or "account" in c:
        return "🔑"
    elif "credit" in c or "card" in c:
        return "💳"
    elif "note" in c:
        return "📝"
    elif "identity" in c:
        return "🪪"
    elif "api" in c:
        return "⚡"
    elif "ssh" in c:
        return "💻"
    elif "bank" in c:
        return "🏦"
    elif "crypto" in c or "wallet" in c:
        return "🪙"
    elif "database" in c or "db" in c:
        return "🗄️"
    elif "server" in c:
        return "🖥️"
    elif "software" in c or "license" in c:
        return "📜"
    elif "document" in c:
        return "📄"
    elif "password" in c:
        return "🔒"
    return "🔑"


def get_category_badge_style(cat: str) -> str:
    """Returns subtle flat pill tag styling with no heavy borders."""
    color = get_category_color(cat)
    return f"background-color: {color}22; color: {color}; border: none; border-radius: 4px; padding: 2px 7px; font-weight: 600; font-size: 10px;"


def get_environment_badge_style(env: str) -> str:
    e = env.lower()
    if "prod" in e:
        return "background-color: #3b1114; color: #f87171; border: none; border-radius: 4px; padding: 2px 6px; font-weight: 600; font-size: 10px;"
    elif "stag" in e:
        return "background-color: #382109; color: #fbbf24; border: none; border-radius: 4px; padding: 2px 6px; font-weight: 600; font-size: 10px;"
    elif "test" in e:
        return "background-color: #1f1b3d; color: #a78bfa; border: none; border-radius: 4px; padding: 2px 6px; font-weight: 600; font-size: 10px;"
    else:  # Development
        return "background-color: #0d2e23; color: #34d399; border: none; border-radius: 4px; padding: 2px 6px; font-weight: 600; font-size: 10px;"

"""
LocalVault - Military-Grade 100% Offline Key and Password Manager
Unified GUI and Developer CLI Entrypoint.
"""

import os
import sys
import getpass
import argparse
import subprocess
from pathlib import Path

from core.storage import load_vault
from core.references import resolve_reference, inject_env
from core.audit import run_vault_audit

# Ensure standard streams use UTF-8 on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_active_window = None


def run_gui(vault_path: Path):
    """Launches the PySide6 Desktop GUI Application."""
    # Ensure the background tray & extension service is running detached
    try:
        import win32com.client
        sh = win32com.client.Dispatch("WScript.Shell")
        vbs_launcher = Path(__file__).parent / "start_service.vbs"
        if vbs_launcher.exists():
            sh.Run(f'wscript.exe "{vbs_launcher}"', 0, False)
    except Exception:
        pass

    from PySide6.QtWidgets import QApplication
    from ui.styles import DARK_THEME_QSS
    from ui.unlock_dialog import UnlockDialog
    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("LocalVault")
    app.setOrganizationName("LocalVault")
    app.setStyleSheet(DARK_THEME_QSS)

    unlock_dlg = UnlockDialog(vault_path=str(vault_path))
    if unlock_dlg.exec() and unlock_dlg.unlocked_data:
        global _active_window
        _active_window = MainWindow(
            vault_data=unlock_dlg.unlocked_data,
            master_password=unlock_dlg.master_password,
            vault_path=unlock_dlg.vault_path,
        )
        _active_window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)


def prompt_master_password() -> str:
    """Gets the master password from environment variable or secure CLI prompt."""
    env_pwd = os.environ.get("LVAULT_PASSWORD")
    if env_pwd:
        return env_pwd
    return getpass.getpass("Enter LocalVault Master Password: ")


def cli_run_command(vault_path: Path, env_template_path: str, command_args: list):
    """Resolves secret references in an env template and injects them into child process memory."""
    if not Path(env_template_path).exists():
        print(f"[!] Error: Environment template '{env_template_path}' not found.", file=sys.stderr)
        sys.exit(1)

    password = prompt_master_password()
    try:
        vault = load_vault(str(vault_path), password)
    except Exception as e:
        print(f"[!] Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)

    with open(env_template_path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        injected_env = inject_env(content, vault)
    except Exception as e:
        print(f"[!] Secret reference resolution error: {e}", file=sys.stderr)
        sys.exit(1)

    child_env = os.environ.copy()
    child_env.update(injected_env)

    cmd_str = " ".join(command_args)
    print(f"[*] Injected {len(injected_env)} secret reference(s). Executing: {cmd_str}", file=sys.stderr)

    try:
        result = subprocess.run(command_args, env=child_env, shell=True)
        sys.exit(result.returncode)
    except Exception as e:
        print(f"[!] Execution failed: {e}", file=sys.stderr)
        sys.exit(1)


def cli_get_secret(vault_path: Path, reference_uri: str):
    """Resolves a single secret reference or live TOTP code to stdout."""
    password = prompt_master_password()
    try:
        vault = load_vault(str(vault_path), password)
        val = resolve_reference(reference_uri, vault)
        print(val)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


def cli_audit_vault(vault_path: Path):
    """Executes a terminal security audit on the vault."""
    password = prompt_master_password()
    try:
        vault = load_vault(str(vault_path), password)
        report = run_vault_audit(vault)

        print("\n" + "=" * 60)
        print(f"[*] LOCALVAULT SECURITY AUDIT (WATCHTOWER)")
        print("=" * 60)
        print(f"Overall Health Score:  {report.score} / 100")
        print(f"Security Grade:        {report.grade}")
        print(f"Total Items Scanned:   {report.total_items_scanned}")
        print("-" * 60)
        print(f"Weak Passwords:        {report.weak_passwords_count}")
        print(f"Reused Passwords:      {report.reused_passwords_count}")
        print(f"Missing 2FA Seeds:     {report.missing_2fa_count}")
        print(f"Expired / Stale Keys:  {report.expired_keys_count + report.stale_keys_count}")
        print("-" * 60)

        if not report.issues:
            print("[+] No security issues detected. Your vault adheres to top security standards!")
        else:
            print("[!] Flagged Issues & Recommendations:")
            for idx, issue in enumerate(report.issues, 1):
                print(f"\n{idx}. [{issue.severity}] {issue.category}: {issue.item_title}")
                print(f"    Issue: {issue.description}")
                print(f"    Action: {issue.recommendation}")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    default_vault_path = Path("vault.lvault").resolve()

    # If no CLI arguments provided at all, directly launch GUI with default vault
    if len(sys.argv) == 1:
        run_gui(default_vault_path)
        return

    parser = argparse.ArgumentParser(
        description="LocalVault Developer CLI - 100% Offline Secret Injection and Management"
    )
    parser.add_argument("--vault", default=str(default_vault_path), help="Path to .lvault database file")
    subparsers = parser.add_subparsers(dest="subcommand")

    # Subcommand: run
    run_parser = subparsers.add_parser(
        "run",
        help="Inject secret references from an env template directly into a process without writing files",
    )
    run_parser.add_argument("--env", required=True, help="Path to .env or .env.template file")
    run_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (e.g. -- python app.py)")

    # Subcommand: get
    get_parser = subparsers.add_parser(
        "get",
        help="Resolve a single secret reference (lvault://...) or live TOTP code to stdout",
    )
    get_parser.add_argument("uri", help="Secret reference URI (e.g. lvault://api_keys/OpenAI/secret_key)")

    # Subcommand: audit
    subparsers.add_parser("audit", help="Run a security health audit (Watchtower) in terminal")

    args = parser.parse_args()
    v_path = Path(args.vault).resolve()

    if args.subcommand == "run":
        cmd_args = args.cmd
        if cmd_args and cmd_args[0] == "--":
            cmd_args = cmd_args[1:]
        if not cmd_args:
            print("[!] Error: No command specified to run.", file=sys.stderr)
            sys.exit(1)
        cli_run_command(v_path, args.env, cmd_args)

    elif args.subcommand == "get":
        cli_get_secret(v_path, args.uri)

    elif args.subcommand == "audit":
        cli_audit_vault(v_path)

    else:
        # e.g., python main.py --vault other.lvault (no subcommand specified)
        run_gui(v_path)


if __name__ == "__main__":
    main()

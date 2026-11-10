"""
LocalVault Secret References Engine (lvault:// URI Scheme)
Resolves secret references dynamically into process memory without writing plaintext credentials to disk.
Supports direct field extraction and on-the-fly RFC 6238 TOTP code generation.
"""

import re
import urllib.parse
from typing import Dict, Any, Optional

from core.models import VaultData, APIKeyEntry, LoginEntry, SSHEntry, SecureNoteEntry
from core.totp import calculate_totp

REFERENCE_PATTERN = re.compile(r"lvault://([a-zA-Z0-9_\-]+)/([^/]+)/([a-zA-Z0-9_\-]+)")


def format_reference(category: str, item_name: str, field_name: str) -> str:
    """Creates a canonical lvault:// reference URI."""
    cat_clean = category.lower().replace(" ", "_")
    return f"lvault://{cat_clean}/{item_name}/{field_name}"


def normalize_category(category_raw: str) -> str:
    c = category_raw.lower().strip()
    if c in ["api", "api_key", "api_keys", "apikeys"]:
        return "api_keys"
    elif c in ["login", "logins", "password", "passwords"]:
        return "logins"
    elif c in ["ssh", "ssh_key", "ssh_keys", "sshkeys", "server", "servers"]:
        return "ssh_keys"
    elif c in ["note", "notes", "secure_note", "secure_notes"]:
        return "secure_notes"
    return c


def resolve_reference(reference_uri: str, vault_data: VaultData) -> str:
    """
    Resolves an lvault://<category>/<item_name_or_id>/<field> URI from decrypted VaultData.
    Raises ValueError if reference cannot be parsed or item/field is not found.
    """
    match = REFERENCE_PATTERN.match(reference_uri.strip())
    if not match:
        raise ValueError(
            f"Invalid secret reference format: '{reference_uri}'. "
            "Expected: lvault://<category>/<item_name_or_id>/<field_name>"
        )

    cat_raw, item_identifier, field_name = match.groups()
    cat = normalize_category(cat_raw)
    field_lower = field_name.lower().strip()

    # Search items in the target category
    target_item = None
    if cat == "api_keys":
        for item in vault_data.api_keys:
            if item.id == item_identifier or item.name.lower() == item_identifier.lower():
                target_item = item
                break
    elif cat == "logins":
        for item in vault_data.logins:
            if item.id == item_identifier or item.title.lower() == item_identifier.lower():
                target_item = item
                break
    elif cat == "ssh_keys":
        for item in vault_data.ssh_keys:
            if item.id == item_identifier or item.name.lower() == item_identifier.lower():
                target_item = item
                break
    elif cat == "secure_notes":
        for item in vault_data.secure_notes:
            if item.id == item_identifier or item.title.lower() == item_identifier.lower():
                target_item = item
                break
    else:
        raise ValueError(f"Unknown category '{cat_raw}' in reference: '{reference_uri}'")

    if not target_item:
        raise ValueError(f"Item '{item_identifier}' not found in category '{cat}'")

    # Dynamic TOTP code generation support
    if field_lower in ["totp", "totp_code", "otp", "2fa"]:
        if isinstance(target_item, LoginEntry) and target_item.totp_secret:
            code, _, _ = calculate_totp(
                secret_base32=target_item.totp_secret,
                period=target_item.totp_period,
                digits=target_item.totp_digits,
                algorithm=target_item.totp_algorithm,
            )
            return code
        else:
            raise ValueError(f"Item '{item_identifier}' does not have a configured TOTP secret")

    # Indexed URL / Site lookup (e.g. url_1, url_2, site_1)
    url_indexed = re.match(r"^(?:url|site|website)_(\d+)$", field_lower)
    if url_indexed and isinstance(target_item, LoginEntry) and target_item.urls:
        idx = int(url_indexed.group(1)) - 1
        if 0 <= idx < len(target_item.urls):
            return target_item.urls[idx]
        raise ValueError(f"Site index {idx + 1} out of range for item '{item_identifier}' (has {len(target_item.urls)} site(s))")

    # URL / Site aliases
    if field_lower in ["url", "site", "website"]:
        if isinstance(target_item, LoginEntry) and target_item.urls:
            return target_item.urls[0]
        elif hasattr(target_item, "base_url") and getattr(target_item, "base_url"):
            return str(getattr(target_item, "base_url"))
        return ""

    if field_lower in ["urls", "sites", "websites"]:
        if isinstance(target_item, LoginEntry) and target_item.urls:
            return ", ".join(target_item.urls)
        elif hasattr(target_item, "base_url") and getattr(target_item, "base_url"):
            return str(getattr(target_item, "base_url"))
        return ""

    # Standard field lookup
    if hasattr(target_item, field_lower):
        val = getattr(target_item, field_lower)
        if isinstance(val, (list, dict)):
            import json
            return json.dumps(val)
        return str(val)

    # Aliases
    aliases = {
        "key": "secret_key",
        "secret": "secret_key",
        "token": "secret_key",
        "client_id": "key_id",
        "public_key": "key_id",
        "user": "username",
        "email": "username",
        "pass": "password",
        "pwd": "password",
        "note": "notes",
        "host": "hostname",
        "private": "private_key",
    }
    if field_lower in aliases:
        alias_attr = aliases[field_lower]
        if hasattr(target_item, alias_attr):
            return str(getattr(target_item, alias_attr))

    raise ValueError(f"Field '{field_name}' not found on item '{item_identifier}'")


def inject_env(template_content: str, vault_data: VaultData) -> Dict[str, str]:
    """
    Parses a .env template containing key=value pairs or lvault:// references
    and returns a dictionary of resolved environment variables ready for subprocess injection.
    """
    resolved_env = {}

    for line in template_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip("'\"")

        # Check if value contains an lvault reference
        def _replace_match(m):
            ref = m.group(0)
            return resolve_reference(ref, vault_data)

        resolved_val = REFERENCE_PATTERN.sub(_replace_match, val)
        resolved_env[key] = resolved_val

    return resolved_env

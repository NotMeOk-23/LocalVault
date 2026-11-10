"""
LocalVault Authenticator Engine (RFC 6238 / RFC 4226)
Generates and verifies Time-Based One-Time Passwords (TOTP) without external network calls.
Fully compatible with Google Authenticator, Authy, Microsoft Authenticator, and Aegis.
"""

import hmac
import hashlib
import time
import base64
import struct
import re
import urllib.parse
from typing import Tuple, Optional


def normalize_secret(secret_str: str) -> str:
    """Removes spaces, hyphens, and converts to uppercase for standard Base32 parsing."""
    return re.sub(r"[\s\-]+", "", secret_str).upper()


def generate_totp_secret(num_bytes: int = 20) -> str:
    """Generates a cryptographically secure random Base32 secret key (160-bit standard)."""
    import os
    random_bytes = os.urandom(num_bytes)
    return base64.b32encode(random_bytes).decode("utf-8").rstrip("=")


def parse_otpauth_uri(uri: str) -> dict:
    """
    Parses an otpauth://totp/ URI string extracted from QR codes or exported configs.
    Example: otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub
    """
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError("Not a valid otpauth URI scheme")

    query_params = urllib.parse.parse_qs(parsed.query)
    secret = query_params.get("secret", [""])[0]
    issuer = query_params.get("issuer", [""])[0]
    digits = int(query_params.get("digits", [6])[0])
    period = int(query_params.get("period", [30])[0])
    algorithm = query_params.get("algorithm", ["SHA1"])[0].upper()

    # Label extraction
    label = urllib.parse.unquote(parsed.path.lstrip("/"))

    return {
        "secret": normalize_secret(secret),
        "label": label,
        "issuer": issuer,
        "digits": digits,
        "period": period,
        "algorithm": algorithm,
    }


def get_hash_func(algorithm: str):
    algo = algorithm.upper()
    if algo == "SHA256":
        return hashlib.sha256
    elif algo == "SHA512":
        return hashlib.sha512
    return hashlib.sha1


def calculate_totp(
    secret_base32: str,
    for_time: Optional[float] = None,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> Tuple[str, int, float]:
    """
    Calculates the TOTP code for the given secret at a specific timestamp (default: now).
    
    Returns:
        (code_string, seconds_remaining, progress_ratio_0_to_1)
    """
    clean_secret = normalize_secret(secret_base32)
    # Add Base32 padding if missing
    missing_padding = len(clean_secret) % 8
    if missing_padding != 0:
        clean_secret += "=" * (8 - missing_padding)

    try:
        key = base64.b32decode(clean_secret, casefold=True)
    except Exception as e:
        raise ValueError(f"Invalid Base32 secret key: {e}")

    current_t = time.time() if for_time is None else for_time
    counter = int(current_t // period)
    time_into_step = int(current_t % period)
    seconds_remaining = period - time_into_step
    progress_ratio = (period - seconds_remaining) / period

    # Pack counter as 8-byte big-endian integer (RFC 4226)
    counter_bytes = struct.pack(">Q", counter)

    hash_func = get_hash_func(algorithm)
    hmac_digest = hmac.new(key, counter_bytes, hash_func).digest()

    # Dynamic truncation
    offset = hmac_digest[-1] & 0x0F
    code_int = struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code_mod = code_int % (10 ** digits)

    formatted_code = str(code_mod).zfill(digits)
    return formatted_code, seconds_remaining, progress_ratio


def verify_totp(
    token: str,
    secret_base32: str,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    allowed_drift_steps: int = 1,
) -> bool:
    """
    Verifies a user-supplied token against the secret with drift tolerance (+- 1 interval).
    """
    clean_token = re.sub(r"\s+", "", token)
    if len(clean_token) != digits or not clean_token.isdigit():
        return False

    current_t = time.time()
    for drift in range(-allowed_drift_steps, allowed_drift_steps + 1):
        test_time = current_t + (drift * period)
        try:
            expected_code, _, _ = calculate_totp(
                secret_base32=secret_base32,
                for_time=test_time,
                period=period,
                digits=digits,
                algorithm=algorithm,
            )
            if hmac.compare_digest(clean_token, expected_code):
                return True
        except Exception:
            continue

    return False

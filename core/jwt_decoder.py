"""
LocalVault Offline JWT Decoder & Inspector
Parses and inspects JSON Web Tokens (JWT) completely offline without network calls.
Extracts headers, payload claims, expiration timestamps, and algorithms.
"""

import json
import base64
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple


def base64url_decode(segment: str) -> bytes:
    """Decodes a base64url-encoded string with padding normalization."""
    # Replace URL-safe characters
    clean = segment.replace("-", "+").replace("_", "/")
    # Add padding if needed
    missing_padding = len(clean) % 4
    if missing_padding != 0:
        clean += "=" * (4 - missing_padding)
    return base64.b64decode(clean)


def is_jwt_token(token: str) -> bool:
    """Checks if a string has the 3-segment structure of a JSON Web Token."""
    if not token or not isinstance(token, str):
        return False
    parts = token.strip().split(".")
    if len(parts) != 3:
        return False
    # Validate each part is non-empty and decodable
    try:
        header_bytes = base64url_decode(parts[0])
        header = json.loads(header_bytes.decode("utf-8"))
        return isinstance(header, dict) and "alg" in header
    except Exception:
        return False


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes an offline JWT token into structured metadata.
    Returns None if the token is not a valid JWT.
    """
    if not is_jwt_token(token):
        return None

    parts = token.strip().split(".")
    try:
        header_raw = base64url_decode(parts[0]).decode("utf-8")
        payload_raw = base64url_decode(parts[1]).decode("utf-8")

        header = json.loads(header_raw)
        payload = json.loads(payload_raw)

        # Extract standard claims
        exp = payload.get("exp")
        iat = payload.get("iat")
        nbf = payload.get("nbf")
        iss = payload.get("iss", "None")
        sub = payload.get("sub", "None")
        aud = payload.get("aud", "None")

        # Expiration status
        now = time.time()
        is_expired = False
        time_to_expire = None
        exp_formatted = None

        if exp is not None and isinstance(exp, (int, float)):
            is_expired = now > exp
            time_to_expire = exp - now
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            exp_formatted = exp_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        iat_formatted = None
        if iat is not None and isinstance(iat, (int, float)):
            iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
            iat_formatted = iat_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        return {
            "algorithm": header.get("alg", "Unknown"),
            "token_type": header.get("typ", "JWT"),
            "key_id": header.get("kid"),
            "issuer": iss,
            "subject": sub,
            "audience": aud,
            "expires_at": exp,
            "expires_at_formatted": exp_formatted,
            "is_expired": is_expired,
            "seconds_to_expire": time_to_expire,
            "issued_at_formatted": iat_formatted,
            "header": header,
            "payload": payload,
            "signature_present": bool(parts[2]),
        }
    except Exception:
        return None

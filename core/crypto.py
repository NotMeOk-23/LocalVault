"""
LocalVault Cryptographic Engine
Implements Argon2id (RFC 9106) Key Derivation and AES-256-GCM (AEAD) encryption.
"""

import os
import zlib
from typing import Tuple
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from core.memory import SecureMemoryBuffer, secure_zero_memory

# Argon2id Gold Standard Recommended Parameters (RFC 9106 / Bitwarden / OWASP)
ARGON2_TIME_COST = 3          # 3 iterations
ARGON2_MEMORY_COST = 65536     # 64 MiB (in KiB)
ARGON2_PARALLELISM = 4         # 4 threads
ARGON2_HASH_LEN = 32           # 256-bit derived key
SALT_LENGTH = 32               # 256-bit CSPRNG salt
NONCE_LENGTH = 12              # 96-bit CSPRNG nonce for AES-GCM
AUTH_TAG_LENGTH = 16           # 128-bit authentication tag


class CryptoError(Exception):
    """Base exception for cryptographic failures."""
    pass


class AuthenticationFailedError(CryptoError):
    """Raised when master password is incorrect or ciphertext has been tampered with."""
    pass


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Generate cryptographically secure random bytes for KDF salt."""
    return os.urandom(length)


def generate_nonce(length: int = NONCE_LENGTH) -> bytes:
    """Generate fresh 96-bit CSPRNG nonce for AES-GCM. Nonces must never be reused."""
    return os.urandom(length)


def derive_master_key(
    password: str,
    salt: bytes,
    memory_cost: int = ARGON2_MEMORY_COST,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> SecureMemoryBuffer:
    """
    Derives a 256-bit master key from the master password and salt using Argon2id.
    Returns a locked SecureMemoryBuffer that must be wiped after use.
    """
    pwd_bytes = password.encode("utf-8")
    try:
        derived_raw = hash_secret_raw(
            secret=pwd_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=ARGON2_HASH_LEN,
            type=Type.ID,
            version=0x13,
        )
        return SecureMemoryBuffer(derived_raw)
    finally:
        # Wipe temporary utf-8 password bytes if possible
        if isinstance(pwd_bytes, bytearray):
            secure_zero_memory(pwd_bytes)


def encrypt_payload(
    payload_bytes: bytes,
    key_buffer: SecureMemoryBuffer,
    compress: bool = True,
    associated_data: bytes = b"",
) -> Tuple[bytes, bytes]:
    """
    Encrypts arbitrary bytes using AES-256-GCM with a fresh CSPRNG nonce.
    Optional zlib compression reduces payload size and eliminates repeating plaintext patterns.
    
    Returns:
        (nonce_12_bytes, ciphertext_with_tag)
    """
    if compress:
        data_to_encrypt = zlib.compress(payload_bytes, level=9)
    else:
        data_to_encrypt = payload_bytes

    nonce = generate_nonce(NONCE_LENGTH)
    key_bytes = key_buffer.get_bytes()
    try:
        aesgcm = AESGCM(key_bytes)
        # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext
        ciphertext_and_tag = aesgcm.encrypt(nonce, data_to_encrypt, associated_data)
        return nonce, ciphertext_and_tag
    finally:
        # Avoid leaving raw key bytes in local scope
        del key_bytes


def decrypt_payload(
    nonce: bytes,
    ciphertext_and_tag: bytes,
    key_buffer: SecureMemoryBuffer,
    decompress: bool = True,
    associated_data: bytes = b"",
) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext and validates the 16-byte authentication tag.
    Raises AuthenticationFailedError if the key is wrong or if any bit was tampered with.
    """
    key_bytes = key_buffer.get_bytes()
    try:
        aesgcm = AESGCM(key_bytes)
        try:
            decrypted = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)
        except InvalidTag:
            raise AuthenticationFailedError("Decryption failed: Invalid master password or corrupted/tampered vault.")
        
        if decompress:
            try:
                return zlib.decompress(decrypted)
            except Exception as e:
                raise CryptoError(f"Decompression error after successful decryption: {e}")
        return decrypted
    finally:
        del key_bytes

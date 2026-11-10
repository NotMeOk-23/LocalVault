"""
LocalVault Storage Engine
Handles atomic file writes, binary envelope serialization (LVKM), and AEAD verification.
"""

import os
import json
import struct
from pathlib import Path
from typing import Tuple

from core.models import VaultData
from core.crypto import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    SALT_LENGTH,
    NONCE_LENGTH,
    generate_salt,
    derive_master_key,
    encrypt_payload,
    decrypt_payload,
    AuthenticationFailedError,
    CryptoError,
)

# Header Constants
MAGIC_BYTES = b"LVKM"  # LocalVault Key Manager
FORMAT_VERSION = 1
KDF_TYPE_ARGON2ID = 1

# Header structure format:
# 4s (Magic) + H (Version) + B (KDF Type) + I (Memory) + I (Time) + H (Parallelism)
HEADER_PACK_FORMAT = ">4sHBI I H"
HEADER_PREFIX_SIZE = struct.calcsize(HEADER_PACK_FORMAT)


def pack_header(
    salt: bytes,
    memory_cost: int = ARGON2_MEMORY_COST,
    time_cost: int = ARGON2_TIME_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    """Serializes the authenticated header bytes (excluding nonce and ciphertext)."""
    prefix = struct.pack(
        HEADER_PACK_FORMAT,
        MAGIC_BYTES,
        FORMAT_VERSION,
        KDF_TYPE_ARGON2ID,
        memory_cost,
        time_cost,
        parallelism,
    )
    return prefix + salt


def unpack_header(raw_bytes: bytes) -> Tuple[int, int, int, int, int, bytes, int]:
    """
    Parses and verifies the binary envelope header.
    Returns (version, kdf_type, memory_cost, time_cost, parallelism, salt, total_header_len).
    """
    min_size = HEADER_PREFIX_SIZE + SALT_LENGTH
    if len(raw_bytes) < min_size:
        raise CryptoError("File is corrupted or too short to be a valid LocalVault envelope.")

    magic, version, kdf_type, mem_cost, time_cost, parallelism = struct.unpack_from(
        HEADER_PACK_FORMAT, raw_bytes, 0
    )

    if magic != MAGIC_BYTES:
        raise CryptoError("Invalid vault file format: Missing 'LVKM' magic identifier.")

    if version != FORMAT_VERSION:
        raise CryptoError(f"Unsupported vault format version {version} (expected {FORMAT_VERSION}).")

    salt = raw_bytes[HEADER_PREFIX_SIZE : HEADER_PREFIX_SIZE + SALT_LENGTH]
    total_header_len = HEADER_PREFIX_SIZE + SALT_LENGTH
    return version, kdf_type, mem_cost, time_cost, parallelism, salt, total_header_len


def save_vault(vault_data: VaultData, file_path: str, master_password: str) -> None:
    """
    Saves the vault with atomic write semantics:
    1. Derives master key via Argon2id with a fresh 32-byte salt.
    2. Encrypts compressed JSON payload via AES-256-GCM.
    3. Writes complete envelope to a temporary file.
    4. Flushes OS file buffers (fsync).
    5. Atomically replaces target file using OS rename.
    """
    target_path = Path(file_path).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = target_path.with_name(f"{target_path.name}.tmp.{os.getpid()}")

    # Generate salt and derive key
    salt = generate_salt(SALT_LENGTH)
    key_buffer = derive_master_key(
        password=master_password,
        salt=salt,
        memory_cost=ARGON2_MEMORY_COST,
        time_cost=ARGON2_TIME_COST,
        parallelism=ARGON2_PARALLELISM,
    )

    try:
        # Build authenticated header (AAD)
        header_bytes = pack_header(
            salt=salt,
            memory_cost=ARGON2_MEMORY_COST,
            time_cost=ARGON2_TIME_COST,
            parallelism=ARGON2_PARALLELISM,
        )

        # Serialize JSON payload
        vault_json = json.dumps(vault_data.to_dict(), indent=None)
        payload_bytes = vault_json.encode("utf-8")

        # Encrypt with AAD bound to the header to prevent header modification
        nonce, ciphertext_and_tag = encrypt_payload(
            payload_bytes=payload_bytes,
            key_buffer=key_buffer,
            compress=True,
            associated_data=header_bytes,
        )

        # Assemble full binary envelope
        full_envelope = header_bytes + nonce + ciphertext_and_tag

        # Write to temporary file with OS-level fsync
        with open(temp_path, "wb") as f:
            f.write(full_envelope)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace (guarantees zero corruption on crash)
        os.replace(temp_path, target_path)

    finally:
        key_buffer.wipe()
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def load_vault(file_path: str, master_password: str) -> VaultData:
    """
    Loads and decrypts the vault file:
    1. Validates magic bytes, format version, and reads Argon2id parameters.
    2. Derives master key.
    3. Decrypts AES-256-GCM payload with header AAD validation.
    4. Deserializes JSON into typed VaultData dataclasses.
    """
    target_path = Path(file_path).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Vault file does not exist: {file_path}")

    with open(target_path, "rb") as f:
        file_bytes = f.read()

    (
        version,
        kdf_type,
        mem_cost,
        time_cost,
        parallelism,
        salt,
        header_len,
    ) = unpack_header(file_bytes)

    header_bytes = file_bytes[:header_len]
    remaining = file_bytes[header_len:]

    if len(remaining) < NONCE_LENGTH + 16:  # 12-byte nonce + min 16-byte tag
        raise CryptoError("Corrupted vault payload: Payload too short.")

    nonce = remaining[:NONCE_LENGTH]
    ciphertext_and_tag = remaining[NONCE_LENGTH:]

    # Derive key using parameters stored in vault header
    key_buffer = derive_master_key(
        password=master_password,
        salt=salt,
        memory_cost=mem_cost,
        time_cost=time_cost,
        parallelism=parallelism,
    )

    try:
        decrypted_bytes = decrypt_payload(
            nonce=nonce,
            ciphertext_and_tag=ciphertext_and_tag,
            key_buffer=key_buffer,
            decompress=True,
            associated_data=header_bytes,
        )

        data_dict = json.loads(decrypted_bytes.decode("utf-8"))
        return VaultData.from_dict(data_dict)
    finally:
        key_buffer.wipe()

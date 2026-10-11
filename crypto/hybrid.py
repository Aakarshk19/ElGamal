"""
Hybrid ElGamal file encryption.

ElGamal is a public-key scheme. Encrypting large files directly with ElGamal
is slow and produces bulky ciphertext. Practical systems therefore:

  1. Generate a random symmetric session key (AES-128).
  2. Encrypt the file with AES-GCM (confidentiality + authenticity of the payload).
  3. Encrypt the short session key with ElGamal (so only the private-key holder
     can recover it).

This module labels that process clearly as Hybrid ElGamal File Encryption.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

from .elgamal import decrypt_integer, encrypt_integer, int_to_bytes, parse_key_int
from .hashing import sha256_hex

PACKAGE_FORMAT = "elgamal-hybrid-v1"
AES_KEY_BYTES = 16
MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MB educational limit


def encrypt_file_bytes(
    data: bytes,
    original_name: str,
    p: int,
    g: int,
    y: int,
) -> dict[str, Any]:
    if not data:
        raise ValueError("The selected file is empty.")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(
            f"This demonstration limits files to {MAX_FILE_BYTES // (1024 * 1024)} MB. "
            "ElGamal key wrapping plus AES is still expensive to demo on very large files."
        )

    original_hash = sha256_hex(data)
    session_key = secrets.token_bytes(AES_KEY_BYTES)
    nonce = secrets.token_bytes(12)
    aes = AESGCM(session_key)
    payload = aes.encrypt(nonce, data, None)

    m = int.from_bytes(session_key, "big")
    wrapped = encrypt_integer(m, p, g, y)

    package = {
        "format": PACKAGE_FORMAT,
        "scheme": "Hybrid ElGamal File Encryption (ElGamal + AES-128-GCM)",
        "original_name": original_name,
        "original_size": len(data),
        "original_sha256": original_hash,
        "elgamal": {
            "c1": str(wrapped["c1"]),
            "c2": str(wrapped["c2"]),
        },
        "aes_gcm": {
            "nonce": nonce.hex(),
            "ciphertext": payload.hex(),
        },
    }

    calculations = {
        "summary": [
            "Hybrid encryption is used because ElGamal is not efficient for large files.",
            f"Original file SHA-256 = {original_hash}",
            f"Random AES-128 session key (integer) m = {m}",
            f"Ephemeral k = {wrapped['k']}",
            f"ElGamal c1 = g^k mod p = {wrapped['c1']}",
            f"ElGamal c2 = m × y^k mod p = {wrapped['c2']}",
            "The file bytes are encrypted with AES-128-GCM using that session key.",
            "Only the 16-byte session key is protected directly by ElGamal.",
        ],
        "k": str(wrapped["k"]),
        "session_key_int": str(m),
        "c1": str(wrapped["c1"]),
        "c2": str(wrapped["c2"]),
        "original_sha256": original_hash,
    }

    encoded = json.dumps(package, indent=2).encode("utf-8")
    download_name = _safe_stem(original_name) + ".elgamal.json"

    return {
        "package_bytes": encoded,
        "download_name": download_name,
        "original_sha256": original_hash,
        "original_size": len(data),
        "calculations": calculations,
        "scheme": package["scheme"],
    }


def decrypt_file_package(package_bytes: bytes, p: int, x: int) -> dict[str, Any]:
    try:
        package = json.loads(package_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "The uploaded file is not a valid ElGamal hybrid package (JSON parse failed)."
        ) from exc

    if not isinstance(package, dict) or package.get("format") != PACKAGE_FORMAT:
        raise ValueError(
            "Unrecognized encrypted-file format. Upload a file produced by this tool."
        )

    try:
        c1 = parse_key_int(package["elgamal"]["c1"], "c1")
        c2 = parse_key_int(package["elgamal"]["c2"], "c2")
        nonce = bytes.fromhex(package["aes_gcm"]["nonce"])
        payload = bytes.fromhex(package["aes_gcm"]["ciphertext"])
        original_name = str(package.get("original_name") or "decrypted.bin")
        stored_hash = str(package.get("original_sha256") or "")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Encrypted package is missing required fields or has invalid values.") from exc

    try:
        recovered = decrypt_integer(c1, c2, p, x)
        session_key = int_to_bytes(recovered["m"], AES_KEY_BYTES)
    except ValueError as exc:
        raise ValueError(
            "Could not recover the session key. Check that the correct private key is in use."
        ) from exc

    try:
        aes = AESGCM(session_key)
        plaintext = aes.decrypt(nonce, payload, None)
    except Exception as exc:
        raise ValueError(
            "AES-GCM decryption failed. The file may be corrupted or the private key may be wrong."
        ) from exc

    decrypted_hash = sha256_hex(plaintext)
    match = bool(stored_hash) and stored_hash == decrypted_hash

    calculations = {
        "summary": [
            f"Recovered session-key integer m using ElGamal: s = c1^x mod p = {recovered['s']}",
            f"s⁻¹ mod p = {recovered['s_inv']}",
            f"m = c2 × s⁻¹ mod p = {recovered['m']}",
            "AES-128-GCM then decrypts the file payload with that session key.",
            f"Original SHA-256 (stored) = {stored_hash or '(not stored)'}",
            f"Decrypted SHA-256 = {decrypted_hash}",
            "Hash match" if match else "Hash mismatch or original hash missing",
        ]
    }

    return {
        "plaintext": plaintext,
        "original_name": original_name,
        "original_sha256": stored_hash,
        "decrypted_sha256": decrypted_hash,
        "integrity_match": match,
        "calculations": calculations,
        "size": len(plaintext),
    }


def _safe_stem(name: str) -> str:
    stem = name.replace("\\", "/").split("/")[-1].strip() or "file"
    for ch in '<>:"|?*':
        stem = stem.replace(ch, "_")
    return stem

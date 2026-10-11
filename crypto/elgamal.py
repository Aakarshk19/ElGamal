"""
Manual ElGamal public-key cryptography.

All core operations use Python integer arithmetic:
  - modular exponentiation via pow(base, exp, mod)
  - modular inverse via the extended Euclidean algorithm

No third-party ElGamal library is used.
"""

from __future__ import annotations

import math
import secrets
from typing import Any

SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
]


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) with ax + by = gcd."""
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = egcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def modinv(a: int, modulus: int) -> int:
    """Modular inverse of a modulo modulus, or raise ValueError."""
    a %= modulus
    gcd, x, _ = egcd(a, modulus)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist for the given value.")
    return x % modulus


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller–Rabin probable-prime test."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        witness = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                witness = True
                break
        if not witness:
            return False
    return True


def _random_odd_with_bits(bits: int) -> int:
    n = secrets.randbits(bits)
    n |= 1 << (bits - 1)
    n |= 1
    return n


def generate_prime(bits: int) -> int:
    """Generate a probable prime with the requested bit length."""
    if bits < 16:
        raise ValueError("Prime size is too small for this demonstration.")
    while True:
        candidate = _random_odd_with_bits(bits)
        if _is_probable_prime(candidate, rounds=8) and _is_probable_prime(candidate):
            return candidate


def generate_safe_prime(bits: int) -> tuple[int, int]:
    """
    Generate a safe prime p = 2q + 1 of approximately `bits` bits.
    Returns (p, q) where q is also prime.
    """
    q_bits = bits - 1
    while True:
        q = generate_prime(q_bits)
        p = 2 * q + 1
        if p.bit_length() == bits and _is_probable_prime(p):
            return p, q


def find_generator(p: int, q: int) -> int:
    """
    Find a generator g of the multiplicative group modulo a safe prime p = 2q + 1.
    g is a primitive root if g^2 ≢ 1 (mod p) and g^q ≢ 1 (mod p).
    """
    for g in [2, 3, 5, 6, 7, 10, 11]:
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g
    while True:
        g = secrets.randbelow(p - 3) + 2
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


def generate_keys(bits: int = 256) -> dict[str, Any]:
    """
    ElGamal key generation:
      1. Choose a safe prime p
      2. Choose a generator g
      3. Choose private key x in [2, p-2]
      4. Compute y = g^x mod p
    Public key = (p, g, y), private key = x
    """
    p, q = generate_safe_prime(bits)
    g = find_generator(p, q)
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)

    calculations = {
        "steps": [
            f"Selected safe prime p ({p.bit_length()} bits) where p = 2q + 1.",
            f"p = {p}",
            f"q = {q}",
            f"Selected generator g = {g} (primitive root modulo p).",
            f"Selected private key x uniformly from [2, p-2].",
            f"x = {x}",
            "Computed public value y = g^x mod p.",
            f"y = {g}^{x} mod {p}",
            f"y = {y}",
        ],
        "p": str(p),
        "g": str(g),
        "x": str(x),
        "y": str(y),
        "formula_y": "y = g^x mod p",
    }

    return {
        "public_key": {"p": str(p), "g": str(g), "y": str(y)},
        "private_key": {"x": str(x)},
        "bits": p.bit_length(),
        "calculations": calculations,
    }


def max_block_bytes(p: int) -> int:
    """Largest byte block whose integer value is guaranteed to be < p."""
    size = (p.bit_length() - 1) // 8
    return max(1, size)


def bytes_to_int(data: bytes) -> int:
    if not data:
        raise ValueError("Cannot convert empty data to an integer.")
    return int.from_bytes(data, "big")


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("Negative integers cannot be decoded as message bytes.")
    if value == 0:
        return b"\x00" if not length else b"\x00" * length
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if length is None:
        return raw
    if len(raw) > length:
        raise ValueError("Integer does not fit into the requested byte length.")
    return raw.rjust(length, b"\x00")


def _split_blocks(data: bytes, block_size: int) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def encrypt_integer(m: int, p: int, g: int, y: int, k: int | None = None) -> dict[str, Any]:
    """Encrypt a single integer m with 0 < m < p. Returns c1, c2 and calculation details."""
    if m <= 0 or m >= p:
        raise ValueError("Message integer must satisfy 0 < m < p.")
    if k is None:
        k = secrets.randbelow(p - 3) + 2
        while math.gcd(k, p - 1) != 1:
            k = secrets.randbelow(p - 3) + 2
    c1 = pow(g, k, p)
    yk = pow(y, k, p)
    c2 = (m * yk) % p
    return {
        "c1": c1,
        "c2": c2,
        "k": k,
        "yk": yk,
        "m": m,
    }


def decrypt_integer(c1: int, c2: int, p: int, x: int) -> dict[str, Any]:
    """Decrypt a single ElGamal pair (c1, c2)."""
    if c1 <= 0 or c1 >= p or c2 < 0 or c2 >= p:
        raise ValueError("Ciphertext values are outside the valid range for this modulus.")
    s = pow(c1, x, p)
    s_inv = modinv(s, p)
    m = (c2 * s_inv) % p
    return {"s": s, "s_inv": s_inv, "m": m}


def encrypt_text(message: str, p: int, g: int, y: int) -> dict[str, Any]:
    """Encrypt UTF-8 text by splitting it into integer blocks and applying ElGamal."""
    if not message or not message.strip():
        raise ValueError("Message cannot be empty.")

    data = message.encode("utf-8")
    block_size = max_block_bytes(p)
    blocks = _split_blocks(data, block_size)
    pairs = []
    calc_blocks = []

    for index, block in enumerate(blocks):
        m = bytes_to_int(block)
        result = encrypt_integer(m, p, g, y)
        pairs.append({"c1": str(result["c1"]), "c2": str(result["c2"]), "block_len": len(block)})
        calc_blocks.append(
            {
                "index": index,
                "plaintext_bytes": block.hex(),
                "m": str(result["m"]),
                "k": str(result["k"]),
                "c1": str(result["c1"]),
                "c2": str(result["c2"]),
                "formula_c1": "c1 = g^k mod p",
                "formula_c2": "c2 = m × y^k mod p",
            }
        )

    first = calc_blocks[0]
    calculations = {
        "encoding": "The message is encoded as UTF-8 bytes, then converted to integers (big-endian).",
        "message": message,
        "utf8_hex": data.hex(),
        "block_size_bytes": block_size,
        "block_count": len(blocks),
        "blocks": calc_blocks,
        "summary": [
            f"Message = {message!r}",
            f"UTF-8 bytes (hex) = {data.hex()}",
            f"Block size = {block_size} bytes (so that m < p)",
            f"Number of ElGamal blocks = {len(blocks)}",
            f"For block 0: m = {first['m']}",
            f"Random ephemeral k = {first['k']}",
            f"c1 = g^k mod p = {first['c1']}",
            f"c2 = m × y^k mod p = {first['c2']}",
            "Ciphertext is the sequence of pairs (c1, c2) for each block.",
        ],
    }

    return {
        "ciphertext": pairs,
        "display": format_ciphertext(pairs),
        "block_count": len(pairs),
        "calculations": calculations,
    }


def decrypt_text(pairs: list[dict[str, Any]], p: int, x: int) -> dict[str, Any]:
    """Decrypt a list of ElGamal pairs back to UTF-8 text."""
    if not pairs:
        raise ValueError("Ciphertext is empty.")

    recovered = bytearray()
    calc_blocks = []

    for index, pair in enumerate(pairs):
        try:
            c1 = int(pair["c1"])
            c2 = int(pair["c2"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Ciphertext format is invalid. Expected pairs of (c1, c2).") from exc

        result = decrypt_integer(c1, c2, p, x)
        block_len = pair.get("block_len")
        raw = int_to_bytes(result["m"], int(block_len) if block_len else None)
        recovered.extend(raw)
        calc_blocks.append(
            {
                "index": index,
                "c1": str(c1),
                "c2": str(c2),
                "s": str(result["s"]),
                "s_inv": str(result["s_inv"]),
                "m": str(result["m"]),
                "formula_s": "s = c1^x mod p",
                "formula_m": "m = c2 × s⁻¹ mod p",
            }
        )

    try:
        message = bytes(recovered).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Decryption produced invalid UTF-8. The private key may be incorrect, "
            "or the ciphertext may be corrupted."
        ) from exc

    first = calc_blocks[0]
    calculations = {
        "blocks": calc_blocks,
        "summary": [
            f"For block 0: s = c1^x mod p = {first['s']}",
            f"s⁻¹ mod p = {first['s_inv']}",
            f"m = c2 × s⁻¹ mod p = {first['m']}",
            "Integers are converted back to UTF-8 bytes to recover the message.",
            f"Recovered message = {message!r}",
        ],
    }

    return {
        "message": message,
        "calculations": calculations,
        "verified": True,
    }


def format_ciphertext(pairs: list[dict[str, Any]]) -> str:
    if len(pairs) == 1:
        return f"(c1, c2) = ({pairs[0]['c1']}, {pairs[0]['c2']})"
    lines = [f"Ciphertext contains {len(pairs)} ElGamal pair(s):"]
    for i, pair in enumerate(pairs):
        lines.append(f"  Block {i}: (c1, c2) = ({pair['c1']}, {pair['c2']})")
    return "\n".join(lines)


def parse_key_int(value: Any, name: str) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return parsed

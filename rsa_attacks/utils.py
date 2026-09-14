"""
RSA Utilities
=============
Shared helpers for key I/O, textbook RSA operations, and arithmetic
primitives used across the attack modules.

External dependencies:
    pycryptodome  — PEM key parsing (Crypto.PublicKey.RSA)
    gmpy2         — Fast modular inverse and big-integer arithmetic

IMPORTANT: The textbook RSA operations (no padding) are intentionally
insecure and exist solely to create controllable test fixtures.
Never use them in production.
"""

import math
import random
from dataclasses import dataclass

import gmpy2
from Crypto.PublicKey import RSA


# ---------------------------------------------------------------------------
# Dataclasses (used by textbook encrypt/decrypt and parity oracle)
# ---------------------------------------------------------------------------

@dataclass
class RSAPublicKey:
    e: int
    n: int


@dataclass
class RSAPrivateKey:
    d: int
    n: int


# ---------------------------------------------------------------------------
# PEM key I/O
# ---------------------------------------------------------------------------

def load_public_key(path: str) -> tuple[int, int]:
    """Load a PEM-encoded RSA public key and return (n, e).

    Accepts both bare public keys (BEGIN PUBLIC KEY / BEGIN RSA PUBLIC KEY)
    and the public component of a private key file.

    Args:
        path: Filesystem path to the PEM file.

    Returns:
        (n, e) — modulus and public exponent as Python ints.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file cannot be parsed as an RSA key, or if the
                    file contains a private key where a public key is expected.

    Example:
        >>> n, e = load_public_key("data/sample_keys/pub.pem")
        >>> e
        65537
    """
    try:
        with open(path, "rb") as fh:
            key = RSA.import_key(fh.read())
    except (ValueError, IndexError, TypeError) as exc:
        raise ValueError(f"Cannot parse RSA key from {path!r}: {exc}") from exc

    if key.has_private():
        raise ValueError(
            f"{path!r} contains a private key; expected a public-only key. "
            "Use load_private_key() instead."
        )

    return int(key.n), int(key.e)


def load_private_key(path: str) -> tuple[int, int, int]:
    """Load a PEM-encoded RSA private key and return (n, e, d).

    Args:
        path: Filesystem path to the PEM file.

    Returns:
        (n, e, d) — modulus, public exponent, and private exponent as
        Python ints.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the file cannot be parsed, or if it contains only a
                    public key (no private exponent present).

    Example:
        >>> n, e, d = load_private_key("data/sample_keys/priv.pem")
    """
    try:
        with open(path, "rb") as fh:
            key = RSA.import_key(fh.read())
    except (ValueError, IndexError, TypeError) as exc:
        raise ValueError(f"Cannot parse RSA key from {path!r}: {exc}") from exc

    if not key.has_private():
        raise ValueError(
            f"{path!r} does not contain a private key (no private exponent d). "
            "Use load_public_key() instead."
        )

    return int(key.n), int(key.e), int(key.d)


# ---------------------------------------------------------------------------
# CRT key reconstruction
# ---------------------------------------------------------------------------

def reconstruct_private_key(n: int, e: int, p: int, q: int) -> dict:
    """Compute full RSA private-key parameters from the prime factors.

    Given the factorisation n = p·q, derives all standard CRT parameters
    used in PKCS#1 private key representations:

        φ(n)  = (p − 1)(q − 1)
        d     = e⁻¹  mod φ(n)          (private exponent)
        dₚ    = d    mod (p − 1)        (CRT exponent for p)
        d_q   = d    mod (q − 1)        (CRT exponent for q)
        q_inv = q⁻¹  mod p              (CRT coefficient)

    The CRT form lets implementations split modular exponentiation into two
    half-size exponentiations — roughly 4× faster than working mod n directly.

    Args:
        n:  RSA modulus.  Must equal p * q exactly.
        e:  Public exponent.  Must be coprime with φ(n).
        p:  First prime factor of n.
        q:  Second prime factor of n.

    Returns:
        Dict with keys: ``n``, ``e``, ``d``, ``p``, ``q``, ``dp``, ``dq``, ``qinv``.
        All values are Python ints.

    Raises:
        ValueError: If p * q ≠ n, if gcd(e, φ(n)) ≠ 1, or if p and q are
                    not coprime (which would make q_inv undefined).

    Example:
        >>> from rsa_attacks.utils import textbook_rsa_keypair
        >>> pub, priv = textbook_rsa_keypair(512)
        >>> # Pretend we recovered p and q via an attack:
        >>> params = reconstruct_private_key(pub.n, pub.e, p, q)
        >>> params["d"] == priv.d
        True
    """
    if p <= 1 or q <= 1:
        raise ValueError(f"p and q must both be > 1 (got p={p}, q={q})")
    if p * q != n:
        raise ValueError(
            f"p * q = {p * q} does not equal n = {n}; "
            "verify the prime factors are correct."
        )

    phi = (p - 1) * (q - 1)

    g = math.gcd(e, phi)
    if g != 1:
        raise ValueError(
            f"e={e} is not invertible mod φ(n)={phi} (gcd={g}); "
            "e must be coprime with (p−1)(q−1)."
        )

    # gmpy2.invert raises ZeroDivisionError if not invertible; we already
    # checked, but keep the guard for safety.
    try:
        d = int(gmpy2.invert(e, phi))
    except ZeroDivisionError:  # pragma: no cover
        raise ValueError(f"e={e} has no inverse mod φ(n)={phi}")

    dp = d % (p - 1)
    dq = d % (q - 1)

    if math.gcd(q, p) != 1:
        raise ValueError(f"p={p} and q={q} are not coprime; q_inv is undefined.")

    try:
        qinv = int(gmpy2.invert(q, p))
    except ZeroDivisionError:  # pragma: no cover
        raise ValueError(f"q={q} has no inverse mod p={p}")

    return {
        "n":    n,
        "e":    e,
        "d":    d,
        "p":    p,
        "q":    q,
        "dp":   dp,
        "dq":   dq,
        "qinv": qinv,
    }


# ---------------------------------------------------------------------------
# Byte / integer conversion
# ---------------------------------------------------------------------------

def int_to_bytes(n: int, length: int | None = None) -> bytes:
    """Convert a non-negative integer to its big-endian byte representation.

    Args:
        n:      Non-negative integer to encode.
        length: Desired output length in bytes.  The result is zero-padded
                on the left to reach this length.  If omitted, the minimum
                number of bytes required to represent *n* is used (at least 1
                for n == 0).

    Returns:
        Big-endian bytes of length ``length`` (or minimum length when omitted).

    Raises:
        ValueError: If *n* is negative, or if *length* is smaller than the
                    minimum number of bytes required to encode *n*.

    Example:
        >>> int_to_bytes(256)
        b'\\x01\\x00'
        >>> int_to_bytes(1, length=4)
        b'\\x00\\x00\\x00\\x01'
    """
    if n < 0:
        raise ValueError(f"n must be non-negative, got {n}")

    min_length = (n.bit_length() + 7) // 8 if n > 0 else 1

    if length is None:
        length = min_length
    elif length < min_length:
        raise ValueError(
            f"length={length} is too small to encode n "
            f"(minimum {min_length} byte{'s' if min_length != 1 else ''} required)"
        )

    return n.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to a non-negative integer.

    Args:
        b: Byte string to decode (big-endian, unsigned).

    Returns:
        Non-negative integer value.

    Raises:
        ValueError: If *b* is empty.

    Example:
        >>> bytes_to_int(b'\\x01\\x00')
        256
    """
    if len(b) == 0:
        raise ValueError("Cannot convert empty byte string to int")
    return int.from_bytes(b, "big")


# ---------------------------------------------------------------------------
# Key generation (textbook — no padding, for test fixtures only)
# ---------------------------------------------------------------------------

def textbook_rsa_keypair(bits: int = 512, e: int = 65537) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Generate a textbook RSA key pair with a modulus of *bits* bits.

    Args:
        bits: Desired bit-length of the modulus.  Minimum 64.
        e:    Public exponent (default 65537).

    Returns:
        (RSAPublicKey, RSAPrivateKey) tuple.
    """
    if bits < 64:
        raise ValueError(f"bits must be >= 64, got {bits}")

    half = bits // 2
    p = _random_prime(half)
    q = _random_prime(half)
    while q == p:
        q = _random_prime(half)

    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        raise ValueError(f"e={e} is not coprime with φ(n); choose a different e.")

    d = int(gmpy2.invert(e, phi))
    return RSAPublicKey(e=e, n=n), RSAPrivateKey(d=d, n=n)


def make_weak_pair(bits: int = 512, e: int = 65537):
    """Create two RSA public keys that share a prime factor (intentionally weak).

    The shared prime is used as the *p* component of both keys.
    Useful for demonstrating the common-factor attack.

    Returns:
        (key1, key2) as common_factor.RSAPublicKey objects.
    """
    from .common_factor import RSAPublicKey as CFKey

    half = bits // 2
    shared_p = _random_prime(half)
    q1 = _random_prime(half)
    q2 = _random_prime(half)
    while q2 == q1:
        q2 = _random_prime(half)

    return CFKey(n=shared_p * q1, e=e), CFKey(n=shared_p * q2, e=e)


# ---------------------------------------------------------------------------
# Textbook RSA encrypt / decrypt
# ---------------------------------------------------------------------------

def textbook_encrypt(message: int, pub: RSAPublicKey) -> int:
    """Encrypt an integer with textbook RSA (no padding).  c = mᵉ mod n.

    Args:
        message: Integer plaintext, 0 ≤ message < n.
        pub:     RSA public key.

    Returns:
        Integer ciphertext.
    """
    if not (0 <= message < pub.n):
        raise ValueError(f"message must satisfy 0 ≤ m < n (n={pub.n})")
    return int(gmpy2.powmod(message, pub.e, pub.n))


def textbook_decrypt(ciphertext: int, priv: RSAPrivateKey) -> int:
    """Decrypt an integer with textbook RSA (no padding).  m = cᵈ mod n.

    Args:
        ciphertext: Integer ciphertext, 0 ≤ ciphertext < n.
        priv:       RSA private key.

    Returns:
        Integer plaintext.
    """
    if not (0 <= ciphertext < priv.n):
        raise ValueError(f"ciphertext must satisfy 0 ≤ c < n (n={priv.n})")
    return int(gmpy2.powmod(ciphertext, priv.d, priv.n))


# ---------------------------------------------------------------------------
# Arithmetic helpers
# ---------------------------------------------------------------------------

def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse of *a* mod *m* using gmpy2.

    Computes x such that a·x ≡ 1 (mod m).

    Args:
        a: Integer to invert.
        m: Modulus (must be > 1).

    Returns:
        Inverse in the range [0, m).

    Raises:
        ValueError: If gcd(a, m) ≠ 1 (inverse does not exist).
    """
    if m <= 1:
        raise ValueError(f"Modulus must be > 1, got {m}")
    if math.gcd(a % m, m) != 1:
        raise ValueError(
            f"Inverse of {a} mod {m} does not exist "
            f"(gcd={math.gcd(a % m, m)})"
        )
    return int(gmpy2.invert(a, m))


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns (g, x, y) such that  a·x + b·y = g = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _random_prime(bits: int) -> int:
    """Generate a random *bits*-bit prime via Miller-Rabin filtering."""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # force MSB set and odd
        if _miller_rabin(candidate):
            return candidate


def _miller_rabin(n: int, rounds: int = 20) -> bool:
    """Probabilistic Miller-Rabin primality test.

    False-positive probability is at most 4⁻ʳᵒᵘⁿᵈˢ.
    """
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small:
        return True
    if any(n % p == 0 for p in small):
        return False

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

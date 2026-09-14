"""
RSA Parity Oracle Attack
=========================
Educational implementation of the classical LSB (parity) oracle attack,
a form of adaptive chosen-ciphertext attack (CCA2).

How it works:
  RSA is multiplicatively homomorphic:
      Enc(m · f) = Enc(m) · Enc(f)  (mod n)

  Choose f = 2^e mod n.  Then:
      c' = c · f^e  mod n   decrypts to   m' = m · 2  mod n

  An oracle that reveals only the parity (odd / even) of the decrypted
  plaintext leaks one bit of information per query.  After ⌈log₂(n)⌉
  queries the plaintext is fully recovered via binary search on the interval
  containing m·2^k mod n.

  This attack works against raw (textbook) RSA only.  OAEP and PKCS#1 v1.5
  padding render it impractical (see Bleichenbacher 1998 for the PKCS attack).

Complexity: O(log₂ n) oracle queries.

Reference:
  Manger, J. (2001). "A Chosen Ciphertext Attack on RSA Optimal Asymmetric
  Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0."
  CRYPTO 2001, LNCS 2139, pp. 230–238.

  Boneh, D. (1999). "Twenty Years of Attacks on the RSA Cryptosystem."
  Notices of the AMS, 46(2), 203–213.
"""

import bisect
from typing import Callable

from Crypto.Util.number import getPrime


class Ranges:
    """A sorted, canonical set of disjoint integer intervals [lo, hi] (inclusive).

    Internally stores intervals as a list of ``(lo, hi)`` tuples that are
    sorted by ``lo``, non-overlapping, and non-adjacent (adjacent intervals
    are merged on construction).  All arithmetic uses Python's arbitrary-
    precision integers — no floats are involved.

    Typical use: tracking the set of candidate plaintext values during an
    oracle-based attack (e.g. Bleichenbacher 1998, Manger 2001) as the
    attacker progressively narrows down the plaintext range.

    Example:
        >>> r = Ranges((0, 10), (20, 30))
        >>> r
        [0, 10] U [20, 30]
        >>> len(r)
        22
        >>> 5 in r
        True
        >>> 15 in r
        False
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, *intervals: tuple[int, int]) -> None:
        """Initialise from zero or more (lo, hi) tuples.

        Each tuple must satisfy ``lo <= hi``.  Overlapping and adjacent
        intervals are merged automatically so the internal representation
        is always canonical.

        Args:
            *intervals: Any number of ``(lo, hi)`` pairs of integers.

        Raises:
            ValueError: If any tuple has ``lo > hi``.

        Example:
            >>> Ranges((0, 5), (3, 8), (20, 25))
            [0, 8] U [20, 25]
            >>> Ranges()
            ∅
        """
        for lo, hi in intervals:
            if lo > hi:
                raise ValueError(f"Invalid interval ({lo}, {hi}): lo must be <= hi")

        sorted_pairs: list[tuple[int, int]] = sorted(intervals)
        merged: list[list[int]] = []
        for lo, hi in sorted_pairs:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self._intervals: list[tuple[int, int]] = [(lo, hi) for lo, hi in merged]

    # ------------------------------------------------------------------
    # Built-ins
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        """Return the total number of integers covered by this set.

        Example:
            >>> len(Ranges((0, 9), (20, 24)))
            15
            >>> len(Ranges())
            0
        """
        return sum(hi - lo + 1 for lo, hi in self._intervals)

    def __repr__(self) -> str:
        """Return a human-readable representation of the interval set.

        Example:
            >>> repr(Ranges((0, 10), (20, 30)))
            '[0, 10] U [20, 30]'
            >>> repr(Ranges())
            '(empty)'
        """
        if not self._intervals:
            return "(empty)"
        return " U ".join(f"[{lo}, {hi}]" for lo, hi in self._intervals)

    def __contains__(self, x: int) -> bool:
        """Return True if integer *x* belongs to any interval in the set.

        Uses binary search — O(log k) where k is the number of intervals.

        Example:
            >>> r = Ranges((0, 10), (20, 30))
            >>> 5 in r
            True
            >>> 15 in r
            False
            >>> 20 in r
            True
        """
        lows = [lo for lo, _ in self._intervals]
        idx = bisect.bisect_right(lows, x) - 1
        if idx >= 0:
            lo, hi = self._intervals[idx]
            return lo <= x <= hi
        return False

    # ------------------------------------------------------------------
    # Set operations
    # ------------------------------------------------------------------

    def intersection(self, other: "Ranges") -> "Ranges":
        """Return the intersection of this set and *other*.

        Uses a two-pointer sweep over the two sorted interval lists —
        O(k₁ + k₂) where k₁, k₂ are the respective interval counts.

        Args:
            other: Another :class:`Ranges` instance.

        Returns:
            A new :class:`Ranges` containing only integers present in both.

        Example:
            >>> Ranges((0, 10), (20, 30)).intersection(Ranges((5, 25)))
            [5, 10] U [20, 25]
            >>> Ranges((0, 5)).intersection(Ranges((10, 15)))
            (empty)
        """
        result: list[tuple[int, int]] = []
        i, j = 0, 0
        a, b = self._intervals, other._intervals
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                result.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return Ranges(*result)

    def shift_and_scale(self, a: int, b: int) -> "Ranges":
        """Return the image of this set under the map x -> (x * a) // b.

        For each interval ``[lo, hi]`` computes
        ``[(lo * a) // b, (hi * a) // b]`` then merges any overlaps.
        All arithmetic is exact integer floor division — no floats.

        This operation is the core building block of the Bleichenbacher /
        Manger oracle attacks: after multiplying the ciphertext by some
        blinding factor, the set of candidate plaintexts transforms by
        exactly this rule.

        Args:
            a: Non-negative integer multiplier.
            b: Positive integer divisor.

        Returns:
            A new :class:`Ranges` representing the scaled image.

        Raises:
            ValueError: If ``a < 0`` or ``b <= 0``.

        Example:
            >>> Ranges((0, 10), (20, 30)).shift_and_scale(3, 2)
            [0, 15] U [30, 45]
            >>> Ranges((4, 8)).shift_and_scale(1, 4)
            [1, 2]
        """
        if b <= 0:
            raise ValueError(f"b must be positive, got {b}")
        if a < 0:
            raise ValueError(f"a must be non-negative, got {a}")
        result = [(lo * a // b, hi * a // b) for lo, hi in self._intervals]
        return Ranges(*result)

    # ------------------------------------------------------------------
    # Convergence check
    # ------------------------------------------------------------------

    def to_int(self) -> "int | None":
        """Return the single integer in this set, or None if there is not exactly one.

        Useful as a convergence check in oracle attacks: when the candidate
        set has narrowed to a single value, the plaintext has been recovered.

        Returns:
            The integer if ``len(self) == 1``, otherwise ``None``.

        Example:
            >>> Ranges((7, 7)).to_int()
            7
            >>> Ranges((0, 10)).to_int() is None
            True
            >>> Ranges().to_int() is None
            True
        """
        if len(self._intervals) == 1:
            lo, hi = self._intervals[0]
            if lo == hi:
                return lo
        return None


# Type alias: an oracle accepts a ciphertext integer and returns the LSB (0 or 1)
# of the corresponding decrypted plaintext.
ParityOracle = Callable[[int], int]


def _narrow_interval(interval: "Ranges", mult: int, n: int, bit: int) -> "Ranges":
    """Return the subset of *interval* consistent with the oracle parity *bit*.

    At step k (mult = 2^k, k >= 1):
        q = floor(m * mult / n)
        (m * mult) mod n  is odd  iff  q is odd   (because n is odd)
    So  q % 2 == bit  selects the valid candidates.
    For each valid q, m lies in [ceil(q*n/mult), floor((q+1)*n/mult - epsilon)].
    """
    new_intervals: list[tuple[int, int]] = []
    for lo, hi in interval._intervals:
        q_lo = lo * mult // n
        q_hi = hi * mult // n
        first_q = q_lo + ((q_lo % 2) != bit)   # first q with correct parity
        for q in range(first_q, q_hi + 1, 2):
            m_lo = max(lo, (q * n + mult - 1) // mult)       # ceil(q*n/mult)
            m_hi = min(hi, ((q + 1) * n - 1) // mult)        # floor((q+1)*n/mult - ε)
            if m_lo <= m_hi:
                new_intervals.append((m_lo, m_hi))
    return Ranges(*new_intervals)


def parity_oracle_attack(
    n: int,
    e: int,
    c: int,
    oracle: ParityOracle,
    max_iterations: int = 10000,
) -> int:
    """Recover the plaintext of *c* using an LSB (parity) oracle.

    This is an adaptive chosen-ciphertext attack (CCA2) against textbook RSA.
    RSA's multiplicative homomorphism means that given any ciphertext c = m^e
    mod n, the attacker can produce c' = (c · s^e) mod n, which decrypts to
    m·s mod n.  Choosing s = 2^k reveals the parity (LSB) of m·2^k mod n via
    the oracle.  One oracle query per step yields one bit of information about
    m, so the plaintext is fully recovered in O(log n) queries.

    The candidate set of possible plaintexts is tracked as a :class:`Ranges`
    object.  At each step the oracle bit identifies which q = floor(m*2^k/n)
    values are consistent, halving the candidate set.  Convergence is detected
    when the :class:`Ranges` collapses to a single integer.

    This attack only applies to raw (textbook/unpadded) RSA.  OAEP and
    PKCS#1 v1.5 padding defeat it in practice; see Bleichenbacher (1998) for
    the PKCS-padding variant.

    References:
        Bleichenbacher, D. (1998). "Chosen Ciphertext Attacks Against
        Protocols Based on the RSA Encryption Standard PKCS #1."
        CRYPTO 1998, LNCS 1462, pp. 1–12.

        Boneh, D. (1999). "Twenty Years of Attacks on the RSA Cryptosystem."
        Notices of the AMS, 46(2), 203–213.

    Args:
        n: RSA public modulus.
        e: RSA public exponent.
        c: Integer ciphertext satisfying 0 < c < n.
        oracle: Callable(c: int) -> int — returns the LSB (0 or 1) of the
                plaintext obtained by decrypting *c* under the target key.
        max_iterations: Safety limit on oracle queries.  A 2048-bit key
                        needs at most 2048 queries; the default of 10 000
                        is generous for any practical key size.

    Returns:
        The recovered plaintext as a Python integer.

    Raises:
        RuntimeError: If *max_iterations* is exhausted before convergence.

    Example:
        >>> p, q, e = 61, 53, 17          # toy RSA (n = 3233)
        >>> n = p * q
        >>> d = pow(e, -1, (p - 1) * (q - 1))
        >>> m = 42
        >>> c = pow(m, e, n)
        >>> oracle = lambda ct: pow(ct, d, n) % 2
        >>> parity_oracle_attack(n, e, c, oracle)
        42
    """
    interval = Ranges((0, n - 1))
    multiplier = 1

    for _ in range(max_iterations):
        c_prime = (c * pow(multiplier, e, n)) % n
        bit = oracle(c_prime)

        # mult=1: q = floor(m/n) = 0 for all m in [0, n-1]; q-filtering is
        # a no-op here, so skip the update for this first (unblinded) query.
        if multiplier > 1:
            interval = _narrow_interval(interval, multiplier, n, bit)

        result = interval.to_int()
        if result is not None:
            return result

        multiplier *= 2

    raise RuntimeError(
        f"parity_oracle_attack did not converge within {max_iterations} iterations"
    )


def make_oracle(private_key: "RSAPrivateKey") -> ParityOracle:  # type: ignore[name-defined]
    """Build a parity oracle from a plaintext RSA private key object.

    The oracle decrypts any integer ciphertext and returns True if even.
    Intended for local / simulation use in tests and notebooks.

    Args:
        private_key: An object with attributes (d, n) representing the RSA
                     private key, as returned by utils.textbook_rsa_keypair.

    Returns:
        A ParityOracle callable.
    """
    def oracle(c: int) -> int:
        plaintext = pow(c, private_key.d, private_key.n)
        return plaintext % 2

    return oracle


class SimulatedOracle:
    """A callable that simulates a server leaking the LSB of each decryption.

    Unlike :func:`make_oracle`, this class accepts raw integer key components
    rather than a key object, making it convenient for scripted tests.

    Args:
        n: RSA public modulus.
        e: RSA public exponent (stored but not used for decryption).
        d: RSA private exponent.

    Example:
        >>> oracle = SimulatedOracle(n=3233, e=17, d=2753)
        >>> oracle(pow(42, 17, 3233))   # encrypt 42, ask parity
        0
    """

    def __init__(self, n: int, e: int, d: int) -> None:
        self.n = n
        self.e = e
        self.d = d

    def __call__(self, c: int) -> int:
        """Decrypt *c* and return the LSB (0 = even, 1 = odd) of the plaintext."""
        return pow(c, self.d, self.n) % 2


def test_attack_locally(key_size: int = 256, message: bytes = b"hello") -> bool:
    """Generate a fresh RSA key and verify parity_oracle_attack recovers the message.

    Uses raw (textbook) RSA encryption so the oracle-based attack applies.
    PKCS#1 v1.5 or OAEP padding would defeat the attack in practice.

    Args:
        key_size: RSA modulus size in bits (256 for speed; >=1024 for security).
        message:  Plaintext bytes to encrypt and recover.

    Returns:
        True if the recovered integer equals the original plaintext integer.
    """
    import math
    e = 65537
    half = key_size // 2
    while True:
        p, q = getPrime(half), getPrime(half)
        if p != q and math.gcd(e, (p - 1) * (q - 1)) == 1:
            break
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))

    m = int.from_bytes(message, "big")
    c = pow(m, e, n)

    oracle = SimulatedOracle(n, e, d)
    recovered = parity_oracle_attack(n, e, c, oracle)
    return recovered == m

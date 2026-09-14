"""
Common-Factor (Shared-Prime) Attack on RSA
==========================================
Educational implementation of the batch-GCD attack demonstrated by
Heninger et al. (2012) against real-world RSA public keys.

How it works
------------
When two RSA moduli N₁ and N₂ are generated with insufficient entropy,
they may share a prime factor p:

    N₁ = p · q₁    N₂ = p · q₂

Because GCD(N₁, N₂) = p, both private keys can be recovered immediately —
no factorisation algorithm is required.

Naive approach
--------------
Computing GCD for every pair of N moduli is O(N²) — feasible for small
corpora but impractical for the millions of keys seen in the wild.

Batch-GCD (Bernstein's algorithm)
----------------------------------
Uses a product tree and remainder tree to compute, for each N_i, the GCD
of N_i against the product of all other N_j.  Running time is O(N log² N)
bit-operations, reducing an N²-pair problem to roughly N log N GCDs.

Mathematical basis:
  Let M_i = ∏_{j ≠ i} N_j.  Build a product tree over [N_0, …, N_{k-1}]
  (root = ∏ N_j), then propagate a remainder tree top-down via

      r_child = r_parent mod child²

  At each leaf:  r_i = N_i · (M_i mod N_i),  so  r_i // N_i = M_i mod N_i.
  Therefore:

      g_i = gcd(N_i, r_i // N_i) = gcd(N_i, M_i)

  This equals a non-trivial factor of N_i iff N_i shares a prime with any
  other modulus; otherwise g_i = 1.

References
----------
Heninger, N., Durumeric, Z., Wustrow, E., Halderman, J. A. (2012).
"Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network
Devices."  USENIX Security Symposium.
https://factorable.net/paper.html

Bernstein, D. J. (2004). "How to find smooth parts of integers."
https://cr.yp.to/factorization/smoothparts-20040510.pdf
"""

import math
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Data types (kept for backward compatibility with utils.py and existing tests)
# ---------------------------------------------------------------------------

@dataclass
class RSAPublicKey:
    n: int  # modulus
    e: int  # public exponent


@dataclass
class FactoredKey:
    key: RSAPublicKey
    p: int
    q: int

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    def private_exponent(self) -> int:
        return pow(self.key.e, -1, self.phi)


# ---------------------------------------------------------------------------
# Part A — Naive O(N²) pairwise GCD
# ---------------------------------------------------------------------------

def find_shared_factors_naive(moduli: list[int]) -> dict[int, int]:
    """Find all moduli that share a prime factor using pairwise GCD checks.

    For a corpus of size N this runs in O(N²) time.  Use it only for small
    corpora or as a ground-truth check against batch_gcd.

    Args:
        moduli: List of RSA moduli (positive integers).

    Returns:
        Dict mapping index ``i`` to the shared factor ``g = gcd(N_i, N_j)``
        for some ``j ≠ i`` where ``g > 1``.  Indices with no shared factor
        are absent from the dict.  When N_i shares factors with multiple
        other moduli the first factor found is recorded.

    Example:
        >>> find_shared_factors_naive([101*103, 101*107, 109*113])
        {0: 101, 1: 101}
    """
    result: dict[int, int] = {}
    n = len(moduli)
    for i in range(n):
        for j in range(i + 1, n):
            g = math.gcd(moduli[i], moduli[j])
            if g > 1:
                if i not in result:
                    result[i] = g
                if j not in result:
                    result[j] = g
    return result


# ---------------------------------------------------------------------------
# Part B — Batch GCD via product / remainder tree   O(N log² N)
# ---------------------------------------------------------------------------

def batch_gcd(moduli: list[int]) -> list[int]:
    """Compute shared-factor GCDs for all moduli using Bernstein's algorithm.

    For each index ``i`` returns ``gcd(N_i, ∏_{j ≠ i} N_j)``.  This equals
    a non-trivial factor of ``N_i`` if ``N_i`` shares any prime with another
    modulus, and equals ``1`` otherwise.

    Args:
        moduli: List of RSA moduli (positive integers).

    Returns:
        List of the same length as *moduli*.  ``result[i] > 1`` means a shared
        factor was found; ``result[i] == 1`` means no shared factor.

    Example:
        >>> batch_gcd([101*103, 101*107, 109*113])
        [101, 101, 1]
    """
    if not moduli:
        return []

    # ------------------------------------------------------------------
    # Step 1: Build product tree bottom-up.
    # tree[0] = leaves (the original moduli).
    # tree[-1] = [root] = [product of all moduli].
    # ------------------------------------------------------------------
    tree: list[list[int]] = [list(moduli)]
    while len(tree[-1]) > 1:
        level = tree[-1]
        tree.append([
            level[i] * level[i + 1] if i + 1 < len(level) else level[i]
            for i in range(0, len(level), 2)
        ])

    # ------------------------------------------------------------------
    # Step 2: Propagate remainder tree top-down.
    # Start from the root; for each parent node with value r, compute
    #   r_child = r_parent mod child²
    # so that at the leaves r_i = N_i · (M_i mod N_i).
    # ------------------------------------------------------------------
    remainders: list[int] = [tree[-1][0]]  # root
    for level in reversed(tree[:-1]):
        new_remainders: list[int] = []
        for i, r in enumerate(remainders):
            left = level[2 * i]
            new_remainders.append(r % (left * left))
            if 2 * i + 1 < len(level):
                right = level[2 * i + 1]
                new_remainders.append(r % (right * right))
        remainders = new_remainders  # advance to the next level down

    # ------------------------------------------------------------------
    # Step 3: At each leaf, gcd(N_i, r_i // N_i) = gcd(N_i, M_i mod N_i)
    #         = gcd(N_i, M_i) — the shared-factor GCD.
    # ------------------------------------------------------------------
    return [math.gcd(r // n, n) for n, r in zip(moduli, remainders)]


# ---------------------------------------------------------------------------
# Part C — High-level attack wrapper
# ---------------------------------------------------------------------------

def attack(moduli: list[int]) -> list[dict]:
    """Recover prime factors for every vulnerable modulus in *moduli*.

    Uses batch_gcd to identify all moduli that share a prime with at least
    one other modulus, then returns the recovered factor pair for each.

    Args:
        moduli: List of RSA moduli to test.

    Returns:
        List of dicts, one per vulnerable modulus, each containing:
        ``{"index": i, "n": N_i, "p": shared_factor, "q": N_i // shared_factor}``.
        The list is ordered by index.

    Raises:
        ValueError: If no shared factors are found among *moduli*.

    Example:
        >>> results = attack([101*103, 101*107, 109*113])
        >>> len(results)
        2
        >>> results[0]["p"]
        101
    """
    gcds = batch_gcd(moduli)
    results = [
        {"index": i, "n": n, "p": g, "q": n // g}
        for i, (n, g) in enumerate(zip(moduli, gcds))
        if g > 1
    ]
    if not results:
        raise ValueError(
            f"No shared factors found among {len(moduli)} moduli."
        )
    return results


# ---------------------------------------------------------------------------
# Legacy high-level API (kept for backward compatibility)
# ---------------------------------------------------------------------------

def common_factor_attack(keys: list[RSAPublicKey]) -> list[FactoredKey]:
    """Find all keys in *keys* that share a prime factor with another key.

    Args:
        keys: List of RSA public keys (n, e pairs) to test.

    Returns:
        List of FactoredKey objects for every vulnerable key found.
        Keys with no shared factor are omitted.
    """
    factored: list[FactoredKey] = []
    for i, ki in enumerate(keys):
        for j, kj in enumerate(keys):
            if i >= j:
                continue
            g = math.gcd(ki.n, kj.n)
            if g > 1 and g != ki.n:
                _append_if_new(factored, ki, g, ki.n // g)
                _append_if_new(factored, kj, g, kj.n // g)
    return factored


def _append_if_new(
    factored: list[FactoredKey], key: RSAPublicKey, p: int, q: int
) -> None:
    if not any(fk.key.n == key.n for fk in factored):
        factored.append(FactoredKey(key=key, p=p, q=q))

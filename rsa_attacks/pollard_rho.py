"""
Pollard's Rho Factorisation Algorithm
======================================
Educational implementation of Pollard's rho algorithm (1975).

Algorithm overview
------------------
Choose a pseudo-random polynomial  f(x) = (x² + c) mod n  and iterate two
sequences starting from the same seed:

    tortoise:  xᵢ₊₁ = f(xᵢ)
    hare:      yᵢ₊₁ = f(f(yᵢ))          (double speed)

By Floyd's cycle-detection theorem the two sequences must eventually meet
inside the cycle.  The key insight is that, while the sequences are computed
mod n, they are also implicitly computed mod every prime factor p of n.  The
orbit length mod p is O(√p) by the birthday paradox, so a collision
GCD(|xᵢ − yᵢ|, n) > 1 is expected after O(p^(1/2)) steps — and since the
smallest prime factor p of an RSA modulus satisfies p ≈ n^(1/2), the overall
expected cost is O(n^(1/4)) modular multiplications.

Special cases handled before the main loop
-------------------------------------------
- n ≤ 1                 → ValueError  (not a valid factorisation target)
- n even                → return 2    (cheapest possible factor)
- n prime               → return None (no non-trivial factor exists)
- n a perfect power b^k → return b    (factor found analytically)

Reference
---------
Pollard, J. M. (1975). "A Monte Carlo method for factorization."
BIT Numerical Mathematics, 15(3), 331–334.
https://doi.org/10.1007/BF01933667
"""

import math
import random

import sympy


# ---------------------------------------------------------------------------
# Private helper
# ---------------------------------------------------------------------------

def _f(x: int, c: int, n: int) -> int:
    return (x * x + c) % n


# ---------------------------------------------------------------------------
# Primary public API
# ---------------------------------------------------------------------------

def pollard_rho(n: int, max_iterations: int = 1_000_000) -> int | None:
    """Return a non-trivial factor of *n*, or None if the algorithm fails.

    The function applies the following guards in order before entering the
    main Floyd cycle-detection loop:

    1. ``n ≤ 1``  — invalid input, raises ValueError.
    2. ``n`` even  — trivially return 2.
    3. ``n`` prime — no factor exists, return None.
    4. ``n = b^k`` (perfect power) — return the base ``b`` as a factor.

    Args:
        n: Composite integer to factor.  Must be > 1.
        max_iterations: Maximum cycle-detection steps per random seed before
            trying a new seed.  Up to 20 seeds are tried in total.

    Returns:
        A non-trivial factor ``d`` satisfying ``1 < d < n``, or ``None`` if
        no factor was found within the iteration budget.

    Raises:
        ValueError: If ``n ≤ 1``.

    Example:
        >>> pollard_rho(8051) in {83, 97}
        True
    """
    if n <= 1:
        raise ValueError(f"n must be > 1, got {n}")

    if n % 2 == 0:
        return 2

    if sympy.isprime(n):
        return None

    # Perfect-power check: n = b^k  →  b is a non-trivial factor.
    # k ranges from 2 up to log₂(n) because 2^k ≤ n requires k ≤ log₂(n).
    for k in range(2, n.bit_length() + 1):
        root, exact = sympy.integer_nthroot(n, k)
        if exact and root > 1:
            return root
        if root < 2:
            break

    # Floyd's cycle detection — retry with fresh random seeds on failure.
    for _ in range(20):
        x = random.randint(2, n - 1)
        y = x
        c = random.randint(1, n - 1)

        for _ in range(max_iterations):
            x = _f(x, c, n)
            y = _f(_f(y, c, n), c, n)
            d = math.gcd(abs(x - y), n)

            if d == n:
                # The cycle collapsed: every element mapped to 0 mod p,
                # so GCD became trivial.  Restart with a different c.
                break
            if d > 1:
                return d

    return None


def factorize(n: int) -> list[int]:
    """Recursively factor *n* into a sorted list of prime factors.

    Uses ``pollard_rho`` to split composites, falling back to trial division
    for small numbers where Pollard's rho may be unreliable.

    Args:
        n: Positive integer to fully factor.  Returns ``[]`` for n ≤ 1.

    Returns:
        Sorted list of prime factors with repetition, e.g.::

            factorize(360)  →  [2, 2, 2, 3, 3, 5]

    Example:
        >>> import math
        >>> n = 2 * 3 * 5 * 7 * 11 * 13
        >>> math.prod(factorize(n)) == n
        True
    """
    if n <= 1:
        return []

    if sympy.isprime(n):
        return [n]

    factor = pollard_rho(n)

    if factor is None:
        # Trial-division fallback for numbers that stumped Pollard's rho.
        for p in range(2, min(10_000, n)):
            if n % p == 0:
                factor = p
                break
        else:
            return [n]  # treat as prime — best effort

    return sorted(factorize(factor) + factorize(n // factor))


# ---------------------------------------------------------------------------
# Backward-compatibility aliases
# (tests/test_pollard.py and __init__.py import these names)
# ---------------------------------------------------------------------------

pollard_rho_factor = pollard_rho
factorise = factorize


def _is_prime(n: int) -> bool:
    """Thin wrapper around ``sympy.isprime``; retained for backward compatibility."""
    return sympy.isprime(n)

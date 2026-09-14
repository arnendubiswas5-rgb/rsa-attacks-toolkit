"""
Tests for rsa_attacks.pollard_rho
"""

import math
import time

import pytest
import sympy

from rsa_attacks.pollard_rho import factorize, pollard_rho


# ---------------------------------------------------------------------------
# test_small_composites
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n, expected", [
    (15,  [3, 5]),
    (21,  [3, 7]),
    (91,  [7, 13]),
    (143, [11, 13]),
])
def test_small_composites(n, expected):
    result = factorize(n)
    assert result == expected, f"factorize({n}) = {result}, expected {expected}"
    assert math.prod(result) == n


# ---------------------------------------------------------------------------
# test_power_of_two
# ---------------------------------------------------------------------------

def test_power_of_two():
    # 1024 = 2^10
    result = factorize(1024)
    assert result == [2] * 10
    assert math.prod(result) == 1024


# ---------------------------------------------------------------------------
# test_prime_input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("p", [17, 104729])
def test_prime_input(p):
    # pollard_rho must return None for prime inputs — not raise, not return a factor.
    assert pollard_rho(p) is None


# ---------------------------------------------------------------------------
# test_semiprime_64bit
# ---------------------------------------------------------------------------

# 2^64 + 1 = F6 (6th Fermat number) = 274177 × 67280421310721
# Both factors are prime; smallest factor ≈ 2^18 → O(2^9) expected iterations.
_F6 = 18_446_744_073_709_551_617
_F6_FACTORS = [274_177, 67_280_421_310_721]


def test_semiprime_64bit():
    result = factorize(_F6)
    assert result == _F6_FACTORS, f"factorize(F6) = {result}"
    assert math.prod(result) == _F6
    assert all(sympy.isprime(f) for f in result)


# ---------------------------------------------------------------------------
# test_performance
# ---------------------------------------------------------------------------

# Two consecutive 32-bit primes — deterministic, avoids random prime generation
# at test time.  Their product is a ~64-bit semiprime Pollard's rho handles
# in well under a second (smallest factor p ≈ 2^31 → O(2^15.5) ≈ 46k steps).
_P = sympy.nextprime(2**31)   # 2147483659
_Q = sympy.nextprime(_P)      # 2147483693
_SEMIPRIME = _P * _Q


def test_performance():
    start = time.perf_counter()
    factors = factorize(_SEMIPRIME)
    elapsed = time.perf_counter() - start

    assert math.prod(factors) == _SEMIPRIME
    assert all(sympy.isprime(f) for f in factors)
    assert elapsed < 5.0, f"factorize took {elapsed:.3f}s, expected < 5s"

"""
Tests for rsa_attacks.common_factor
"""

import math
import time

import pytest
from Crypto.Util.number import getPrime

from rsa_attacks.common_factor import (
    RSAPublicKey,
    FactoredKey,
    find_shared_factors_naive,
    batch_gcd,
    attack,
    common_factor_attack,
)


# ---------------------------------------------------------------------------
# Shared deterministic prime pool for correctness tests
# 36 distinct primes: _PRIMES[0] = 101 is the shared prime for corpus tests.
# ---------------------------------------------------------------------------

_PRIMES = [
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
    199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283,
]

# 20-moduli corpus: 5 vulnerable (indices 0–4) sharing _PRIMES[0], 15 normal.
_SHARED_P   = _PRIMES[0]                                         # 101
_VULNERABLE = [_SHARED_P * _PRIMES[i] for i in range(1, 6)]     # 5 moduli
_NORMAL     = [_PRIMES[6 + 2*i] * _PRIMES[7 + 2*i]
               for i in range(15)]                               # 15 moduli
_CORPUS     = _VULNERABLE + _NORMAL                              # 20 total


# ---------------------------------------------------------------------------
# 1. test_naive_small
# ---------------------------------------------------------------------------

def test_naive_small():
    """[15, 21, 35] — every pair shares a prime; all three indices must appear."""
    # 15 = 3×5, 21 = 3×7, 35 = 5×7
    moduli = [15, 21, 35]
    result = find_shared_factors_naive(moduli)

    # All three indices are vulnerable.
    assert set(result.keys()) == {0, 1, 2}

    # find_shared_factors_naive records the first GCD found per index.
    # Iteration order: (0,1) → gcd(15,21)=3; (0,2) → gcd(15,35)=5; (1,2) → gcd(21,35)=7
    # Index 0 gets 3 (first pair), index 1 gets 3 (same pair), index 2 gets 5 (pair 0↔2).
    assert result[0] == 3
    assert result[1] == 3
    assert result[2] == 5

    # Each value must be a proper divisor of the corresponding modulus.
    for i, g in result.items():
        assert g > 1
        assert moduli[i] % g == 0
        assert g * (moduli[i] // g) == moduli[i]


# ---------------------------------------------------------------------------
# 2. test_batch_gcd_matches_naive
# ---------------------------------------------------------------------------

def test_batch_gcd_matches_naive():
    """20 semiprimes (5 vulnerable) — batch_gcd and naive agree on vulnerable indices."""
    naive = find_shared_factors_naive(_CORPUS)
    batch = batch_gcd(_CORPUS)

    naive_vuln = set(naive.keys())
    batch_vuln = {i for i, g in enumerate(batch) if g > 1}

    # Both algorithms must identify exactly the 5 vulnerable indices.
    assert naive_vuln == batch_vuln == {0, 1, 2, 3, 4}

    # Each factor returned by batch_gcd must actually divide the modulus.
    for i in batch_vuln:
        assert _CORPUS[i] % batch[i] == 0

    # Normal moduli must be clean in both algorithms.
    for i in range(5, 20):
        assert i not in naive_vuln
        assert batch[i] == 1


# ---------------------------------------------------------------------------
# 3. test_attack_recovers_factors
# ---------------------------------------------------------------------------

def test_attack_recovers_factors():
    """attack() on the 20-moduli corpus recovers correct p, q for all 5 vulnerable keys."""
    results = attack(_CORPUS)

    assert len(results) == 5
    assert {r["index"] for r in results} == {0, 1, 2, 3, 4}

    for r in results:
        n, p, q = r["n"], r["p"], r["q"]
        # Factorisation is correct.
        assert p * q == n
        # The shared prime is one of the two factors.
        assert p == _SHARED_P or q == _SHARED_P
        # Factors are coprime (not a trivial split).
        assert math.gcd(p, q) == 1
        # Factors are non-trivial.
        assert 1 < p < n and 1 < q < n


# ---------------------------------------------------------------------------
# 4. test_batch_gcd_performance
# ---------------------------------------------------------------------------

def test_batch_gcd_performance():
    """200 1024-bit semiprimes with 10 vulnerable — batch_gcd must finish in < 10s."""
    shared_p  = getPrime(512)
    vulnerable = [shared_p * getPrime(512) for _ in range(10)]
    normal     = [getPrime(512) * getPrime(512) for _ in range(190)]
    moduli     = vulnerable + normal   # vulnerable at indices 0–9

    start   = time.perf_counter()
    gcds    = batch_gcd(moduli)
    elapsed = time.perf_counter() - start

    assert elapsed < 10.0, (
        f"batch_gcd took {elapsed:.2f}s on 200×1024-bit moduli; expected < 10s"
    )

    # All 10 vulnerable moduli must be detected.
    assert all(gcds[i] > 1 for i in range(10)), (
        "Some vulnerable keys were not detected"
    )
    # All 190 normal moduli must be clean.
    assert all(gcds[i] == 1 for i in range(10, 200)), (
        "A non-vulnerable key was incorrectly flagged"
    )


# ---------------------------------------------------------------------------
# 5. test_no_vulnerable_keys
# ---------------------------------------------------------------------------

def test_no_vulnerable_keys():
    """10 semiprimes with 20 distinct prime factors — attack() must raise ValueError."""
    # Each semiprime uses a unique pair; no prime appears twice.
    moduli = [_PRIMES[2 * i] * _PRIMES[2 * i + 1] for i in range(10)]

    assert find_shared_factors_naive(moduli) == {}

    with pytest.raises(ValueError, match="No shared factors"):
        attack(moduli)


# ---------------------------------------------------------------------------
# Legacy tests — common_factor_attack (RSAPublicKey interface)
# ---------------------------------------------------------------------------

def _make_key(p: int, q: int, e: int = 65537) -> RSAPublicKey:
    return RSAPublicKey(n=p * q, e=e)


_P1, _Q1 = 101, 103   # shared prime = 101
_P2, _Q2 = 101, 107


class TestCommonFactorAttack:
    def test_detects_shared_prime(self):
        k1 = _make_key(_P1, _Q1)
        k2 = _make_key(_P2, _Q2)
        results = common_factor_attack([k1, k2])
        assert len(results) == 2
        ns = {fk.key.n for fk in results}
        assert k1.n in ns and k2.n in ns

    def test_factors_correct(self):
        k1, k2 = _make_key(_P1, _Q1), _make_key(_P2, _Q2)
        for fk in common_factor_attack([k1, k2]):
            assert fk.p * fk.q == fk.key.n
            assert fk.p > 1 and fk.q > 1

    def test_no_shared_factor(self):
        assert common_factor_attack([_make_key(101, 103), _make_key(107, 109)]) == []

    def test_single_key_returns_empty(self):
        assert common_factor_attack([_make_key(101, 103)]) == []

    def test_private_exponent_recoverable(self):
        k1, k2 = _make_key(_P1, _Q1), _make_key(_P2, _Q2)
        for fk in common_factor_attack([k1, k2]):
            d = fk.private_exponent()
            m = 42
            assert pow(pow(m, fk.key.e, fk.key.n), d, fk.key.n) == m

    def test_three_keys_one_shared(self):
        k1 = _make_key(101, 103)
        k2 = _make_key(101, 107)
        k3 = _make_key(109, 113)
        results = common_factor_attack([k1, k2, k3])
        ns = {fk.key.n for fk in results}
        assert k1.n in ns and k2.n in ns and k3.n not in ns

    def test_no_duplicate_entries(self):
        k1, k2 = _make_key(_P1, _Q1), _make_key(_P2, _Q2)
        ns = [fk.key.n for fk in common_factor_attack([k1, k2])]
        assert len(ns) == len(set(ns))


class TestBatchGcd:
    def test_finds_shared_prime(self):
        results = batch_gcd([101 * 103, 101 * 107, 109 * 113])
        assert results[0] == 101
        assert results[1] == 101
        assert results[2] == 1

    def test_empty_input(self):
        assert batch_gcd([]) == []

    def test_single_modulus_no_match(self):
        assert batch_gcd([101 * 103]) == [1]

    def test_all_independent(self):
        assert all(r == 1 for r in batch_gcd([101 * 103, 107 * 109, 113 * 127]))

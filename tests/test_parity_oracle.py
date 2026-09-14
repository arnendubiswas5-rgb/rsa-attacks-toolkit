"""
Tests for rsa_attacks.parity_oracle
"""

import pytest

from rsa_attacks.parity_oracle import Ranges, parity_oracle_attack
from rsa_attacks.parity_oracle import test_attack_locally as _run_attack_locally


def test_ranges_intersection():
    """Ranges((0,10),(20,30)) intersect Ranges((5,25)) == [(5,10),(20,25)]."""
    result = Ranges((0, 10), (20, 30)).intersection(Ranges((5, 25)))
    assert result._intervals == [(5, 10), (20, 25)]


def test_ranges_len():
    """Ranges((0,4),(10,14)) covers 5 + 5 = 10 integers."""
    assert len(Ranges((0, 4), (10, 14))) == 10


def test_oracle_small_key():
    """Attack recovers b'AB' from a fresh 128-bit key."""
    assert _run_attack_locally(key_size=128, message=b"AB") is True


def test_oracle_medium_key():
    """Attack recovers the default message from a fresh 256-bit key."""
    assert _run_attack_locally(key_size=256) is True


def test_oracle_max_iterations():
    """A broken oracle (always 0) with max_iterations=5 raises RuntimeError.

    n=3233 is 12-bit; convergence requires ~12 oracle queries.  Five iterations
    are far too few, so the RuntimeError safety limit is triggered.
    """
    with pytest.raises(RuntimeError, match="did not converge"):
        parity_oracle_attack(
            n=3233,
            e=17,
            c=pow(42, 17, 3233),
            oracle=lambda c: 0,
            max_iterations=5,
        )

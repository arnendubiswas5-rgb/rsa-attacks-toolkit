"""
Tests for rsa_attacks.utils
"""

import random
import tempfile
import os

import pytest
from Crypto.PublicKey import RSA

from rsa_attacks.utils import (
    load_public_key,
    load_private_key,
    reconstruct_private_key,
    int_to_bytes,
    bytes_to_int,
)


# ---------------------------------------------------------------------------
# reconstruct_private_key
# ---------------------------------------------------------------------------

class TestReconstructPrivateKey:
    @pytest.fixture(scope="class")
    @classmethod
    def rsa_components(cls):
        """Generate a real 1024-bit RSA key via pycryptodome once per class."""
        key = RSA.generate(1024)
        return {
            "n": int(key.n),
            "e": int(key.e),
            "d": int(key.d),
            "p": int(key.p),
            "q": int(key.q),
        }

    def test_returns_all_keys(self, rsa_components):
        c = rsa_components
        params = reconstruct_private_key(c["n"], c["e"], c["p"], c["q"])
        assert set(params.keys()) == {"n", "e", "d", "p", "q", "dp", "dq", "qinv"}

    def test_d_matches_pycryptodome(self, rsa_components):
        c = rsa_components
        params = reconstruct_private_key(c["n"], c["e"], c["p"], c["q"])
        # pycryptodome computes d mod lcm(p-1, q-1); ours uses phi = (p-1)(q-1).
        # Both are valid private exponents: verify via encrypt-then-decrypt.
        m = 0xDEADBEEF
        ciphertext = pow(m, c["e"], c["n"])
        assert pow(ciphertext, params["d"], params["n"]) == m

    def test_encrypt_decrypt_roundtrip(self, rsa_components):
        c = rsa_components
        params = reconstruct_private_key(c["n"], c["e"], c["p"], c["q"])
        for m in [0, 1, 2, 1337, 2**16, c["n"] - 1]:
            ciphertext = pow(m, params["e"], params["n"])
            assert pow(ciphertext, params["d"], params["n"]) == m

    def test_crt_parameters_correct(self, rsa_components):
        c = rsa_components
        params = reconstruct_private_key(c["n"], c["e"], c["p"], c["q"])
        d, p, q = params["d"], params["p"], params["q"]
        assert params["dp"] == d % (p - 1)
        assert params["dq"] == d % (q - 1)
        assert (params["qinv"] * q) % p == 1

    def test_p_q_order_invariant(self, rsa_components):
        """reconstruct_private_key(n, e, p, q) and (n, e, q, p) must both work."""
        c = rsa_components
        params_pq = reconstruct_private_key(c["n"], c["e"], c["p"], c["q"])
        params_qp = reconstruct_private_key(c["n"], c["e"], c["q"], c["p"])
        m = 42
        ct = pow(m, c["e"], c["n"])
        assert pow(ct, params_pq["d"], params_pq["n"]) == m
        assert pow(ct, params_qp["d"], params_qp["n"]) == m

    def test_raises_wrong_factors(self, rsa_components):
        c = rsa_components
        with pytest.raises(ValueError, match="does not equal n"):
            reconstruct_private_key(c["n"], c["e"], c["p"], c["p"])

    def test_raises_e_not_coprime(self, rsa_components):
        c = rsa_components
        # e=1 is always coprime, but e = (p-1) shares a factor with phi
        bad_e = c["p"] - 1
        with pytest.raises(ValueError, match="not invertible|not coprime"):
            reconstruct_private_key(c["n"], bad_e, c["p"], c["q"])

    def test_raises_small_factors(self, rsa_components):
        c = rsa_components
        with pytest.raises(ValueError, match="must both be > 1"):
            reconstruct_private_key(c["n"], c["e"], 1, c["q"])


# ---------------------------------------------------------------------------
# int_to_bytes / bytes_to_int round-trip
# ---------------------------------------------------------------------------

class TestIntBytesRoundtrip:
    def test_zero(self):
        assert bytes_to_int(int_to_bytes(0)) == 0

    def test_one(self):
        assert bytes_to_int(int_to_bytes(1)) == 1

    def test_power_of_two_boundary(self):
        for exp in [7, 8, 15, 16, 23, 24, 31, 32, 63, 64]:
            x = 2**exp
            assert bytes_to_int(int_to_bytes(x)) == x

    def test_random_integers(self):
        rng = random.Random(42)
        for _ in range(200):
            bit_len = rng.randint(1, 4096)
            x = rng.getrandbits(bit_len)
            assert bytes_to_int(int_to_bytes(x)) == x

    def test_explicit_length_pads(self):
        assert int_to_bytes(1, length=4) == b"\x00\x00\x00\x01"
        assert int_to_bytes(256, length=4) == b"\x00\x00\x01\x00"

    def test_explicit_length_exact(self):
        assert int_to_bytes(255, length=1) == b"\xff"

    def test_length_too_small_raises(self):
        with pytest.raises(ValueError, match="too small"):
            int_to_bytes(256, length=1)  # 256 needs 2 bytes

    def test_negative_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            int_to_bytes(-1)

    def test_empty_bytes_raises(self):
        with pytest.raises(ValueError, match="empty"):
            bytes_to_int(b"")

    def test_known_encoding(self):
        assert int_to_bytes(0x0102) == b"\x01\x02"
        assert int_to_bytes(0xDEADBEEF) == b"\xde\xad\xbe\xef"


# ---------------------------------------------------------------------------
# load_public_key
# ---------------------------------------------------------------------------

class TestLoadPublicKey:
    @pytest.fixture()
    def tmp_pub_pem(self, tmp_path):
        """Write a fresh 2048-bit public key to a temp file and yield its path."""
        key = RSA.generate(2048)
        pem = key.publickey().export_key("PEM")
        pem_path = tmp_path / "pub.pem"
        pem_path.write_bytes(pem)
        return str(pem_path), int(key.n), int(key.e)

    @pytest.fixture()
    def tmp_priv_pem(self, tmp_path):
        """Write a fresh 2048-bit private key to a temp file and yield its path."""
        key = RSA.generate(2048)
        pem = key.export_key("PEM")
        pem_path = tmp_path / "priv.pem"
        pem_path.write_bytes(pem)
        return str(pem_path), int(key.n), int(key.e), int(key.d)

    def test_n_and_e_match(self, tmp_pub_pem):
        path, expected_n, expected_e = tmp_pub_pem
        n, e = load_public_key(path)
        assert n == expected_n
        assert e == expected_e

    def test_returns_python_ints(self, tmp_pub_pem):
        path, _, _ = tmp_pub_pem
        n, e = load_public_key(path)
        assert type(n) is int
        assert type(e) is int

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_public_key("/nonexistent/path/pub.pem")

    def test_invalid_pem_raises(self, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text("this is not a PEM file")
        with pytest.raises(ValueError, match="Cannot parse"):
            load_public_key(str(bad))

    def test_private_key_file_rejected(self, tmp_priv_pem):
        path, _, _, _ = tmp_priv_pem
        with pytest.raises(ValueError, match="private key"):
            load_public_key(path)

    def test_load_private_key_n_e_d_match(self, tmp_priv_pem):
        path, expected_n, expected_e, expected_d = tmp_priv_pem
        n, e, d = load_private_key(path)
        assert n == expected_n
        assert e == expected_e
        assert d == expected_d

    def test_load_private_key_rejects_public(self, tmp_pub_pem):
        path, _, _ = tmp_pub_pem
        with pytest.raises(ValueError, match="private key"):
            load_private_key(path)


# ---------------------------------------------------------------------------
# test_bad_input (ValueError on negative modulus)
# ---------------------------------------------------------------------------

class TestBadInput:
    def test_negative_n_in_reconstruct(self):
        with pytest.raises(ValueError):
            reconstruct_private_key(n=-1, e=65537, p=3, q=5)

    def test_int_to_bytes_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            int_to_bytes(-999)

    def test_bytes_to_int_empty(self):
        with pytest.raises(ValueError, match="empty"):
            bytes_to_int(b"")

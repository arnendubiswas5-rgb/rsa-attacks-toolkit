"""
rsa_attacks — Educational RSA cryptography attack toolkit.

Modules:
    pollard_rho    : Pollard's rho factorisation algorithm
    common_factor  : GCD-based attack when public moduli share a prime
    parity_oracle  : Chosen-ciphertext parity oracle decryption
    utils          : Shared RSA helpers and arithmetic primitives
"""

from .pollard_rho import pollard_rho, pollard_rho_factor
from .common_factor import common_factor_attack
from .parity_oracle import parity_oracle_attack

__all__ = [
    "pollard_rho",
    "pollard_rho_factor",
    "common_factor_attack",
    "parity_oracle_attack",
]

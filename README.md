# rsa-attacks-toolkit

Educational Python implementations of three classical RSA cryptanalysis techniques.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)

---

## Overview

This toolkit implements three well-studied attacks against RSA, each exploiting a
different class of real-world weakness:

| Module | Attack | Exploits |
|---|---|---|
| `pollard_rho` | Pollard's rho factorisation | Small or smooth prime factors |
| `common_factor` | Shared-prime / batch-GCD | Keys generated with insufficient entropy |
| `parity_oracle` | LSB parity oracle decryption | Decryption oracles on unpadded ciphertext |

**Why these attacks matter:**

- **Heninger et al. (2012)** scanned 11 million TLS and SSH hosts and found that
  approximately 0.2% of RSA public keys shared a prime factor with another key —
  meaning both corresponding private keys could be computed instantly with a single
  GCD. The root cause was entropy-starved random number generators on embedded
  devices (routers, firewalls, VPN appliances).

- **Bleichenbacher (1998)** demonstrated that SSL servers using PKCS#1 v1.5 padding
  would leak one bit of information per decryption attempt through error messages alone.
  Roughly one million adaptive chosen-ciphertext queries were sufficient to recover a
  session key. The attack affected Netscape, IIS, and dozens of other servers.

- **Pollard (1975)** introduced his rho algorithm as a probabilistic method to find
  factors in O(n^(1/4)) time. It remains the fastest general-purpose algorithm for
  factors up to roughly 10^20 and is the basis for the factorisation step in many
  real-world cryptanalysis tools.

Each module is self-contained, documented with inline references, and tested.

---

## Installation

```bash
git clone <repo-url>
cd rsa-attacks-toolkit

python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
pip install -e .
```

**Platform note:** `gmpy2` requires the GMP library.

- Ubuntu/Debian: `sudo apt install libgmp-dev libmpfr-dev libmpc-dev`
- macOS (Homebrew): `brew install gmp`
- Windows: `conda install -c conda-forge gmpy2` or use a pre-built wheel from PyPI

---

## Quick Start

### Pollard's rho — factor a semiprime

```python
from rsa_attacks import pollard_rho
from rsa_attacks.pollard_rho import factorize

# Return one non-trivial factor of n
n = 2_147_483_659 * 2_147_483_693   # product of two 32-bit primes
print(pollard_rho(n))               # e.g. 2147483659

# Full prime factorisation (sorted list)
print(factorize(360))               # [2, 2, 2, 3, 3, 5]
```

### Common-factor / batch GCD — detect shared primes across many keys

```python
from rsa_attacks.common_factor import attack, batch_gcd

# High-level: recover factors for every vulnerable modulus
results = attack([n0, n1, n2, ...])          # list of RSA moduli as integers
for r in results:
    print(f"Key #{r['index']}  p={hex(r['p'])[:18]}…  q={hex(r['q'])[:18]}…")

# Low-level: just find the shared factors (O(N log² N))
gcds = batch_gcd([n0, n1, n2, ...])         # list[int], 1 = no shared factor
```

Run the bundled end-to-end demo against the included sample key dataset:

```bash
# Generate 100 keys (10 share a prime)
python scripts/generate_shared_prime_keys.py

# Run the batch-GCD attack and print a precision report
python scripts/run_common_factor_attack.py
```

Expected output (excerpt):

```
Keys scanned      : 100
Vulnerable found  : 10
Time taken        : 0.028s
Recall            : 10/10 (100%)
False positives   : 0/100 (0.00%)
```

### Parity oracle — recover plaintext one bit at a time

```python
from rsa_attacks.parity_oracle import parity_oracle_attack, SimulatedOracle

# Build a simulated oracle from raw key integers (n, e, d)
oracle = SimulatedOracle(n, e, d)

# Encrypt with raw (textbook) RSA, then recover the plaintext
c = pow(m, e, n)
recovered = parity_oracle_attack(n, e, c, oracle)
assert recovered == m

# Self-contained smoke test (generates a fresh 256-bit key internally)
from rsa_attacks.parity_oracle import test_attack_locally
print(test_attack_locally())    # True
```

---

## Project Structure

```
rsa-attacks-toolkit/
├── rsa_attacks/
│   ├── __init__.py          # Package exports
│   ├── common_factor.py     # Batch-GCD (Bernstein) + naive O(N²) pairwise GCD
│   ├── parity_oracle.py     # LSB oracle attack, Ranges interval arithmetic
│   ├── pollard_rho.py       # Pollard's rho + full recursive factorisation
│   └── utils.py             # PEM I/O, CRT reconstruction, int<->bytes helpers
├── scripts/
│   ├── generate_shared_prime_keys.py  # Create a sample vulnerable key dataset
│   └── run_common_factor_attack.py    # End-to-end common-factor attack demo
├── tests/
│   ├── test_common_factor.py
│   ├── test_parity_oracle.py
│   ├── test_pollard.py
│   └── test_utils.py
├── data/
│   └── sample_keys/         # 100 PEM files; 10 share a prime (manifest.json)
├── requirements.txt
└── setup.py
```

---

## Testing

```bash
pytest tests/ -v
```

All tests are self-contained — no external services or network access required.
The performance tests (`test_batch_gcd_performance`, `test_performance`) assert
wall-clock bounds and are designed to pass on any modern laptop.

```bash
# Run a single module's tests
pytest tests/test_common_factor.py -v

# With coverage
pytest tests/ -v --cov=rsa_attacks
```

---

## References

1. Pollard, J. M. (1975). "A Monte Carlo method for factorization."
   *BIT Numerical Mathematics*, 15(3), 331–334.

2. Heninger, N., Durumeric, Z., Wustrow, E., & Halderman, J. A. (2012).
   "Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices."
   *USENIX Security Symposium 2012.*
   https://factorable.net/paper.html

3. Bleichenbacher, D. (1998). "Chosen Ciphertext Attacks Against Protocols Based
   on the RSA Encryption Standard PKCS #1."
   *CRYPTO 1998*, LNCS 1462, pp. 1–12.

4. Bernstein, D. J. (2004). "How to find smooth parts of integers."
   https://cr.yp.to/factorization/smoothparts-20040510.pdf

5. Boneh, D. (1999). "Twenty Years of Attacks on the RSA Cryptosystem."
   *Notices of the AMS*, 46(2), 203–213.

6. Manger, J. (2001). "A Chosen Ciphertext Attack on RSA Optimal Asymmetric
   Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0."
   *CRYPTO 2001*, LNCS 2139, pp. 230–238.

---

## Security Notice

> This toolkit is for **educational purposes and authorized security testing only**.
> Do not use it against systems you do not own or have explicit written permission
> to test. Unauthorized use may violate computer fraud and abuse laws in your
> jurisdiction.

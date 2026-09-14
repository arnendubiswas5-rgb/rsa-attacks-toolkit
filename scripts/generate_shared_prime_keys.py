"""
Generate a mixed RSA key dataset for common-factor attack demonstrations.

Produces N RSA private-key PEM files in the output directory.
A configurable subset of those keys share a single prime factor p,
making them instantly factorable by a GCD attack once two of them are seen.

Output
------
  key_000.pem … key_099.pem   Private-key PEM files (PKCS#1 format)
  manifest.json               Records factor details for vulnerable keys only

Usage
-----
  python scripts/generate_shared_prime_keys.py
  python scripts/generate_shared_prime_keys.py --count 50 --vulnerable 5
  python scripts/generate_shared_prime_keys.py --bits 2048 --out /tmp/keys
"""

import argparse
import json
import math
import sys
from pathlib import Path

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime

E = 65537  # standard public exponent


# ---------------------------------------------------------------------------
# Key construction helpers
# ---------------------------------------------------------------------------

def _generate_q(shared_p: int, half_bits: int) -> int:
    """Return a prime q suitable for pairing with shared_p.

    Retries until q ≠ shared_p and gcd(E, φ(n)) = 1, which is almost always
    true on the first attempt for random 512-bit primes.
    """
    while True:
        q = getPrime(half_bits)
        if q != shared_p and math.gcd(E, (shared_p - 1) * (q - 1)) == 1:
            return q


def _build_vulnerable_key(shared_p: int, q: int) -> RSA.RsaKey:
    """Construct a pycryptodome RsaKey from known prime factors.

    RSA.construct expects (n, e, d, p, q, u) where
        u = p⁻¹ mod q   (pycryptodome's CRT coefficient convention).
    """
    n   = shared_p * q
    phi = (shared_p - 1) * (q - 1)
    d   = pow(E, -1, phi)
    u   = pow(shared_p, -1, q)
    return RSA.construct((n, E, d, shared_p, q, u))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate(count: int, n_vulnerable: int, bits: int, out_dir: Path) -> None:
    if n_vulnerable > count:
        raise ValueError(f"--vulnerable ({n_vulnerable}) cannot exceed --count ({count})")
    if bits < 512 or bits % 2 != 0:
        raise ValueError(f"--bits must be an even integer >= 512, got {bits}")

    out_dir.mkdir(parents=True, exist_ok=True)
    half_bits = bits // 2

    # Shared prime used by all vulnerable keys — generated once.
    print(f"Generating shared prime ({half_bits} bits)…")
    shared_p = getPrime(half_bits)
    print(f"  p = {hex(shared_p)[:18]}…")

    # First n_vulnerable indices are vulnerable; the rest are normal.
    vulnerable_indices = set(range(n_vulnerable))
    manifest: dict[str, dict] = {}

    print(f"\nGenerating {count} keys ({n_vulnerable} vulnerable) -> {out_dir}")
    for i in range(count):
        filename = f"key_{i:03d}.pem"
        out_path = out_dir / filename

        if i in vulnerable_indices:
            q   = _generate_q(shared_p, half_bits)
            key = _build_vulnerable_key(shared_p, q)
            n   = key.n
            manifest[filename] = {
                "vulnerable": True,
                "n": hex(int(n)),
                "p": hex(shared_p),
                "q": hex(q),
            }
            tag = " [VULNERABLE]"
        else:
            key = RSA.generate(bits)
            tag = ""

        out_path.write_bytes(key.export_key("PEM"))
        print(f"  [{i + 1:3d}/{count}] {filename}{tag}")

    # Write manifest — vulnerable keys only, as specified.
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\nWrote {count} PEM files and manifest.json to {out_dir}")
    print(f"Vulnerable keys  : {n_vulnerable}  (indices 000–{n_vulnerable - 1:03d})")
    print(f"Normal keys      : {count - n_vulnerable}")
    print(f"Shared prime p   : {hex(shared_p)[:26]}…")


def _parse_args() -> argparse.Namespace:
    # Resolve the default output directory relative to this script's location
    # so the script works regardless of the working directory it is invoked from.
    default_out = Path(__file__).parent.parent / "data" / "sample_keys"

    parser = argparse.ArgumentParser(
        description="Generate a mixed RSA key dataset for common-factor attack demos.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count",      type=int, default=100,          help="Total number of keys to generate")
    parser.add_argument("--vulnerable", type=int, default=10,           help="Number of keys that share a prime")
    parser.add_argument("--bits",       type=int, default=1024,         help="RSA modulus size in bits")
    parser.add_argument("--out",        type=Path, default=default_out, help="Output directory for PEM files")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        generate(
            count=args.count,
            n_vulnerable=args.vulnerable,
            bits=args.bits,
            out_dir=args.out,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

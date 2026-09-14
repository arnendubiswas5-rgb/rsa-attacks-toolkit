"""
Run the common-factor (shared-prime) attack against a directory of RSA PEM files.

Loads all *.pem files, extracts their moduli, and runs batch_gcd via attack().
Results are cross-referenced against manifest.json (if present) and a precision
report is printed.

Usage
-----
  python scripts/run_common_factor_attack.py
  python scripts/run_common_factor_attack.py --keys /path/to/keys
"""

import argparse
import json
import sys
import time
from pathlib import Path

from Crypto.PublicKey import RSA

_DEFAULT_KEY_DIR = Path(__file__).parent.parent / "data" / "sample_keys"


def main(key_dir: Path) -> None:
    from rsa_attacks.common_factor import attack

    # ------------------------------------------------------------------
    # Step 1: Load PEM files (sorted for stable index mapping).
    # ------------------------------------------------------------------
    pem_files = sorted(key_dir.glob("*.pem"))
    if not pem_files:
        print(f"No PEM files found in {key_dir}", file=sys.stderr)
        sys.exit(1)

    moduli: list[int] = []
    filenames: list[str] = []
    for pem_path in pem_files:
        key = RSA.import_key(pem_path.read_bytes())
        moduli.append(int(key.n))
        filenames.append(pem_path.name)

    # ------------------------------------------------------------------
    # Step 2: Load manifest (ground truth for vulnerable keys).
    # ------------------------------------------------------------------
    manifest_path = key_dir / "manifest.json"
    if manifest_path.exists():
        manifest: dict = json.loads(manifest_path.read_text())
        expected_vulnerable = {
            fname for fname, info in manifest.items() if info.get("vulnerable")
        }
    else:
        manifest = {}
        expected_vulnerable = set()

    # ------------------------------------------------------------------
    # Step 3: Run the batch-GCD attack.
    # ------------------------------------------------------------------
    start = time.perf_counter()
    try:
        results = attack(moduli)
    except ValueError as exc:
        print(f"No shared factors found: {exc}")
        sys.exit(0)
    elapsed = time.perf_counter() - start

    # ------------------------------------------------------------------
    # Step 4: Cross-reference results with manifest.
    # ------------------------------------------------------------------
    found_names = {filenames[r["index"]] for r in results}
    true_positives  = found_names & expected_vulnerable
    false_positives = found_names - expected_vulnerable
    false_negatives = expected_vulnerable - found_names

    if expected_vulnerable:
        recall  = len(true_positives) / len(expected_vulnerable)
        fp_rate = len(false_positives) / len(moduli)
        recall_str  = f"{len(true_positives)}/{len(expected_vulnerable)} ({recall:.0%})"
        fp_str      = f"{len(false_positives)}/{len(moduli)} ({fp_rate:.2%})"
    else:
        recall_str = "N/A (no manifest)"
        fp_str     = "N/A (no manifest)"

    # ------------------------------------------------------------------
    # Step 5: Print report.
    # ------------------------------------------------------------------
    print(f"Keys scanned      : {len(moduli)}")
    print(f"Vulnerable found  : {len(results)}")
    print(f"Time taken        : {elapsed:.3f}s")
    print(f"Recall            : {recall_str}")
    print(f"False positives   : {fp_str}")
    print()

    col_file   = 16
    col_status = 14
    col_hex    = 26
    header = (
        f"{'File':<{col_file}}  {'Status':<{col_status}}  "
        f"{'p (hex, truncated)':<{col_hex}}  q (hex, truncated)"
    )
    print(header)
    print("-" * 90)
    for r in sorted(results, key=lambda x: x["index"]):
        fname  = filenames[r["index"]]
        status = "TRUE POS" if fname in expected_vulnerable else "FALSE POS"
        p_hex  = hex(r["p"])[:col_hex]
        q_hex  = hex(r["q"])[:col_hex]
        print(f"{fname:<{col_file}}  {status:<{col_status}}  {p_hex:<{col_hex}}  {q_hex}")

    if false_negatives:
        print()
        print("Missed (false negatives):")
        for fname in sorted(false_negatives):
            print(f"  {fname}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run common-factor attack on a directory of RSA key PEM files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--keys",
        type=Path,
        default=_DEFAULT_KEY_DIR,
        help="Directory containing *.pem files and manifest.json",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    main(args.keys)

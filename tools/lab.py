"""Reproducible diagnostics and a positive-control attack. No security scores."""

import argparse
from collections import Counter
import json
import random
from statistics import mean
import time

from cairn.core import Cipher


def diagnostics(samples: int, seed: int) -> dict:
    if samples < 1:
        raise ValueError("samples must be positive")
    rng = random.Random(seed)  # Public, reproducible experiment data only.
    key = rng.randbytes(32)
    inputs = [rng.randbytes(16) for _ in range(samples)]
    rows = []
    for rounds in (1, 2, 4, 8, 16):
        cipher = Cipher(key, rounds)
        distances = []
        for plain in inputs:
            original = int.from_bytes(cipher.encrypt_block(plain), "big")
            changed = (int.from_bytes(plain, "big") ^ (1 << rng.randrange(128))).to_bytes(16, "big")
            distances.append((original ^ int.from_bytes(cipher.encrypt_block(changed), "big")).bit_count())
        rows.append({"rounds": rounds, "trials": samples, "mean_changed_bits": mean(distances),
                     "minimum": min(distances), "maximum": max(distances)})
    cipher = Cipher(key)
    plain = rng.randbytes(16)
    original = int.from_bytes(cipher.encrypt_block(plain), "big")
    key_distances = []
    for bit in range(256):
        changed_key = (int.from_bytes(key, "big") ^ (1 << bit)).to_bytes(32, "big")
        key_distances.append((original ^ int.from_bytes(Cipher(changed_key).encrypt_block(plain), "big")).bit_count())
    # Fixed input difference; list counts, not a p-value or a security verdict.
    differences = Counter()
    delta = 1 << 64
    for plain in inputs:
        changed = (int.from_bytes(plain, "big") ^ delta).to_bytes(16, "big")
        difference = int.from_bytes(cipher.encrypt_block(plain), "big") ^ int.from_bytes(cipher.encrypt_block(changed), "big")
        differences[f"{difference:032x}"] += 1
    start = time.perf_counter()
    for plain in inputs:
        cipher.encrypt_block(plain)
    elapsed = time.perf_counter() - start
    return {"seed": seed, "plaintext_avalanche": rows,
            "key_avalanche": {"trials": 256, "mean_changed_bits": mean(key_distances),
                              "minimum": min(key_distances), "maximum": max(key_distances)},
            "fixed_difference": {"input_xor": f"{delta:032x}", "pairs": samples,
                                 "distinct_output_differences": len(differences), "top_counts": differences.most_common(5)},
            "performance": {"blocks": samples, "seconds": elapsed,
                            "bytes_per_second": 16 * samples / elapsed},
            "interpretation": "Sanity diagnostics only. Diffusion and no sampled collisions do not establish security."}


def positive_control(samples: int, seed: int) -> dict:
    rng = random.Random(seed)
    # The attack receives only oracle access. It never uses this key.
    cipher = Cipher(rng.randbytes(32), 1)
    delta = 0x0100000000000000
    hits = 0
    for _ in range(samples):
        plain = rng.randbytes(16)
        changed = (int.from_bytes(plain[:8], "big") ^ delta).to_bytes(8, "big") + plain[8:]
        first, second = cipher.encrypt_block(plain), cipher.encrypt_block(changed)
        hits += first[:8] == second[:8] and int.from_bytes(first[8:], "big") ^ int.from_bytes(second[8:], "big") == delta
    return {"attack": "one-round chosen-plaintext structural distinguisher", "rounds": 1,
            "pairs": samples, "queries": samples * 2, "matching_pairs": hits,
            "expected_random_permutation_probability_per_pair": "1 / (2^128 - 1)",
            "scope": "Reduced-round positive control; not key recovery or a 16-round break."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", choices=("diagnostics", "positive-control"))
    parser.add_argument("--samples", type=int, default=256)
    parser.add_argument("--seed", type=int, default=20261017)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    operation = diagnostics if args.experiment == "diagnostics" else positive_control
    print(json.dumps(operation(args.samples, args.seed), indent=2))


if __name__ == "__main__":
    main()

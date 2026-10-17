"""Targeted held-out validation of fixed analytical predictions and one trail.

NumPy dependency already listed in requirements.txt. Does not search or tune.
"""
import argparse
import json
from pathlib import Path
import time

import numpy as np

from cairn.core import Cipher, expand_key
from cryptanalysis.reproduce import enc, vr
from cryptanalysis.structural import PUBLIC_KEYS, four_round_parity, mix, finish


def check(source, pairs=1 << 20):
    rng = np.random.default_rng(0xC417B0)
    selected = next(run for run in source["searches"] if run["key_name"] == "selected4"
                    and run["input_label"] == "selected_skeleton")
    snapshot = selected["snapshots"][3]
    rows = []
    for name, key in PUBLIC_KEYS.items():
        rk = expand_key(key)
        parity_hits = trail_hits = endpoint_hits = old_endpoint_hits = 0
        first_witness = None
        scalar_comparisons = 0
        for offset in range(0, pairs, 1 << 16):
            n = min(1 << 16, pairs - offset)
            left = rng.integers(0, 1 << 64, n, dtype=np.uint64)
            right = rng.integers(0, 1 << 64, n, dtype=np.uint64)
            a, _ = enc(left, right, rk[:4])
            b, _ = enc(left ^ np.uint64(1 << 63), right, rk[:4])
            # The original fixed parity mask, not chosen from this sample.
            delta = a ^ b
            parity = np.zeros(n, dtype=np.uint64)
            for j in range(64):
                if (0x9DA28B88C58AB380 >> j) & 1:
                    parity ^= (delta >> np.uint64(j)) & np.uint64(1)
            parity_hits += int(np.count_nonzero(parity))
            if name != "selected4":
                continue
            dl, dr = selected["input_difference"]
            l, r = left.copy(), right.copy()
            lp, rp = l ^ np.uint64(dl), r ^ np.uint64(dr)
            follows = np.ones(n, dtype=bool)
            for (u, v), expected in zip(rk[:4], snapshot["trail"]):
                x, xp = r + np.uint64(u), rp + np.uint64(u)
                y, yp = x ^ vr(x, 13) ^ vr(x, 37), xp ^ vr(xp, 13) ^ vr(xp, 37)
                z, zp = y + np.uint64(v), yp + np.uint64(v)
                follows &= ((r ^ rp) == np.uint64(expected["alpha"]))
                follows &= ((x ^ xp) == np.uint64(expected["beta"]))
                follows &= ((z ^ zp) == np.uint64(expected["gamma"]))
                f, fp = vr(z ^ vr(z, 17) ^ vr(z, 41), 29), vr(zp ^ vr(zp, 17) ^ vr(zp, 41), 29)
                l, r, lp, rp = r, l ^ f, rp, lp ^ fp
            endpoint = ((l ^ lp) == np.uint64(snapshot["output_difference"][0])) & ((r ^ rp) == np.uint64(snapshot["output_difference"][1]))
            # Compare the OLD published endpoint under exactly the same inputs.
            old_l, old_r = dl, dr
            for _ in range(4):
                old_l, old_r = old_r, old_l ^ finish(mix(old_r))
            old_endpoint_hits += int(np.count_nonzero(((l ^ lp) == np.uint64(old_l)) & ((r ^ rp) == np.uint64(old_r))))
            trail_hits += int(np.count_nonzero(follows))
            endpoint_hits += int(np.count_nonzero(endpoint))
            # Every new trail hit is independently replayed through frozen scalar.
            for j in np.flatnonzero(follows):
                plain = (int(left[j]) << 64) | int(right[j])
                other = plain ^ (dl << 64) ^ dr
                cipher = Cipher(key, 4)
                c = int.from_bytes(cipher.encrypt_block(plain.to_bytes(16, "big")), "big")
                cp = int.from_bytes(cipher.encrypt_block(other.to_bytes(16, "big")), "big")
                assert (c ^ cp) == ((snapshot["output_difference"][0] << 64) | snapshot["output_difference"][1])
                scalar_comparisons += 2
                if first_witness is None:
                    first_witness = f"{plain:032x}"
        row = {"key_name": name, "pairs": pairs, "four_round_original_parity_ones": parity_hits,
               "analytical_parity_interval": four_round_parity(key)}
        if name == "selected4":
            row.update({"new_internal_trail_hits": trail_hits, "new_endpoint_differential_hits": endpoint_hits,
                        "old_endpoint_differential_hits": old_endpoint_hits,
                        "new_endpoint_difference": snapshot["output_difference"],
                        "old_endpoint_difference": [old_l, old_r], "input_difference": [dl, dr],
                        "first_plaintext_witness": first_witness,
                        "frozen_scalar_encryptions_of_new_trail_hits": scalar_comparisons})
        rows.append(row)
    return {"numpy_seed": 0xC417B0, "observations": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("cryptanalysis/structural-results.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    start = time.perf_counter()
    result = check(json.loads(args.source.read_text(encoding="utf-8")))
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {args.output.name}; elapsed {time.perf_counter() - start:.2f}s.")


if __name__ == "__main__":
    main()

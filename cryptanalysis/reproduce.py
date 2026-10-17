"""Portable reproductions adapted from the 2026-10-17 local audit.

Only public deterministic test keys. No contestant folders or operator files.
Run: python -m cryptanalysis.reproduce --output replay.json
"""
import argparse
import json
import math
import hashlib
from pathlib import Path
import random
import time
import numpy as np
from cairn.core import Cipher, expand_key, round_function, rol

MASK = (1 << 64) - 1
HIGH = 1 << 63
BIT_MASK = 0x9DA28B88C58AB380


def ror(x, n):
    return rol(x, 64 - n)


def mix(x, a, b):
    return x ^ rol(x, a) ^ rol(x, b)


def undo_output(x):
    x = ror(x, 29)
    for _ in range(7):
        x = mix(x, 17, 41)
    return x


def vr(x, n):
    return (x << np.uint64(n)) | (x >> np.uint64(64 - n))


def enc(left, right, keys):
    for u, v in keys:
        x = right + np.uint64(u)
        x = x ^ vr(x, 13) ^ vr(x, 37)
        x = x + np.uint64(v)
        x = x ^ vr(x, 17) ^ vr(x, 41)
        left, right = right, left ^ vr(x, 29)
    return left, right


def vunmix(x):
    x = vr(x, 35)
    for _ in range(7):
        x = x ^ vr(x, 17) ^ vr(x, 41)
    return x


def skeleton(x):
    return rol(mix(mix(x, 13, 37), 17, 41), 29)


def linear_algebra():
    def order(function):
        images = [1 << bit for bit in range(64)]
        for n in range(1, 65):
            images = [function(x) for x in images]
            if images == [1 << bit for bit in range(64)]:
                return n
        return None

    def nullity(images):
        pivots = {}
        for x in images:
            while x:
                bit = x.bit_length() - 1
                if bit in pivots:
                    x ^= pivots[bit]
                else:
                    pivots[bit] = x
                    break
        return len(images) - len(pivots)

    def feistel(x):
        return ((x & MASK) << 64) | ((x >> 64) ^ skeleton(x & MASK))

    kernels = {}
    for n in (3, 12, 16, 48):
        images = []
        for bit in range(128):
            x = 1 << bit
            for _ in range(n):
                x = feistel(x)
            images.append(x ^ (1 << bit))
        kernels[str(n)] = nullity(images)
    return {"L1_order": order(lambda x: mix(x, 13, 37)),
            "L2_order": order(lambda x: mix(x, 17, 41)),
            "M_order": order(skeleton), "skeleton_fixed_space_dimensions": kernels}


def vector_check():
    rng = random.Random(0x20261017)
    passed = 0
    for rounds in range(1, 17):
        key = rng.randbytes(32)
        cipher = Cipher(key, rounds)
        blocks = [rng.randbytes(16) for _ in range(64)]
        left = np.array([int.from_bytes(b[:8], "big") for b in blocks], dtype=np.uint64)
        right = np.array([int.from_bytes(b[8:], "big") for b in blocks], dtype=np.uint64)
        a, b = enc(left, right, expand_key(key)[:rounds])
        for i, block in enumerate(blocks):
            assert cipher.encrypt_block(block) == int(a[i]).to_bytes(8, "big") + int(b[i]).to_bytes(8, "big")
            passed += 1
    derived_mask = sum(1 << bit for bit in range(64) if (undo_output(1 << bit) >> 1) & 1)
    assert derived_mask == BIT_MASK
    return {"batch_vs_original_blocks": passed, "round_counts": 16, "ellie_bit1_mask": f"{derived_mask:016x}"}


def ellie(rounds, keys, pairs, seed):
    rng = random.Random(seed)
    rows = []
    for _ in range(keys):
        key = rng.randbytes(32)
        words = np.array([rng.getrandbits(64) for _ in range(pairs * 2)], dtype=np.uint64).reshape(pairs, 2)
        left, right = words[:, 0], words[:, 1]
        rk = expand_key(key)[:rounds]
        a, _ = enc(left, right, rk)
        b, _ = enc(left ^ np.uint64(HIGH), right, rk)
        transformed = vunmix(a ^ b)
        rows.append({"bit1_ones": int(np.count_nonzero(transformed & np.uint64(2))),
                     "low12_zeroes": int(np.count_nonzero((transformed & np.uint64(4095)) == 0))})
    ones = sum(r["bit1_ones"] for r in rows)
    return {"rounds": rounds, "keys": keys, "pairs_per_key": pairs, "pairs": keys * pairs,
            "seed": seed, "bit1_ones": ones, "bit1_rate": ones / (keys * pairs),
            "low12_zeroes": sum(r["low12_zeroes"] for r in rows),
            "key_rate_min": min(r["bit1_ones"] / pairs for r in rows),
            "key_rate_max": max(r["bit1_ones"] / pairs for r in rows), "per_key": rows}


def per_key_followup():
    # Reconstruct the 64 fresh exploration keys, then use independent plaintexts.
    # Pooled 50% can hide opposite-sign biases under different keys.
    prng = random.Random(0x5C0A710)
    keys = []
    for _ in range(64):
        keys.append(prng.randbytes(32))
        for _ in range(4096 * 2):
            prng.getrandbits(64)
    rng = np.random.default_rng(0x50B1A5)
    n = 65536
    rows = []
    for rounds in (5, 6, 16):
        counts = []
        for key in keys:
            left = rng.integers(0, 1 << 64, size=n, dtype=np.uint64)
            right = rng.integers(0, 1 << 64, size=n, dtype=np.uint64)
            rk = expand_key(key)[:rounds]
            a, _ = enc(left, right, rk)
            b, _ = enc(left ^ np.uint64(HIGH), right, rk)
            counts.append(int(np.count_nonzero(vunmix(a ^ b) & np.uint64(2))))
        z = [(count - n / 2) / math.sqrt(n / 4) for count in counts]
        rows.append({"rounds": rounds, "keys": 64, "pairs_per_key": n,
                     "pooled_rate": sum(counts) / (n * 64),
                     "minimum_key_rate": min(counts) / n, "maximum_key_rate": max(counts) / n,
                     "keys_exceeding_5sigma": sum(abs(x) > 5 for x in z),
                     "sum_squared_z": sum(x * x for x in z), "null_expected_sum_squared_z": 64,
                     "per_key_ones": counts})
        if rounds == 5:
            scalar = []
            for index in (min(range(64), key=counts.__getitem__), max(range(64), key=counts.__getitem__)):
                cipher = Cipher(keys[index], 5)
                check_rng = random.Random(0xD1AEC7 + index)
                hits = 0
                for _ in range(8192):
                    plain = check_rng.randbytes(16)
                    other = (int.from_bytes(plain, "big") ^ (HIGH << 64)).to_bytes(16, "big")
                    a = int.from_bytes(cipher.encrypt_block(plain)[:8], "big")
                    b = int.from_bytes(cipher.encrypt_block(other)[:8], "big")
                    hits += ((a ^ b) & BIT_MASK).bit_count() & 1
                scalar.append({"key_index": index, "pairs": 8192, "bit1_ones": hits,
                               "rate": hits / 8192, "key_sha256": hashlib.sha256(keys[index]).hexdigest()})
            rows[-1]["original_scalar_heldout"] = scalar
    return rows


def two_round_relation():
    """Generic two-round Feistel identity, measured through the frozen scalar."""
    rng = random.Random(0xD550)
    cipher = Cipher(rng.randbytes(32), 2)
    for _ in range(256):
        left, right, delta = (rng.getrandbits(64) for _ in range(3))
        a = cipher.encrypt_block(left.to_bytes(8, "big") + right.to_bytes(8, "big"))
        b = cipher.encrypt_block((left ^ delta).to_bytes(8, "big") + right.to_bytes(8, "big"))
        assert int.from_bytes(a[:8], "big") ^ int.from_bytes(b[:8], "big") == delta
    return {"rounds": 2, "pairs": 256, "identity_hits": 256}


def selected_key_differential():
    """GLM's public selected-key four-round experiment, fresh batch code."""
    key = bytes.fromhex("80a557b4d8e5a404b1905568b0af068817ad63cabed2f9119950807984d97a61")
    subkeys = expand_key(key)[:4]
    dl, dr = skeleton(HIGH), HIGH
    start_l, start_r = dl, dr
    for _ in range(4):
        dl, dr = dr, dl ^ skeleton(dr)
    rng = np.random.default_rng(0x61A2026)
    hits = 0
    trials = 1 << 24
    for _ in range(trials // (1 << 18)):
        left = rng.integers(0, 1 << 64, size=1 << 18, dtype=np.uint64)
        right = rng.integers(0, 1 << 64, size=1 << 18, dtype=np.uint64)
        a, b = enc(left, right, subkeys)
        c, d = enc(left ^ np.uint64(start_l), right ^ np.uint64(start_r), subkeys)
        hits += int(np.count_nonzero(((a ^ c) == np.uint64(dl)) & ((b ^ d) == np.uint64(dr))))
    assert hits == 765
    return {"rounds": 4, "public_test_key": key.hex(), "pairs": trials, "hits": hits,
            "input_difference": [f"{start_l:016x}", f"{start_r:016x}"],
            "output_difference": [f"{dl:016x}", f"{dr:016x}"],
            "scope": "Selected test key, not a proven full-round weak-key class."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new JSON file; never overwrite")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a new path")
    start = time.perf_counter()
    result = {"algorithm": "Cairn-128/256-v0.1", "two_round": two_round_relation(),
              "batch_validation": vector_check(), "linear_algebra": linear_algebra()}
    print("Scalar controls, 1,024 batch comparisons and mask derivation passed.", flush=True)
    result["ellie_original_seeds"] = [ellie(r, 16, 8192, 0xF1EED + 23 * r) for r in (3, 4, 5, 16)]
    assert [r["bit1_ones"] for r in result["ellie_original_seeds"]] == [0, 128088, 65512, 65623]
    assert [r["low12_zeroes"] for r in result["ellie_original_seeds"]] == [131072, 0, 31, 24]
    result["ellie_fresh_keys"] = [ellie(r, 64, 4096, 0x5C0A710) for r in (3, 4, 5, 16)]
    result["full_round_replication"] = ellie(16, 256, 8192, 0x16C0FFEE)
    result["per_key_heldout"] = per_key_followup()
    assert result["per_key_heldout"][0]["keys_exceeding_5sigma"] == 5
    assert [row["bit1_ones"] for row in result["per_key_heldout"][0]["original_scalar_heldout"]] == [3632, 4723]
    print("Three-/four-round relations and five-round held-out bias reproduced.", flush=True)
    result["selected_key_differential"] = selected_key_differential()
    result["scope"] = "Public deterministic test keys only; no challenge-key queries or key recovery."
    # Keep the scientific output deterministic; timing is printed, not committed.
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {args.output.name}; elapsed {time.perf_counter() - start:.2f} seconds.")


if __name__ == "__main__":
    main()

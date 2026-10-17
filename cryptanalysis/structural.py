"""Exact constant-addition counts and bounded, fixed-schedule trail exploration.

Standard library only. No independent-key assumption is made by exact counts.
Search scores multiply round marginals ONLY as a heuristic, never a probability.
See STRUCTURAL.md for definitions, proofs, limits and reproduction commands.
"""
import argparse
from collections import Counter
from fractions import Fraction
from functools import lru_cache
import json
from pathlib import Path
import random
import time

from cairn.core import GOLDEN, MASK, Cipher, expand_key, rol, round_function


def rot(x, r, n=64):
    r %= n
    return ((x << r) | (x >> ((n - r) % n))) & ((1 << n) - 1)


def mix(x, n=64):
    return x ^ rot(x, 13, n) ^ rot(x, 37, n)


def finish(x, n=64):
    return rot(x ^ rot(x, 17, n) ^ rot(x, 41, n), 29, n)


def function(x, u, v, n=64):
    mask = (1 << n) - 1
    return finish((mix((x + u) & mask, n) + v) & mask, n)


def schedule_step(state, i):
    a, b, c, d = state
    A = (a + rol(b, 9) + (i + 1) * GOLDEN) & MASK
    C = c ^ rol(A, 23)
    D = (d + rol(C, 31)) & MASK
    B = rol(b ^ D, 17)
    return B, C, D, A


def schedule_inverse(state, i):
    B, C, D, A = state
    b = rol(B, 47) ^ D
    d = (D - rol(C, 31)) & MASK
    c = C ^ rol(A, 23)
    a = (A - rol(b, 9) - (i + 1) * GOLDEN) & MASK
    return a, b, c, d


def key_for_pair(u, v, round_index=0, a=0, b=0):
    """Invert a freely chosen post-emission state; 2^128 choices of (a,b)."""
    assert 0 <= round_index < 16
    state = a, b, a ^ u, (v - b) & MASK
    for i in range(8 + round_index, -1, -1):
        state = schedule_inverse(state, i)
    return b"".join(x.to_bytes(8, "big") for x in state)


def edges(i, state, alpha, key, n):
    c, d = state
    a, k = (alpha >> i) & 1, (key >> i) & 1
    beta = a ^ c ^ d
    for x in (0, 1):
        nxt = ((x + k + c) >> 1, ((x ^ a) + k + d) >> 1)
        # Final carries are discarded modulo 2^n.
        yield x, beta, nxt if i + 1 < n else (0, 0)


def add_count(alpha, beta, key, n=64):
    """Exact numerator over 2^n, four paired-carry states, O(n)."""
    states = {(0, 0): 1}
    for i in range(n):
        new = Counter()
        for state, count in states.items():
            for _, bit, nxt in edges(i, state, alpha, key, n):
                if bit == ((beta >> i) & 1):
                    new[nxt] += count
        states = new
    return sum(states.values())


def add_correlation_sum(alpha, output_mask, key, n=64):
    """Exact signed count sum_x (-1)^<mask,A_k(x) XOR A_k(x XOR alpha)>."""
    states = {(0, 0): 1}
    for i in range(n):
        new = Counter()
        for state, count in states.items():
            for _, bit, nxt in edges(i, state, alpha, key, n):
                new[nxt] += -count if bit and ((output_mask >> i) & 1) else count
        states = new
    return sum(states.values())


def four_round_parity(key, width=256):
    """Rigorous interval for the existing FOUR-round left-half parity statistic.

    The two active round-function inputs are independent uniform words. The
    final output mask selects bit 1 before finish(), so the second addition's
    masked derivative is affine. Only the distribution of the first active
    round's second-addition difference needs enumeration; omitted mass yields
    an explicit rigorous interval, not a guessed tail.
    """
    mask = 0x9DA28B88C58AB380
    assert all(((finish(1 << j) & mask).bit_count() & 1) == int(j == 1) for j in range(64))
    rk = expand_key(key)
    v1 = rk[1][1]
    u2, v2 = rk[2]
    low_mask = 2 ^ (v2 & 1)
    before_mix_mask = sum(1 << j for j in range(64) if (mix(1 << j) & low_mask).bit_count() & 1)
    outcomes = add_candidates(mix(1 << 63), v1, width=width, take=width)
    mass_count = sum(count for _, count in outcomes)
    signed = sum(count * add_correlation_sum(finish(gamma), before_mix_mask, u2)
                 for gamma, count in outcomes)
    if (mask & (1 << 63)).bit_count() & 1:
        signed = -signed
    omitted = Fraction((1 << 64) - mass_count, 1 << 64)
    center = Fraction(signed, 1 << 128)
    lower = max(Fraction(0), (1 - center - omitted) / 2)
    upper = min(Fraction(1), (1 - center + omitted) / 2)
    return {"retained_outputs": len(outcomes), "prefix_width": width,
            "omitted_probability_mass": fraction_json(omitted),
            "parity_ones_probability_lower": fraction_json(lower),
            "parity_ones_probability_upper": fraction_json(upper)}


class BudgetExceeded(Exception):
    """No exact answer returned when a representation budget is exceeded."""


def add_cubes(alpha, beta, key, n=64, cap=256):
    """Disjoint bit cubes (mask,value) describing exactly the accepted inputs."""
    nodes = {0: None, 1: None}
    unique = {}

    @lru_cache(None)
    def build(i, state):
        if i == n:
            return 1
        children = [build(i + 1, nxt) if bit == ((beta >> i) & 1) else 0
                    for _, bit, nxt in edges(i, state, alpha, key, n)]
        if children[0] == children[1]:
            return children[0]
        signature = i, *children
        if signature not in unique:
            node = len(nodes)
            unique[signature] = node
            nodes[node] = signature
        return unique[signature]

    result = []

    def visit(node, mask, value):
        if node == 0:
            return
        if node == 1:
            result.append((mask, value))
            if len(result) > cap:
                raise BudgetExceeded("constant-addition cube cap")
            return
        i, low, high = nodes[node]
        visit(low, mask | (1 << i), value)
        visit(high, mask | (1 << i), value | (1 << i))

    visit(build(0, (0, 0)), 0, 0)
    assert sum(1 << (n - mask.bit_count()) for mask, _ in result) == add_count(alpha, beta, key, n)
    return result


def affine_count(equations, n):
    """Number of solutions of a binary affine system, by Gaussian elimination."""
    pivots = {}
    for row, rhs in equations:
        while row:
            bit = row.bit_length() - 1
            if bit in pivots:
                other, value = pivots[bit]
                row, rhs = row ^ other, rhs ^ value
            else:
                pivots[bit] = row, rhs
                break
        if row == 0 and rhs:
            return 0
    return 1 << (n - len(pivots))


@lru_cache(None)
def mix_is_permutation(n):
    return affine_count([(mix(1 << j, n), 0) for j in range(n)], n) == 1


@lru_cache(4096)
def joint_count(alpha, beta, gamma, u, v, n=64, cap=256):
    """Exact joint numerator for both additions, over a uniform n-bit right.

    Change variable x=r+u. First event becomes A_-u(x) XOR
    A_-u(x XOR beta)=alpha. Intersect its cubes with second-event cubes on P(x).
    P is linear; all intersections are affine systems. No independence shortcut.
    """
    c1 = add_count(alpha, beta, u, n)
    c2 = add_count(mix(beta, n), gamma, v, n)
    if c1 == 0 or c2 == 0:
        return 0
    if c1 == 1 << n and mix_is_permutation(n):
        return c2
    if c2 == 1 << n:
        return c1
    first = add_cubes(beta, alpha, (-u) & ((1 << n) - 1), n, cap)
    second = add_cubes(mix(beta, n), gamma, v, n, cap)
    total = 0
    for m, value in first:
        base = [(1 << j, (value >> j) & 1) for j in range(n) if (m >> j) & 1]
        for q, z in second:
            equations = list(base)
            for j in range(n):
                if (q >> j) & 1:
                    row = (1 << j) ^ (1 << ((j - 13) % n)) ^ (1 << ((j - 37) % n))
                    equations.append((row, (z >> j) & 1))
            total += affine_count(equations, n)
    return total


def add_candidates(alpha, key, n=64, width=8, take=2):
    """Bounded output-prefix beam; exact counts for each retained full output.

    Prefix count / 2^i is an upper bound for any descendant output, but pruned
    prefixes are not revisited. This is NOT a certified maximum-probability search.
    """
    beam = [(0, {(0, 0): 1})]
    for i in range(n):
        next_beam = []
        for prefix, states in beam:
            split = [Counter(), Counter()]
            for state, count in states.items():
                for _, bit, nxt in edges(i, state, alpha, key, n):
                    split[bit][nxt] += count
            for bit, new in enumerate(split):
                if new:
                    next_beam.append((prefix | (bit << i), dict(new)))
        beam = sorted(next_beam, key=lambda row: (-sum(row[1].values()), row[0]))[:width]
    result = [(beta, sum(states.values())) for beta, states in beam[:take]]
    assert all(count == add_count(alpha, beta, key, n) for beta, count in result)
    return result


def fraction_json(p):
    return {"numerator": p.numerator, "denominator": p.denominator}


PUBLIC_KEYS = {
    "range32": bytes(range(32)),
    "selected4": bytes.fromhex("80a557b4d8e5a404b1905568b0af068817ad63cabed2f9119950807984d97a61"),
}


def validate():
    checks = Counter()
    # Exhaust ALL (key,alpha,beta,x) at four bits. Toy width validates the
    # model only; rotations reduced modulo n do not model 64-bit security.
    n = 4
    for key in range(1 << n):
        for alpha in range(1 << n):
            histogram = Counter(((x + key) & 15) ^ (((x ^ alpha) + key) & 15) for x in range(16))
            for beta in range(16):
                assert add_count(alpha, beta, key, n) == histogram[beta]
                cubes = add_cubes(alpha, beta, key, n)
                for x in range(16):
                    assert sum((x & m) == v for m, v in cubes) == int(
                        (((x + key) & 15) ^ (((x ^ alpha) + key) & 15)) == beta)
                checks["exhaustive_add_equations_n4"] += 1
            for output_mask in range(16):
                signed = sum(count * (-1 if (beta & output_mask).bit_count() & 1 else 1)
                             for beta, count in histogram.items())
                assert add_correlation_sum(alpha, output_mask, key, n) == signed
                checks["exhaustive_add_mask_equations_n4"] += 1
    rng = random.Random(0xCA1701)
    for u in range(32):
        for v in range(32):
            constant = function(0, u, v, 5)
            basis = [function(1 << j, u, v, 5) ^ constant for j in range(5)]
            affine = True
            for x in range(32):
                expected = constant
                for j in range(5):
                    if (x >> j) & 1:
                        expected ^= basis[j]
                affine &= function(x, u, v, 5) == expected
            assert affine == (u % 8 == 0 and v % 8 == 0)
            assert (affine and constant == 0) == (u == 0 and v == 0)
            checks["exhaustive_affine_subkey_pairs_n5"] += 1
    dependence_example = None
    for _ in range(64):
        n = 5
        mask = (1 << n) - 1
        alpha, u, v = (rng.randrange(1 << n) for _ in range(3))
        hist = Counter()
        for r in range(1 << n):
            x, xp = (r + u) & mask, ((r ^ alpha) + u) & mask
            y, yp = mix(x, n), mix(xp, n)
            hist[x ^ xp, ((y + v) & mask) ^ ((yp + v) & mask)] += 1
        for beta in range(1 << n):
            for gamma in range(1 << n):
                count = joint_count(alpha, beta, gamma, u, v, n)
                assert count == hist[beta, gamma]
                product = Fraction(add_count(alpha, beta, u, n) * add_count(mix(beta, n), gamma, v, n), 1 << (2 * n))
                if count and product != Fraction(count, 1 << n) and dependence_example is None:
                    dependence_example = {"n": n, "alpha": alpha, "beta": beta, "gamma": gamma,
                                          "u": u, "v": v, "joint": fraction_json(Fraction(count, 1 << n)),
                                          "incorrect_product": fraction_json(product)}
                checks["exhaustive_joint_equations_n5"] += 1
    for _ in range(64):
        key = rng.randbytes(32)
        state = tuple(int.from_bytes(key[i:i + 8], "big") for i in range(0, 32, 8))
        emitted = []
        for i in range(24):
            nxt = schedule_step(state, i)
            assert schedule_inverse(nxt, i) == state
            state = nxt
            if i >= 8:
                a, b, c, d = state
                emitted.append((a ^ c, (b + d) & MASK))
        assert tuple(emitted) == expand_key(key)
        checks["schedule_forward_inverse_keys"] += 1
    # The theorem applies to Cairn's 64-bit P. Verify its inverse/order exactly.
    for bit in range(64):
        for layer in (mix, lambda x: x ^ rol(x, 17) ^ rol(x, 41)):
            x = 1 << bit
            for _ in range(8):
                x = layer(x)
            assert x == 1 << bit
            checks["linear_layer_basis_orders"] += 1
    for u in (0, 1 << 62, 1 << 63, 3 << 62):
        for v in (0, 1 << 62, 1 << 63, 3 << 62):
            constant = round_function(0, u, v)
            images = [round_function(1 << i, u, v) ^ constant for i in range(64)]
            for _ in range(16):
                x = rng.getrandbits(64)
                expected = constant
                for i in range(64):
                    if (x >> i) & 1:
                        expected ^= images[i]
                assert round_function(x, u, v) == expected
                checks["affine_64bit_evaluations"] += 1
            for round_index in (0, 7, 15):
                key = key_for_pair(u, v, round_index)
                assert expand_key(key)[round_index] == (u, v)
                checks["constructed_reachable_pairs"] += 1
    for _ in range(128):
        r, u, v = (rng.getrandbits(64) for _ in range(3))
        assert function(r, u, v) == round_function(r, u, v)
        assert add_count(1 << 63, 1 << 63, u) == 1 << 64
        checks["scalar_64bit_checks"] += 1
    gamma = MASK ^ (1 << 13) ^ (1 << 37)
    c1, c2 = add_count(MASK, 1, MASK), add_count(mix(1), gamma, 1)
    joint = joint_count(MASK, 1, gamma, MASK, 1)
    assert (c1, c2, joint) == (4, 4, 2)
    return {"checks": dict(checks), "toy_dependence_counterexample": dependence_example,
            "64bit_dependence_counterexample": {"alpha": MASK, "beta": 1, "gamma": gamma,
                "u": MASK, "v": 1, "joint": fraction_json(Fraction(joint, 1 << 64)),
                "incorrect_product": fraction_json(Fraction(c1 * c2, 1 << 128)),
                "reachable_round0_public_key": key_for_pair(MASK, 1).hex()}}


def reachability():
    result = []
    for index in (0, 7, 15):
        key = key_for_pair(0, 0, index)
        keys = expand_key(key)
        affine = [i for i, (u, v) in enumerate(keys) if not ((u | v) & ((1 << 62) - 1))]
        result.append({"round_index": index, "public_master_key": key.hex(),
                       "affine_round_indices": affine})
    return result


def search(key, start, rounds=16, beam_width=4, prefix_width=8, take=2):
    # beam entries: score, dl, dr, trail. A trail lists internal beta/gamma too.
    beam = [(Fraction(1), *start, [])]
    snapshots = []
    skipped = 0
    for index, (u, v) in enumerate(expand_key(key)[:rounds]):
        next_beam = []
        for score, dl, dr, trail in beam:
            for beta, c1 in add_candidates(dr, u, width=prefix_width, take=take):
                for gamma, c2 in add_candidates(mix(beta), v, width=prefix_width, take=take):
                    try:
                        count = joint_count(dr, beta, gamma, u, v)
                    except BudgetExceeded:
                        skipped += 1
                        count = None
                    if count != 0:
                        lower = max(0, c1 + c2 - (1 << 64)) if count is None else count
                        upper = min(c1, c2) if count is None else count
                        p = Fraction(c1 * c2, 1 << 128) if count is None else Fraction(count, 1 << 64)
                        row = {"alpha": dr, "beta": beta, "gamma": gamma,
                               "output": finish(gamma), "exact_count_over_2pow64": count,
                               "count_lower_bound": lower, "count_upper_bound": upper,
                               "single_addition_counts": [c1, c2]}
                        next_beam.append((score * p, dr, dl ^ finish(gamma), trail + [row]))
        next_beam.sort(key=lambda row: (-row[0], row[1], row[2], tuple(x["beta"] for x in row[3]),
                                       tuple(x["gamma"] for x in row[3])))
        beam = next_beam[:beam_width]
        if not beam:
            return {"completed_rounds": index, "exact_count_budget_fallbacks": skipped, "snapshots": snapshots}
        score, dl, dr, trail = beam[0]
        # Exact upper bound on the full internal trail: any two base right
        # words one or two rounds apart are independent (F is a permutation).
        ps = [Fraction(t["count_upper_bound"], 1 << 64) for t in trail]
        bounds = ps + [ps[i] * ps[j] for i in range(len(ps)) for j in range(i + 1, min(i + 3, len(ps)))]
        active = [i for i, p in enumerate(ps) if p != 1]
        exact_probability = None
        if all(t["exact_count_over_2pow64"] is not None for t in trail) and (len(active) <= 1 or
                (len(active) == 2 and active[1] - active[0] <= 2)):
            exact_probability = fraction_json(score)
        snapshots.append({"rounds": index + 1, "output_difference": [dl, dr],
                          "heuristic_product_NOT_probability": fraction_json(score),
                          "proven_trail_upper_bound": fraction_json(min(bounds)),
                          "exact_trail_probability_if_proven": exact_probability, "trail": trail})
    return {"completed_rounds": len(snapshots), "exact_count_budget_fallbacks": skipped, "snapshots": snapshots}


def measure(key, start, snapshot, pairs=16384, seed=0xC417):
    """Scalar fixed-key validation of an internal trail AND endpoint differential."""
    rng = random.Random(seed)
    rounds = snapshot["rounds"]
    rk = expand_key(key)[:rounds]
    trail_hits = endpoint_hits = 0
    first_witness = None
    for _ in range(pairs):
        l, r = rng.getrandbits(64), rng.getrandbits(64)
        plain = (l << 64) | r
        lp, rp = l ^ start[0], r ^ start[1]
        follows = True
        for (u, v), expected in zip(rk, snapshot["trail"]):
            x, xp = (r + u) & MASK, (rp + u) & MASK
            y, yp = mix(x), mix(xp)
            z, zp = (y + v) & MASK, (yp + v) & MASK
            follows &= (r ^ rp, x ^ xp, z ^ zp) == (expected["alpha"], expected["beta"], expected["gamma"])
            l, r = r, l ^ finish(z)
            lp, rp = rp, lp ^ finish(zp)
        # Check complete trajectory against the untouched cipher for selected cases.
        if _ < 4:
            cipher = Cipher(key, rounds)
            assert cipher.encrypt_block(plain.to_bytes(16, "big")) == ((l << 64) | r).to_bytes(16, "big")
        endpoint_hits += [l ^ lp, r ^ rp] == snapshot["output_difference"]
        trail_hits += follows
        if follows and first_witness is None:
            first_witness = f"{plain:032x}"
    return {"rounds": rounds, "pairs": pairs, "seed": seed,
            "internal_trail_hits": trail_hits, "endpoint_differential_hits": endpoint_hits,
            "first_plaintext_witness": first_witness}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    begin = time.perf_counter()
    result = {"validation": validate(), "reachability": reachability(),
              "four_round_parity_intervals": {name: four_round_parity(key) for name, key in PUBLIC_KEYS.items()}}
    print(f"Exact model and schedule checks passed ({time.perf_counter() - begin:.2f}s).", flush=True)
    if not args.validate_only:
        h = 1 << 63
        starts = {"left_high": (h, 0), "selected_skeleton": (finish(mix(h)), h)}
        result["search_config"] = {"beam_width": 4, "add_prefix_width": 8, "outputs_per_add": 2,
                                   "cube_cap_per_add": 256, "max_rounds": 16}
        result["searches"] = []
        for name, key in PUBLIC_KEYS.items():
            for label, start in starts.items():
                run = search(key, start)
                print(f"{name}/{label}: {run['completed_rounds']} rounds, {run['exact_count_budget_fallbacks']} exact-count budget fallbacks.", flush=True)
                checks = [measure(key, start, snap) for snap in run["snapshots"] if snap["rounds"] in (2, 3, 4, 5)]
                result["searches"].append({"key_name": name, "public_master_key": key.hex(),
                                           "input_label": label, "input_difference": list(start),
                                           **run, "scalar_validation": checks})
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"Wrote {args.output.name}; elapsed {time.perf_counter() - begin:.2f}s.", flush=True)


if __name__ == "__main__":
    main()

# Historical implementation baseline, 2026-10-17

This records the initial implementation checks before contestant runs. For the
subsequent cryptanalysis, see `../cryptanalysis/FINDINGS.md` and its reproductions.

Environment: Windows, CPython 3.14.7, standard library only. This file records implementation checks and a small diagnostic experiment, not independent cryptanalysis or a security assessment.

## Correctness and operational checks

Command: `python -m unittest discover -v`.

All 12 test groups passed. They cover:

- 20 frozen known-answer vectors checked by the primary and separately written reference implementation.
- 128 additional deterministic key/block cases across every round count from 1 through 16, including inversions of arbitrary ciphertext blocks.
- File round trips at 0, 1, 15, 16, 17, 65,535, 65,536, 65,537 and 131,089 bytes.
- A literal file-format calculation using the separate primitive implementation and standard HMAC, checking nonce, labeled derivation, header layout, counter encoding and final partial block.
- Wrong keys, modified headers/ciphertext/tags, truncation and trailing data rejected before any plaintext transformation.
- Existing outputs preserved, including a simulated publication race; temporary staging cleaned on handled errors.
- Real CLI key generation/encryption/decryption, invalid inputs and JSONL query limits.
- Generated challenge key/plaintext acceptance and wrong solution rejection.
- Public ZIP inventory/hash verification, no operator key or target plaintext in ZIP members, dropped private manifest fields and refusal to overwrite an existing ZIP.

The reference implementation is separate code by the same development agent. It is not independent human/agent review. Tests do not establish mathematical resistance.

## Diagnostic observations

Commands:

```text
python -m tools.lab diagnostics --samples 512 --seed 20261017
python -m tools.lab positive-control --samples 64 --seed 20261017
```

Saved raw reports: `examples/baseline-diagnostics.json`, `examples/positive-control.json`. Each avalanche row uses 512 random plaintexts and one randomly chosen input bit flip per plaintext under one public deterministic key. Key avalanche flips all 256 key bits for one plaintext. The pseudo-random source is for reproducible public experiments, never challenge secrets. Performance numbers vary by run and machine.

| Rounds | Mean output bits changed by one plaintext bit flip |
| --- | --- |
| 1 | 9.12109375 / 128 |
| 2 | 31.80859375 / 128 |
| 4 | 63.322265625 / 128 |
| 8 | 64.365234375 / 128 |
| 16 | 64.400390625 / 128 |

At 16 rounds, key-bit flips changed a mean 63.97265625 / 128 output bits. The 512 sampled pairs for one fixed input XOR difference produced 512 distinct output differences. These samples are much too small to exclude useful differential trails and do not test a full differential distribution or weak-key classes. The avalanche rows also draw different flip positions, so they are descriptive samples, not a controlled ranking of round counts.

## Reproduced attack: one round only

For two plaintext blocks `(L,R)` and `(L XOR d,R)`, one-round outputs are:

```text
(R, L XOR F(R))
(R, L XOR d XOR F(R))
```

Their ciphertext XOR is exactly `(0,d)`, for every nonzero `d`, independent of the key. The positive control tested 64 pairs / 128 queries and observed the relation in all 64. For one distinct pair under a uniform random 128-bit permutation, the probability of this exact nonzero output difference is `1 / (2^128 - 1)`.

This is a genuine chosen-plaintext distinguisher of the one-round research variant. It recovers neither the 256-bit master key nor the full-round target plaintext. It validates that the harness can demonstrate a structural weakness; it says nothing about the adequacy of 16 rounds.

## Status at the time of this baseline

At that point no independent contestant run, full-round cryptanalytic campaign,
hosted oracle or public publication had occurred. Later agent runs and reviews
are summarized in `../cryptanalysis/REVIEW.md`. No lower bound on attack cost has
been established. The current public attack model is in `ATTACK_BRIEF.md`.

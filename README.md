# Cairn v0.1

An experimental **16-round Feistel cipher with 128-bit blocks and a 256-bit key**,
published for cryptanalysis. The round function and key schedule use 64-bit
addition, rotation and XOR. Familiar ingredients, custom parameter choices.

**Known findings:** an exact three-round constraint, strong four-round
distinguishers, and a five-round statistical bias whose sign and size depend on
the key. No full-round break or challenge solution has been verified in the work
so far. The most interesting open question is why that five-round bias occurs
and whether it can be extended.

New [structural analysis](cryptanalysis/STRUCTURAL.md) classifies exactly which
round keys make the function affine, constructs reachable schedule examples,
and derives tight fixed-key bounds for the four-round parity statistic. A
carry-aware search improves the selected-key four-round endpoint; its 16-round
candidates do not establish full-round differential bounds.

This is a learning and research project, developed and attacked with AI agents.
It makes no security-level or novelty claim. **Do not use Cairn to protect real
secrets.** A 256-bit key parameter is not a demonstrated 256-bit security level.

## Start here

Python 3.11+, standard library only for the cipher, CLI, verifier and tests.
Run these commands from the repository root:

```sh
python -m unittest discover -v
python -m tools.vectors
```

The [specification](docs/SPEC.md) defines every operation and encoding;
[`cairn/core.py`](cairn/core.py) is the complete primitive. Reduced-round variants
use the first 1–16 keys from the unchanged full key schedule.

[Technical schematics](docs/SCHEMATICS.md) show the complete Feistel round,
both keyed additions and rotation/XOR layers, and the 256-bit key schedule.

```python
from cairn.core import Cipher

key = bytes(range(32))  # Public example key, never a secret.
plain = bytes(16)
cipher = Cipher(key, rounds=16)
assert cipher.decrypt_block(cipher.encrypt_block(plain)) == plain
```

## Known cryptanalysis

| Rounds | Verified observation |
| --- | --- |
| 1–2 | Generic exact Feistel relations; useful controls |
| 3 | Exact low-12-bit constraint for a chosen input difference |
| 4 | Strong differential parity bias; also a selected-key exact-output differential |
| 5 | Key-dependent parity bias, confirmed with fresh plaintexts and the scalar cipher |
| 6 / 16 | No positive result in the fixed-statistic follow-up; no verified full-round break |

These are different attack types, not a measured security curve. The five-round
result applies to some tested keys; it is not yet a calibrated blind classifier
for arbitrary keys. See [findings and derivation](cryptanalysis/FINDINGS.md),
[saved counts](cryptanalysis/results.json), and [credits and corrections](cryptanalysis/REVIEW.md).

See also the [keyed-addition derivations and initial trail search](cryptanalysis/STRUCTURAL.md),
[new reproducible counts](cryptanalysis/structural-results.json),
[held-out validation](cryptanalysis/structural-followup-results.json), and
[scope of the additional external feedback](cryptanalysis/EXTERNAL_REVIEW.md).

Reproduce the main findings without any local contestant folders:

```sh
python -m pip install -r cryptanalysis/requirements.txt
python -m cryptanalysis.reproduce --output replay.json
```

NumPy is needed only for the larger analysis experiments. The script refuses to
overwrite a file. It reconstructs public test keys and uses fresh-plaintext
validation sets; rerunning the same seeds is reproducibility, not new evidence.

## Attack the frozen target

[`challenge/challenge.json`](challenge/challenge.json) supplies eight known
plaintext/ciphertext pairs and four target ciphertext blocks under one unknown
key. The target plaintext is 64 random bytes with a public SHA-256 commitment.
This tests the raw 16-round primitive, independently of the file wrapper.

**No challenge-key oracle is available.** Work under your own keys is unrestricted.
There is no contest deadline, prize or fixed compute budget. Reduced-round
findings are welcome; you do not need to solve this target to contribute.

```sh
python -m tools.challenge verify challenge/challenge.json --key-file candidate.key
python -m tools.challenge verify challenge/challenge.json --plaintext candidate.bin
```

See the [attack brief](docs/ATTACK_BRIEF.md) for models, verification and reporting.
Report findings in GitHub issues; submit runnable attacks through pull requests.
Please include commands, data/time/memory costs, assumptions and negative controls.
[Contribution guide](CONTRIBUTING.md).

## File experiments

```sh
python -m cairn keygen experiment.key
python -m cairn encrypt input.bin encrypted.cairn --key-file experiment.key
python -m cairn decrypt encrypted.cairn restored.bin --key-file experiment.key
```

The wrapper uses nonce-derived keys, Cairn CTR and HMAC-SHA-256. HMAC does not
validate Cairn's confidentiality. This Python implementation is not constant-time.
Files are never overwritten; atomic publication requires hard-link support,
tested locally on Windows NTFS. Use disposable experiment data.

v0.1's primitive, key schedule, specification and vectors are frozen. This public
repository starts with fresh history and an explicit export list. The original
target is unchanged; its public oracle allowance is now zero.
[Source provenance](docs/PROVENANCE.md) · [Design rationale](docs/DESIGN.md) ·
[Historical implementation baseline](docs/BASELINE.md) · [MIT license](LICENSE).

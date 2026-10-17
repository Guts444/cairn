# Verified findings, 2026-10-17

These results concern the frozen v0.1 primitive. They are reproducible experiments
and a short algebraic derivation, not independent expert review. The scalar
cipher is unchanged from the original source archive. All experiment keys below
are public deterministic test data, unrelated to the challenge key.

Run `python -m cryptanalysis.reproduce --output replay.json` from the root after
installing `cryptanalysis/requirements.txt`. Compare parsed JSON to `results.json`.
The public export reproduced the stored measurements in 9.89 seconds locally
with CPython 3.14.7 and NumPy 2.5.4 on Windows; runtime varies with the host.
The exported script has no dependencies on author or contestant directories.
NumPy's batch path is checked against the original scalar on 1,024 blocks spanning
all round counts. The parity mask is derived from basis vectors and asserted.

## Exact two-/three-round relations

For a two-round Feistel network and equal input right halves,
`Delta C_left = Delta P_left`, independently of the round function. This generic
control passes 256/256 pairs with the original scalar cipher.

For the three-round result, take `(L,R)` and `(L XOR 2^63,R)`. Their round-two
right inputs differ by exactly `h = 2^63`. Addition by a fixed word preserves
that top-bit XOR difference modulo 2^64. The first linear layer maps `h` to
`h XOR 2^12 XOR 2^36`. The second addition cannot change equality of the low
12 bits of those two intermediate words.

Let `D` be the XOR of left ciphertext halves after three rounds, and define

```text
L2(x) = x XOR ROL(x,17) XOR ROL(x,41)
U = L2^-1(ROR(D,29))
```

The Feistel state exposes the round-two function difference in that left half.
Therefore **U's low 12 bits are zero for every key and every such input pair**.
`L2` has order eight, so its inverse is its seventh power, not itself.

The selected bit `U[1]` is equivalently
`parity(D AND 0x9da28b88c58ab380)`. This fixed mask and top-bit input difference
are used in the following statistics. For a uniform permutation this parity is
approximately balanced; the exact single-pair probability differs from 1/2 by
order 2^-128. Distinct-output/sampling corrections are negligible here.

## Four rounds

On 64 additional deterministic test keys with 4,096 pairs each, that same parity
was one in **256,074 / 262,144 pairs (97.6845%)**. Three-round counts were zero.
Four-round low-12-zero events were rare but possible (one in this sample); do not
turn an observed absence in a smaller sample into an impossibility theorem.

GLM also supplied a selected-key exact-output differential. Its public key and
input/output differences are in `results.json`. The portable reproduction obtains
**765 hits / 16,777,216 pairs**. This is a selected reduced-round key result;
it does not establish a full-round weak-key class or a multi-round probability
by multiplying single-addition probabilities.

## Five rounds: opposite-sign biases hidden by pooling

An exploratory sample used 64 keys and 4,096 pairs each. A pooled result close
to 50% concealed large per-key deviations. Validation reconstructed those same
keys but used **independent plaintexts, 65,536 pairs per key**. The statistic was
fixed before validation: the same input difference, parity mask and two-sided
deviation from 50%.

| Rounds | Pooled rate | Minimum per-key rate | Maximum per-key rate | Keys beyond 5 null standard deviations |
| --- | --- | --- | --- | --- |
| 5 | 50.0464% | 45.1797% | 56.5231% | 5/64 |
| 6 | 50.0016% | 49.4263% | 50.5219% | 0/64 |
| 16 | 50.0051% | 49.3210% | 50.4776% | 0/64 |

The binomial fair-bit reference uses count standard deviation `sqrt(N/4)`.
The sum of squared standardized deviations over 64 keys was 2,120.06 at five
rounds, versus null expectation 64; the six-/sixteen-round values were 68.95
and 81.79. No exact five-round probability has been derived.

The most negative/positive five-round keys were then tested through the
**unmodified scalar implementation**, using another independent 8,192 pairs:

| Reconstructed public key index | Ones / pairs | Rate |
| --- | --- | --- |
| 27 | 3,632 / 8,192 | 44.3359% |
| 52 | 4,723 / 8,192 | 57.6538% |

These reproduce the direction and magnitude of the selected biases. The key
generation, plaintext seeds, key hashes and per-key counts are executable/saved.
Extrema were selected exploratorily; their confirmation plaintexts were held out.

This demonstrates a five-round keyed statistical weakness for some tested keys.
It does not recover keys, prove the fraction of affected keys, or establish a
reliable blind classifier on arbitrary unseen keys. The large validation sample
uses **131,072 encryptions per key**, exceeding the old 4,096-query agent allowance.
An oracle-limited challenge attack would need a separate cost/success evaluation.
The public target has no chosen-plaintext access at all.

## Full-round status and the next question

No full-16-round break, challenge key or target plaintext recovery has been
verified. The specific parity follow-ups did not extend the finding to six or
sixteen rounds. This does not quantify a security margin.

Other locally audited experiments included a 240-second full-round SMT timeout
and a 2,621,440-pair full-round byte-XOR projection experiment with no significant
primary rejection. They are negative results for specific configurations, not
attack-cost bounds. The main portable reproduction here covers the parity,
selected differential and algebra results above; it does not replay those other
solver/projection experiments.

The best next contribution would explain which carries, rotations and round-key
relations produce the five-round bias; characterize it on fresh keys; measure a
blind decision rule and false positives; or extend it to six rounds. Key-schedule
attacks, alternative masks and unrelated full-round approaches remain welcome.

# Attack Cairn v0.1

The algorithm and source are public. Attack it mathematically, inspect the
implementation, or use agents, SMT/SAT and custom experiments. There is no hidden
algorithm, image puzzle or reverse-engineering prerequisite.

## Public target and access

`challenge/challenge.json` fixes Cairn-128/256-v0.1 at exactly 16 rounds. Eight
known pairs and four raw target blocks use one OS-random 256-bit key. The target
plaintext is 64 OS-random bytes. Its length and SHA-256 commitment let anyone
verify a complete plaintext recovery locally. There is no file-wrapper HMAC in
this primitive target.

**No challenge-key encryption or decryption oracle is offered in this public
release: zero queries.** The initial private agent experiment offered up to 4,096
operator-mediated encryptions. That historical allowance is not public access.
The pairs, ciphertext and plaintext commitment have not changed.

Under your own test keys, chosen-plaintext work is unrestricted. The included
`cairn oracle` command is a local simulator using a key you supply; it does not
contact the maintainer. Its budget is per invocation, not persistent enforcement.
If you create your own challenge with `tools.challenge create`, its default
4,096-query metadata describes that separate operator-run experiment.

There is no deadline, prize, time limit or compute restriction for public
analysis. State the resources actually used. Keep known-plaintext results on
the supplied target separate from chosen-plaintext results on your own keys.

## Findings we want

1. **Key recovery:** supply a 32-byte candidate key that passes all pairs and the
   target commitment. This establishes a working key, not necessarily uniqueness.
2. **Plaintext recovery:** supply all 64 bytes passing the length/hash commitment.
3. **Structural analysis:** give a derivation and runnable invariant, distinguisher,
   differential/linear attack, weak-key result or key-schedule analysis. Specify
   rounds, access model and data/time/memory complexity.
4. **Implementation defects:** reproduce the issue in the CLI, file wrapper,
   reference, verifier or experiment. Classify it separately from a primitive break.

A useful full-round distinguisher counts as a result even without key recovery.
Reduced-round findings are also welcome. Do not alter constants, use full-round
ciphertexts as reduced-round solver inputs, or confuse independent round keys
with the actual master-key schedule without identifying the changed model.

## Reproduce and report

Open an issue using the finding template; submit executable attacks by pull
request. Include the commit or source inventory hash, rounds, model, tools,
commands, input data/seeds, success rate and cost. Label extrapolations.
For a statistic, include per-key counts, a justified null model, multiple-testing
handling, fresh-key/plaintext validation, and measured false positives if claiming
a blind distinguisher. Preserve failed approaches that could save others time.

Known weaknesses and their limits are in `cryptanalysis/FINDINGS.md`. A pooled
50% rate can hide opposite-sign per-key biases. A solver timeout, avalanche score
or failed attack is not a lower bound on the best possible attack.

The published source contains only public material. Access to operator files,
accounts or infrastructure would be a different problem and is unnecessary here.

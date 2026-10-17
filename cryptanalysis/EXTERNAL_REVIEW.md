# Scope of the additional external feedback

This note separates the supplied source-blind image-container report from
algorithm-aware cryptanalysis. The private image, ciphertext and original local
report are not included in this repository.

## Source-blind file experiment

The supplied DeepSeek report says it did not decrypt the image. Its recovered
layout matches the frozen v1 wrapper: eight-byte magic, 16-byte nonce, big-endian
64-bit length, ciphertext body and a 32-byte tag. A local read-only check confirmed
the reported file hash and exact length arithmetic. The implementation identifies
the actual construction as nonce-derived encryption/authentication keys, Cairn
CTR and HMAC-SHA-256 over the entire header and ciphertext.

The report's algorithm/KDF guesses and randomness statistics are not a
differential analysis of Cairn. We did not rerun its broad password, primitive or
PRNG guessing scripts: those do not address the round-function questions here.
The file experiment supplies no new primitive-security bound or full-round break.

Several interpretations in that report need narrowing:

* A random-looking sample does not establish computational indistinguishability.
* A random nonce makes collisions unlikely; one observed nonce cannot establish
  uniqueness across encryptions.
* A body length six bytes beyond a multiple of 16 does not imply a six-byte
  prefix. CTR naturally permits any byte length, as the known source confirms.
* Failed guesses exclude those tested candidates, not entire algorithms or KDF
  classes. A strict JPEG validator helps reject false positives but does not
  make the search coverage complete.
* One ciphertext can be sufficient against a structurally weak cipher. Failure
  to find a path from this source-blind sample is a limitation of that analysis,
  not a theorem that the sample is intrinsically unbreakable.

## Fixed-key additions and the Reddit comment

The substantive observation is correct: for a fixed master key, each addition
in Cairn's F adds a fixed constant, rather than another variable state word.
It deserves a constant-specific differential model. Powers of two are a useful
family to inspect: adding 2^63 is XOR, adding 2^62 is affine, and adding 2^t
for t<=61 has algebraic degree 63-t. The complete round is affine only when
**both** words are multiples of 2^62, including zero; the
[structural report](STRUCTURAL.md) proves this and uses the real schedule to
construct reachable examples.

The suggested change to key XOR placement would create a different cipher and
is outside frozen v0.1 analysis. XORing a key before an addition also does not
by itself establish good differential properties: the variable operands,
schedule, carries and dependencies still require analysis. We make no claim
that Cairn's construction is novel, or that fixed-constant additions alone
constitute a general impossibility theorem for secure block ciphers.

The assertion about a likely related-key break is a hypothesis, not a supplied
attack. An actual result needs a relation between **master keys**, induced
schedule differences, an attack model, data/time costs and a successful
distinguishing or recovery experiment. Being able to prescribe a single
round-key pair is not independently controlling successive round keys. No such
full-round related-key result has been established here. Using a block cipher
inside a hash construction would require a separate construction and analysis;
Cairn makes no hash-security claim.

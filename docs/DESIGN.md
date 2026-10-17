# Design notes and attack priorities

## What was chosen, and why

A balanced Feistel network keeps inversion simple and makes reduced-round experiments easy. A 128-bit block avoids designing around a tiny block space; a 256-bit key allows key-schedule research without a deliberately brute-forceable default. Neither choice establishes a security level.

The round function has two modular additions separated by fixed rotation/XOR mixing. Addition carries provide nonlinearity over XOR; fixed rotations are easy to model in bit-vector solvers. Three XOR terms in each mixing layer avoid the immediate parity collapse of `x XOR ROL(x,n)`, which always has even bit parity. An early, unshipped draft used that two-term expression and was corrected before freezing any vectors. That observation motivates attacking algebraic structure; it does not validate the final layers.

The four-word schedule uses the whole key, public round constants and a short warmup. The constant is the familiar golden-ratio constant, not a secret. Rotation counts and the 8-step warmup/16-round choice are heuristic baseline choices. No differential bound, linear bound, related-key bound or justified security margin has been established. More rounds and healthy avalanche numbers do not substitute for these analyses.

The wrapper uses standard HMAC for integrity and labeled per-file keys so file-format errors do not dominate primitive experiments. It is deliberately excluded from the raw-block challenge. Publishing only authenticated files would needlessly entangle mathematical confidentiality attacks with HMAC and format handling.

## Most useful attacks next

1. Model the round function and key schedule in SMT/SAT; measure solve time versus rounds and known pairs. A time-limited solver failure is not a security bound.
2. Search XOR and modular-addition differences through carries, especially high-bit/rotation-aligned differences, and validate promising trails with fresh queries and fresh keys.
3. Search linear masks, half-state parity invariants, impossible differentials, integrals and rotational relations. Preserve an explicit random-permutation control and distinguish a sampled bias from a reproducible distinguisher.
4. Look for equivalent keys, weak-key classes and round-key relations. Separate single-key attacks from stronger related-key access.
5. Reproduce successful reduced-round attacks, then extend them. Report data, time, memory and success rate over multiple fresh keys; retain scripts and transcripts.

Differential resistance is a design question beyond seeing diffusion: [Mind the Gap, IACR ePrint 2018/689](https://eprint.iacr.org/2018/689) is relevant background on evaluating differential characteristics and bounds.

## Things that would change the next revision

A verified full-round invariant or cheap distinguisher would count as a design failure even without plaintext recovery. A key-schedule weakness calls for a schedule change; increasing rounds blindly could conceal rather than address it. A wrapper bug gets its own regression and finding. Freeze the current artifacts when recording an attack, and create a new algorithm/format version for incompatible fixes.

No obfuscation, executable packing, steganography or secret round constants are
used. Source-level mathematical analysis is immediately available here.

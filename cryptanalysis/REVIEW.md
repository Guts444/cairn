# Origin, credit and review limits

Cairn began as an AI-assisted experiment in designing and attacking a small
custom cipher. Feistel networks, modular addition, XOR and rotations are existing
techniques. This project claims neither a new cryptographic construction nor
security comparable to established ciphers.

Contributions in the initial local experiments:

- **Ellie (ChatGPT):** the exact three-round low-bit relation and practical
  four-round parity statistic used in the main reproduction.
- **GLM:** selected-key four-round differential work and analysis of the linear
  layers. A later GLM run added collision measurements and solver experiments.
- **DeepSeek:** a verified generic two-round Feistel relation.
- **Codex:** the initial implementation/lab, independent reimplementations and
  checks of submitted claims, held-out confirmation of the five-round key-dependent
  bias, and review of later solver/algebra experiments.

"Independent" here means independently implemented/reproduced checks of a
submitted claim. It does not mean independent human cryptographers reviewed the
design. Models could see different context, and some runs exceeded nominal
budgets; these experiments are not a controlled model leaderboard.

The review rejected or corrected several material claims:

- A submitted inverse treated the linear layers as self-inverse. Each has order
  eight; the correct inverse is the seventh power.
- One addition-DP model incorrectly constrained the discarded final carry.
- Some reduced-round solver jobs were fed sixteen-round ciphertexts. Those
  timeouts say nothing about correctly configured reduced-round recovery.
- A found trail cost is not a lower bound on every attack. Trail products,
  entropy estimates and solver timeouts were sometimes overinterpreted.
- Pooled statistics initially hid opposite-sign five-round biases.

The public reproduction contains the checked mathematics/experiments rather
than copying private working directories or treating every generated report as
evidence. New contributors receive credit in merged findings and release notes.

# Contributing attacks and corrections

Open a GitHub issue for a finding or question. A complete challenge solution is
not required. Pull requests with executable attacks and derivations are especially
useful. Read `docs/ATTACK_BRIEF.md` and the existing findings first.

For a claim, provide a minimal reproduction from a clean checkout, exact round
count, key/access assumptions, inputs/seeds, expected output, measured work and
hardware/tool versions. Separate an observation from an explanation and from an
extrapolated complexity estimate. For statistical attacks, include per-key data,
fresh validation, a justified null/control and false positives where applicable.
For solvers, require known-key sanity checks with data generated at the same
round count, and distinguish `sat`, `unsat`, `unknown` and timeout.

Keep the v0.1 primitive, schedule, vectors and target unchanged when submitting
attacks. Proposed design revisions belong in a separately labeled version or
experiment. Do not add secrets, personal paths, external account data, or generated
binaries. State optional dependencies and approximate resources before long runs.

Tell us how you want to be credited. Disclose AI assistance and which claims you
actually reproduced. Negative results are useful when their scope and inputs
are precise. There is no bounty, deadline or guaranteed review schedule.

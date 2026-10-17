# Release provenance

The original local source archive was frozen on 2026-10-17:

`cairn-v0.1-public.zip`

SHA-256: `28ea1e202cf6e1de0d413aee176063bda49f686aed376cc11077b0e660f7fa4c`.

This repository was created in an empty directory from an explicit file/member
allowlist, with fresh Git history. No author private directory, old Git history,
contestant workspace or image-puzzle artifact was imported.

The primitive, wrapper/CLI, exact specification, conformance vectors and separate
reference implementation are byte-identical to that archive. Their original
hashes are in `FROZEN_SHA256.json`; release tests enforce them. The reference was
written in the same development session, so agreement is a transcription check,
not independent expert review.

The original eight known pairs, four target blocks, plaintext commitment and
algorithm parameters are unchanged. The manifest's `oracle_query_budget` changes
from 4,096 to **0**, and its note now states that no public oracle is available.
`challenge_identity` in the hash table is SHA-256 of the original immutable fields
(`algorithm`, `rounds`, `track`, `known_pairs`, `target_ciphertext`,
`target_plaintext_sha256`, `target_bytes`, `goals`, `mode`), serialized as sorted
JSON with separators `(',', ':')`. This excludes only the access budget and note.

README/brief and historical status wording were updated for public analysis.
The portable analysis code exports self-contained audit functions, adds a
standalone driver and selected-key experiment, and drops local contestant-folder
inspection. Its result file was regenerated from the exported source. All its
keys are public deterministic experiments, not the unknown challenge key.

The repository adds contribution/issue instructions, CI checks and an MIT license.
`tools.bundle` uses an explicit allowlist for the new release contents. Package a
fresh source release with:

```sh
python -m tools.bundle --challenge challenge/challenge.json --output dist/cairn-v0.1-public-release.zip
```

The source release ZIP includes `SHA256SUMS.json` covering its other members.
Checksums identify bytes; they are not digital signatures or proof of security.
The old local archive remains preserved separately, with its original checksum.

## Subsequent structural analysis, 2026-10-17

The schematics and keyed-addition/differential analysis were added after the
initial public commit `e6e5b8c8df21e1847c434d6366aff8e0c8877471`. The primitive,
wrapper, specification, vectors, challenge identity, original research scripts
and original saved measurements remain unchanged. New research files and diagrams
are explicitly included in the bundle allowlist; CI also reproduces their saved
results. The additional private image/container experiment is discussed only in
a scope review; its ciphertext, image, local report and guessing scripts were not
imported. This documentation update does not replace the original frozen archive
or alter its checksum.

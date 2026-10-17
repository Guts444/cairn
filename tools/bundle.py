"""Create a public ZIP from an explicit allowlist; no directory recursion."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ".gitignore", ".gitattributes", ".github/ISSUE_TEMPLATE/finding.md", ".github/workflows/checks.yml",
    "README.md", "LICENSE", "CONTRIBUTING.md", "pyproject.toml",
    "cairn/__init__.py", "cairn/__main__.py", "cairn/core.py", "cairn/files.py",
    "docs/SPEC.md", "docs/DESIGN.md", "docs/ATTACK_BRIEF.md", "docs/BASELINE.md",
    "docs/PROVENANCE.md", "docs/FROZEN_SHA256.json",
    "docs/SCHEMATICS.md",
    "cryptanalysis/__init__.py", "cryptanalysis/reproduce.py", "cryptanalysis/results.json",
    "cryptanalysis/requirements.txt", "cryptanalysis/FINDINGS.md", "cryptanalysis/REVIEW.md",
    "cryptanalysis/STRUCTURAL.md", "cryptanalysis/EXTERNAL_REVIEW.md",
    "cryptanalysis/structural.py", "cryptanalysis/structural_followup.py",
    "cryptanalysis/structural-results.json", "cryptanalysis/structural-followup-results.json",
    "examples/vectors.json", "examples/baseline-diagnostics.json", "examples/positive-control.json",
    "tests/__init__.py", "tests/reference.py", "tests/test_cairn.py", "tests/test_release.py",
    "tools/__init__.py", "tools/vectors.py", "tools/lab.py", "tools/challenge.py", "tools/bundle.py",
)


def create_bundle(output: Path, challenge: Path | None = None) -> dict:
    payload = {name: (ROOT / name).read_bytes() for name in SOURCES}
    if challenge is not None:
        data = json.loads(challenge.read_text(encoding="utf-8"))
        # Rebuild the manifest from public fields, excluding any accidental extras.
        fields = ("algorithm", "rounds", "track", "known_pairs", "target_ciphertext", "target_plaintext_sha256",
                  "target_bytes", "oracle_query_budget", "goals", "mode", "note")
        data = {field: data[field] for field in fields}
        data["known_pairs"] = [{"plaintext": pair["plaintext"], "ciphertext": pair["ciphertext"]} for pair in data["known_pairs"]]
        payload["challenge/challenge.json"] = (json.dumps(data, indent=2) + "\n").encode()
    inventory = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(payload.items())}
    payload["SHA256SUMS.json"] = (json.dumps(inventory, indent=2) + "\n").encode()
    with output.open("xb") as dst:
        with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(payload.items()):
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 17, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--challenge", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        inventory = create_bundle(args.output, args.challenge)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"bundle: {error}\n")
    print(f"Created public bundle with {len(inventory)} inventoried files.")


if __name__ == "__main__":
    main()

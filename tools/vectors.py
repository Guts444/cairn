"""Generate or check the public, non-secret conformance vectors."""

import argparse
import json
from pathlib import Path

from cairn.core import Cipher
from tests.reference import encrypt

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "examples" / "vectors.json"


def vectors():
    cases = [(bytes(32), bytes(16)), (bytes([255]) * 32, bytes([255]) * 16),
             (bytes(range(32)), bytes(range(16))),
             (bytes(range(31, -1, -1)), bytes.fromhex("80000000000000000000000000000001"))]
    rows = []
    for key, plain in cases:
        for rounds in (1, 2, 4, 8, 16):
            expected = encrypt(key, plain, rounds)
            actual = Cipher(key, rounds).encrypt_block(plain)
            if actual != expected:
                raise RuntimeError("core and separate reference implementation disagree")
            rows.append({"key": key.hex(), "plaintext": plain.hex(), "rounds": rounds, "ciphertext": expected.hex()})
    return {"algorithm": "Cairn-128/256-v0.1", "warning": "All keys in this file are PUBLIC test data.", "vectors": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="explicitly regenerate the frozen fixture")
    args = parser.parse_args()
    result = vectors()
    if args.write:
        DESTINATION.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("Wrote 20 public vectors checked against the separate reference implementation.")
    else:
        if json.loads(DESTINATION.read_text(encoding="utf-8")) != result:
            raise SystemExit("Frozen vectors differ; investigate before changing the fixture.")
        print("20 frozen vectors agree with both implementations.")


if __name__ == "__main__":
    main()

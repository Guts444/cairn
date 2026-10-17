"""Generate a public raw-primitive challenge and separate operator secrets."""

import argparse
import hashlib
import json
from pathlib import Path
import secrets

from cairn.core import Cipher
from cairn.__main__ import read_key


def generate(public: Path, private: Path, rounds: int) -> dict:
    public, private = public.resolve(), private.resolve()
    if public == private or public in private.parents or private in public.parents:
        raise ValueError("public and private directories must be separate, non-nested paths")
    if public.exists() or private.exists():
        raise ValueError("challenge destinations must not already exist")
    key = secrets.token_bytes(32)
    cipher = Cipher(key, rounds)
    pairs = []
    for _ in range(8):
        plain = secrets.token_bytes(16)
        pairs.append({"plaintext": plain.hex(), "ciphertext": cipher.encrypt_block(plain).hex()})
    target = secrets.token_bytes(64)
    encrypted = b"".join(cipher.encrypt_block(target[i:i + 16]) for i in range(0, 64, 16))
    manifest = {"algorithm": "Cairn-128/256-v0.1", "rounds": rounds,
                "track": "full-round" if rounds == 16 else "reduced-round",
                "known_pairs": pairs, "target_ciphertext": encrypted.hex(),
                "target_plaintext_sha256": hashlib.sha256(target).hexdigest(),
                "target_bytes": 64, "oracle_query_budget": 4096,
                "goals": ["recover the master key", "recover all 64 target plaintext bytes"],
                "mode": "four independent raw blocks, no file wrapper",
                "note": "All known pairs and target blocks use the same random key. Query access is operator-mediated; no online service included."}
    private.mkdir(parents=True)
    (private / "operator.key").write_bytes(key)
    (private / "target.bin").write_bytes(target)
    (private / "operator.json").write_text(json.dumps({"rounds": rounds, "query_budget": 4096}, indent=2) + "\n", encoding="utf-8")
    public.mkdir(parents=True)
    (public / "challenge.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify(manifest: dict, key: bytes | None = None, plaintext: bytes | None = None) -> bool:
    if key is not None:
        cipher = Cipher(key, manifest["rounds"])
        if not all(cipher.encrypt_block(bytes.fromhex(p["plaintext"])).hex() == p["ciphertext"] for p in manifest["known_pairs"]):
            return False
        encrypted = bytes.fromhex(manifest["target_ciphertext"])
        plaintext = b"".join(cipher.decrypt_block(encrypted[i:i + 16]) for i in range(0, len(encrypted), 16))
    return (plaintext is not None and len(plaintext) == manifest["target_bytes"]
            and secrets.compare_digest(hashlib.sha256(plaintext).hexdigest(), manifest["target_plaintext_sha256"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    make = sub.add_parser("create")
    make.add_argument("--public", type=Path, required=True)
    make.add_argument("--private", type=Path, required=True)
    make.add_argument("--rounds", type=int, choices=range(1, 17), default=16)
    check = sub.add_parser("verify")
    check.add_argument("manifest", type=Path)
    group = check.add_mutually_exclusive_group(required=True)
    group.add_argument("--key-file", type=Path)
    group.add_argument("--plaintext", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "create":
            generate(args.public, args.private, args.rounds)
            print("Created public challenge and separate private operator material.")
        else:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            passed = verify(manifest, read_key(args.key_file) if args.key_file else None,
                            args.plaintext.read_bytes() if args.plaintext else None)
            print("Accepted." if passed else "Rejected.")
            return 0 if passed else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"challenge: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

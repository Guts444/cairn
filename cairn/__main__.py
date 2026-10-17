import argparse
import json
from pathlib import Path
import secrets
import sys

from .core import Cipher, KEY_SIZE
from .files import decrypt_file, encrypt_file


def read_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError("key file must contain exactly 32 raw bytes")
    return key


def main() -> int:
    parser = argparse.ArgumentParser(description="Cairn v0.1 experimental cipher research CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="create a raw 256-bit key; never overwrite")
    keygen.add_argument("output", type=Path)
    for name in ("encrypt", "decrypt"):
        cmd = commands.add_parser(name)
        cmd.add_argument("source", type=Path)
        cmd.add_argument("output", type=Path)
        cmd.add_argument("--key-file", type=Path, required=True)
    block = commands.add_parser("block", help="raw block experiment; output hex")
    block.add_argument("block_hex")
    block.add_argument("--key-file", type=Path, required=True)
    block.add_argument("--rounds", type=int, default=16)
    block.add_argument("--decrypt", action="store_true")
    oracle = commands.add_parser("oracle", help="LOCAL simulator, not a security boundary; JSONL stdin/stdout")
    oracle.add_argument("--key-file", type=Path, required=True)
    oracle.add_argument("--rounds", type=int, default=16)
    oracle.add_argument("--limit", type=int, default=4096)
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            with args.output.open("xb") as dst:
                dst.write(secrets.token_bytes(KEY_SIZE))
            print("Created key file.")
        elif args.command in ("encrypt", "decrypt"):
            operation = encrypt_file if args.command == "encrypt" else decrypt_file
            operation(args.source, args.output, read_key(args.key_file))
            print("Completed.")
        else:
            cipher = Cipher(read_key(args.key_file), args.rounds)
            if args.command == "block":
                operation = cipher.decrypt_block if args.decrypt else cipher.encrypt_block
                print(operation(bytes.fromhex(args.block_hex)).hex())
            else:
                if args.limit < 1:
                    raise ValueError("oracle limit must be positive")
                # Every input line consumes the budget, including invalid requests.
                for query in range(1, args.limit + 1):
                    line = sys.stdin.buffer.readline(4097)
                    if not line:
                        break
                    if len(line) > 4096:
                        print(json.dumps({"error": "request too long"}), flush=True)
                        return 2
                    try:
                        request = json.loads(line)
                        value = cipher.encrypt_block(bytes.fromhex(request["plaintext"]))
                        response = {"query": query, "ciphertext": value.hex()}
                    except (ValueError, TypeError, KeyError):
                        response = {"query": query, "error": "expected plaintext: 32 hex characters"}
                    print(json.dumps(response), flush=True)
        return 0
    except (OSError, ValueError, OverflowError) as error:
        print(f"cairn: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

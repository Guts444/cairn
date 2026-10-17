import hashlib
import hmac
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cairn.core import Cipher
from cairn.files import CHUNK, HEADER, decrypt_file, encrypt_file, transform
from tests.reference import encrypt as reference_encrypt
from tools.challenge import generate, verify
from tools.lab import positive_control
from tools.bundle import create_bundle

ROOT = Path(__file__).resolve().parents[1]


class PrimitiveTests(unittest.TestCase):
    def test_frozen_vectors(self):
        data = json.loads((ROOT / "examples/vectors.json").read_text())
        for row in data["vectors"]:
            with self.subTest(rounds=row["rounds"], key=row["key"]):
                key, plain, expected = (bytes.fromhex(row[k]) for k in ("key", "plaintext", "ciphertext"))
                cipher = Cipher(key, row["rounds"])
                self.assertEqual(cipher.encrypt_block(plain), expected)
                self.assertEqual(cipher.decrypt_block(expected), plain)
                self.assertEqual(reference_encrypt(key, plain, row["rounds"]), expected)

    def test_all_round_counts_and_arbitrary_ciphertexts(self):
        rng = random.Random(713)
        for rounds in range(1, 17):
            for _ in range(8):
                key, plain, encrypted = rng.randbytes(32), rng.randbytes(16), rng.randbytes(16)
                cipher = Cipher(key, rounds)
                self.assertEqual(cipher.encrypt_block(plain), reference_encrypt(key, plain, rounds))
                self.assertEqual(cipher.decrypt_block(cipher.encrypt_block(plain)), plain)
                self.assertEqual(cipher.encrypt_block(cipher.decrypt_block(encrypted)), encrypted)

    def test_validation(self):
        for rounds in (0, 17, -1, True, 1.5):
            with self.assertRaises(ValueError):
                Cipher(bytes(32), rounds)
        for size in (0, 16, 31, 33):
            with self.assertRaises(ValueError):
                Cipher(bytes(size))
        for size in (0, 15, 17):
            with self.assertRaises(ValueError):
                Cipher(bytes(32)).encrypt_block(bytes(size))

    def test_attack_positive_control(self):
        result = positive_control(32, 71)
        self.assertEqual(result["matching_pairs"], 32)


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.encrypted, self.restored = (self.root / name for name in ("source.bin", "cipher.bin", "restored.bin"))
        self.key = bytes(range(32))

    def test_empty_partial_and_streaming_boundaries(self):
        rng = random.Random(72)
        for size in (0, 1, 15, 16, 17, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 17):
            with self.subTest(size=size):
                payload = rng.randbytes(size)
                self.source.write_bytes(payload)
                encrypt_file(self.source, self.encrypted, self.key)
                self.assertEqual(self.encrypted.stat().st_size, size + HEADER.size + 32)
                decrypt_file(self.encrypted, self.restored, self.key)
                self.assertEqual(self.restored.read_bytes(), payload)
                self.encrypted.unlink()
                self.restored.unlink()

    def test_wrong_key_tampering_truncation_and_appending(self):
        self.source.write_bytes(bytes(range(256)))
        encrypt_file(self.source, self.encrypted, self.key)
        original = self.encrypted.read_bytes()
        cases = [(original, bytes([255]) * 32)]
        for offset in (0, 8, 24, 31, 32, len(original) - 1):
            changed = bytearray(original)
            changed[offset] ^= 1
            cases.append((bytes(changed), self.key))
        cases.extend((original[:size], self.key) for size in (0, 1, 31, 32, 33, len(original) - 1))
        cases.append((original + b"extra", self.key))
        for content, key in cases:
            self.encrypted.write_bytes(content)
            with patch("cairn.files.transform", side_effect=AssertionError("plaintext before authentication")):
                with self.assertRaises(ValueError):
                    decrypt_file(self.encrypted, self.restored, key)
            self.assertFalse(self.restored.exists())
            self.assertFalse(list(self.root.glob(".cairn-*")))

    def test_no_overwrite_including_publication_race(self):
        self.source.write_bytes(b"source")
        self.encrypted.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            encrypt_file(self.source, self.encrypted, self.key)
        self.assertEqual(self.encrypted.read_bytes(), b"keep")
        self.encrypted.unlink()
        with patch("cairn.files._publish", side_effect=FileExistsError("simulated race")):
            with self.assertRaises(FileExistsError):
                encrypt_file(self.source, self.encrypted, self.key)
        self.assertFalse(self.encrypted.exists())
        self.assertFalse(list(self.root.glob(".cairn-*")))
        with self.assertRaises(FileExistsError):
            encrypt_file(self.source, self.source, self.key)
        self.assertEqual(self.source.read_bytes(), b"source")

    def test_nonce_uniqueness_and_stream_segmentation(self):
        self.source.write_bytes(b"repeated data")
        encrypt_file(self.source, self.encrypted, self.key)
        other = self.root / "other.bin"
        encrypt_file(self.source, other, self.key)
        self.assertNotEqual(self.encrypted.read_bytes(), other.read_bytes())
        cipher = Cipher(self.key)
        data = bytes(range(256)) * 3 + b"x"
        whole, end = transform(data, cipher, 0)
        first, counter = transform(data[:256], cipher, 0)
        second, next_counter = transform(data[256:], cipher, counter)
        self.assertEqual(first + second, whole)
        self.assertEqual(next_counter, end)

    def test_file_format_against_separate_primitive_and_literal_layout(self):
        nonce = bytes(range(16))
        payload = bytes(range(49))
        self.source.write_bytes(payload)
        with patch("cairn.files.os.urandom", return_value=nonce):
            encrypt_file(self.source, self.encrypted, self.key)
        enc_key = hmac.digest(self.key, b"cairn/file/encryption/v1\x00" + nonce, "sha256")
        mac_key = hmac.digest(self.key, b"cairn/file/authentication/v1\x00" + nonce, "sha256")
        stream = b"".join(reference_encrypt(enc_key, i.to_bytes(16, "big")) for i in range(4))
        expected = b"CAIRN01\x00" + nonce + len(payload).to_bytes(8, "big")
        expected += bytes(a ^ b for a, b in zip(payload, stream))
        expected += hmac.digest(mac_key, expected, "sha256")
        self.assertEqual(self.encrypted.read_bytes(), expected)


class ChallengeAndCLITests(unittest.TestCase):
    def test_public_bundle_inventory_and_no_private_material(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            public, private = root / "public", root / "private"
            generate(public, private, 16)
            # Even accidentally attached private fields are dropped by packaging.
            manifest = public / "challenge.json"
            data = json.loads(manifest.read_text())
            data["operator_key"] = (private / "operator.key").read_bytes().hex()
            data["known_pairs"][0]["private_note"] = "do not publish"
            manifest.write_text(json.dumps(data))
            output = root / "public.zip"
            inventory = create_bundle(output, manifest)
            secret = (private / "operator.key").read_bytes()
            target = (private / "target.bin").read_bytes()
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()), set(inventory) | {"SHA256SUMS.json"})
                self.assertEqual(json.loads(archive.read("SHA256SUMS.json")), inventory)
                for name, digest in inventory.items():
                    content = archive.read(name)
                    self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
                    self.assertNotIn(secret, content)
                    self.assertNotIn(secret.hex().encode(), content)
                    self.assertNotIn(target, content)
                packaged = json.loads(archive.read("challenge/challenge.json"))
                self.assertNotIn("operator_key", packaged)
                self.assertNotIn("private_note", packaged["known_pairs"][0])
            with self.assertRaises(FileExistsError):
                create_bundle(output, manifest)

    def test_challenge_and_verifier(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for rounds in (1, 16):
                public, private = root / f"public{rounds}", root / f"private{rounds}"
                result = generate(public, private, rounds)
                key, clear = (private / "operator.key").read_bytes(), (private / "target.bin").read_bytes()
                self.assertTrue(verify(result, key=key))
                self.assertTrue(verify(result, plaintext=clear))
                self.assertFalse(verify(result, key=bytes(32)))
                self.assertFalse(verify(result, plaintext=bytes(64)))
                self.assertEqual([p.name for p in public.iterdir()], ["challenge.json"])
            with self.assertRaises(ValueError):
                generate(root / "a", root / "a/b", 16)

    def test_cli_roundtrip_oracle_and_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            key, source, encrypted, clear = (root / n for n in ("local.key", "plain.bin", "enc.bin", "clear.bin"))

            def run(*args, stdin=None):
                return subprocess.run([sys.executable, "-m", "cairn", *map(str, args)], input=stdin,
                                      text=True, capture_output=True, cwd=ROOT)

            self.assertEqual(run("keygen", key).returncode, 0)
            original_key = key.read_bytes()
            self.assertEqual(len(original_key), 32)
            self.assertEqual(run("keygen", key).returncode, 2)
            self.assertEqual(key.read_bytes(), original_key)
            source.write_bytes(bytes(range(256)) + b"\x00\xff")
            self.assertEqual(run("encrypt", source, encrypted, "--key-file", key).returncode, 0)
            self.assertEqual(run("decrypt", encrypted, clear, "--key-file", key).returncode, 0)
            self.assertEqual(clear.read_bytes(), source.read_bytes())
            self.assertEqual(run("block", "bad", "--key-file", key).returncode, 2)
            query = json.dumps({"plaintext": bytes(16).hex()})
            result = run("oracle", "--key-file", key, "--limit", 2, stdin="[]\n" + query + "\n" + query + "\n")
            lines = [json.loads(x) for x in result.stdout.splitlines()]
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(lines), 2)
            self.assertIn("error", lines[0])
            self.assertEqual(lines[1]["ciphertext"], Cipher(original_key).encrypt_block(bytes(16)).hex())
            result = run("oracle", "--key-file", key, stdin="x" * 5000 + "\n")
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()

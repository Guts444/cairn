"""Guard the frozen primitive and target while public documentation evolves."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_frozen_implementation_spec_and_vectors(self):
        hashes = json.loads((ROOT / "docs/FROZEN_SHA256.json").read_text())
        for name, expected in hashes.items():
            if name != "challenge_identity":
                with self.subTest(path=name):
                    self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)

    def test_original_target_preserved_with_zero_public_queries(self):
        data = json.loads((ROOT / "challenge/challenge.json").read_text())
        fields = ("algorithm", "rounds", "track", "known_pairs", "target_ciphertext",
                  "target_plaintext_sha256", "target_bytes", "goals", "mode")
        identity = json.dumps({field: data[field] for field in fields}, sort_keys=True, separators=(",", ":"))
        hashes = json.loads((ROOT / "docs/FROZEN_SHA256.json").read_text())
        self.assertEqual(hashlib.sha256(identity.encode()).hexdigest(), hashes["challenge_identity"])
        self.assertEqual(data["oracle_query_budget"], 0)
        self.assertEqual(data["rounds"], 16)
        self.assertEqual(len(data["known_pairs"]), 8)


if __name__ == "__main__":
    unittest.main()

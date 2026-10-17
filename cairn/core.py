"""The complete Cairn-128/256 primitive. See docs/SPEC.md."""

import struct

MASK = (1 << 64) - 1
ROUNDS = 16
BLOCK_SIZE = 16
KEY_SIZE = 32
GOLDEN = 0x9E3779B97F4A7C15


def rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK


def expand_key(key: bytes) -> tuple[tuple[int, int], ...]:
    if len(key) != KEY_SIZE:
        raise ValueError("key must contain exactly 32 bytes")
    a, b, c, d = struct.unpack(">4Q", key)
    result = []
    for i in range(8 + ROUNDS):
        a = (a + rol(b, 9) + ((i + 1) * GOLDEN & MASK)) & MASK
        c ^= rol(a, 23)
        d = (d + rol(c, 31)) & MASK
        b = rol(b ^ d, 17)
        a, b, c, d = b, c, d, a
        if i >= 8:
            result.append((a ^ c, (b + d) & MASK))
    return tuple(result)


def round_function(right: int, k0: int, k1: int) -> int:
    x = (right + k0) & MASK
    x ^= rol(x, 13) ^ rol(x, 37)
    x = (x + k1) & MASK
    x ^= rol(x, 17) ^ rol(x, 41)
    return rol(x, 29)


class Cipher:
    def __init__(self, key: bytes, rounds: int = ROUNDS):
        if type(rounds) is not int or not 1 <= rounds <= ROUNDS:
            raise ValueError("research rounds must be an integer from 1 to 16")
        self.subkeys = expand_key(key)[:rounds]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("block must contain exactly 16 bytes")
        left, right = struct.unpack(">2Q", block)
        for k0, k1 in self.subkeys:
            left, right = right, left ^ round_function(right, k0, k1)
        return struct.pack(">2Q", left, right)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("block must contain exactly 16 bytes")
        left, right = struct.unpack(">2Q", block)
        for k0, k1 in reversed(self.subkeys):
            left, right = right ^ round_function(left, k0, k1), left
        return struct.pack(">2Q", left, right)

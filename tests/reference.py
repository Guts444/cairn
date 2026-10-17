"""Separate, literal spec implementation; deliberately imports no cairn code.

This checks transcription/encoding errors, not independent cryptographic review.
"""


def encrypt(key: bytes, block: bytes, rounds: int = 16) -> bytes:
    modulus = 2 ** 64

    def rotate(value, count):
        # Alternate formulation: rotation through bit strings.
        bits = format(value, "064b")
        return int(bits[count:] + bits[:count], 2)

    state = [int.from_bytes(key[i:i + 8], "big") for i in range(0, 32, 8)]
    keys = []
    for index in range(24):
        state[0] = (state[0] + rotate(state[1], 9) + (index + 1) * 0x9E3779B97F4A7C15) % modulus
        state[2] = state[2] ^ rotate(state[0], 23)
        state[3] = (state[3] + rotate(state[2], 31)) % modulus
        state[1] = rotate(state[1] ^ state[3], 17)
        state = state[1:] + state[:1]
        if index >= 8:
            keys.append((state[0] ^ state[2], (state[1] + state[3]) % modulus))
    halves = [int.from_bytes(block[:8], "big"), int.from_bytes(block[8:], "big")]
    for first, second in keys[:rounds]:
        v = (halves[1] + first) % modulus
        v = v ^ rotate(v, 13) ^ rotate(v, 37)
        v = (v + second) % modulus
        v = v ^ rotate(v, 17) ^ rotate(v, 41)
        v = rotate(v, 29)
        halves = [halves[1], halves[0] ^ v]
    return b"".join(h.to_bytes(8, "big") for h in halves)

# Cairn-128/256-v0.1 specification

Status: research baseline, not a security standard. Full round count: 16. Block size: 128 bits. Master key size: 256 bits. All integer encodings are unsigned, big endian. All word operations are on 64 bits; every addition is modulo 2^64. `ROL(x,n)` rotates a 64-bit word left by `n`. XOR is bitwise. Each right-hand side uses values before its assignment; sequential lines use the updated state. There are no S-boxes, multiplication of secret words or data-dependent rotations.

## Key schedule

Parse the 32-byte key into four consecutive 64-bit words `(a,b,c,d)`. Set `G = 0x9E3779B97F4A7C15`. For `i = 0..23`, perform:

```text
a = a + ROL(b, 9) + ((i + 1) * G)
c = c XOR ROL(a, 23)
d = d + ROL(c, 31)
b = ROL(b XOR d, 17)
(a,b,c,d) = (b,c,d,a)       # simultaneous reassignment
if i >= 8:
    round_key[i - 8] = (a XOR c, b + d)
```

The first eight iterations emit no keys. All 16 round keys are generated even for a reduced-round experiment; such an experiment uses their prefix. No whitening keys are used.

## Round function

Given a 64-bit half-block `r` and two-word round key `(u,v)`:

```text
x = r + u
x = x XOR ROL(x,13) XOR ROL(x,37)
x = x + v
x = x XOR ROL(x,17) XOR ROL(x,41)
F(r,u,v) = ROL(x,29)
```

## Encryption and decryption

Parse a block into two 64-bit words `(L,R)`. In increasing round order:

```text
(L,R) = (R, L XOR F(R,u,v))
```

Return `BE64(L) || BE64(R)` after the final round. **There is no additional final swap.** Decryption starts with these output halves and, in reverse round-key order, applies:

```text
(L,R) = (R XOR F(L,u,v), L)
```

The research API accepts 1..16 rounds. The file format always uses 16. `examples/vectors.json` contains 20 public known-answer vectors for four key/block combinations at 1, 2, 4, 8 and 16 rounds. The reference implementation uses bit-string rotations and separate encoding/scheduling code.

## File container v1

The primitive challenge bypasses this wrapper. File encryption uses:

```text
header = magic[8] || nonce[16] || plaintext_length_BE64[8]
file   = header || ciphertext[plaintext_length] || tag[32]
magic  = ASCII("CAIRN01") || 0x00
nonce  = 16 fresh OS-random bytes
Kenc   = HMAC-SHA-256(master_key, ASCII("cairn/file/encryption/v1") || 0x00 || nonce)
Kmac   = HMAC-SHA-256(master_key, ASCII("cairn/file/authentication/v1") || 0x00 || nonce)
stream[j] = Cairn_16rounds(Kenc, BE128(j)), starting at j=0
ciphertext = plaintext XOR concatenated stream, truncated to plaintext length
tag = HMAC-SHA-256(Kmac, header || ciphertext)
```

No padding. The final stream block may be partial. Random nonce reuse repeats the derived keys and keystream and is forbidden; random 128-bit nonce collisions grow with the birthday bound. File lengths are below 2^64 bytes; counters cannot wrap within that limit. Applications creating very many files would need an explicit nonce-management policy. This lab makes no workload security claim.

Decryption rejects bad magic, truncation, trailing data and a mismatched tag. It snapshots/authenticates ciphertext before decryption, then publishes the complete plaintext without replacing an existing path. Tag checking uses `hmac.compare_digest`. File encryption never calls the raw primitive directly with the master key: primitive challenges do, so wrapper key derivation does not hide weaknesses in those experiments.

CTR's requirement for unique counter blocks under each encryption key is documented in [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final). This reference explains the mode; it provides no endorsement or validation of Cairn.

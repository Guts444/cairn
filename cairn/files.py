"""Streaming CTR + encrypt-then-HMAC wrapper around the experimental primitive."""

import hashlib
import hmac
import os
from pathlib import Path
import struct
import tempfile

from .core import Cipher, KEY_SIZE

MAGIC = b"CAIRN01\x00"
HEADER = struct.Struct(">8s16sQ")
TAG_SIZE = 32
CHUNK = 64 * 1024  # Must be a multiple of the block size.
ENC_LABEL = b"cairn/file/encryption/v1\x00"
MAC_LABEL = b"cairn/file/authentication/v1\x00"


def derive_keys(key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    if len(key) != KEY_SIZE or len(nonce) != 16:
        raise ValueError("invalid key or nonce size")
    return tuple(hmac.digest(key, label + nonce, "sha256") for label in (ENC_LABEL, MAC_LABEL))


def transform(data: bytes, cipher: Cipher, counter: int) -> tuple[bytes, int]:
    out = bytearray(len(data))
    for offset in range(0, len(data), 16):
        stream = cipher.encrypt_block(counter.to_bytes(16, "big"))
        part = data[offset:offset + 16]
        out[offset:offset + len(part)] = bytes(a ^ b for a, b in zip(part, stream))
        counter += 1
    return bytes(out), counter


def _publish(temp: Path, output: Path) -> None:
    # A hard link publishes a complete file atomically and fails if output exists.
    # Same-directory staging keeps both paths on the same filesystem.
    os.link(temp, output)


def encrypt_file(source: Path, output: Path, key: bytes) -> None:
    nonce = os.urandom(16)
    encryption_key, mac_key = derive_keys(key, nonce)
    cipher = Cipher(encryption_key)
    if output.exists():
        raise FileExistsError("output already exists")
    fd, name = tempfile.mkstemp(prefix=".cairn-", dir=output.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, "wb") as dst, source.open("rb") as src:
            size = os.fstat(src.fileno()).st_size
            header = HEADER.pack(MAGIC, nonce, size)
            auth = hmac.new(mac_key, header, hashlib.sha256)
            dst.write(header)
            counter = consumed = 0
            while data := src.read(CHUNK):
                consumed += len(data)
                encrypted, counter = transform(data, cipher, counter)
                dst.write(encrypted)
                auth.update(encrypted)
            if consumed != size:
                raise ValueError("source size changed during encryption")
            dst.write(auth.digest())
            dst.flush()
            os.fsync(dst.fileno())
        _publish(temp, output)
    finally:
        temp.unlink(missing_ok=True)


def decrypt_file(source: Path, output: Path, key: bytes) -> None:
    if output.exists():
        raise FileExistsError("output already exists")
    # Authenticate and snapshot ciphertext before creating any plaintext. This
    # also avoids a source-file modification race between verification and use.
    with source.open("rb") as src, tempfile.TemporaryFile(mode="w+b", dir=output.parent) as snapshot:
        header = src.read(HEADER.size)
        if len(header) != HEADER.size:
            raise ValueError("truncated header")
        magic, nonce, size = HEADER.unpack(header)
        if magic != MAGIC:
            raise ValueError("unsupported file format")
        encryption_key, mac_key = derive_keys(key, nonce)
        auth = hmac.new(mac_key, header, hashlib.sha256)
        remaining = size
        while remaining:
            data = src.read(min(CHUNK, remaining))
            if not data:
                raise ValueError("truncated ciphertext")
            remaining -= len(data)
            snapshot.write(data)
            auth.update(data)
        tag = src.read(TAG_SIZE)
        if len(tag) != TAG_SIZE or src.read(1):
            raise ValueError("invalid file length")
        if not hmac.compare_digest(tag, auth.digest()):
            raise ValueError("authentication failed (wrong key or modified file)")
        snapshot.seek(0)
        cipher = Cipher(encryption_key)
        fd, name = tempfile.mkstemp(prefix=".cairn-", dir=output.parent)
        temp = Path(name)
        try:
            with os.fdopen(fd, "wb") as dst:
                counter = 0
                while data := snapshot.read(CHUNK):
                    clear, counter = transform(data, cipher, counter)
                    dst.write(clear)
                dst.flush()
                os.fsync(dst.fileno())
            _publish(temp, output)
        finally:
            temp.unlink(missing_ok=True)

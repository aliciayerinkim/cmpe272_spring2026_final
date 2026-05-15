"""SHA-256 helpers for verifying plaintext after transfer (stdlib hashlib only)."""

from __future__ import annotations

import hashlib
from pathlib import Path

from common.constants import DEFAULT_CHUNK_SIZE_BYTES
from common.streaming import iter_file_chunks


class StreamingSha256:
    """Incremental SHA-256 hasher for streaming pipelines."""

    __slots__ = ("_digest",)

    def __init__(self) -> None:
        self._digest = hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._digest.update(data)

    def digest(self) -> bytes:
        return self._digest.digest()

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def sha256_hex_digest_file(
    path: Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> str:
    """Compute the lowercase hex SHA-256 digest of a file without loading it whole."""
    hasher = StreamingSha256()
    for chunk in iter_file_chunks(path, chunk_size=chunk_size):
        hasher.update(chunk)
    return hasher.hexdigest()


def verify_file_sha256_hex(
    path: Path,
    expected_hex: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> bool:
    """Return True if the file's SHA-256 matches ``expected_hex`` (case-insensitive)."""
    actual = sha256_hex_digest_file(path, chunk_size=chunk_size)
    return actual.lower() == expected_hex.strip().lower()

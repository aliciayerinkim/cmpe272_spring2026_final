"""Chunked file streaming helpers (never read entire file into memory at once)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from common.constants import DEFAULT_CHUNK_SIZE_BYTES


def iter_file_chunks(
    path: Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> Iterator[bytes]:
    """Yield successive chunks from a file opened in binary mode.

    Each ``read`` requests at most ``chunk_size`` bytes; the final chunk may be
    shorter. At most one chunk is resident in memory at a time.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    with path.open("rb") as handle:
        yield from iter_fixed_chunks_from_stream(handle, chunk_size=chunk_size)


def iter_fixed_chunks_from_stream(
    stream: BinaryIO,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE_BYTES,
) -> Iterator[bytes]:
    """Yield ``stream.read(chunk_size)`` results until EOF (empty read)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        yield chunk


def read_exact_stream(stream: BinaryIO, nbytes: int) -> bytes:
    """Read exactly ``nbytes`` from ``stream``, raising ``EOFError`` on short read."""
    if nbytes < 0:
        raise ValueError("nbytes must be non-negative")
    if nbytes == 0:
        return b""

    parts: list[bytes] = []
    remaining = nbytes
    while remaining:
        piece = stream.read(remaining)
        if not piece:
            raise EOFError(f"expected {nbytes} bytes, got {nbytes - remaining}")
        parts.append(piece)
        remaining -= len(piece)
    return b"".join(parts)


def write_chunks_to_stream(
    chunks: Iterator[bytes],
    destination: BinaryIO,
    *,
    chunk_size: int | None = None,
) -> int:
    """Write ``chunks`` to ``destination``; return total bytes written."""
    _ = chunk_size
    total = 0
    for chunk in chunks:
        destination.write(chunk)
        total += len(chunk)
    return total

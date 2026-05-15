"""Low-level TCP helpers: exact-length reads, reliable sends, buffer hints."""

from __future__ import annotations

import errno
import socket

from common.constants import (
    DEFAULT_CONNECT_TIMEOUT_SEC,
    DEFAULT_READ_TIMEOUT_SEC,
    DEFAULT_SOCKET_BUFFER_BYTES,
)
from common.errors import ConnectionClosedError


def send_all(sock: socket.socket, data: bytes | bytearray | memoryview) -> None:
    """Send all bytes in ``data``; raise on hard errors or non-recoverable stalls."""
    try:
        sock.sendall(data)
    except OSError as exc:
        if exc.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
            raise ConnectionClosedError(str(exc)) from exc
        raise


def recv_exact(
    sock: socket.socket,
    nbytes: int,
    *,
    chunk_hint: int = DEFAULT_SOCKET_BUFFER_BYTES,
) -> bytes:
    """Read exactly ``nbytes`` from ``sock`` (may perform multiple ``recv`` calls)."""
    if nbytes < 0:
        raise ValueError("nbytes must be non-negative")
    if nbytes == 0:
        return b""

    chunks: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        try:
            chunk = sock.recv(min(chunk_hint, remaining))
        except OSError as exc:
            if exc.errno in (errno.ECONNRESET, errno.ETIMEDOUT, errno.EPIPE):
                raise ConnectionClosedError(str(exc)) from exc
            raise
        if not chunk:
            raise ConnectionClosedError(
                f"connection closed after {nbytes - remaining} of {nbytes} bytes"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def apply_socket_buffer_hints(
    sock: socket.socket,
    *,
    buffer_bytes: int = DEFAULT_SOCKET_BUFFER_BYTES,
) -> None:
    """Best-effort ``SO_SNDBUF`` / ``SO_RCVBUF`` tuning; ignores platforms that reject it."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_bytes)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_bytes)
    except OSError:
        # Non-fatal: defaults are still usable.
        pass


def configure_blocking_socket(
    sock: socket.socket,
    *,
    timeout_sec: float | None = DEFAULT_READ_TIMEOUT_SEC,
    buffer_bytes: int = DEFAULT_SOCKET_BUFFER_BYTES,
) -> None:
    """Apply buffer hints and a default blocking :meth:`socket.socket.settimeout`.

    The standard library uses a single timeout value for blocking operations on
    a socket; treat ``timeout_sec`` as the default deadline for both reads and
    writes in simple scripts.
    """
    apply_socket_buffer_hints(sock, buffer_bytes=buffer_bytes)
    sock.settimeout(timeout_sec)


def with_connect_timeout(sock: socket.socket, host: str, port: int) -> None:
    """Connect with :data:`DEFAULT_CONNECT_TIMEOUT_SEC`, restoring the prior timeout."""
    previous = sock.gettimeout()
    sock.settimeout(DEFAULT_CONNECT_TIMEOUT_SEC)
    try:
        sock.connect((host, port))
    finally:
        sock.settimeout(previous)

"""Length-prefixed message framing for TCP (JSON control messages + binary chunks)."""

from __future__ import annotations

import json
import struct
from typing import Any

import socket

from common.constants import (
    LENGTH_PREFIX_BYTES,
    MAX_BINARY_PAYLOAD_BYTES,
    MAX_JSON_PAYLOAD_BYTES,
)
from common.errors import FrameTooLargeError, FramingError
from common.tcp import recv_exact, send_all


def _unpack_length(prefix: bytes) -> int:
    if len(prefix) != LENGTH_PREFIX_BYTES:
        raise FramingError("internal error: invalid length prefix size")
    (length,) = struct.unpack("!I", prefix)
    return int(length)


def send_json_frame(sock: socket.socket, payload: Any) -> None:
    """Send a UTF-8 JSON object prefixed with a 4-byte big-endian length."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_JSON_PAYLOAD_BYTES:
        raise FrameTooLargeError(
            f"JSON encoded size {len(body)} exceeds MAX_JSON_PAYLOAD_BYTES"
        )
    header = struct.pack("!I", len(body))
    send_all(sock, header + body)


def recv_json_frame(
    sock: socket.socket,
    *,
    max_payload_bytes: int = MAX_JSON_PAYLOAD_BYTES,
) -> Any:
    """Receive a length-prefixed JSON object; reject oversize length before reading body."""
    prefix = recv_exact(sock, LENGTH_PREFIX_BYTES)
    length = _unpack_length(prefix)
    if length > max_payload_bytes:
        raise FrameTooLargeError(
            f"declared JSON payload {length} bytes exceeds max {max_payload_bytes}"
        )
    body = recv_exact(sock, length)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FramingError("invalid JSON frame body") from exc


def send_binary_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a length-prefixed binary blob (e.g., ciphertext chunk)."""
    if len(payload) > MAX_BINARY_PAYLOAD_BYTES:
        raise FrameTooLargeError(
            f"binary payload {len(payload)} bytes exceeds MAX_BINARY_PAYLOAD_BYTES"
        )
    header = struct.pack("!I", len(payload))
    send_all(sock, header + payload)


def recv_binary_frame(
    sock: socket.socket,
    *,
    max_payload_bytes: int = MAX_BINARY_PAYLOAD_BYTES,
) -> bytes:
    """Receive a length-prefixed binary blob."""
    prefix = recv_exact(sock, LENGTH_PREFIX_BYTES)
    length = _unpack_length(prefix)
    if length > max_payload_bytes:
        raise FrameTooLargeError(
            f"declared binary payload {length} bytes exceeds max {max_payload_bytes}"
        )
    return recv_exact(sock, length)


__all__ = [
    "send_json_frame",
    "recv_json_frame",
    "send_binary_frame",
    "recv_binary_frame",
    "FrameTooLargeError",
    "FramingError",
]

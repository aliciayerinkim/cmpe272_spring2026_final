"""Approach A sender: mutual TLS (client) and length-prefixed framed file upload.

Wire protocol matches ``receiver.py``:

1. After TLS, send one JSON frame with ``filename``, ``size``, ``sha256_hex``.
2. Send the file as length-prefixed binary chunks; payload sizes must stay within
   ``common.constants.MAX_BINARY_PAYLOAD_BYTES``.

The sender negotiates **TLS 1.2 only** to match the receiver. It **streams the
file twice on disk**: first pass computes SHA-256 without holding more than one
chunk in memory; second pass transmits the same chunks.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from common.constants import (
    DEFAULT_CHUNK_SIZE_BYTES,
    DEFAULT_CONNECT_TIMEOUT_SEC,
    MAX_BINARY_PAYLOAD_BYTES,
    TLS12_MT_ALLOWED_CIPHER_LIST,
)
from common.errors import FrameTooLargeError
from common.framing import send_binary_frame, send_json_frame
from common.hashing import StreamingSha256
from common.streaming import iter_file_chunks
from common.tcp import apply_socket_buffer_hints


def _format_mb_per_s(size_bytes: int, elapsed_s: float) -> str:
    if elapsed_s <= 0:
        return "n/a"
    mb_s = (size_bytes / 1_000_000.0) / elapsed_s
    mib_s = (size_bytes / (1024.0 * 1024.0)) / elapsed_s
    return f"{mb_s:.2f} MB/s (SI)  |  {mib_s:.2f} MiB/s (1024^2)"


def _validate_remote_name(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("remote filename must be non-empty")
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("remote filename must not contain path separators")
    if Path(name).name != name:
        raise ValueError("remote filename must be a single path component")
    return name


def _build_client_ssl_context(*, ca_cert: Path, client_cert: Path, client_key: Path) -> ssl.SSLContext:
    if not ca_cert.is_file():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert}")
    if not client_cert.is_file():
        raise FileNotFoundError(f"client certificate not found: {client_cert}")
    if not client_key.is_file():
        raise FileNotFoundError(f"client private key not found: {client_key}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(ca_cert))
    context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.set_ciphers(TLS12_MT_ALLOWED_CIPHER_LIST)
    except ssl.SSLError as exc:
        raise ssl.SSLError(
            f"failed to restrict TLS 1.2 to AEAD ciphers ({exc}); "
            "check Python/OpenSSL cipher support on this machine"
        ) from exc
    return context


def _server_hostname_for_tls(connect_host: str) -> str:
    """Return a name suitable for certificate verification (SAN/CN matching)."""
    if connect_host in {"127.0.0.1", "::1", "localhost"}:
        return "localhost"
    return connect_host


def _stream_hash_file(
    path: Path,
    *,
    chunk_size: int,
    progress_interval_bytes: int,
    label: str,
) -> tuple[str, int, float]:
    """Return ``(sha256_hex_lower, size_bytes, elapsed_seconds)``."""
    expected_size = path.stat().st_size
    hasher = StreamingSha256()
    read_total = 0
    next_report = (
        min(progress_interval_bytes, expected_size)
        if expected_size and progress_interval_bytes > 0
        else 0
    )
    t0 = time.perf_counter()
    for chunk in iter_file_chunks(path, chunk_size=chunk_size):
        hasher.update(chunk)
        read_total += len(chunk)
        if progress_interval_bytes > 0 and read_total >= next_report:
            pct = 100.0 * read_total / expected_size
            if read_total < expected_size:
                print(
                    f"{label}: {read_total}/{expected_size} bytes ({pct:.1f}%)",
                    flush=True,
                )
            while next_report <= read_total:
                next_report += progress_interval_bytes
    elapsed = time.perf_counter() - t0
    if read_total != expected_size:
        raise RuntimeError("file size changed while hashing; aborting send")
    if expected_size > 0:
        print(f"{label}: {expected_size}/{expected_size} bytes (100.0%)", flush=True)
    return hasher.hexdigest().lower(), expected_size, elapsed


def _send_file_payload(
    ssl_sock: ssl.SSLSocket,
    path: Path,
    *,
    expected_size: int,
    chunk_size: int,
    progress_interval_bytes: int,
    label: str,
) -> float:
    """Stream ``path`` over ``ssl_sock``; return seconds spent in the send loop."""
    read_total = 0
    next_report = (
        min(progress_interval_bytes, expected_size)
        if expected_size and progress_interval_bytes > 0
        else 0
    )
    t0 = time.perf_counter()
    for chunk in iter_file_chunks(path, chunk_size=chunk_size):
        send_binary_frame(ssl_sock, chunk)
        read_total += len(chunk)
        if read_total > expected_size:
            raise RuntimeError("read more bytes than expected during send")
        if progress_interval_bytes > 0 and read_total >= next_report:
            pct = 100.0 * read_total / expected_size
            if read_total < expected_size:
                print(
                    f"{label}: {read_total}/{expected_size} bytes ({pct:.1f}%)",
                    flush=True,
                )
            while next_report <= read_total:
                next_report += progress_interval_bytes
    elapsed = time.perf_counter() - t0
    if read_total != expected_size:
        raise RuntimeError("file size changed during send")
    if expected_size > 0:
        print(f"{label}: {expected_size}/{expected_size} bytes (100.0%)", flush=True)
    return elapsed


def main(argv: list[str] | None = None) -> int:
    default_cert_dir = Path(__file__).resolve().parent / "certs"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Server hostname or IP (default loopback IPv4).")
    parser.add_argument("--port", type=int, default=8443, help="Server port.")
    parser.add_argument("--ca-cert", type=Path, default=default_cert_dir / "ca-cert.pem")
    parser.add_argument("--client-cert", type=Path, default=default_cert_dir / "client-cert.pem")
    parser.add_argument("--client-key", type=Path, default=default_cert_dir / "client-key.pem")
    parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="Path to the file to upload (read in chunks only).",
    )
    parser.add_argument(
        "--remote-name",
        type=str,
        default=None,
        help="Filename the receiver should store (default: basename of --file).",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE_BYTES,
        help=f"Read/send chunk size in bytes (default {DEFAULT_CHUNK_SIZE_BYTES}; must fit in a binary frame).",
    )
    parser.add_argument(
        "--progress-interval-mib",
        type=int,
        default=32,
        help="Print progress after this many MiB (1024^2) per phase (0 disables intermediate lines).",
    )
    args = parser.parse_args(argv)

    path: Path = args.file.expanduser().resolve()
    if not path.is_file():
        print(f"ERROR: not a regular file: {path}", file=sys.stderr)
        return 1

    chunk_size = int(args.chunk_size)
    if chunk_size <= 0:
        print("ERROR: --chunk-size must be positive", file=sys.stderr)
        return 1
    if chunk_size > MAX_BINARY_PAYLOAD_BYTES:
        print(
            f"ERROR: --chunk-size {chunk_size} exceeds MAX_BINARY_PAYLOAD_BYTES ({MAX_BINARY_PAYLOAD_BYTES})",
            file=sys.stderr,
        )
        return 1

    remote_name = args.remote_name if args.remote_name is not None else path.name
    try:
        remote_name = _validate_remote_name(remote_name)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    progress_interval_bytes = max(0, int(args.progress_interval_mib)) * 1024 * 1024

    try:
        sha256_hex, size, hash_elapsed = _stream_hash_file(
            path,
            chunk_size=chunk_size,
            progress_interval_bytes=progress_interval_bytes,
            label="Hashing",
        )
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: failed to read file for hashing: {exc}", file=sys.stderr)
        return 1

    print(
        f"SHA-256 (streaming): {sha256_hex}  ({size} bytes)  [{_format_mb_per_s(size, hash_elapsed)}]",
        flush=True,
    )

    try:
        context = _build_client_ssl_context(
            ca_cert=args.ca_cert,
            client_cert=args.client_cert,
            client_key=args.client_key,
        )
    except (OSError, ssl.SSLError, ValueError) as exc:
        print(f"ERROR: TLS configuration failed: {exc}", file=sys.stderr)
        return 1

    connect_host = str(args.host)
    connect_port = int(args.port)
    server_hostname = _server_hostname_for_tls(connect_host)

    try:
        with socket.create_connection(
            (connect_host, connect_port),
            timeout=DEFAULT_CONNECT_TIMEOUT_SEC,
        ) as raw_sock:
            apply_socket_buffer_hints(raw_sock)
            raw_sock.settimeout(None)
            with context.wrap_socket(raw_sock, server_hostname=server_hostname) as ssl_sock:
                send_json_frame(
                    ssl_sock,
                    {"filename": remote_name, "size": size, "sha256_hex": sha256_hex},
                )
                send_elapsed = _send_file_payload(
                    ssl_sock,
                    path,
                    expected_size=size,
                    chunk_size=chunk_size,
                    progress_interval_bytes=progress_interval_bytes,
                    label="Sending",
                )
    except (OSError, ssl.SSLError, ValueError, RuntimeError, FrameTooLargeError) as exc:
        print(f"ERROR: connect or send failed: {exc}", file=sys.stderr)
        return 1

    print(f"OK: sent {remote_name!r} ({size} bytes)", flush=True)
    print(f"Send throughput: {_format_mb_per_s(size, send_elapsed)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

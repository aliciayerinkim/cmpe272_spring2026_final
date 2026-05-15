#!/usr/bin/env python3
"""Approach A TLS client: send correct file bytes but declare a wrong sha256_hex in metadata.

The receiver should ingest chunks, then fail closed on SHA-256 mismatch (no final rename).
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from common.constants import DEFAULT_CHUNK_SIZE_BYTES, DEFAULT_CONNECT_TIMEOUT_SEC, MAX_BINARY_PAYLOAD_BYTES
from common.errors import FrameTooLargeError
from common.framing import send_binary_frame, send_json_frame
from common.hashing import StreamingSha256
from common.streaming import iter_file_chunks
from common.tcp import apply_socket_buffer_hints


def _build_client_ssl_context(*, ca_cert: Path, client_cert: Path, client_key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(ca_cert))
    context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _server_hostname(connect_host: str) -> str:
    if connect_host in {"127.0.0.1", "::1", "localhost"}:
        return "localhost"
    return connect_host


def main(argv: list[str] | None = None) -> int:
    default_cert_dir = _REPO_ROOT / "approach-a-mtls" / "certs"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca-cert", type=Path, default=default_cert_dir / "ca-cert.pem")
    parser.add_argument("--client-cert", type=Path, default=default_cert_dir / "client-cert.pem")
    parser.add_argument("--client-key", type=Path, default=default_cert_dir / "client-key.pem")
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--remote-name", type=str, default=None)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE_BYTES)
    args = parser.parse_args(argv)

    path = args.file.expanduser().resolve()
    if not path.is_file():
        print(f"ERROR: not a file: {path}", file=sys.stderr)
        return 1
    chunk_size = int(args.chunk_size)
    if chunk_size <= 0 or chunk_size > MAX_BINARY_PAYLOAD_BYTES:
        print("ERROR: invalid --chunk-size", file=sys.stderr)
        return 1

    remote = args.remote_name or path.name
    if "/" in remote or "\\" in remote:
        print("ERROR: --remote-name must be a single path component", file=sys.stderr)
        return 1

    hasher = StreamingSha256()
    size = 0
    for chunk in iter_file_chunks(path, chunk_size=chunk_size):
        hasher.update(chunk)
        size += len(chunk)
    real_sha = hasher.hexdigest().lower()
    wrong_sha = "0" * 64
    print(f"Real SHA-256: {real_sha}", flush=True)
    print(f"Sending metadata sha256_hex (wrong): {wrong_sha}", flush=True)

    ctx = _build_client_ssl_context(
        ca_cert=args.ca_cert.resolve(),
        client_cert=args.client_cert.resolve(),
        client_key=args.client_key.resolve(),
    )
    host = str(args.host)
    try:
        with socket.create_connection((host, int(args.port)), timeout=DEFAULT_CONNECT_TIMEOUT_SEC) as raw:
            apply_socket_buffer_hints(raw)
            raw.settimeout(None)
            with ctx.wrap_socket(raw, server_hostname=_server_hostname(host)) as tls:
                send_json_frame(
                    tls,
                    {"filename": remote, "size": size, "sha256_hex": wrong_sha},
                )
                for chunk in iter_file_chunks(path, chunk_size=chunk_size):
                    send_binary_frame(tls, chunk)
    except (OSError, ssl.SSLError, FrameTooLargeError) as exc:
        print(f"Expected failure / disconnect: {exc}", flush=True)
        return 0

    print("WARNING: transfer completed without error (receiver may not have verified yet)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Approach A receiver: mutual TLS (server) and length-prefixed framed file ingest.

Wire protocol (after TLS handshake), using ``common.framing``:

1. One JSON frame (UTF-8, length-prefixed) with keys:

   - ``filename`` (non-empty string, no path separators)
   - ``size`` (integer, total plaintext bytes, ``0`` allowed)
   - ``sha256_hex`` (64 hex characters, case-insensitive)

2. Zero or more binary frames (length-prefixed). The concatenation of all chunk
   payloads MUST equal ``size`` bytes exactly.

The server negotiates **TLS 1.2 only** (``minimum_version`` / ``maximum_version``)
for predictable mutual-auth behavior across platforms; the sender should match.

The receiver writes to ``<output-dir>/<filename>.part``, updates SHA-256
incrementally, then renames to the final path only when size and digest match.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from common.atomic_io import replace_with_final
from common.constants import TLS12_MT_ALLOWED_CIPHER_LIST
from common.errors import AtomicCommitError, ConnectionClosedError, FrameTooLargeError, FramingError
from common.framing import recv_binary_frame, recv_json_frame
from common.hashing import StreamingSha256
from common.temp_files import open_part_file, try_unlink
from common.tcp import apply_socket_buffer_hints

_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class TransferFailed(Exception):
    """Raised after a loud stderr diagnostic when a transfer cannot be committed."""


def _fail(message: str, *, part_path: Path | None = None, output_dir: Path | None = None) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    if part_path is not None and part_path.exists() and output_dir is not None:
        _quarantine_or_delete(part_path, output_dir)
    elif part_path is not None and part_path.exists():
        try_unlink(part_path)
    print("TRANSFER FAILED", file=sys.stderr)
    raise TransferFailed(message)


def _quarantine_or_delete(part_path: Path, output_dir: Path) -> None:
    """Move a corrupt partial next to outputs or delete it if quarantine fails."""
    qdir = output_dir / ".quarantine"
    try:
        qdir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        target = qdir / f"{part_path.name}.failed.{stamp}"
        part_path.rename(target)
        print(f"QUARANTINED partial file -> {target}", file=sys.stderr)
    except OSError as exc:
        print(f"Could not quarantine {part_path} ({exc}); deleting partial.", file=sys.stderr)
        try_unlink(part_path)


def _parse_metadata(raw: object) -> tuple[str, int, str]:
    if not isinstance(raw, dict):
        raise ValueError("metadata must be a JSON object")
    filename = raw.get("filename")
    size = raw.get("size")
    sha256_hex = raw.get("sha256_hex")
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("metadata.filename must be a non-empty string")
    if "/" in filename or "\\" in filename or filename in {".", ".."}:
        raise ValueError("metadata.filename must not contain path separators")
    if Path(filename).name != filename:
        raise ValueError("metadata.filename must be a single path component")
    if type(size) is not int:
        raise ValueError("metadata.size must be an integer byte length")
    if size < 0:
        raise ValueError("metadata.size must be non-negative")
    if not isinstance(sha256_hex, str) or not _SHA256_HEX_RE.match(sha256_hex):
        raise ValueError("metadata.sha256_hex must be a 64-character hex string")
    return filename, size, sha256_hex.lower()


def _build_ssl_context(
    *,
    ca_cert: Path,
    server_cert: Path,
    server_key: Path,
) -> ssl.SSLContext:
    if not ca_cert.is_file():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert}")
    if not server_cert.is_file():
        raise FileNotFoundError(f"server certificate not found: {server_cert}")
    if not server_key.is_file():
        raise FileNotFoundError(f"server private key not found: {server_key}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Windows Schannel/OpenSSL stacks occasionally disagree on TLS 1.3 post-handshake
    # client auth edge cases; TLS 1.2 keeps classroom setups predictable.
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    context.load_verify_locations(cafile=str(ca_cert))
    context.verify_mode = ssl.CERT_REQUIRED
    if hasattr(ssl, "VERIFY_FAIL_IF_NO_PEER_CERT"):
        context.verify_flags |= ssl.VERIFY_FAIL_IF_NO_PEER_CERT
    try:
        context.set_ciphers(TLS12_MT_ALLOWED_CIPHER_LIST)
    except ssl.SSLError as exc:
        raise ssl.SSLError(
            f"failed to restrict TLS 1.2 to AEAD ciphers ({exc}); "
            "check Python/OpenSSL cipher support on this machine"
        ) from exc
    return context


def _peer_common_name(cert: dict) -> str | None:
    for rdn in cert.get("subject", ()):
        for attr, value in rdn:
            if attr == "commonName":
                return str(value)
    return None


def _format_mb_per_s(size_bytes: int, elapsed_s: float) -> str:
    if elapsed_s <= 0:
        return "n/a"
    mb_s = (size_bytes / 1_000_000.0) / elapsed_s
    mib_s = (size_bytes / (1024.0 * 1024.0)) / elapsed_s
    return f"{mb_s:.2f} MB/s (SI)  |  {mib_s:.2f} MiB/s (1024^2)"


def _serve_one_client(
    ssl_sock: ssl.SSLSocket,
    *,
    output_dir: Path,
    max_bytes: int,
    progress_interval_bytes: int,
) -> None:
    meta = recv_json_frame(ssl_sock)
    filename, size, expected_sha = _parse_metadata(meta)
    if size > max_bytes:
        raise ValueError(f"metadata.size {size} exceeds configured --max-bytes {max_bytes}")

    final_path = (output_dir / filename).resolve()
    try:
        final_path.relative_to(output_dir.resolve())
    except ValueError as exc:
        raise ValueError("refusing to write outside of output directory") from exc

    output_dir.mkdir(parents=True, exist_ok=True)

    hasher = StreamingSha256()
    received = 0
    payload_started_at: float | None = None
    next_report = min(progress_interval_bytes, size) if size and progress_interval_bytes > 0 else 0

    print(
        f"Accepted metadata: name={filename!r} size={size} bytes sha256={expected_sha}",
        flush=True,
    )

    ssl_sock.settimeout(None)

    with open_part_file(final_path) as (handle, part_path):
        while received < size:
            chunk = recv_binary_frame(ssl_sock)
            if payload_started_at is None:
                payload_started_at = time.perf_counter()
            handle.write(chunk)
            hasher.update(chunk)
            received += len(chunk)
            if received > size:
                raise ValueError(
                    f"received {received} bytes which exceeds declared size {size}"
                )

            if progress_interval_bytes > 0 and received >= next_report:
                pct = 100.0 * received / size
                if received < size:
                    print(
                        f"Progress: {received}/{size} bytes ({pct:.1f}%)",
                        flush=True,
                    )
                while next_report <= received:
                    next_report += progress_interval_bytes

        if received != size:
            raise ValueError(f"short read: got {received} bytes, expected {size}")

        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError as exc:
            raise RuntimeError(f"fsync failed: {exc}") from exc

    if size > 0:
        print(f"Progress: {size}/{size} bytes (100.0%)", flush=True)

    part_size = part_path.stat().st_size
    if part_size != size:
        _fail(
            f"on-disk size {part_size} does not match declared size {size}",
            part_path=part_path,
            output_dir=output_dir,
        )

    actual_sha = hasher.hexdigest().lower()
    if actual_sha != expected_sha:
        _fail(
            f"SHA-256 mismatch: expected {expected_sha} got {actual_sha}",
            part_path=part_path,
            output_dir=output_dir,
        )

    payload_elapsed = 0.0
    if size > 0 and payload_started_at is not None:
        payload_elapsed = time.perf_counter() - payload_started_at

    try:
        replace_with_final(part_path, final_path)
    except AtomicCommitError as exc:
        _fail(
            f"failed to promote verified partial file: {exc}",
            part_path=part_path,
            output_dir=output_dir,
        )

    print(f"OK: wrote {final_path}", flush=True)
    print(f"Throughput: {_format_mb_per_s(size, payload_elapsed)}", flush=True)


def main(argv: list[str] | None = None) -> int:
    default_cert_dir = Path(__file__).resolve().parent / "certs"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default localhost).")
    parser.add_argument("--port", type=int, default=8443, help="Listen port.")
    parser.add_argument("--ca-cert", type=Path, default=default_cert_dir / "ca-cert.pem")
    parser.add_argument("--server-cert", type=Path, default=default_cert_dir / "server-cert.pem")
    parser.add_argument("--server-key", type=Path, default=default_cert_dir / "server-key.pem")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("received"),
        help="Directory for finished files (created if missing).",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=8 * 1024**3,
        help="Reject metadata larger than this many bytes (default 8 GiB).",
    )
    parser.add_argument(
        "--progress-interval-mib",
        type=int,
        default=32,
        help="Print progress after this many MiB (1024^2) of payload.",
    )
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    progress_interval_bytes = max(0, int(args.progress_interval_mib)) * 1024 * 1024

    try:
        context = _build_ssl_context(
            ca_cert=args.ca_cert,
            server_cert=args.server_cert,
            server_key=args.server_key,
        )
    except (OSError, ValueError, ssl.SSLError) as exc:
        print(f"ERROR: TLS configuration failed: {exc}", file=sys.stderr)
        return 1

    listen_host = str(args.host)
    listen_port = int(args.port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        apply_socket_buffer_hints(listen_sock)
        listen_sock.bind((listen_host, listen_port))
        listen_sock.listen(1)
        print(f"Listening on {listen_host}:{listen_port} (mTLS required)...", flush=True)

        conn, peer = listen_sock.accept()
        print(f"Accepted TCP connection from {peer}", flush=True)

        conn.settimeout(120.0)
        try:
            ssl_sock = context.wrap_socket(conn, server_side=True)
        except ssl.SSLError as exc:
            print(f"ERROR: TLS handshake failed: {exc}", file=sys.stderr)
            conn.close()
            return 1

        with ssl_sock:
            peer_der = ssl_sock.getpeercert(binary_form=True)
            if not peer_der:
                print(
                    "ERROR: peer did not present a certificate (mTLS required).",
                    file=sys.stderr,
                )
                return 1
            cert_dict = ssl_sock.getpeercert()
            common_name = _peer_common_name(cert_dict) if cert_dict else None
            if common_name is not None:
                print(f"Client authenticated: CN={common_name!r}", flush=True)
            else:
                print("Client authenticated (certificate chain verified).", flush=True)

            try:
                _serve_one_client(
                    ssl_sock,
                    output_dir=output_dir,
                    max_bytes=int(args.max_bytes),
                    progress_interval_bytes=progress_interval_bytes,
                )
            except TransferFailed:
                return 1
            except (
                ConnectionClosedError,
                FrameTooLargeError,
                FramingError,
                OSError,
                ssl.SSLError,
                ValueError,
                RuntimeError,
            ) as exc:
                print(f"ERROR: transfer aborted: {exc}", file=sys.stderr)
                print("TRANSFER FAILED", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

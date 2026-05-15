"""Approach B receiver: plain TCP + application-layer AEAD (see DESIGN.md §5)."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.atomic_io import replace_with_final
from common.constants import MAX_BINARY_PAYLOAD_BYTES
from common.errors import AtomicCommitError, ConnectionClosedError, FrameTooLargeError, FramingError
from common.framing import recv_binary_frame, recv_json_frame, send_binary_frame, send_json_frame
from common.hashing import StreamingSha256
from common.temp_files import open_part_file, try_unlink
from common.tcp import apply_socket_buffer_hints

PROTOCOL_VERSION = 1
_SESSION_ID_DONE: set[str] = set()

_SESSION_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class TransferFailed(Exception):
    """Raised after stderr diagnostics when a transfer cannot be committed."""


def _fail(message: str, *, part_path: Path | None = None, output_dir: Path | None = None) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    if part_path is not None and part_path.exists() and output_dir is not None:
        _quarantine_or_delete(part_path, output_dir)
    elif part_path is not None and part_path.exists():
        try_unlink(part_path)
    print("TRANSFER FAILED", file=sys.stderr)
    raise TransferFailed(message)


def _quarantine_or_delete(part_path: Path, output_dir: Path) -> None:
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


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _handshake_transcript_bytes(
    *,
    session_id_hex: str,
    sender_eph_b64url: str,
    receiver_eph_b64url: str,
    protocol_version: int,
    chunk_plaintext_max: int,
) -> bytes:
    parts = (
        "CMPE272-B-HANDSHAKE-v1\n"
        f"{session_id_hex}\n"
        f"{sender_eph_b64url}\n"
        f"{receiver_eph_b64url}\n"
        f"{protocol_version}\n"
        f"{chunk_plaintext_max}\n"
    )
    return parts.encode("utf-8")


def _canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _hkdf_file_key(ikm: bytes, session_id_raw: bytes) -> bytes:
    salt = hashlib.sha256(b"cmpe272-b-session-v1" + session_id_raw).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"cmpe272-approach-b/file-aead-key/v1",
    )
    return hkdf.derive(ikm)


def _chunk_nonce(session_id_raw: bytes, chunk_index: int) -> bytes:
    h = hashlib.sha256(
        b"cmpe272-b-nonce-v1" + session_id_raw + chunk_index.to_bytes(4, "big")
    ).digest()
    return h[:12]


def _chunk_aad(session_id_raw: bytes, chunk_index: int, chunk_plaintext_len: int) -> bytes:
    return (
        "CMPE272-B-CHUNK-v1".encode("utf-8")
        + b"\x00"
        + session_id_raw
        + chunk_index.to_bytes(4, "big")
        + chunk_plaintext_len.to_bytes(4, "big")
    )


def _load_ed25519_private(path: Path) -> ed25519.Ed25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError(f"expected Ed25519 private key in {path}")
    return key


def _load_ed25519_public(path: Path) -> ed25519.Ed25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError(f"expected Ed25519 public key in {path}")
    return key


def _load_x25519_private(path: Path) -> x25519.X25519PrivateKey:
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise TypeError(f"expected X25519 private key in {path}")
    return key


def _load_x25519_public(path: Path) -> x25519.X25519PublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, x25519.X25519PublicKey):
        raise TypeError(f"expected X25519 public key in {path}")
    return key


def _ed25519_identity_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _expected_chunk_count(size_bytes: int, chunk_plaintext_max: int) -> int:
    if size_bytes < 0 or chunk_plaintext_max <= 0:
        raise ValueError("invalid size or chunk_plaintext_max")
    if size_bytes == 0:
        return 0
    return (size_bytes + chunk_plaintext_max - 1) // chunk_plaintext_max


def _safe_filename(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("filename must be non-empty")
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("filename must not contain path separators")
    if Path(name).name != name:
        raise ValueError("filename must be a single path component")
    return name


def _run_transfer(
    sock: socket.socket,
    *,
    keys_dir: Path,
    output_dir: Path,
    max_bytes: int,
    progress_interval_bytes: int,
) -> None:
    sender_ed_pub = _load_ed25519_public(keys_dir / "sender_ed25519_public.pem")
    recv_ed_priv = _load_ed25519_private(keys_dir / "receiver_ed25519_private.pem")
    sender_x_pub = _load_x25519_public(keys_dir / "sender_x25519_public.pem")
    recv_x_priv = _load_x25519_private(keys_dir / "receiver_x25519_private.pem")

    expected_sender_identity = _ed25519_identity_hex(sender_ed_pub)

    hello1 = recv_json_frame(sock)
    if not isinstance(hello1, dict) or hello1.get("msg_type") != "HELLO1":
        raise ValueError("expected HELLO1 JSON frame")
    if int(hello1.get("protocol_version", -1)) != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol_version")
    session_id_hex = str(hello1.get("session_id", "")).lower()
    if not _SESSION_HEX_RE.match(session_id_hex):
        raise ValueError("session_id must be 32 hex chars (16 bytes)")
    if session_id_hex in _SESSION_ID_DONE:
        raise ValueError("session_id replay rejected")
    sender_eph_b64 = str(hello1.get("sender_ephemeral_x25519_pub", ""))
    sender_eph_pub = x25519.X25519PublicKey.from_public_bytes(_b64url_decode(sender_eph_b64))
    chunk_plaintext_max = int(hello1.get("chunk_plaintext_max", 0))
    if chunk_plaintext_max <= 0 or chunk_plaintext_max > MAX_BINARY_PAYLOAD_BYTES - 32:
        raise ValueError("invalid chunk_plaintext_max")

    recv_eph = x25519.X25519PrivateKey.generate()
    recv_eph_pub = recv_eph.public_key()
    recv_eph_b64 = base64.urlsafe_b64encode(
        recv_eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii").rstrip("=")

    hello2 = {
        "msg_type": "HELLO2",
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id_hex,
        "receiver_ephemeral_x25519_pub": recv_eph_b64,
    }
    send_json_frame(sock, hello2)

    transcript = _handshake_transcript_bytes(
        session_id_hex=session_id_hex,
        sender_eph_b64url=sender_eph_b64,
        receiver_eph_b64url=recv_eph_b64,
        protocol_version=PROTOCOL_VERSION,
        chunk_plaintext_max=chunk_plaintext_max,
    )

    sig_s = recv_binary_frame(sock, max_payload_bytes=128)
    if len(sig_s) != 64:
        raise ValueError("HANDSHAKE_SIG_S must be 64 bytes")
    try:
        sender_ed_pub.verify(sig_s, transcript)
    except InvalidSignature as exc:
        raise ValueError("invalid sender handshake signature") from exc

    sig_r = recv_ed_priv.sign(transcript)
    send_binary_frame(sock, sig_r)

    manifest_raw = recv_json_frame(sock)
    if not isinstance(manifest_raw, dict) or manifest_raw.get("msg_type") != "MANIFEST":
        raise ValueError("expected MANIFEST JSON frame")
    manifest_sig = recv_binary_frame(sock, max_payload_bytes=128)
    if len(manifest_sig) != 64:
        raise ValueError("MANIFEST_SIG must be 64 bytes")

    manifest = dict(manifest_raw)
    canonical = _canonical_manifest_bytes(manifest)
    try:
        sender_ed_pub.verify(manifest_sig, canonical)
    except InvalidSignature as exc:
        raise ValueError("invalid manifest signature") from exc

    if str(manifest.get("session_id", "")).lower() != session_id_hex:
        raise ValueError("manifest session_id mismatch")
    if int(manifest.get("protocol_version", -1)) != PROTOCOL_VERSION:
        raise ValueError("manifest protocol_version mismatch")
    if int(manifest.get("chunk_plaintext_max", 0)) != chunk_plaintext_max:
        raise ValueError("manifest chunk_plaintext_max mismatch")

    filename = _safe_filename(str(manifest.get("filename", "")))
    size_bytes = int(manifest.get("size_bytes", -1))
    chunk_count = int(manifest.get("chunk_count", -1))
    if size_bytes < 0 or size_bytes > max_bytes:
        raise ValueError("invalid size_bytes")
    if chunk_count != _expected_chunk_count(size_bytes, chunk_plaintext_max):
        raise ValueError("chunk_count inconsistent with size_bytes and chunk_plaintext_max")

    sha_expected = str(manifest.get("plaintext_sha256_hex", "")).lower()
    if not _SHA256_HEX_RE.match(sha_expected):
        raise ValueError("invalid plaintext_sha256_hex")

    sender_identity = str(manifest.get("sender_identity", ""))
    if sender_identity != expected_sender_identity:
        raise ValueError("sender_identity does not match configured sender Ed25519 public key")

    ts = manifest.get("timestamp")
    if type(ts) is not int:
        raise ValueError("manifest.timestamp must be int unix seconds")
    if abs(int(time.time()) - int(ts)) > 600:
        raise ValueError("manifest.timestamp outside allowed skew (10 minutes)")

    aead_name = str(manifest.get("aead", "")).lower()
    if aead_name not in ("chacha20-poly1305", "aes-256-gcm"):
        raise ValueError("unsupported aead")

    session_id_raw = binascii.unhexlify(session_id_hex.encode("ascii"))

    k1 = recv_x_priv.exchange(sender_eph_pub)
    k2 = recv_eph.exchange(sender_x_pub)
    ikm = k1 + k2
    file_key = _hkdf_file_key(ikm, session_id_raw)

    final_path = (output_dir / filename).resolve()
    try:
        final_path.relative_to(output_dir.resolve())
    except ValueError as exc:
        raise ValueError("refusing to write outside output directory") from exc
    output_dir.mkdir(parents=True, exist_ok=True)

    max_chunk_frame = 8 + chunk_plaintext_max + 16
    if max_chunk_frame > MAX_BINARY_PAYLOAD_BYTES:
        raise ValueError("chunk_plaintext_max too large for framing limits")

    hasher = StreamingSha256()
    expected_next = 0
    plaintext_written = 0
    payload_started_at: float | None = None
    next_report = (
        min(progress_interval_bytes, size_bytes)
        if size_bytes and progress_interval_bytes > 0
        else 0
    )

    print(
        f"Manifest OK: file={filename!r} size={size_bytes} chunks={chunk_count} aead={aead_name}",
        flush=True,
    )

    if aead_name == "chacha20-poly1305":
        aead = ChaCha20Poly1305(file_key)
    else:
        aead = AESGCM(file_key)

    with open_part_file(final_path) as (handle, part_path):
        try:
            while expected_next < chunk_count:
                frame = recv_binary_frame(sock, max_payload_bytes=max_chunk_frame)
                if len(frame) < 8:
                    raise ValueError("chunk frame too short")
                chunk_index = int.from_bytes(frame[0:4], "big")
                ct_len = int.from_bytes(frame[4:8], "big")
                if chunk_index != expected_next:
                    raise ValueError(
                        f"chunk_index {chunk_index} out of order (expected {expected_next})"
                    )
                if ct_len < 16 or ct_len != len(frame) - 8:
                    raise ValueError("invalid ciphertext length")
                ciphertext = frame[8:]
                if payload_started_at is None:
                    payload_started_at = time.perf_counter()

                nonce = _chunk_nonce(session_id_raw, chunk_index)
                pt_len = ct_len - 16
                aad = _chunk_aad(session_id_raw, chunk_index, pt_len)
                try:
                    plaintext = aead.decrypt(nonce, ciphertext, aad)
                except InvalidTag as exc:
                    raise ValueError(f"AEAD tag verification failed at chunk {chunk_index}") from exc
                except Exception as exc:
                    raise ValueError(f"AEAD decrypt failed at chunk {chunk_index}") from exc
                if len(plaintext) != pt_len:
                    raise ValueError("plaintext length mismatch after decrypt")
                if len(plaintext) > chunk_plaintext_max:
                    raise ValueError("chunk plaintext exceeds manifest maximum")
                if chunk_count > 1 and expected_next < chunk_count - 1:
                    if len(plaintext) != chunk_plaintext_max:
                        raise ValueError("non-final chunk must be full size")
                if expected_next == chunk_count - 1:
                    tail = size_bytes - (chunk_count - 1) * chunk_plaintext_max
                    if len(plaintext) != tail:
                        raise ValueError("final chunk size mismatch")

                handle.write(plaintext)
                hasher.update(plaintext)
                plaintext_written += len(plaintext)
                expected_next += 1

                if progress_interval_bytes > 0 and size_bytes and plaintext_written >= next_report:
                    pct = 100.0 * min(plaintext_written, size_bytes) / size_bytes
                    if plaintext_written < size_bytes:
                        print(
                            f"Progress: {min(plaintext_written, size_bytes)}/{size_bytes} bytes ({pct:.1f}%)",
                            flush=True,
                        )
                    while next_report <= plaintext_written:
                        next_report += progress_interval_bytes

            if expected_next != chunk_count:
                raise ValueError("short read: not all chunks received")

            handle.flush()
            try:
                import os

                os.fsync(handle.fileno())
            except OSError as exc:
                raise RuntimeError(f"fsync failed: {exc}") from exc
        except Exception:
            if part_path.exists():
                try:
                    try_unlink(part_path)
                except OSError:
                    pass
            raise

    if size_bytes > 0:
        print(f"Progress: {size_bytes}/{size_bytes} bytes (100.0%)", flush=True)

    part_size = part_path.stat().st_size
    if part_size != size_bytes:
        _fail(
            f"on-disk size {part_size} expected {size_bytes}",
            part_path=part_path,
            output_dir=output_dir,
        )

    actual_sha = hasher.hexdigest().lower()
    if actual_sha != sha_expected:
        _fail(
            f"SHA-256 mismatch: expected {sha_expected} got {actual_sha}",
            part_path=part_path,
            output_dir=output_dir,
        )

    payload_elapsed = 0.0
    if size_bytes > 0 and payload_started_at is not None:
        payload_elapsed = time.perf_counter() - payload_started_at

    try:
        replace_with_final(part_path, final_path)
    except AtomicCommitError as exc:
        _fail(f"atomic rename failed: {exc}", part_path=part_path, output_dir=output_dir)

    _SESSION_ID_DONE.add(session_id_hex)

    mb_s = (size_bytes / 1_000_000.0) / payload_elapsed if payload_elapsed > 0 else 0.0
    mib_s = (size_bytes / (1024.0 * 1024.0)) / payload_elapsed if payload_elapsed > 0 else 0.0
    tp = (
        f"{mb_s:.2f} MB/s (SI)  |  {mib_s:.2f} MiB/s (1024^2)"
        if payload_elapsed > 0
        else "n/a"
    )
    print(f"OK: wrote {final_path}", flush=True)
    print(f"Payload throughput: {tp}", flush=True)


def main(argv: list[str] | None = None) -> int:
    default_keys = Path(__file__).resolve().parent / "keys"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--keys-dir", type=Path, default=default_keys)
    parser.add_argument("--output-dir", type=Path, default=Path("received-b"))
    parser.add_argument("--max-bytes", type=int, default=8 * 1024**3)
    parser.add_argument("--progress-interval-mib", type=int, default=32)
    args = parser.parse_args(argv)

    keys_dir = args.keys_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    progress_interval_bytes = max(0, int(args.progress_interval_mib)) * 1024 * 1024

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    apply_socket_buffer_hints(listen_sock)
    try:
        listen_sock.bind((str(args.host), int(args.port)))
        listen_sock.listen(1)
    except OSError as exc:
        print(f"ERROR: bind failed: {exc}", file=sys.stderr)
        return 1

    print(f"Listening on {args.host}:{args.port} (Approach B envelope)...", flush=True)
    conn, peer = listen_sock.accept()
    listen_sock.close()
    print(f"Accepted TCP from {peer}", flush=True)
    conn.settimeout(600.0)

    try:
        with conn:
            _run_transfer(
                conn,
                keys_dir=keys_dir,
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
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("TRANSFER FAILED", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

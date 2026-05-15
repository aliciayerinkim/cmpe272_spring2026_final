"""Approach B sender: plain TCP + application-layer AEAD (see DESIGN.md §5)."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import secrets
import socket
import sys
import time
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.constants import (
    DEFAULT_CHUNK_SIZE_BYTES,
    DEFAULT_CONNECT_TIMEOUT_SEC,
    DEFAULT_READ_TIMEOUT_SEC,
    MAX_BINARY_PAYLOAD_BYTES,
)
from common.errors import ConnectionClosedError, FrameTooLargeError, FramingError
from common.framing import recv_binary_frame, recv_json_frame, send_binary_frame, send_json_frame
from common.hashing import StreamingSha256
from common.streaming import iter_file_chunks
from common.tcp import apply_socket_buffer_hints

PROTOCOL_VERSION = 1


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _format_mb_per_s(size_bytes: int, elapsed_s: float) -> str:
    if elapsed_s <= 0:
        return "n/a"
    mb_s = (size_bytes / 1_000_000.0) / elapsed_s
    mib_s = (size_bytes / (1024.0 * 1024.0)) / elapsed_s
    return f"{mb_s:.2f} MB/s (SI)  |  {mib_s:.2f} MiB/s (1024^2)"


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


def _validate_remote_name(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("remote filename must be non-empty")
    if "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError("remote filename must not contain path separators")
    if Path(name).name != name:
        raise ValueError("remote filename must be a single path component")
    return name


def _stream_hash_file(
    path: Path,
    *,
    chunk_size: int,
    progress_interval_bytes: int,
) -> tuple[str, int, float]:
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
                    f"Hashing: {read_total}/{expected_size} bytes ({pct:.1f}%)",
                    flush=True,
                )
            while next_report <= read_total:
                next_report += progress_interval_bytes
    elapsed = time.perf_counter() - t0
    if read_total != expected_size:
        raise RuntimeError("file size changed while hashing; aborting send")
    if expected_size > 0:
        print(f"Hashing: {expected_size}/{expected_size} bytes (100.0%)", flush=True)
    return hasher.hexdigest().lower(), expected_size, elapsed


def _send_encrypted_chunks(
    sock: socket.socket,
    path: Path,
    *,
    expected_size: int,
    chunk_plaintext_max: int,
    chunk_count: int,
    session_id_raw: bytes,
    file_key: bytes,
    aead_name: str,
    progress_interval_bytes: int,
) -> float:
    read_total = 0
    next_report = (
        min(progress_interval_bytes, expected_size)
        if expected_size and progress_interval_bytes > 0
        else 0
    )
    t0 = time.perf_counter()
    chunk_index = 0
    if aead_name == "chacha20-poly1305":
        aead = ChaCha20Poly1305(file_key)
    else:
        aead = AESGCM(file_key)
    for plaintext in iter_file_chunks(path, chunk_size=chunk_plaintext_max):
        if chunk_index >= chunk_count:
            raise RuntimeError("read more chunks than manifest chunk_count")
        if len(plaintext) > chunk_plaintext_max:
            raise RuntimeError("chunk larger than chunk_plaintext_max")

        nonce = _chunk_nonce(session_id_raw, chunk_index)
        aad = _chunk_aad(session_id_raw, chunk_index, len(plaintext))
        ct_with_tag = aead.encrypt(nonce, plaintext, aad)
        ct_len = len(ct_with_tag)
        frame = chunk_index.to_bytes(4, "big") + ct_len.to_bytes(4, "big") + ct_with_tag
        send_binary_frame(sock, frame)

        read_total += len(plaintext)
        chunk_index += 1
        if progress_interval_bytes > 0 and read_total >= next_report:
            pct = 100.0 * read_total / expected_size
            if read_total < expected_size:
                print(
                    f"Sending: {read_total}/{expected_size} bytes ({pct:.1f}%)",
                    flush=True,
                )
            while next_report <= read_total:
                next_report += progress_interval_bytes

    elapsed = time.perf_counter() - t0
    if chunk_index != chunk_count:
        raise RuntimeError("fewer chunks read than manifest chunk_count")
    if read_total != expected_size:
        raise RuntimeError("byte count mismatch after send loop")
    if expected_size > 0:
        print(f"Sending: {expected_size}/{expected_size} bytes (100.0%)", flush=True)
    return elapsed


def _run_transfer(
    sock: socket.socket,
    *,
    keys_dir: Path,
    file_path: Path,
    remote_name: str,
    chunk_plaintext_max: int,
    aead_name: str,
    progress_interval_bytes: int,
    max_bytes: int,
) -> None:
    sender_ed_priv = _load_ed25519_private(keys_dir / "sender_ed25519_private.pem")
    sender_ed_pub = sender_ed_priv.public_key()
    recv_ed_pub = _load_ed25519_public(keys_dir / "receiver_ed25519_public.pem")
    sender_x_priv = _load_x25519_private(keys_dir / "sender_x25519_private.pem")
    recv_x_pub = _load_x25519_public(keys_dir / "receiver_x25519_public.pem")

    sha256_hex, size_bytes, hash_elapsed = _stream_hash_file(
        file_path,
        chunk_size=chunk_plaintext_max,
        progress_interval_bytes=progress_interval_bytes,
    )
    if size_bytes > max_bytes:
        raise ValueError(f"file size {size_bytes} exceeds --max-bytes {max_bytes}")

    if file_path.stat().st_size != size_bytes:
        raise RuntimeError("file size changed between hash phase and transfer")

    print(
        f"SHA-256 (streaming): {sha256_hex}  ({size_bytes} bytes)  [{_format_mb_per_s(size_bytes, hash_elapsed)}]",
        flush=True,
    )

    session_id_hex = secrets.token_hex(16)
    sender_eph = x25519.X25519PrivateKey.generate()
    sender_eph_pub = sender_eph.public_key()
    sender_eph_b64 = base64.urlsafe_b64encode(
        sender_eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii").rstrip("=")

    hello1 = {
        "msg_type": "HELLO1",
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id_hex,
        "sender_ephemeral_x25519_pub": sender_eph_b64,
        "chunk_plaintext_max": chunk_plaintext_max,
    }
    send_json_frame(sock, hello1)

    hello2 = recv_json_frame(sock)
    if not isinstance(hello2, dict) or hello2.get("msg_type") != "HELLO2":
        raise ValueError("expected HELLO2 JSON frame")
    if int(hello2.get("protocol_version", -1)) != PROTOCOL_VERSION:
        raise ValueError("HELLO2 protocol_version mismatch")
    if str(hello2.get("session_id", "")).lower() != session_id_hex:
        raise ValueError("HELLO2 session_id mismatch")
    recv_eph_b64 = str(hello2.get("receiver_ephemeral_x25519_pub", ""))
    recv_eph_pub = x25519.X25519PublicKey.from_public_bytes(_b64url_decode(recv_eph_b64))

    transcript = _handshake_transcript_bytes(
        session_id_hex=session_id_hex,
        sender_eph_b64url=sender_eph_b64,
        receiver_eph_b64url=recv_eph_b64,
        protocol_version=PROTOCOL_VERSION,
        chunk_plaintext_max=chunk_plaintext_max,
    )

    sig_s = sender_ed_priv.sign(transcript)
    send_binary_frame(sock, sig_s)

    sig_r = recv_binary_frame(sock, max_payload_bytes=128)
    if len(sig_r) != 64:
        raise ValueError("HANDSHAKE_SIG_R must be 64 bytes")
    try:
        recv_ed_pub.verify(sig_r, transcript)
    except InvalidSignature as exc:
        raise ValueError("invalid receiver handshake signature") from exc

    chunk_count = _expected_chunk_count(size_bytes, chunk_plaintext_max)
    sender_identity = _ed25519_identity_hex(sender_ed_pub)
    manifest: dict[str, Any] = {
        "msg_type": "MANIFEST",
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id_hex,
        "filename": remote_name,
        "size_bytes": size_bytes,
        "chunk_count": chunk_count,
        "chunk_plaintext_max": chunk_plaintext_max,
        "plaintext_sha256_hex": sha256_hex,
        "aead": aead_name,
        "sender_identity": sender_identity,
        "timestamp": int(time.time()),
    }
    manifest_sig = sender_ed_priv.sign(_canonical_manifest_bytes(manifest))
    send_json_frame(sock, manifest)
    send_binary_frame(sock, manifest_sig)

    session_id_raw = binascii.unhexlify(session_id_hex.encode("ascii"))
    k1 = sender_eph.exchange(recv_x_pub)
    k2 = sender_x_priv.exchange(recv_eph_pub)
    file_key = _hkdf_file_key(k1 + k2, session_id_raw)

    send_elapsed = _send_encrypted_chunks(
        sock,
        file_path,
        expected_size=size_bytes,
        chunk_plaintext_max=chunk_plaintext_max,
        chunk_count=chunk_count,
        session_id_raw=session_id_raw,
        file_key=file_key,
        aead_name=aead_name,
        progress_interval_bytes=progress_interval_bytes,
    )

    print(f"OK: sent {remote_name!r} ({size_bytes} bytes)", flush=True)
    print(f"Payload throughput: {_format_mb_per_s(size_bytes, send_elapsed)}", flush=True)


def main(argv: list[str] | None = None) -> int:
    default_keys = Path(__file__).resolve().parent / "keys"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--keys-dir", type=Path, default=default_keys)
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
        "--chunk-plaintext-max",
        type=int,
        default=DEFAULT_CHUNK_SIZE_BYTES,
        help=f"Max plaintext bytes per AEAD chunk (default {DEFAULT_CHUNK_SIZE_BYTES}).",
    )
    parser.add_argument(
        "--aead",
        choices=("chacha20-poly1305", "aes-256-gcm"),
        default="chacha20-poly1305",
        help="AEAD algorithm (must match receiver expectations; default ChaCha20-Poly1305).",
    )
    parser.add_argument("--max-bytes", type=int, default=8 * 1024**3)
    parser.add_argument("--progress-interval-mib", type=int, default=32)
    args = parser.parse_args(argv)

    keys_dir = args.keys_dir.resolve()
    file_path: Path = args.file.expanduser().resolve()
    if not file_path.is_file():
        print(f"ERROR: not a regular file: {file_path}", file=sys.stderr)
        return 1

    chunk_plaintext_max = int(args.chunk_plaintext_max)
    if chunk_plaintext_max <= 0 or chunk_plaintext_max > MAX_BINARY_PAYLOAD_BYTES - 32:
        print("ERROR: invalid --chunk-plaintext-max", file=sys.stderr)
        return 1
    max_chunk_frame = 8 + chunk_plaintext_max + 16
    if max_chunk_frame > MAX_BINARY_PAYLOAD_BYTES:
        print(
            f"ERROR: encrypted chunk frame ({max_chunk_frame} bytes) exceeds MAX_BINARY_PAYLOAD_BYTES",
            file=sys.stderr,
        )
        return 1

    remote_name = args.remote_name if args.remote_name is not None else file_path.name
    try:
        remote_name = _validate_remote_name(remote_name)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    progress_interval_bytes = max(0, int(args.progress_interval_mib)) * 1024 * 1024
    aead_name: str = str(args.aead)

    try:
        with socket.create_connection(
            (str(args.host), int(args.port)),
            timeout=DEFAULT_CONNECT_TIMEOUT_SEC,
        ) as sock:
            apply_socket_buffer_hints(sock)
            sock.settimeout(DEFAULT_READ_TIMEOUT_SEC)
            _run_transfer(
                sock,
                keys_dir=keys_dir,
                file_path=file_path,
                remote_name=remote_name,
                chunk_plaintext_max=chunk_plaintext_max,
                aead_name=aead_name,
                progress_interval_bytes=progress_interval_bytes,
                max_bytes=int(args.max_bytes),
            )
    except (
        ConnectionClosedError,
        FrameTooLargeError,
        FramingError,
        InvalidSignature,
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

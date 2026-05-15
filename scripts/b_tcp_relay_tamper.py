#!/usr/bin/env python3
"""TCP relay for Approach B: sender connects here; traffic is forwarded to the real receiver.

Use this to demonstrate fail-closed behaviour when one byte of the MANIFEST JSON,
the MANIFEST signature blob, or the first ciphertext chunk is flipped in flight.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
from pathlib import Path
from typing import Callable

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from common.errors import ConnectionClosedError
from common.tcp import recv_exact, send_all


def _read_frame(sock: socket.socket) -> bytes:
    prefix = recv_exact(sock, 4)
    (n,) = struct.unpack("!I", prefix)
    body = recv_exact(sock, n)
    return prefix + body


def _write_frame(sock: socket.socket, frame: bytes) -> None:
    send_all(sock, frame)


def _tamper_manifest_json(body: bytes) -> bytes:
    """Change the first ASCII digit in the JSON so the body no longer matches MANIFEST_SIG."""
    ba = bytearray(body)
    for i, ch in enumerate(ba):
        if 0x30 <= ch <= 0x39:
            ba[i] = ((ch - 0x30 + 1) % 10) + 0x30
            break
    return bytes(ba)


def _tamper_last_byte(body: bytes) -> bytes:
    if not body:
        return body
    ba = bytearray(body)
    ba[-1] ^= 0x01
    return bytes(ba)


def _relay_loop(
    reader: socket.socket,
    writer: socket.socket,
    *,
    mutator: Callable[[int, bytes], bytes | None] | None = None,
) -> None:
    idx = 0
    try:
        while True:
            frame = _read_frame(reader)
            body = frame[4:]
            hdr = frame[:4]
            if mutator is not None:
                nb = mutator(idx, body)
                if nb is not None:
                    body = nb
                    hdr = struct.pack("!I", len(body))
            _write_frame(writer, hdr + body)
            idx += 1
    except ConnectionClosedError:
        pass
    except OSError:
        pass
    finally:
        try:
            reader.close()
        except OSError:
            pass
        try:
            writer.close()
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument(
        "--mode",
        choices=("manifest-json", "manifest-sig-byte", "first-chunk-byte"),
        required=True,
        help="Which forwarded frame from the sender to corrupt (see TESTING.md).",
    )
    args = parser.parse_args(argv)
    mode = str(args.mode)

    def mutator(idx: int, body: bytes) -> bytes | None:
        if mode == "manifest-json" and idx == 2:
            return _tamper_manifest_json(body)
        if mode == "manifest-sig-byte" and idx == 3:
            return _tamper_last_byte(body)
        if mode == "first-chunk-byte" and idx == 4:
            return _tamper_last_byte(body)
        return None

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((str(args.listen_host), int(args.listen_port)))
    listen_sock.listen(1)
    print(
        f"Relay listening {args.listen_host}:{args.listen_port} -> "
        f"{args.upstream_host}:{args.upstream_port} mode={mode}",
        flush=True,
    )
    client_sock, peer = listen_sock.accept()
    listen_sock.close()
    print(f"Accepted sender TCP from {peer}", flush=True)

    upstream_sock = socket.create_connection(
        (str(args.upstream_host), int(args.upstream_port)),
        timeout=30.0,
    )
    print(f"Connected upstream to {args.upstream_host}:{args.upstream_port}", flush=True)

    t = threading.Thread(
        target=_relay_loop,
        args=(upstream_sock, client_sock),
        kwargs={"mutator": None},
        daemon=True,
    )
    t.start()
    try:
        _relay_loop(client_sock, upstream_sock, mutator=mutator)
    finally:
        t.join(timeout=3.0)

    print("Relay finished.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

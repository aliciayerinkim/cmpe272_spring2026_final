"""Security-negative tests for Approach B (Ed25519 + AEAD chunked transfer)."""

from __future__ import annotations

import binascii
import contextlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from helper_load_hyphen_package import REPO_ROOT, load_module_from_path

_brecv = load_module_from_path(
    REPO_ROOT / "approach-b-envelope" / "receiver.py",
    "_cmpe272_test_b_receiver",
)
_bsend = load_module_from_path(
    REPO_ROOT / "approach-b-envelope" / "sender.py",
    "_cmpe272_test_b_sender",
)


def _run_generate_keys(output_dir: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "approach-b-envelope" / "generate_keys.py"),
            "--output-dir",
            str(output_dir),
            "--force",
        ],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )


def _paired_tcp() -> tuple[socket.socket, socket.socket]:
    srv, cli = socket.socketpair()
    srv.settimeout(60.0)
    cli.settimeout(60.0)
    return srv, cli


class TestApproachBaeadPrimitives(unittest.TestCase):
    """Unit-level guarantees for nonce + AEAD-associated data bindings."""

    def test_chunk_aad_binds_session_id_and_big_endian_chunk_index(self) -> None:
        session_id_raw = binascii.unhexlify("abcd1234ef567890fedcba0987654321")
        ci = 0x01020304
        pt_len = 4096
        aad = _brecv._chunk_aad(session_id_raw, ci, pt_len)
        self.assertIn(session_id_raw, aad)
        self.assertIn(ci.to_bytes(4, "big"), aad)

    def test_chunk_nonces_differ_between_indices_and_stable_for_identity(self) -> None:
        session_id_raw = b"\xaa" + b"\x00" * 15
        n0 = _brecv._chunk_nonce(session_id_raw, 0)
        n1 = _brecv._chunk_nonce(session_id_raw, 1)
        self.assertEqual(len(n0), 12)
        self.assertNotEqual(n0, n1)
        self.assertEqual(_brecv._chunk_nonce(session_id_raw, 0), n0)


class TestApproachBProtocolFailClosed(unittest.TestCase):
    base_tmp: tempfile.TemporaryDirectory | None = None

    sender_keys: Path
    receiver_keys_mismatched_sender_pub: Path
    receiver_keys_matching: Path
    mismatch_output: Path

    payload_path: Path
    two_chunk_payload_path: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.base_tmp = tempfile.TemporaryDirectory()
        root = Path(cls.base_tmp.name)
        alice = root / "alice"
        bob = root / "bob"
        _run_generate_keys(alice)
        _run_generate_keys(bob)
        mismatch = root / "recv_mismatch"
        shutil.copytree(alice, mismatch)
        shutil.copy2(bob / "sender_ed25519_public.pem", mismatch / "sender_ed25519_public.pem")

        cls.sender_keys = alice
        cls.receiver_keys_matching = alice
        cls.receiver_keys_mismatched_sender_pub = mismatch

        cls.mismatch_output = root / "out_bad"
        cls.out_manifest_tamper = root / "out_manifest"
        cls.out_aead_tamper = root / "out_aead"
        cls.out_chunk_index = root / "out_chunk_idx"
        cls.out_dup_chunk = root / "out_dup_idx"
        for p in (
            cls.mismatch_output,
            cls.out_manifest_tamper,
            cls.out_aead_tamper,
            cls.out_chunk_index,
            cls.out_dup_chunk,
        ):
            p.mkdir(parents=True, exist_ok=True)

        cls.payload_path = root / "payload.bin"
        cls.payload_path.write_bytes(b"z" * 512)
        cls.two_chunk_payload_path = root / "payload_twice.bin"
        cls.two_chunk_payload_path.write_bytes(b"x" * 8200)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.base_tmp is not None:
            cls.base_tmp.cleanup()

    def setUp(self) -> None:
        _brecv._SESSION_ID_DONE.clear()

    def tearDown(self) -> None:
        pass

    def _run_pair(
        self,
        *,
        receiver_keys_dir: Path,
        output_dir: Path,
        expect_recv_substrings: tuple[str, ...],
        sender_patch: Any = None,
        file_path: Path | None = None,
        chunk_plaintext_max: int | None = None,
    ) -> None:
        srv, cli = _paired_tcp()
        recv_err: list[BaseException] = []
        send_err: list[BaseException] = []

        def recv_thr() -> None:
            threading.current_thread().name = "approach-b-receiver-thread"
            try:
                srv.settimeout(60.0)
                _brecv._run_transfer(
                    srv,
                    keys_dir=receiver_keys_dir,
                    output_dir=output_dir,
                    max_bytes=4 * 1024**3,
                    progress_interval_bytes=0,
                )
            except BaseException as exc:
                recv_err.append(exc)

        def send_thr() -> None:
            threading.current_thread().name = "approach-b-sender-thread"
            try:
                cli.settimeout(60.0)
                cmgr = sender_patch if sender_patch is not None else contextlib.nullcontext()
                with cmgr:
                    _bsend._run_transfer(
                        cli,
                        keys_dir=self.sender_keys,
                        file_path=file_path if file_path is not None else self.payload_path,
                        remote_name=(file_path if file_path is not None else self.payload_path).name,
                        chunk_plaintext_max=(
                            chunk_plaintext_max if chunk_plaintext_max is not None else min(8192, 65536)
                        ),
                        aead_name="chacha20-poly1305",
                        progress_interval_bytes=0,
                        max_bytes=4 * 1024**3,
                    )
            except BaseException as exc:
                send_err.append(exc)

        try:
            tr = threading.Thread(target=recv_thr, name="receiver-core", daemon=True)
            ts = threading.Thread(target=send_thr, name="sender-core", daemon=True)
            tr.start()
            ts.start()
            tr.join(timeout=90.0)
            ts.join(timeout=90.0)
            self.assertFalse(tr.is_alive(), msg=f"receiver hang; errors={recv_err!r}/{send_err!r}")
            self.assertFalse(ts.is_alive(), msg=f"sender hang; errors={recv_err!r}/{send_err!r}")

            self.assertTrue(any(isinstance(exc, ValueError) for exc in recv_err), msg=str(recv_err))
            recv_msg = "".join(str(e) for e in recv_err)
            for needle in expect_recv_substrings:
                self.assertIn(needle.lower(), recv_msg.lower())
        finally:
            for s in (srv, cli):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass

    def test_wrong_receiver_trusted_sender_key_rejects_before_payload(self) -> None:
        self._run_pair(
            receiver_keys_dir=self.receiver_keys_mismatched_sender_pub,
            output_dir=self.mismatch_output,
            expect_recv_substrings=("invalid sender handshake signature",),
        )

    def test_tampered_manifest_signature_detected_at_receiver(self) -> None:
        real_binary_send = _bsend.send_binary_frame

        state = {"n64": 0}

        def guarded(sock: socket.socket, payload: bytes) -> None:
            if threading.current_thread().name != "approach-b-sender-thread":
                return real_binary_send(sock, payload)

            mutated = payload
            if len(payload) == 64:
                state["n64"] += 1
                if state["n64"] == 2:
                    m = bytearray(mutated)
                    m[-1] ^= 0x7A
                    mutated = bytes(m)
            real_binary_send(sock, mutated)

        ctx = patch.object(_bsend, "send_binary_frame", side_effect=guarded)
        self._run_pair(
            receiver_keys_dir=self.receiver_keys_matching,
            output_dir=self.out_manifest_tamper,
            expect_recv_substrings=("manifest", "signature"),
            sender_patch=ctx,
        )

    def test_tampered_ciphertext_aead_failure(self) -> None:
        real_binary_send = _bsend.send_binary_frame

        state = {"sig64_seen": 0, "chunk_frames": 0}

        def guarded(sock: socket.socket, payload: bytes) -> None:
            if threading.current_thread().name != "approach-b-sender-thread":
                return real_binary_send(sock, payload)

            mutated = payload
            if len(payload) == 64:
                state["sig64_seen"] += 1
            else:
                state["chunk_frames"] += 1
                if state["chunk_frames"] == 1:
                    buf = bytearray(mutated)
                    buf[-1] ^= 0x3C
                    mutated = bytes(buf)
            real_binary_send(sock, mutated)

        ctx = patch.object(_bsend, "send_binary_frame", side_effect=guarded)
        self._run_pair(
            receiver_keys_dir=self.receiver_keys_matching,
            output_dir=self.out_aead_tamper,
            expect_recv_substrings=("aead tag verification failed",),
            sender_patch=ctx,
        )

    def test_advanced_chunk_index_rejected(self) -> None:
        real_binary_send = _bsend.send_binary_frame

        state = {"sig64_seen": 0, "chunk_frames": 0}

        def guarded(sock: socket.socket, payload: bytes) -> None:
            if threading.current_thread().name != "approach-b-sender-thread":
                return real_binary_send(sock, payload)

            mutated = payload
            if len(payload) == 64:
                state["sig64_seen"] += 1
            else:
                state["chunk_frames"] += 1
                if state["chunk_frames"] == 1:
                    buf = bytearray(mutated)
                    buf[0:4] = (7).to_bytes(4, "big")
                    mutated = bytes(buf)
            real_binary_send(sock, mutated)

        ctx = patch.object(_bsend, "send_binary_frame", side_effect=guarded)
        self._run_pair(
            receiver_keys_dir=self.receiver_keys_matching,
            output_dir=self.out_chunk_index,
            expect_recv_substrings=("chunk_index", "expected 0"),
            sender_patch=ctx,
        )

    def test_replayed_chunk_index_rejected(self) -> None:
        real_binary_send = _bsend.send_binary_frame
        plain_max = 8192

        state = {"sig64_seen": 0, "chunk_frames": 0}

        def guarded(sock: socket.socket, payload: bytes) -> None:
            if threading.current_thread().name != "approach-b-sender-thread":
                return real_binary_send(sock, payload)

            mutated = payload
            if len(payload) == 64:
                state["sig64_seen"] += 1
            else:
                state["chunk_frames"] += 1
                if state["chunk_frames"] == 2:
                    buf = bytearray(mutated)
                    buf[0:4] = (0).to_bytes(4, "big")
                    mutated = bytes(buf)
            real_binary_send(sock, mutated)

        ctx = patch.object(_bsend, "send_binary_frame", side_effect=guarded)
        self._run_pair(
            receiver_keys_dir=self.receiver_keys_matching,
            output_dir=self.out_dup_chunk,
            expect_recv_substrings=("chunk_index", "expected 1"),
            sender_patch=ctx,
            file_path=self.two_chunk_payload_path,
            chunk_plaintext_max=plain_max,
        )


if __name__ == "__main__":
    unittest.main()

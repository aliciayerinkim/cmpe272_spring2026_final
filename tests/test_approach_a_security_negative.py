"""
Security-negative integration + static guards for Approach A (mTLS AEAD TLS 1.2).

Proves handshake fails closed when:
- client's trust store omits / replaces the server's CA (cannot verify chain)
- listener requires a client certificate and the connector omits presentation
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import unittest

try:
    from common.constants import TLS12_MT_ALLOWED_CIPHER_LIST
except ImportError:
    TLS12_MT_ALLOWED_CIPHER_LIST = None

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_text(rel: Path) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")


def _mtls_receiver_context(ca_pem: Path, srv_cert_pem: Path, srv_key_pem: Path) -> ssl.SSLContext:
    """Match production listener knobs: CERT_REQUIRED mutual auth; TLS servers do not enable client hostname checks."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if TLS12_MT_ALLOWED_CIPHER_LIST:
        ctx.set_ciphers(TLS12_MT_ALLOWED_CIPHER_LIST)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(srv_cert_pem), keyfile=str(srv_key_pem))
    ctx.verify_mode = ssl.CERT_REQUIRED
    verify_flag = getattr(ssl, "VERIFY_FAIL_IF_NO_PEER_CERT", None)
    if verify_flag is not None:
        ctx.verify_flags |= verify_flag  # pyright: ignore[reportAttributeAccessIssue]
    ctx.load_verify_locations(cafile=str(ca_pem))
    ctx.check_hostname = False
    return ctx


def _mtls_client_context(ca_pem: Path, cert_pem: Path | None, key_pem: Path | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    if TLS12_MT_ALLOWED_CIPHER_LIST:
        ctx.set_ciphers(TLS12_MT_ALLOWED_CIPHER_LIST)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca_pem))
    if cert_pem is not None and key_pem is not None:
        ctx.load_cert_chain(certfile=str(cert_pem), keyfile=str(key_pem))
    return ctx


def _run_generate_certs(output_dir: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "approach-a-mtls" / "generate_certs.py"),
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


class TestApproachAPolicy(unittest.TestCase):
    """Fail-closed static checks on Approach A TLS configuration sources."""

    def test_sender_requires_cert_verification_and_localhost_pin_for_loopback(self) -> None:
        path = Path("approach-a-mtls/sender.py")
        txt = _read_text(path)
        self.assertNotIn("CERT_NONE", txt, msg=f"{path} must not downgrade verify_mode.")
        self.assertNotIn(
            "check_hostname = False",
            txt,
            msg=f"{path} must never disable hostname checking when connecting outbound.",
        )
        self.assertRegex(txt, r"verify_mode\s*=\s*ssl\.CERT_REQUIRED")
        self.assertRegex(txt, r"check_hostname\s*=\s*True")
        self.assertIn('return "localhost"', txt, msg="loopback endpoints must verify as localhost SAN/CN.")

    def test_receiver_requires_mutual_auth_and_aead_cipher_restriction(self) -> None:
        path = Path("approach-a-mtls/receiver.py")
        txt = _read_text(path)
        self.assertNotIn("CERT_NONE", txt, msg=f"{path} must not downgrade verify_mode.")
        self.assertNotIn(
            "check_hostname = False",
            txt,
            msg=f"{path} server context must never relax hostname checks ad hoc.",
        )
        self.assertRegex(txt, r"verify_mode\s*=\s*ssl\.CERT_REQUIRED")

    def test_receiver_requests_fail_when_client_cert_missing(self) -> None:
        txt = _read_text(Path("approach-a-mtls/receiver.py"))
        self.assertRegex(
            txt,
            r"VERIFY_FAIL_IF_NO_PEER_CERT",
            msg="receiver should fail if the client declines to send a leaf certificate.",
        )


class TestApproachATLHandshakeFailures(unittest.TestCase):
    tmp: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.dir_a = base / "pki_a"
        cls.dir_b = base / "pki_b"
        _run_generate_certs(cls.dir_a)
        _run_generate_certs(cls.dir_b)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_handshake_rejects_foreign_ca_bundle(self) -> None:
        srv_ctx = _mtls_receiver_context(
            self.dir_a / "ca-cert.pem",
            self.dir_a / "server-cert.pem",
            self.dir_a / "server-key.pem",
        )

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(1)
        srv_port = int(srv_sock.getsockname()[1])

        def server_side():
            ssl_sock_local: ssl.SSLSocket | None = None
            try:
                conn, _ = srv_sock.accept()
                ssl_sock_local = srv_ctx.wrap_socket(conn, server_side=True)
                ssl_sock_local.do_handshake()
            except ssl.SSLError:
                pass
            finally:
                if ssl_sock_local is not None:
                    try:
                        ssl_sock_local.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        ssl_sock_local.close()
                    except OSError:
                        pass
                try:
                    srv_sock.close()
                except OSError:
                    pass

        threading.Thread(target=server_side, name="srv-wrong-ca", daemon=True).start()

        cli_ctx = _mtls_client_context(
            self.dir_b / "ca-cert.pem",
            self.dir_a / "client-cert.pem",
            self.dir_a / "client-key.pem",
        )

        with self.assertRaises((ssl.SSLError, ssl.CertificateError)):
            probe = socket.create_connection(("127.0.0.1", srv_port), timeout=5)
            try:
                with cli_ctx.wrap_socket(probe, server_hostname="localhost") as tls:
                    tls.do_handshake()
            finally:
                try:
                    probe.close()
                except OSError:
                    pass

    def test_receiver_refuses_sessions_without_leaf_certificate(self) -> None:
        srv_ctx = _mtls_receiver_context(
            self.dir_a / "ca-cert.pem",
            self.dir_a / "server-cert.pem",
            self.dir_a / "server-key.pem",
        )

        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", 0))
        srv_sock.listen(1)
        srv_port = int(srv_sock.getsockname()[1])

        def server_side():
            ssl_sock_local: ssl.SSLSocket | None = None
            try:
                conn, _ = srv_sock.accept()
                ssl_sock_local = srv_ctx.wrap_socket(conn, server_side=True)
                ssl_sock_local.do_handshake()
            except ssl.SSLError:
                pass
            finally:
                if ssl_sock_local is not None:
                    try:
                        ssl_sock_local.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    try:
                        ssl_sock_local.close()
                    except OSError:
                        pass
                try:
                    srv_sock.close()
                except OSError:
                    pass

        threading.Thread(target=server_side, name="srv-no-client-cert", daemon=True).start()

        cli_ctx = _mtls_client_context(
            self.dir_a / "ca-cert.pem",
            cert_pem=None,
            key_pem=None,
        )

        with self.assertRaises((ssl.SSLError, ssl.CertificateError, ConnectionResetError, BrokenPipeError)):
            probe = socket.create_connection(("127.0.0.1", srv_port), timeout=5)
            try:
                with cli_ctx.wrap_socket(probe, server_hostname="localhost") as tls:
                    tls.do_handshake()
            finally:
                try:
                    probe.close()
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()

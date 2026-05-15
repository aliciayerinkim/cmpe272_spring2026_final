"""Generate a local dev PKI for Approach A (mTLS): CA, server, and client certificates.

Private keys are generated at runtime and written as PEM files. Key material is
never embedded in this repository. Optional encryption at rest for written
private keys uses the ``MTLS_KEY_ENCRYPTION_PASSWORD`` environment variable.

Outputs (default directory ``approach-a-mtls/certs/``):

- ``ca-key.pem``, ``ca-cert.pem``
- ``server-key.pem``, ``server-cert.pem``
- ``client-key.pem``, ``client-cert.pem``
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE_BITS = 3072


def _pem_encryption() -> serialization.KeySerializationEncryption:
    password = os.environ.get("MTLS_KEY_ENCRYPTION_PASSWORD")
    if password:
        return serialization.BestAvailableEncryption(password.encode("utf-8"))
    return serialization.NoEncryption()


def _write_private_key(path: Path, key: rsa.RSAPrivateKey, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_pem_encryption(),
    )
    path.write_bytes(pem)
    if os.name != "nt":
        path.chmod(0o600)


def _write_certificate(path: Path, cert: x509.Certificate, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if os.name != "nt":
        path.chmod(0o644)


def _build_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CMPE272 Local Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _localhost_san() -> x509.SubjectAlternativeName:
    return x509.SubjectAlternativeName(
        [
            x509.DNSName("localhost"),
            x509.IPAddress(IPv4Address("127.0.0.1")),
            x509.IPAddress(IPv6Address("::1")),
        ]
    )


def _generate_ca(
    *,
    valid_from: datetime,
    valid_to: datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_SIZE_BITS)
    subject = issuer = _build_name("CMPE272 Local Dev CA")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _issue_leaf_certificate(
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    leaf_key: rsa.RSAPrivateKey,
    subject: x509.Name,
    extended_key_usage: list[x509.ObjectIdentifier],
    valid_from: datetime,
    valid_to: datetime,
    key_encipherment: bool,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=key_encipherment,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(_localhost_san(), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage(extended_key_usage),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    return builder.sign(ca_key, hashes.SHA256())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Optional environment variable:\n"
            "  MTLS_KEY_ENCRYPTION_PASSWORD  If set, written private keys use PEM encryption.\n"
            "                                Clear the variable after generation if you use a shell history.\n"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "certs",
        help="Directory for PEM output (created if missing).",
    )
    parser.add_argument(
        "--validity-days",
        type=int,
        default=365,
        help="Certificate validity window in days (not-before is a short clock skew back-dated).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing PEM files in the output directory.",
    )
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    valid_from = now - timedelta(minutes=5)
    valid_to = now + timedelta(days=int(args.validity_days))

    targets = [
        output_dir / "ca-key.pem",
        output_dir / "ca-cert.pem",
        output_dir / "server-key.pem",
        output_dir / "server-cert.pem",
        output_dir / "client-key.pem",
        output_dir / "client-cert.pem",
    ]
    if not args.force:
        existing = [p for p in targets if p.exists()]
        if existing:
            joined = "\n".join(f"  - {p}" for p in existing)
            print(
                "Refusing to overwrite existing PEM files. Pass --force to replace them:\n" + joined,
                file=sys.stderr,
            )
            return 2

    ca_key, ca_cert = _generate_ca(valid_from=valid_from, valid_to=valid_to)
    server_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE_BITS,
    )
    client_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE_BITS,
    )

    server_subject = _build_name("localhost")
    client_subject = _build_name("mtls-client")

    server_cert = _issue_leaf_certificate(
        ca_key=ca_key,
        ca_cert=ca_cert,
        leaf_key=server_key,
        subject=server_subject,
        extended_key_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
        valid_from=valid_from,
        valid_to=valid_to,
        key_encipherment=True,
    )
    client_cert = _issue_leaf_certificate(
        ca_key=ca_key,
        ca_cert=ca_cert,
        leaf_key=client_key,
        subject=client_subject,
        extended_key_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        valid_from=valid_from,
        valid_to=valid_to,
        key_encipherment=False,
    )

    _write_private_key(output_dir / "ca-key.pem", ca_key, force=args.force)
    _write_private_key(output_dir / "server-key.pem", server_key, force=args.force)
    _write_private_key(output_dir / "client-key.pem", client_key, force=args.force)

    _write_certificate(output_dir / "ca-cert.pem", ca_cert, force=args.force)
    _write_certificate(output_dir / "server-cert.pem", server_cert, force=args.force)
    _write_certificate(output_dir / "client-cert.pem", client_cert, force=args.force)

    print(f"Wrote CA, server, and client material under: {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

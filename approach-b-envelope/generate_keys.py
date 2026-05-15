"""Generate long-term keys for Approach B (application-layer envelope over TCP).

Material is produced for local development only; private keys must never be
committed. Optional PEM encryption uses ``ENVELOPE_KEY_ENCRYPTION_PASSWORD``.

Design (used by the upcoming sender/receiver):

- **Ed25519** — one signing key pair per role (``sender``, ``receiver``). These
  authenticate manifests, static key blobs, and endpoint identity via
  signatures.

- **X25519** — one static key agreement key pair per role. The wire protocol will
  combine these with **ephemeral** X25519 keys per session to derive shared
  secrets for **ChaCha20-Poly1305** or **AES-GCM** chunk AEAD (implemented in the
  envelope scripts, not here).

No secrets are embedded in source; all private material is generated at runtime.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

PrivateKeyTypes = Union[ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]


def _pem_encryption() -> serialization.KeySerializationEncryption:
    password = os.environ.get("ENVELOPE_KEY_ENCRYPTION_PASSWORD")
    if password:
        return serialization.BestAvailableEncryption(password.encode("utf-8"))
    return serialization.NoEncryption()


def _write_private_pem(path: Path, key: PrivateKeyTypes, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_pem_encryption(),
    )
    path.write_bytes(pem)
    if os.name != "nt":
        path.chmod(0o600)


def _write_public_pem(path: Path, private_key: PrivateKeyTypes, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    pub = private_key.public_key()
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)
    if os.name != "nt":
        path.chmod(0o644)


def _emit_role_pair(
    output_dir: Path,
    role: str,
    *,
    force: bool,
) -> None:
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    x_priv = x25519.X25519PrivateKey.generate()

    _write_private_pem(output_dir / f"{role}_ed25519_private.pem", ed_priv, force=force)
    _write_public_pem(output_dir / f"{role}_ed25519_public.pem", ed_priv, force=force)
    _write_private_pem(output_dir / f"{role}_x25519_private.pem", x_priv, force=force)
    _write_public_pem(output_dir / f"{role}_x25519_public.pem", x_priv, force=force)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Optional environment variable:\n"
            "  ENVELOPE_KEY_ENCRYPTION_PASSWORD  If set, private keys are written encrypted.\n"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "keys",
        help="Directory for PEM output (created if missing).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key PEM files in the output directory.",
    )
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        output_dir / f"{role}_{kind}_{side}.pem"
        for role in ("sender", "receiver")
        for kind in ("ed25519", "x25519")
        for side in ("private", "public")
    ]
    if not args.force:
        existing = [p for p in targets if p.exists()]
        if existing:
            joined = "\n".join(f"  - {p}" for p in existing)
            print(
                "Refusing to overwrite existing PEM files. Pass --force to replace them:\n"
                + joined,
                file=sys.stderr,
            )
            return 2

    _emit_role_pair(output_dir, "sender", force=args.force)
    _emit_role_pair(output_dir, "receiver", force=args.force)

    print(f"Wrote Ed25519 + X25519 key pairs for sender and receiver under: {output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

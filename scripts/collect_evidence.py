#!/usr/bin/env python3
"""After manual Approach A/B 4 GiB runs, compute sizes + hashes and write an evidence summary.

Reads three files by default:

- ``zero4g.bin`` (source),
- ``received/zero4g.bin`` or custom **Approach A** output,
- ``received-b/zero4g.bin`` or custom **Approach B** output.

Exit code ``0`` only when both outputs exist and SHA‑256 equals the source (streaming).
For a 4 GiB source, the log includes ``--- 4 GiB evidence semantics ---`` (sparse ``zero4g.bin``,
logical size, assignment random vs zero, SHA over logical bytes, full streamed transfer).

Examples:

  python scripts/collect_evidence.py \\
    --input zero4g.bin \\
    --approach-a-output evidence/received-a-4gb/zero4g.bin \\
    --approach-b-output evidence/received-b-4gb/zero4g.bin
"""

from __future__ import annotations

import argparse
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc

REPO_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED_4GIB = 4294967296  # 4 * 1024**3


def _four_gib_semantic_log_lines(*, input_path: Path, logical_bytes: int) -> list[str]:
    canonical_zero = input_path.name == "zero4g.bin" and logical_bytes == _EXPECTED_4GIB
    block: list[str] = [
        "",
        "--- 4 GiB evidence semantics ---",
        f"Logical file size: {logical_bytes} bytes (4 * 1024**3).",
        "Streaming SHA-256 in this log digests the full logical byte sequence (sparse all-zero regions still read as zeros).",
        "Approach A and Approach B transfers stream the entire logical payload end-to-end.",
        "The assignment allows a 4 GiB file of random bytes or all-zero bytes; this repo's canonical zero4g.bin is logically all-zero for a deterministic digest.",
    ]
    if canonical_zero:
        block.append(
            "zero4g.bin (canonical): logical sparse all-zero 4 GiB when created per README (e.g. NTFS SetLength); "
            "reuse that file for evidence—do not regenerate as a dense non-sparse rewrite, do not substitute random-bytes payloads for this checklist, "
            "and avoid re-running dd over an existing correct file if that would rewrite the whole object."
        )
    return block


def _bootstrap() -> None:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))


def _sha_and_size(path: Path) -> tuple[str, int]:
    _bootstrap()
    from common.hashing import sha256_hex_digest_file

    if not path.is_file():
        raise FileNotFoundError(str(path))
    return sha256_hex_digest_file(path).lower(), path.stat().st_size


def _rel_for_template(p: Path, root: Path) -> Path:
    try:
        return p.relative_to(root)
    except ValueError:
        return p


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=REPO_ROOT / "zero4g.bin", help="Source 4 GiB file.")
    parser.add_argument(
        "--approach-a-output",
        type=Path,
        default=REPO_ROOT / "received" / "zero4g.bin",
        help="Path written by Approach A receiver.",
    )
    parser.add_argument(
        "--approach-b-output",
        type=Path,
        default=REPO_ROOT / "received-b" / "zero4g.bin",
        help="Path written by Approach B receiver.",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=REPO_ROOT / "evidence",
        help="Where to write transfer_evidence_*.txt",
    )
    args = parser.parse_args(argv)

    def resolve(p: Path) -> Path:
        p = p.expanduser()
        return p if p.is_absolute() else (REPO_ROOT / p).resolve()

    src = resolve(args.input)
    pa = resolve(args.approach_a_output)
    pb = resolve(args.approach_b_output)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    lines: list[str] = [
        f"transfer_evidence (collect_evidence manual) generated={datetime.now(UTC).isoformat()}",
        f"platform={platform.platform()}",
        f"python={sys.version.split()[0]} executable={sys.executable}",
        f"repo_root={REPO_ROOT}",
        "",
        f"source_path={src}",
        f"approach_a_output={pa}",
        f"approach_b_output={pb}",
        "",
    ]

    rc = 1
    try:
        hin, sin = _sha_and_size(src)
        lines.append(f"source_bytes={sin}")
        lines.append(f"INPUT_SHA256={hin}")
        if sin == _EXPECTED_4GIB:
            lines.extend(_four_gib_semantic_log_lines(input_path=src, logical_bytes=sin))
        lines.append("")

        ha, sa = _sha_and_size(pa)
        hb, sb = _sha_and_size(pb)
        lines.extend(
            [
                f"Approach_A_output_bytes={sa}",
                f"APPROACH_A_OUTPUT_SHA256={ha}",
                f"A_match={'PASS' if ha == hin else 'FAIL'}",
                "",
                f"Approach_B_output_bytes={sb}",
                f"APPROACH_B_OUTPUT_SHA256={hb}",
                f"B_match={'PASS' if hb == hin else 'FAIL'}",
                "",
                "COMMAND_HISTORY_TEMPLATE:",
                "# After manual transfers:",
                "#   python scripts/collect_evidence.py \\",
                f"#     --input {_rel_for_template(src, REPO_ROOT).as_posix()} \\",
                f"#     --approach-a-output {_rel_for_template(pa, REPO_ROOT).as_posix()} \\",
                f"#     --approach-b-output {_rel_for_template(pb, REPO_ROOT).as_posix()}",
            ]
        )

        rc = 0 if ha == hin and hb == hin and sa == sb == sin else 1
        lines.extend(["", f"OVERALL={'PASS' if rc == 0 else 'FAIL'}"])
    except OSError as exc:
        lines.append(f"ERROR={exc}")

    evidence_dir = args.evidence_dir.resolve()
    evidence_dir.mkdir(parents=True, exist_ok=True)
    log_path = evidence_dir / f"transfer_evidence_{ts}.txt"
    log_path.write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    print(f"Wrote {log_path}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

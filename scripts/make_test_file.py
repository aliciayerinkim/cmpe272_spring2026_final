#!/usr/bin/env python3
"""Write a deterministic binary file of an exact size (for failure demos, no huge RAM use)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=1024 * 1024, help="File size in bytes (default 1 MiB).")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path (parent directories are created).",
    )
    parser.add_argument(
        "--pattern-byte",
        type=int,
        default=0x5A,
        help="Single-byte value repeated through the file (default 0x5A).",
    )
    args = parser.parse_args(argv)

    size = int(args.size)
    if size < 0:
        print("ERROR: --size must be non-negative", file=sys.stderr)
        return 1
    out: Path = args.output.expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if size == 0:
        out.write_bytes(b"")
        print(f"Wrote 0 bytes -> {out}", flush=True)
        return 0

    b = int(args.pattern_byte) & 0xFF
    block = bytes([b]) * min(1024 * 1024, size)
    remaining = size
    with out.open("wb") as handle:
        while remaining > 0:
            n = min(len(block), remaining)
            handle.write(block[:n])
            remaining -= n

    print(f"Wrote {size} bytes -> {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

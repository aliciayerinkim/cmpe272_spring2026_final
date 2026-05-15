"""Fail-closed disk patterns: verify partial output, then atomically promote it."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from common.errors import AtomicCommitError
from common.temp_files import part_path_for, try_unlink

# Re-export for callers that colocate "final path" helpers next to commit APIs.
__all__ = ["part_path_for", "replace_with_final", "commit_verified_part"]


def replace_with_final(part_path: Path, final_path: Path) -> None:
    """Atomically promote ``part_path`` to ``final_path`` using ``os.replace``.

    On POSIX this is atomic on the same filesystem; on Windows it overwrites
    ``final_path`` if present. Call only after verification succeeds.
    """
    if part_path.resolve() == final_path.resolve():
        raise ValueError("part_path and final_path must not be the same path")
    if not part_path.is_file():
        raise FileNotFoundError(f"partial file not found: {part_path}")
    final_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(part_path, final_path)
    except OSError as exc:
        raise AtomicCommitError(
            f"failed to promote partial file {part_path} -> {final_path}: {exc}"
        ) from exc


def commit_verified_part(
    part_path: Path,
    final_path: Path,
    verify: Callable[[Path], None],
) -> None:
    """Run ``verify(part_path)`` then rename; remove partial data on any failure.

    ``verify`` should raise if the plaintext (or ciphertext staging file) is
    invalid. This function never leaves a promoted ``final_path`` unless
    ``verify`` completed without raising and ``os.replace`` succeeded.
    """
    try:
        verify(part_path)
    except Exception:
        try:
            try_unlink(part_path)
        except OSError:
            pass
        raise

    try:
        replace_with_final(part_path, final_path)
    except Exception:
        try:
            try_unlink(part_path)
        except OSError:
            pass
        raise

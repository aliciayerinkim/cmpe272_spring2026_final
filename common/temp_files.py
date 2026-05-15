"""Create private temporary output files adjacent to the final path for safe rename."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from common.constants import PARTIAL_SUFFIX


def part_path_for(final_path: Path) -> Path:
    """Return a deterministic sibling path ``<name>.part`` next to ``final_path``."""
    return final_path.with_name(final_path.name + PARTIAL_SUFFIX)


def try_unlink(path: Path) -> None:
    """Remove ``path`` if it exists; ignore ``FileNotFoundError``."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # Permission or transient FS errors should surface to callers when relevant.
        raise


@contextmanager
def open_part_file(final_path: Path) -> Iterator[tuple[BinaryIO, Path]]:
    """Open ``<final>.part`` for write; delete partial file on context failure.

    The parent directory is created if needed. On successful completion of the
    ``with``-suite, the partial file remains on disk for verification/rename.
    """
    final_path.parent.mkdir(parents=True, exist_ok=True)
    part_path = part_path_for(final_path)
    try:
        with part_path.open("wb") as handle:
            yield handle, part_path
    except Exception:
        try:
            try_unlink(part_path)
        except OSError:
            pass
        raise


@contextmanager
def open_unique_temp_in_final_dir(final_path: Path) -> Iterator[tuple[BinaryIO, Path]]:
    """Create a unique ``mkstemp`` file in ``final_path.parent`` for isolated writes.

    Prefer this over :func:`open_part_file` when leftover ``*.part`` files from
    crashed runs should not be truncated in place.
    """
    directory = final_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    prefix = final_path.name + "."
    suffix = PARTIAL_SUFFIX
    fd, raw = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=directory)
    temp_path = Path(raw)
    try:
        stream = os.fdopen(fd, "wb")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            try_unlink(temp_path)
        except OSError:
            pass
        raise

    try:
        with stream:
            yield stream, temp_path
    except Exception:
        try:
            try_unlink(temp_path)
        except OSError:
            pass
        raise

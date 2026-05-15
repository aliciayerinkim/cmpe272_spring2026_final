"""Load a module from ``approach-b-envelope/*.py`` (hyphen dirname → importlib only)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module_from_path(path: Path, logical_name: str):
    """Load module from filesystem path without installing a package."""
    path = path.resolve()
    spec = importlib.util.spec_from_file_location(logical_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(logical_name)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[logical_name] = mod  # hyphen children may expect package-style imports skipped
    spec.loader.exec_module(mod)
    return mod

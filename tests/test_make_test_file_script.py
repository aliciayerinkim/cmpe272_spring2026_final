"""Smoke tests for scripts/make_test_file.py (exact output size; stdlib only)."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "scripts" / "make_test_file.py"


class TestMakeTestFileScript(unittest.TestCase):
    def test_writes_exact_size(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.bin"
            r = subprocess.run(
                [sys.executable, str(_SCRIPT), "--size", "12345", "--output", str(out)],
                cwd=str(_REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
            self.assertTrue(out.is_file())
            self.assertEqual(out.stat().st_size, 12345)

    def test_zero_bytes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "empty.bin"
            r = subprocess.run(
                [sys.executable, str(_SCRIPT), "--size", "0", "--output", str(out)],
                cwd=str(_REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
            self.assertTrue(out.is_file())
            self.assertEqual(out.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()

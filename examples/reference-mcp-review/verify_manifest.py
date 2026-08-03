#!/usr/bin/env python3
"""Verify the pinned reference-review evidence files and expected retest."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def main() -> int:
    manifest = json.loads((ROOT / "EVIDENCE-MANIFEST.json").read_text())
    failures: list[str] = []
    for relative, expected in manifest["files"].items():
        path = ROOT / relative
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            failures.append(f"{relative}: expected {expected}, got {actual}")

    if failures:
        print("Evidence manifest FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(ROOT / "tests"),
         "-p", "test_*.py", "-v"],
        cwd=ROOT.parent.parent,
    )
    if proc.returncode:
        return proc.returncode
    print(f"Evidence manifest PASS — {len(manifest['files'])} pinned file(s), retest passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Proves RugPullBaselineDetector is a transparent wrapper by re-running
lab/baseline/test_watch.py's 12 existing tests, UNMODIFIED, against it.

lab/baseline/test_watch.py's test methods call `process_record` as a bare name
imported into that module's own namespace (`from watch import ...
process_record ...`); two of them (TestIdempotentReplay) instead call
`process_file`, which is watch.py's own function and resolves ITS internal
`process_record` call via watch.py's *own* module namespace, not
test_watch.py's. To route every one of the 12 tests through the wrapper --
not just the 10 that call `process_record` directly -- this monkeypatches
both names at runtime, restoring them in a `finally` block. Neither
lab/baseline/watch.py nor lab/baseline/test_watch.py is edited on disk; both stay
byte-identical (verified separately by this migration's hard gate). The
wrapper itself always calls a reference to the ORIGINAL process_record
captured before any patching (framework/stateful.py's
_ORIGINAL_PROCESS_RECORD), so repointing watch_mod.process_record at the
wrapper here cannot recurse.

Run: python3 framework/tests/test_rugpull_wrapper_parity.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "lab" / "baseline"))
sys.path.insert(0, str(REPO_ROOT))

import test_watch as test_watch_mod  # noqa: E402 -- lab/baseline/test_watch.py, unmodified
import watch as watch_mod  # noqa: E402 -- lab/baseline/watch.py, unmodified
from framework.stateful import RugPullBaselineDetector  # noqa: E402

_detector = RugPullBaselineDetector()


def _wrapped_process_record(record: dict, state: dict) -> list[dict]:
    return _detector.process_record(record, state)


def run_parity_suite(verbosity: int = 2) -> unittest.TestResult:
    original_in_test_watch = test_watch_mod.process_record
    original_in_watch = watch_mod.process_record
    test_watch_mod.process_record = _wrapped_process_record
    watch_mod.process_record = _wrapped_process_record
    try:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(test_watch_mod)
        runner = unittest.TextTestRunner(verbosity=verbosity)
        return runner.run(suite)
    finally:
        test_watch_mod.process_record = original_in_test_watch
        watch_mod.process_record = original_in_watch


if __name__ == "__main__":
    result = run_parity_suite()
    n = result.testsRun
    print(f"\n{'PASS' if result.wasSuccessful() else 'FAIL'}: "
          f"{n - len(result.failures) - len(result.errors)}/{n} tests passed "
          f"against RugPullBaselineDetector wrapper", file=sys.stderr)
    sys.exit(0 if result.wasSuccessful() else 1)

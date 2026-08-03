#!/usr/bin/env python3
"""Runs the offline framework test files and reports one aggregate pass/fail.

Pass ``--live`` to include the compiler suites that require a running Docker
and Wazuh lab. Keeping those tests explicit makes the default command honest on
a clean clone and suitable for hosted CI.

This closes the "no single command runs all the tests" gap
without adding pytest (this project has stayed dependency-free
throughout; see docs/PHASE6-DESIGN.md's own disclosed reasoning for the
same choice about PyYAML).

Each test file here is invoked as its own subprocess, not folded into one
in-process unittest suite: the compiler checks are standalone scripts with their own `main()`
and real `docker compose`/`wazuh-logtest` side effects, not
`unittest.TestCase` classes, and `test_rugpull_wrapper_parity.py`
deliberately monkeypatches shared module state
(`baseline.watch.process_record`) for the duration of its own run --
running all three in one process risks exactly the cross-test state
leakage subprocess isolation avoids for free. This *is* the stdlib-only
choice for this shape of test suite, not a shortcut around it.

Requires the .venv interpreter (this host's system Python has a broken
`pyexpat` binding needed by framework/compiler.py's XML parsing -- see
docs/PHASE6-COMPILER-REPORT.md). Run with `.venv/bin/python3` explicitly,
or via `python3 framework/tests/run_all.py` if your `python3` already
resolves to a working interpreter; this script does not re-exec itself
into `.venv` automatically, since which interpreter is "correct" is a
per-host fact, not something to silently override.

Usage:
  python3 framework/tests/run_all.py
  python3 framework/tests/run_all.py --live
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent.parent
INTERPRETER = sys.executable

# Order matters only for readability of output -- each test is independent
# (subprocess-isolated), so there's no ordering dependency between them.
OFFLINE_TEST_FILES = [
    "test_assurance.py",
    "test_controls.py",
    "test_audit_safety.py",
    "test_rugpull_wrapper_parity.py",
    "test_repro_offline_stale_rules.py",
    "test_redaction_secret_survival.py",
]

LIVE_TEST_FILES = [
    "test_compiler_regression.py",
    "test_compiler_redteam.py",
]


def run_one(test_file: str) -> tuple[str, bool, float, str]:
    path = TESTS_DIR / test_file
    t0 = time.time()
    child_env = os.environ.copy()
    existing_pythonpath = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = os.pathsep.join((str(REPO_ROOT), str(REPO_ROOT / "lab"))) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    try:
        proc = subprocess.run(
            [INTERPRETER, str(path)],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=REPO_ROOT,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - t0

        def as_text(value: str | bytes | None) -> str:
            if value is None:
                return ""
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return value

        output = as_text(exc.stdout) + as_text(exc.stderr)
        output += f"\nTIMEOUT: {test_file} exceeded 600 seconds\n"
        return test_file, False, elapsed, output
    elapsed = time.time() - t0
    ok = proc.returncode == 0
    output = proc.stdout + proc.stderr
    return test_file, ok, elapsed, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live",
        action="store_true",
        help="include compiler tests that require the running Docker/Wazuh lab",
    )
    args = parser.parse_args()
    test_files = OFFLINE_TEST_FILES + (LIVE_TEST_FILES if args.live else [])

    print(f"Running {len(test_files)} test file(s) via {INTERPRETER}\n")
    if not args.live:
        print("Live Docker/Wazuh compiler suites omitted; use --live to include them.\n")
    results = []
    for test_file in test_files:
        print(f"--- {test_file} ---")
        name, ok, elapsed, output = run_one(test_file)
        # Keep clean output concise, but preserve readiness/retry/rule-sync
        # markers from live Wazuh tests so recovered infrastructure failures
        # remain visible in CI and validation transcripts.
        if not ok:
            print(output)
        else:
            observable = [
                line for line in output.splitlines()
                if line.startswith(("RULE-SYNC CHECK:", "WAZUH-LOGTEST "))
            ]
            if observable:
                print("\n".join(observable))
        print(f"{'PASS' if ok else 'FAIL'} ({elapsed:.1f}s)\n")
        results.append((name, ok, elapsed))

    print("=" * 60)
    all_ok = all(ok for _, ok, _ in results)
    for name, ok, elapsed in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}  ({elapsed:.1f}s)")
    total = sum(elapsed for _, _, elapsed in results)
    print(f"\n{'ALL PASSED' if all_ok else 'FAILURES PRESENT'} -- "
          f"{sum(ok for _, ok, _ in results)}/{len(results)} test files, {total:.1f}s total")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

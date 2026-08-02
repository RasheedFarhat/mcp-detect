#!/usr/bin/env python3
"""Regression: the compiler that catches every historical bug must also
produce zero false rejections against the known-good, migrated set. If any
real rule trips a gate, that is a bug in the gate, not the rule.

This is a thin wrapper around framework/compiler.py's validate_registry()
-- the real orchestration logic lives there now (also runnable directly as
a CLI: `python3 framework/compiler.py validate-all`), not duplicated here.
Test files should test the tool, not be the tool -- this file used to
hand-roll its own per-rule fixture-discovery dict (a real cost
docs/PHASE6-T1105-REPORT.md named: onboarding rule 100108 needed a manual
edit here); that logic is now framework/compiler.py's own
run_attack_corpus(), derived automatically from each Detection's declared
fixtures, and applies to every future detection with no edits needed here.
The benign-corpus sweep this file used to run as its own stopgap (pending
a "fifth gate") is likewise gone -- gate5_benign_fp() is now a real gate
inside validate_registry() itself, so asserting a clean validate_registry()
result already covers it.

Run: python3 framework/tests/test_compiler_regression.py
(Requires the .venv interpreter -- see docs/PHASE6-COMPILER-REPORT.md.)
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from framework.compiler import validate_registry  # noqa: E402


def main() -> int:
    reports, collisions = validate_registry()
    all_ok = not collisions

    for r in reports:
        ok = r.is_clean()
        all_ok = all_ok and ok
        print(f"{r.name}: gate1={len(r.gate1)} gate3={len(r.gate3)} gate4={len(r.gate4)} "
              f"gate5={len(r.gate5)} violation(s), disjointness tally={r.disjointness_tally} "
              f"({'OK' if ok else 'FAIL'})")
        for v in r.gate1 + r.gate3 + r.gate4 + r.gate5[:5]:
            print("  ", v)
        if len(r.gate5) > 5:
            print(f"   ... and {len(r.gate5) - 5} more gate5 violations")
    for v in collisions:
        print("REGISTRY:", v)

    print()
    print("REGRESSION " + ("PASSED -- zero false rejections against the known-good set" if all_ok
                            else "FAILED -- see violations above, this is a gate bug, not a rule bug"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

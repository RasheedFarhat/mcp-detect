#!/usr/bin/env python3
"""Phase 6 migration -- StatefulDetector protocol + RugPullBaselineDetector.

`lab/baseline/watch.py` stays byte-identical (verified by this migration's
hard gate, not just assumed). `RugPullBaselineDetector` below imports it
and delegates every call to its existing `process_record` -- no logic is
copied or re-expressed. Its correctness is inherited from
`lab/baseline/test_watch.py`'s 12 existing tests, which this module's own test
(`framework/tests/test_rugpull_wrapper_parity.py`) re-runs unmodified
against this wrapper before anything else consumes it.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Protocol

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "lab" / "baseline") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "lab" / "baseline"))

import watch as watch_mod  # noqa: E402  -- lab/baseline/watch.py, imported, never copy-edited

# Captured once, at import time, before any test-harness monkeypatching can
# touch watch_mod's own module-global `process_record` name. watch.py's
# `process_file` calls `process_record` via ITS OWN module namespace (not
# this module's), so a wrapper that referenced `watch_mod.process_record`
# live would recurse if something ever repoints that name at the wrapper
# itself (exactly what framework/tests/test_rugpull_wrapper_parity.py does,
# to route process_file-based tests through the wrapper too). Calling this
# captured reference instead makes that safe by construction.
_ORIGINAL_PROCESS_RECORD = watch_mod.process_record


class StatefulDetector(Protocol):
    def process_record(self, record: dict, state: dict) -> list[dict]:
        """Mutates state in place; returns zero or more derived event
        records (schema is detector-specific, same freedom
        lab/baseline/watch.py's own drift-record schema already has)."""
        ...

    def empty_state(self) -> dict:
        ...


class RugPullBaselineDetector:
    """Wraps lab/baseline/watch.py's process_record verbatim -- import and
    delegate, per docs/PHASE6-DESIGN.md Section 3 item 2 ("wrapping
    exercise, not a rewrite"). Every method below is a one-line delegation
    to the real, untouched module."""

    def process_record(self, record: dict, state: dict) -> list[dict]:
        return _ORIGINAL_PROCESS_RECORD(record, state)

    def empty_state(self) -> dict:
        return watch_mod.empty_state()

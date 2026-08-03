#!/usr/bin/env python3
"""Phase 6 migration -- structural backend runner.

Thin reuse of lab/analysis/report.py's real `wazuh-logtest` invocation and
provenance gates -- imported, not reimplemented. The hard gate for this
migration is explicit: all matching goes through real `wazuh-logtest`; if
you start writing regex matching in Python to decide whether a rule fires,
stop. This module never does that -- `run_batch()` below is a direct
delegation to `lab/analysis/report.py`'s own `run_wazuh_logtest_batch()`.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "lab" / "analysis") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "lab" / "analysis"))

import report as report_mod  # noqa: E402 -- lab/analysis/report.py, imported, never duplicated

NO_ALERT_RULE_IDS = {report_mod.NO_ALERT_RULE_ID, "100200"}  # both parents are level-0, no-alert


def verify_rule_sync() -> str:
    return report_mod.verify_rule_sync()


def get_wazuh_version() -> str:
    return report_mod.get_wazuh_version()


def fetch_container_file(service: str, path: str) -> str:
    return report_mod.fetch_container_file(service, path)


def preflight_wazuh_logtest() -> dict:
    return report_mod.preflight_wazuh_logtest()


def run_batch(lines: list[str]) -> list[str | None]:
    """Feed `lines` through one real wazuh-logtest batch invocation; return
    the final matched rule id per line, in order. Never a Python
    reimplementation of rule matching -- see module docstring."""
    return report_mod.run_wazuh_logtest_batch(lines)

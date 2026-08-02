#!/usr/bin/env python3
"""Guard: the synthetic NorthwindPay artifacts must never cite a
record/session/server count that disagrees with the committed source corpus
(northwindpay/telemetry.jsonl). This project's whole brand is "never claim a
number you can't reproduce" -- its own showcase deliverable drifting from its
own source data (samples/REPORT.md once said 4,032/536 while the seeded corpus
is 4,046/538) is exactly the inconsistency a careful evaluator should reject.

Computes ground truth from telemetry.jsonl and asserts the cited counts in
samples/.../REPORT.md and northwindpay/audit_report_run.md match it. Loud,
specific failure -- never a silent pass. Stdlib-only, no live stack needed.

Usage: python3 northwindpay/check_sample_consistency.py   (exit 0 / 1)
Wired as `make check-sample`.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TELEMETRY = REPO_ROOT / "northwindpay" / "telemetry.jsonl"
SAMPLE_REPORT = (REPO_ROOT / "samples" /
                 "NorthwindPay-Agentic-Detection-Readiness-Assessment" / "REPORT.md")
RAW_RUN = REPO_ROOT / "northwindpay" / "audit_report_run.md"


def ground_truth() -> dict:
    records = [json.loads(l) for l in TELEMETRY.read_text().splitlines() if l.strip()]
    sessions = {r["session_id"] for r in records}
    servers = {r.get("server_command") for r in records}
    return {"records": len(records), "sessions": len(sessions), "servers": len(servers)}


def _int(s: str) -> int:
    return int(s.replace(",", ""))


def check_sample_report(gt: dict) -> list[str]:
    """samples/REPORT.md line: 'N MCP servers, M agent sessions, R telemetry records'."""
    text = SAMPLE_REPORT.read_text()
    errors = []
    m = re.search(r"(\d[\d,]*)\s+MCP servers,\s+(\d[\d,]*)\s+agent sessions,\s+(\d[\d,]*)\s+telemetry records", text)
    if not m:
        return [f"{SAMPLE_REPORT.name}: could not find the 'N MCP servers, M agent sessions, "
                f"R telemetry records' header line to check"]
    servers, sessions, records = _int(m.group(1)), _int(m.group(2)), _int(m.group(3))
    for label, cited, truth in [("servers", servers, gt["servers"]),
                                 ("sessions", sessions, gt["sessions"]),
                                 ("records", records, gt["records"])]:
        if cited != truth:
            errors.append(f"{SAMPLE_REPORT.name}: cites {cited} {label}, corpus has {truth}")
    return errors


def check_raw_run(gt: dict) -> list[str]:
    """audit_report_run.md cites 'R records' and 'M sessions' in its header/summary."""
    text = RAW_RUN.read_text()
    errors = []
    mr = re.search(r"(\d[\d,]*)\s+records", text)
    if mr and _int(mr.group(1)) != gt["records"]:
        errors.append(f"{RAW_RUN.name}: cites {_int(mr.group(1))} records, corpus has {gt['records']}")
    ms = re.search(r"(\d[\d,]*)\s+sessions", text)
    if ms and _int(ms.group(1)) != gt["sessions"]:
        errors.append(f"{RAW_RUN.name}: cites {_int(ms.group(1))} sessions, corpus has {gt['sessions']}")
    return errors


def main() -> int:
    gt = ground_truth()
    print(f"[check-sample] corpus ground truth: {gt['records']} records, "
          f"{gt['sessions']} sessions, {gt['servers']} servers")
    errors = check_sample_report(gt) + check_raw_run(gt)
    if errors:
        print("SAMPLE CONSISTENCY FAILED -- a synthetic artifact disagrees with the source corpus:")
        for e in errors:
            print(f"  - {e}")
        print("Regenerate the artifact against the current northwindpay/telemetry.jsonl "
              "(see northwindpay/ASSESSMENT-VALIDATION.md's run recipe).")
        return 1
    print("[check-sample] PASS -- sample + raw-run counts match the source corpus.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

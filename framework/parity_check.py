#!/usr/bin/env python3
"""Phase 6 migration -- the parity gate.

Parses the ACTUAL, currently-committed docs/PHASE4-REPORT.md and
docs/PHASE5-REPORT.md text (never hardcoded remembered numbers) and diffs
every extracted row against the framework/coverage.py-computed equivalent,
member-for-member. Never writes to either report file.

Per the hard gate: on any discrepancy, this prints the exact differing
row(s) and returns a non-zero exit code. It does not attempt to reconcile
by touching corpora, rules, watch.py, or the frozen reports.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from framework.coverage import run_full_pipeline, build_coverage_table, build_evasion_verdicts  # noqa: E402

PHASE4_REPORT = REPO_ROOT / "docs" / "PHASE4-REPORT.md"
PHASE5_REPORT = REPO_ROOT / "docs" / "PHASE5-REPORT.md"


def frac(text: str) -> tuple[int, int]:
    m = re.match(r"(\d+)/(\d+)", text)
    if not m:
        raise ValueError(f"not a fraction: {text!r}")
    return int(m.group(1)), int(m.group(2))


# ---------------------------------------------------------------------------
# Parse docs/PHASE4-REPORT.md
# ---------------------------------------------------------------------------

def parse_phase4_report(text: str) -> dict:
    expected = {}

    m = re.search(r"Recall: \*\*(\d+/\d+) \(", text)
    expected["tool_poisoning_recall"] = frac(m.group(1))

    m = re.search(r"False positives: \*\*(\d+/\d+) \(.*?\*\* benign `tools/list` responses", text)
    expected["tool_poisoning_fp"] = frac(m.group(1))

    m = re.search(r"Read-hop recall \(`100101`\): \*\*(\d+/\d+) \(", text)
    expected["read_hop_recall"] = frac(m.group(1))

    m = re.search(r"Exfil-hop recall, rule family `100103`.`100107` \(any of the 5 fires\): \*\*(\d+/\d+) \(", text)
    expected["exfil_hop_recall"] = frac(m.group(1))

    per_rule_fp = {}
    for m in re.finditer(r"\| `(\d+)` \| `(\w+)` \| (\d+/\d+) \(", text):
        rid, key, fp = m.groups()
        per_rule_fp[rid] = frac(fp)
    m = re.search(r"False positives, read hop \(`100101`\): \*\*(\d+/\d+) \(", text)
    per_rule_fp["100101"] = frac(m.group(1))
    expected["per_rule_fp"] = per_rule_fp

    m = re.search(r"remaining \*\*(\d+) task_ids expected to show drift\*\*, \*\*(\d+)/(\d+) \(", text)
    expected["rug_pull_recall"] = (int(m.group(2)), int(m.group(3)))

    rug_pull_tasks = {}
    table_section = text.split("| task_id | drift field(s) alerted |")[1].split("\n\n")[0]
    for line in table_section.splitlines():
        m = re.match(r"\| `([\w.]+)` \| (.+?) \|$", line.strip())
        if m:
            task_id, rules_str = m.groups()
            rules = [] if "none" in rules_str else [r.strip() for r in rules_str.split(",")]
            rug_pull_tasks[task_id] = sorted(rules)
    expected["rug_pull_tasks"] = rug_pull_tasks

    m = re.search(r"\*\*False positives: (\d+)/(\d+) \(.*?benign records triggered any alert\*\*", text)
    expected["aggregate_fp"] = (int(m.group(1)), int(m.group(2)))

    per_rule_fp["100102"] = expected["tool_poisoning_fp"]

    return expected


def check_phase4(run, table) -> list[str]:
    expected = parse_phase4_report(PHASE4_REPORT.read_text())
    mismatches = []

    def cmp(name, actual, exp):
        if actual != exp:
            mismatches.append(f"{name}: expected {exp}, got {actual}")

    tp = table["detections"]["tool_poisoning_html_comment"]["recall"]["tool_poisoning_html_comment"]
    cmp("tool_poisoning recall", (tp["hit"], tp["total"]), expected["tool_poisoning_recall"])

    ce = table["detections"]["credential_exfil"]["recall"]
    cmp("read_hop recall", (ce["read_hop"]["hit"], ce["read_hop"]["total"]), expected["read_hop_recall"])
    cmp("exfil_hop recall", (ce["exfil_hop"]["hit"], ce["exfil_hop"]["total"]), expected["exfil_hop_recall"])

    rp = table["detections"]["rug_pull_baseline_drift"]["recall"]["rug_pull_baseline_drift"]
    cmp("rug_pull recall", (rp["hit"], rp["total"]), expected["rug_pull_recall"])
    cmp("rug_pull per-task table", rp["per_task"], expected["rug_pull_tasks"])

    for rid, exp_fp in expected["per_rule_fp"].items():
        cmp(f"per-rule FP {rid}", table["per_rule_fp"].get(rid), exp_fp)

    agg = table["aggregate_fp"]
    cmp("aggregate FP", (agg["alerting_records"], agg["total_records"]), expected["aggregate_fp"])

    return mismatches


# ---------------------------------------------------------------------------
# Parse docs/PHASE5-REPORT.md
# ---------------------------------------------------------------------------

def parse_phase5_report(text: str) -> dict:
    expected = {}
    for m in re.finditer(r"\| `(attack_evasion_\w+)` \|.*\| \*\*(EVADED)\*\* \|", text):
        expected[m.group(1)] = "EVADED"
    for m in re.finditer(r"\| `(attack_evasion_\w+)` \| ([\w -]+) \| (100\d+(?:,100\d+)?|\(none\)) \| caught \|", text):
        expected[m.group(1)] = "caught"
    # tool-poisoning table (4 cols) doesn't have the "other signal" column CE table has;
    # re-scan both patterns explicitly to be safe rather than rely on one combined regex.
    for line in text.splitlines():
        m = re.match(r"\| `(attack_evasion_\w+)` \|.*\| (\*\*EVADED\*\*|caught) \|\s*$", line)
        if m:
            tid, verdict = m.groups()
            expected[tid] = "EVADED" if "EVADED" in verdict else "caught"

    m = re.search(r"`e10_legit_upgrade` \| (yes|\*\*no\*\*) \|", text)
    expected["attack_evasion_e10_legit_upgrade"] = "fired" if m.group(1) == "yes" else "did not fire"
    m = re.search(r"`e11_behavior_only` \| (yes|\*\*no\*\*) \|", text)
    expected["attack_evasion_e11_behavior_only"] = "caught" if m.group(1) == "yes" else "EVADED"
    m = re.search(r"`e12_pulled` \| (yes|\*\*no\*\*) \|", text)
    expected["attack_evasion_e12_pulled"] = "caught" if m.group(1) == "yes" else "EVADED"

    return expected


def check_phase5(verdicts: dict) -> list[str]:
    expected = parse_phase5_report(PHASE5_REPORT.read_text())
    mismatches = []
    for tid, exp_verdict in expected.items():
        actual = verdicts.get(tid)
        if actual != exp_verdict:
            mismatches.append(f"evasion {tid}: expected {exp_verdict!r}, got {actual!r}")
    if len(expected) < 12:
        mismatches.append(f"parity_check parsed only {len(expected)}/12+ evasion rows from PHASE5-REPORT.md -- parser gap, not a framework bug; investigate before trusting a clean result")
    return mismatches


def main() -> int:
    import argparse
    import json as json_mod
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true",
                         help="emit a structured {passed, mismatches} JSON object to stdout "
                              "instead of human-readable text to stderr")
    args = parser.parse_args()

    # No --detection scope here, deliberately: this check's whole point is
    # "does the frozen-report parity hold in full" -- check_phase4/check_phase5
    # return plain mismatch strings, not per-technique-tagged results, so a
    # partial filter would be cosmetic rather than actually skip any work.
    # (Contrast framework/coverage.py's --detection, which genuinely narrows
    # the *rendered* table even though the underlying batch run is shared.)
    run = run_full_pipeline()
    table = build_coverage_table(run)
    verdicts = build_evasion_verdicts(run)

    mismatches = check_phase4(run, table) + check_phase5(verdicts)

    if args.json:
        print(json_mod.dumps({"passed": not mismatches, "mismatches": mismatches}, indent=2))
        return 0 if not mismatches else 1

    if mismatches:
        print("PARITY CHECK FAILED -- discrepant rows:", file=sys.stderr)
        for m in mismatches:
            print(f"  - {m}", file=sys.stderr)
        return 1

    print("PARITY CHECK PASSED -- full per-task_id/per-rule-id table matches "
          "docs/PHASE4-REPORT.md and docs/PHASE5-REPORT.md exactly.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

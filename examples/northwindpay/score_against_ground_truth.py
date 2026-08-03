#!/usr/bin/env python3
"""Scores a framework/audit_report.py JSON run against examples/northwindpay/GROUND_TRUTH.json.

This is the ONLY script in this directory that reads GROUND_TRUTH.json -- the
assessment run itself (framework/audit_report.py examples/northwindpay/telemetry.jsonl
--known-good examples/northwindpay/known_good_bom.json) never does, and never can:
GROUND_TRUTH.json is not one of its two CLI arguments.

Usage:
  python3 framework/audit_report.py examples/northwindpay/telemetry.jsonl \\
      --known-good examples/northwindpay/known_good_bom.json --json > /tmp/report.json
  python3 examples/northwindpay/score_against_ground_truth.py /tmp/report.json
"""
import json
import sys
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent


def load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def bom_text(report: dict) -> str:
    """Flattened, greppable text of everything Section 2 (AI-BOM) would show
    -- server commands + trust boundary labels -- since the JSON report's
    `bom` field already carries this structured."""
    parts = []
    for cmd, entry in report["bom"]["servers"].items():
        parts.append(cmd)
        parts.append(entry["trust_boundary"]["label"])
    parts.extend(report.get("shadow_candidates") or [])
    return "\n".join(parts)


def headline_session_ids(report: dict) -> set:
    cf = report["client_findings"]
    ids = set()
    for row in cf["structural_findings"] + cf["rugpull_high"]:
        ids.add(row["session_id"])
    return ids


def all_scanned_session_ids(report: dict) -> set:
    cf = report["client_findings"]
    ids = set()
    for row in cf["structural_findings"] + cf["rugpull_high"] + cf["rugpull_info"]:
        ids.add(row["session_id"])
    return ids


def known_gaps_text(report: dict) -> str:
    return json.dumps(report["detections"])  # known_gaps_count only in JSON; prose lives in markdown_report


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <audit_report.json>", file=sys.stderr)
        return 2

    report = load(sys.argv[1])
    gt = json.loads((OUT_DIR / "GROUND_TRUTH.json").read_text())
    md = report["markdown_report"]

    bom_flat = bom_text(report)
    headline_ids = headline_session_ids(report)
    rugpull_info_ids = {row["session_id"] for row in report["client_findings"]["rugpull_info"]}

    results = {"class_a": [], "class_b": [], "class_c": []}

    print("=" * 78)
    print("CLASS A -- detectable issues (must appear in the report)")
    print("=" * 78)
    for item in gt["class_a_detectable"]:
        sid = item.get("session_id")
        found = False
        how = ""
        if item["id"] == "A1_shadow_mcp_server":
            found = item["server_command"] in (report.get("shadow_candidates") or [])
            how = "shadow_candidates list"
        elif item["id"] == "A2_over_privileged_rw_mount":
            entry = report["bom"]["servers"].get(item["server_command"])
            found = bool(entry) and entry["trust_boundary"]["filesystem_access"] == "rw"
            how = "AI-BOM trust_boundary filesystem_access == rw"
        else:
            found = sid in headline_ids
            how = "Section 3 headline findings (by session_id)"
        results["class_a"].append((item["id"], found, how))
        print(f"[{'PASS' if found else 'FAIL'}] {item['id']:40s} via {how}")

    print()
    print("=" * 78)
    print("CLASS B -- benign decoys (must NOT appear as a headline finding)")
    print("=" * 78)
    by_id: dict = {}
    for item in gt["class_b_benign_decoys"]:
        by_id.setdefault(item["id"], []).append(item)
    for bid, items in by_id.items():
        bad = [it for it in items if it.get("session_id") in headline_ids]
        ok = len(bad) == 0
        results["class_b"].append((bid, ok, f"{len(items)} instance(s) checked"))
        print(f"[{'PASS' if ok else 'FAIL'}] {bid:40s} ({len(items)} instance(s), "
              f"{len(bad)} incorrectly in headline findings)")
    # B2's session also must not silently vanish -- it should appear in the
    # reduced-severity bucket, not nowhere at all (that would be a different
    # kind of dishonesty: silently dropping a real drift event).
    b2 = next(it for it in gt["class_b_benign_decoys"] if it["id"] == "B2_legit_version_bump")
    b2_present_info = b2["session_id"] in rugpull_info_ids
    print(f"[{'PASS' if b2_present_info else 'FAIL'}] B2 still visible in the low-severity bucket "
          f"(not silently dropped): {b2_present_info}")

    print()
    print("=" * 78)
    print("CLASS C -- structurally undetectable (must not be claimed caught; must be disclosed)")
    print("=" * 78)
    for item in gt["class_c_structurally_undetectable"]:
        sids = item.get("session_ids") or [item.get("session_id")]
        not_caught = all(sid not in headline_ids for sid in sids if sid)
        gap_marker = item["known_gap_ref"].split("(")[0].strip().split()[-1]  # e.g. "E11", "E8", "E3b"
        disclosed = gap_marker in md
        ok = not_caught and disclosed
        results["class_c"].append((item["id"], ok, f"not_caught={not_caught} disclosed({gap_marker})={disclosed}"))
        print(f"[{'PASS' if ok else 'FAIL'}] {item['id']:35s} not_caught={not_caught} "
              f"disclosed_in_report({gap_marker})={disclosed}")

    print()
    print("=" * 78)
    a_recall = sum(1 for _, ok, _ in results["class_a"] if ok) / len(results["class_a"])
    b_pass = sum(1 for _, ok, _ in results["class_b"] if ok)
    b_total = len(results["class_b"])
    c_pass = sum(1 for _, ok, _ in results["class_c"] if ok)
    c_total = len(results["class_c"])
    print(f"CLASS A RECALL:  {sum(1 for _, ok, _ in results['class_a'] if ok)}/{len(results['class_a'])} "
          f"({a_recall:.0%})")
    print(f"CLASS B FALSE FINDINGS: {b_total - b_pass}/{b_total} decoys incorrectly flagged")
    print(f"CLASS C HONESTY: {c_pass}/{c_total} correctly non-claimed + disclosed")
    print("=" * 78)

    all_pass = (a_recall == 1.0) and (b_pass == b_total) and (c_pass == c_total) and b2_present_info
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())

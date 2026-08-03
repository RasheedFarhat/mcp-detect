#!/usr/bin/env python3
"""Data Mining Exporter.

Parses JSON files in detections/, XML rules in wazuh/local_rules.xml,
queries live metrics from framework/coverage.py, and outputs a formatted
markdown table to website/data_mining_results.md.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Setup paths
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "lab" / "analysis"))

from framework.registry import load_registry
from framework.coverage import run_full_pipeline, build_coverage_table, build_evasion_verdicts
from framework.fixtures import resolve_benign_denominator, has_evasion_corpus, parse_evasion_task_ids

# Constants/Mappings
TECHNIQUE_NAMES = {
    "SAF-T1001": "Tool Poisoning",
    "SAF-T1104": "Sensitive Absolute Read",
    "SAF-T1105": "Path Traversal",
    "SAF-T1201": "Rug Pull",
    "SAF-T1502": "Credential Exfiltration",
}

HARNESS_MAP = {
    "SAF-T1001": "lab/attacks/harness.py",
    "SAF-T1104": "lab/attacks/abs_path_read_harness.py",
    "SAF-T1105": "lab/attacks/path_traversal_harness.py",
    "SAF-T1201": "lab/attacks/harness.py",
    "SAF-T1502": "lab/attacks/harness.py",
}

VARIANTS_MAP = {
    "SAF-T1001": "12 description-based HTML comment prompts (`TOOL_POISONING_VARIANTS`)",
    "SAF-T1104": "8 absolute paths (`v01_etc_passwd` to `v08_home_env_overlap`)",
    "SAF-T1105": "8 relative traversal sequences (`v01_env_overlap` to `v08_etc_shadow_deep`)",
    "SAF-T1201": "4 version/description drift modes (`baseline`, `pulled`, `desc_only`, `version_only`)",
    "SAF-T1502": "2-hop sequence; 10 exfil argument combinations (`v01` to `v10`)",
}

GAPS_SUMMARY_MAP = {
    "SAF-T1001": "Wording (E1), no comment (E2), homoglyphs (E3b), >120 pad (E4)",
    "SAF-T1104": "Alternate names, unlisted paths, URL encoding, symlinks",
    "SAF-T1105": "Spoof name (E1), URL-enc (E2), Unicode (E3), Double-enc (E4), No-dots (E6)",
    "SAF-T1201": "Legit bump FP (E10), behavior-only pull (E11)",
    "SAF-T1502": "Spoof name (E5), 6th key (E6), secret shape (E7), base64 (E8), renamed path (E9)",
}

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

def strip_comments(xml_text: str) -> str:
    return _COMMENT_RE.sub("", xml_text)

def parse_rules_xml(xml_path: Path) -> dict[str, dict]:
    xml_text = xml_path.read_text()
    clean_xml = strip_comments(xml_text)
    root = ET.fromstring(clean_xml)
    rules = {}
    rule_iter = root.iter("rule") if root.tag != "rule" else [root]
    for rule_el in rule_iter:
        rid = rule_el.get("id")
        if rid is None:
            continue
        fields = []
        for field_el in rule_el.findall("field"):
            fields.append({
                "name": field_el.get("name"),
                "negate": field_el.get("negate", "no"),
                "pattern": field_el.text
            })
        rules[rid] = {
            "id": rid,
            "level": rule_el.get("level"),
            "description": rule_el.find("description").text if rule_el.find("description") is not None else "",
            "fields": fields
        }
    return rules

def parse_scenario_id(attack_corpus_ref: str) -> str:
    if "scenario_id=" in attack_corpus_ref:
        return attack_corpus_ref.split("scenario_id=")[1].split("&")[0]
    if attack_corpus_ref == "live:rugpull_alerts":
        return "rug_pull"
    return "unknown"

def format_rule_ids(rule_ids: list[str]) -> str:
    nums = sorted(int(x) for x in rule_ids)
    ranges = []
    if not nums:
        return ""

    start = nums[0]
    prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
        else:
            if start == prev:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{prev}")
            start = n
            prev = n
    if start == prev:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{prev}")
    return ", ".join(ranges)

def get_evasion_stats_str(d, verdicts) -> str:
    ref = d.fixtures.get("evasion_corpus", "none")
    if not has_evasion_corpus(ref):
        return "0/0 (no evasion corpus)"

    task_ids = parse_evasion_task_ids(ref)
    caught_count = 0
    total_count = 0
    caught_labels = []
    for tid in task_ids:
        if tid == "attack_evasion_e10_legit_upgrade":
            continue
        total_count += 1
        if verdicts.get(tid) == "caught":
            caught_count += 1
            # Try to extract the Exx part
            parts = tid.split("_")
            found_label = False
            for p in parts:
                if len(p) >= 2 and p[0].lower() == 'e' and (p[1:].isdigit() or (p[1:-1].isdigit() and p[-1].isalpha())):
                    caught_labels.append(p.upper())
                    found_label = True
                    break
            if not found_label:
                caught_labels.append(tid)

    if total_count == 0:
        return "0/0 (no evasion corpus)"

    caught_str = f"{caught_count}/{total_count} caught"
    if caught_labels:
        caught_str += f" ({', '.join(caught_labels)})"
    return caught_str

def main():
    print("Loading registry...")
    detections = load_registry()

    print("Parsing rules XML...")
    rules_path = REPO_ROOT / "wazuh" / "local_rules.xml"
    parsed_rules = parse_rules_xml(rules_path)

    print("Running coverage metrics pipeline...")
    run_metrics = run_full_pipeline()
    coverage_table = build_coverage_table(run_metrics)
    evasion_verdicts = build_evasion_verdicts(run_metrics)
    benign_lines = run_metrics["canonical"]["benign_lines"]

    # Generate Section 1 Table
    sec1_rows = []
    for d in detections:
        tech_id = d.technique_id
        tech_name = TECHNIQUE_NAMES.get(tech_id, d.name)
        harness = HARNESS_MAP.get(tech_id, "Unknown")
        scenario_id = parse_scenario_id(d.fixtures.get("attack_corpus", ""))
        variants = VARIANTS_MAP.get(tech_id, "Unknown")
        sec1_rows.append(f"| {tech_id} | {tech_name} | `{harness}` | `{scenario_id}` | {variants} |")
    sec1_table_str = "\n".join(sec1_rows)

    # Generate Section 2 Table
    sec2_rows = []
    for d in detections:
        tech_id = d.technique_id
        name = d.name
        det_type = d.detection_type
        status = d.status

        # backends formatting
        backend_list = []
        for b in d.backends:
            if b.backend == "stateful":
                backend_list.append(f"Stateful: `{b.logic_ref.python_class}`")
            elif b.backend == "wazuh_rule":
                rule_ids_str = format_rule_ids(b.logic_ref.wazuh_rule_ids)
                if len(b.logic_ref.wazuh_rule_ids) == 1:
                    backend_list.append(f"Wazuh Rule `{rule_ids_str}`")
                else:
                    backend_list.append(f"Wazuh Rules `{rule_ids_str}`")
        backends_str = "<br>".join(backend_list)

        # fields formatting
        if tech_id == "SAF-T1201":
            fields_list = ["mcp_drift_marker", "drift_field"]
        else:
            fields_set = set()
            for b in d.backends:
                if b.backend == "wazuh_rule":
                    for rid in b.logic_ref.wazuh_rule_ids:
                        for f in parsed_rules.get(rid, {}).get("fields", []):
                            fields_set.add(f["name"])
            fields_list = sorted(list(fields_set))
        fields_str = ", ".join(f"`{f}`" for f in fields_list)

        sec2_rows.append(f"| {tech_id} | {name} | {det_type} | {backends_str} | {fields_str} | {status} |")
    sec2_table_str = "\n".join(sec2_rows)

    # Generate Section 3 Table
    sec3_rows = []
    for d in detections:
        tech_id = d.technique_id

        # rules formatting
        rule_ids = d.all_wazuh_rule_ids()
        rules_str = format_rule_ids(rule_ids)

        # recall rate
        table_det = coverage_table["detections"][d.name]
        recall_strs = []

        if len(table_det["recall"]) == 1:
            label = list(table_det["recall"].keys())[0]
            r = table_det["recall"][label]
            pct = (r["hit"] / r["total"]) * 100 if r["total"] > 0 else 0.0
            recall_rate_str = f"{r['hit']}/{r['total']} ({pct:.0f}%)"
        else:
            for label, r in table_det["recall"].items():
                pct = (r["hit"] / r["total"]) * 100 if r["total"] > 0 else 0.0
                recall_strs.append(f"{label}: {r['hit']}/{r['total']} ({pct:.0f}%)")
            recall_rate_str = "<br>".join(recall_strs)

        # FP Rate
        fp_count = 0
        for rid in rule_ids:
            fp_count += coverage_table["per_rule_fp"].get(rid, (0, 1))[0]
        denom = resolve_benign_denominator(d.fixtures["benign_denominator"], benign_lines)
        fp_pct = (fp_count / denom) * 100 if denom > 0 else 0.0
        fp_rate_str = f"{fp_count}/{denom} ({fp_pct:.0f}%)"

        # evasions
        evasions_str = get_evasion_stats_str(d, evasion_verdicts)

        # gaps
        gaps_str = GAPS_SUMMARY_MAP.get(tech_id, "; ".join(d.known_gaps))

        sec3_rows.append(f"| {tech_id} | {rules_str} | {recall_rate_str} | {fp_rate_str} | {evasions_str} | {gaps_str} |")
    sec3_table_str = "\n".join(sec3_rows)

    # Write Markdown Document
    md_content = f"""# Data Mining Results

This document compiles the attack techniques catalog, detection methodologies map, and performance & evasion matrix generated from the active detection registry, Wazuh rule definitions, and live metrics pipeline.

## Section 1: Attack Techniques Catalog

| Technique ID | Name | Harness | Scenario ID | Variants |
| :--- | :--- | :--- | :--- | :--- |
{sec1_table_str}

## Section 2: Detections & Methodology Map

| Technique ID | Name | Type | Backends | Fields | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
{sec2_table_str}

## Section 3: Performance & Evasion Matrix

| Technique ID | Alert Rules | Recall Rate | FP Rate (Benign) | Red-Team Evasions (Caught / Total) | Known Gaps (Summary) |
| :--- | :--- | :--- | :--- | :--- | :--- |
{sec3_table_str}
"""
    output_path = REPO_ROOT / "website" / "data_mining_results.md"
    print(f"Writing results to {output_path}...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(md_content)
    print("Done!")

if __name__ == "__main__":
    main()

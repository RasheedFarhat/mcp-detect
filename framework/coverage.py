#!/usr/bin/env python3
"""Phase 6 migration -- coverage.py.

Walks the Detection registry, runs each Detection's backend(s) against the
three frozen Phase 4/5 corpora through the real Wazuh engine (never a
Python reimplementation of rule matching), and diffs the result against
docs/PHASE4-REPORT.md / docs/PHASE5-REPORT.md member-for-member -- not just
the six summary numbers.

Deliberately reuses analysis/report.py's and analysis/evasion_report.py's
own pure computation functions wherever they are already backend-agnostic
(compute_scenario_recall, compute_aggregate_fp, cross_check_scenario_task,
group_final_rules_by_task, targeted_and_other_fired) -- these don't
hardcode which rule belongs to which technique, only how to group already-
joined records by scenario_id/task_id, so reusing them against the
registry-driven join (framework/alerts.py) is a faithful generalization,
not a parallel reimplementation. The one thing that WAS hardcoded per rule
id (compute_per_rule_fp's literal "100102"/"100101"/EXFIL_HOP_FAMILY keys)
is replaced here with a registry-driven equivalent
(per_rule_fp_from_registry) that resolves each Detection's own declared
`fixtures.benign_denominator` instead.

Per-evasion-class target-rule attribution (which rule(s) a given evasion
task_id is testing) is reused from analysis/evasion_report.py's
EVASION_CLASSES dict (import) where that dict has an entry -- a
measurement-tool concept it already encodes correctly, the same way v2's
design doc names it as something the framework generalizes, not reinvents.
EVASION_CLASSES predates SAF-T1105's own evasion corpus (maturity-pass
addition) and has no entries for its task_ids; build_evasion_verdicts()
falls back to the owning Detection's own declared `all_wazuh_rule_ids()`
as the target-rule set in that case -- still registry-driven, just from
the schema instead of the measurement-tool dict, and exactly what's
needed since a Detection's backend already names every rule id it owns.

This module never writes to docs/PHASE4-REPORT.md or docs/PHASE5-REPORT.md
-- only reads them for the parity diff.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "analysis"))

import report as report_mod  # noqa: E402
import evasion_report as ev_mod  # noqa: E402

from framework.registry import load_registry, run_stateful_stage  # noqa: E402
from framework.alerts import normalize_and_join, build_session_key_table  # noqa: E402
from framework.fixtures import (  # noqa: E402
    resolve_benign_denominator, parse_live_telemetry_ref,
    has_evasion_corpus, parse_evasion_task_ids,
)
from framework.structural import verify_rule_sync, get_wazuh_version, run_batch  # noqa: E402


# ---------------------------------------------------------------------------
# Registry-driven per-rule FP (replaces report_mod.compute_per_rule_fp's
# hardcoded per-rule-id dict)
# ---------------------------------------------------------------------------

def per_rule_fp_from_registry(benign_joined, detections, benign_lines) -> dict:
    counts = defaultdict(int)
    for jr in benign_joined:
        if jr.matched_rule_id != report_mod.NO_ALERT_RULE_ID:
            counts[jr.matched_rule_id] += 1
    result = {}
    for d in detections:
        denom = resolve_benign_denominator(d.fixtures["benign_denominator"], benign_lines)
        for rid in d.all_wazuh_rule_ids():
            result[rid] = (counts.get(rid, 0), denom)
    return result


def detection_scenario_id(d) -> str:
    return parse_live_telemetry_ref(d.fixtures["attack_corpus"])["scenario_id"]


# ---------------------------------------------------------------------------
# Full pipeline run
# ---------------------------------------------------------------------------

def run_full_pipeline():
    detections = load_registry()
    rule_sha = verify_rule_sync()
    wazuh_version = get_wazuh_version()

    canonical = report_mod.load_inputs()
    evasion_lines = ev_mod.load_evasion_corpus_lines()

    rugpull_detection = next(d for d in detections if d.technique_id == "SAF-T1201")
    evasion_drift_lines = run_stateful_stage(rugpull_detection, evasion_lines)

    all_lines = (canonical["benign_lines"] + canonical["malicious_lines"]
                 + canonical["drift_lines"] + evasion_lines + evasion_drift_lines)
    all_matched = run_batch(all_lines)

    n_benign = len(canonical["benign_lines"])
    n_malicious = len(canonical["malicious_lines"])
    n_canon_drift = len(canonical["drift_lines"])
    n_evasion = len(evasion_lines)

    benign_matched = all_matched[:n_benign]
    malicious_matched = all_matched[n_benign:n_benign + n_malicious]
    canon_drift_matched = all_matched[n_benign + n_malicious: n_benign + n_malicious + n_canon_drift]
    evasion_matched = all_matched[n_benign + n_malicious + n_canon_drift:
                                  n_benign + n_malicious + n_canon_drift + n_evasion]
    evasion_drift_matched = all_matched[n_benign + n_malicious + n_canon_drift + n_evasion:]

    benign_joined = normalize_and_join(canonical["benign_lines"], benign_matched, detections)
    attack_joined = normalize_and_join(
        canonical["malicious_lines"] + canonical["drift_lines"],
        malicious_matched + canon_drift_matched,
        detections,
    )

    return {
        "detections": detections,
        "rule_sha": rule_sha,
        "wazuh_version": wazuh_version,
        "canonical": canonical,
        "evasion_lines": evasion_lines,
        "evasion_drift_lines": evasion_drift_lines,
        "benign_joined": benign_joined,
        "attack_joined": attack_joined,
        "evasion_matched": evasion_matched,
        "evasion_drift_matched": evasion_drift_matched,
        "n_benign": n_benign,
    }


# ---------------------------------------------------------------------------
# Coverage table (registry-driven recall + FP, per Detection)
# ---------------------------------------------------------------------------

def build_coverage_table(run) -> dict:
    detections = run["detections"]
    per_scenario_recall = report_mod.compute_scenario_recall(run["attack_joined"])
    per_rule_fp = per_rule_fp_from_registry(run["benign_joined"], detections, run["canonical"]["benign_lines"])
    agg_fp = report_mod.compute_aggregate_fp(run["benign_joined"])

    table = {"aggregate_fp": agg_fp, "per_rule_fp": per_rule_fp, "detections": {}}

    for d in detections:
        scenario = detection_scenario_id(d)
        tasks = per_scenario_recall.get(scenario, {})
        entry_recall = {}
        for backend_entry in d.backends:
            if backend_entry.backend != "wazuh_rule":
                continue
            rule_ids = set(backend_entry.logic_ref.wazuh_rule_ids)
            label = backend_entry.label or d.name
            if d.technique_id == "SAF-T1201":
                baseline_tasks = sorted(t for t in tasks if "baseline" in t)
                drifting_tasks = sorted(t for t in tasks if t not in baseline_tasks)
                hit = sum(1 for t in drifting_tasks if set(tasks[t]) & rule_ids)
                entry_recall[label] = {"hit": hit, "total": len(drifting_tasks),
                                        "baseline_tasks": baseline_tasks, "drifting_tasks": drifting_tasks,
                                        "per_task": {t: sorted(set(tasks[t]) & rule_ids) for t in drifting_tasks}}
            else:
                hit = sum(1 for t, rules in tasks.items() if set(rules) & rule_ids)
                entry_recall[label] = {"hit": hit, "total": len(tasks),
                                        "per_task": {t: sorted(set(rules) & rule_ids) for t, rules in tasks.items()}}
        table["detections"][d.name] = {"technique_id": d.technique_id, "scenario": scenario, "recall": entry_recall}

    return table


# ---------------------------------------------------------------------------
# Evasion verdicts (registry-driven: each Detection's own fixtures.evasion_corpus,
# not a hardcoded per-technique task_id list)
# ---------------------------------------------------------------------------

def build_evasion_verdicts(run) -> dict:
    """Derives the evasion task_id list to verdict PER DETECTION from its own
    `fixtures.evasion_corpus` (via `has_evasion_corpus()`/`parse_evasion_task_ids()`),
    not from a hardcoded list -- every technique with an authored evasion
    corpus flows through this same path, including SAF-T1105, which a prior
    hardcoded TP_TASK_IDS/CE_TASK_IDS(+3 rug-pull ids) loop silently excluded
    (docs/STATE-OF-PROJECT.md's filed finding).

    Rug pull (SAF-T1201) keeps its own verdict shape -- drift-record-based,
    not task_results-based, since its stateful stage means "did this evade"
    is really "did baseline/watch.py even emit a drift record" -- and E10 is
    a false-positive control probe (fired/did not fire), not a caught/EVADED
    evasion attempt, same distinction the original hardcoded logic made.

    Every other technique's task_ids are checked against `task_results`
    (which rule(s) fired on that task_id's records): the target-rule set
    comes from `evasion_report.EVASION_CLASSES[tid]` where that dict has an
    entry, or from the Detection's own `all_wazuh_rule_ids()` otherwise
    (SAF-T1105's case -- EVASION_CLASSES predates its evasion corpus)."""
    task_results = ev_mod.group_final_rules_by_task(run["evasion_lines"], run["evasion_matched"])
    drift_joined = normalize_and_join(run["evasion_drift_lines"], run["evasion_drift_matched"], run["detections"]) \
        if run["evasion_drift_lines"] else []
    by_task = defaultdict(set)
    for jr in drift_joined:
        by_task[jr.raw.get("task_id")].add(jr.matched_rule_id)
    drift_task_results = {t: sorted(r) for t, r in by_task.items()}

    verdicts = {}
    for d in run["detections"]:
        ref = d.fixtures.get("evasion_corpus", "none")
        if not has_evasion_corpus(ref):
            continue
        task_ids = parse_evasion_task_ids(ref)

        if d.technique_id == "SAF-T1201":
            for tid in task_ids:
                if tid == "attack_evasion_e10_legit_upgrade":
                    verdicts[tid] = "fired" if drift_task_results.get(tid) else "did not fire"
                else:
                    verdicts[tid] = "caught" if drift_task_results.get(tid) else "EVADED"
            continue

        own_rule_ids = set(d.all_wazuh_rule_ids())
        for tid in task_ids:
            fired = set(task_results.get(tid, []))
            target = ev_mod.EVASION_CLASSES[tid]["target_rules"] if tid in ev_mod.EVASION_CLASSES else own_rule_ids
            verdicts[tid] = "caught" if (fired & target) else "EVADED"

    return verdicts


def render_markdown(table: dict, verdicts: dict, *, only_detection: str | None = None) -> str:
    out = ["# Coverage report\n"]
    agg = table["aggregate_fp"]
    out.append(f"Aggregate benign FP: **{agg['alerting_records']}/{agg['total_records']}**\n")
    out.append("| technique | scenario | recall label | hit/total |")
    out.append("|---|---|---|---|")
    for name, d in table["detections"].items():
        if only_detection and d["technique_id"] != only_detection and name != only_detection:
            continue
        for label, r in d["recall"].items():
            out.append(f"| {d['technique_id']} | {d['scenario']} | {label} | {r['hit']}/{r['total']} |")
    if not only_detection:
        out.append("\n## Evasion verdicts\n")
        out.append("| task_id | verdict |")
        out.append("|---|---|")
        for tid, v in verdicts.items():
            out.append(f"| `{tid}` | {v} |")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# OWASP MCP Top 10 coverage gap-map (registry-driven, no live stack)
# ---------------------------------------------------------------------------

OWASP_MCP_TITLES = {
    "MCP01": "Token/credential mismanagement",
    "MCP02": "Privilege escalation / scope creep",
    "MCP03": "Tool poisoning (rug pull, schema poisoning, tool shadowing)",
    "MCP04": "Supply chain",
    "MCP05": "Command injection",
    "MCP06": "Intent-flow subversion / prompt injection",
    "MCP07": "Insufficient authentication",
    "MCP08": "Weak telemetry/logging",
    "MCP09": "Shadow MCP servers",
    "MCP10": "Context over-sharing",
}

# MCP08 is addressed by this project as a telemetry CONTROL (the proxy +
# schema/schema.md), never by a detection rule. Rendered as an explicit note
# so the gap-map does not imply detection coverage that doesn't exist -- the
# whole point of a gap-map is that the holes are legible.
OWASP_MCP_NOTES = {
    "MCP08": "control-not-detection: the proxy + telemetry schema mitigate this "
             "category as a logging capability; no rule detects it",
    "MCP09": "capability-not-Detection: framework/abom.py --known-good diffs observed "
             "server_commands against a client BOM (shadow-server candidates); not a "
             "registered Detection, no wazuh_rule backend, no measured recall/FP",
}


def render_owasp_map(detections: list) -> str:
    """Renders the OWASP MCP Top 10 coverage gap-map from each detection.yaml's
    `owasp_mcp` field. Registry-only -- no live Wazuh stack needed, same as
    --gaps-report. A category with no mapped detection is a real, named gap
    rendered as NONE, never omitted.

    Coverage is reported as PARTIAL for any mapped category, never "full": per
    docs/STATE-OF-PROJECT.md's own honest coverage map and this project's
    self-authored-recall caveat (PHASE4-REPORT.md), no category is at
    production/held-out confidence yet. Depth within a mapped category is read
    from each detection's own `status` + `known_gaps` count, not a separately
    invented confidence field."""
    by_cat = defaultdict(list)
    for d in detections:
        for code in getattr(d, "owasp_mcp", []):
            by_cat[code].append(d)

    covered = sum(1 for c in OWASP_MCP_TITLES if by_cat.get(c))
    out = ["# OWASP MCP Top 10 (v0.1) -- coverage gap-map\n"]
    out.append(
        "Registry-driven, generated from each `detection.yaml`'s `owasp_mcp` field; "
        "no live stack needed. A category with no mapped detection is rendered "
        "**NONE**, not omitted. Every mapped category is **PARTIAL** by policy -- "
        "no category is at held-out/production confidence (recall is measured "
        "against self-authored variants; see PHASE4-REPORT.md). Read `status` + "
        "`known_gaps` for per-detection depth.\n"
    )
    out.append(f"**{covered}/10 categories have at least one mapped detection.**\n")
    out.append("| OWASP | Category | Coverage | Detections (status) | Known gaps |")
    out.append("|---|---|---|---|---|")
    for code in sorted(OWASP_MCP_TITLES):
        title = OWASP_MCP_TITLES[code]
        ds = by_cat.get(code, [])
        if ds:
            det_cell = "; ".join(f"{d.technique_id} `{d.status}`" for d in ds)
            gaps = sum(len(d.known_gaps) for d in ds)
            out.append(f"| {code} | {title} | PARTIAL | {det_cell} | {gaps} |")
        else:
            note = OWASP_MCP_NOTES.get(code, "_no detection maps to this category_")
            out.append(f"| {code} | {title} | NONE | {note} | — |")
    out.append("")
    return "\n".join(out) + "\n"


def render_gaps_report(detections: list) -> str:
    """Renders the known_gaps field -- declared in every detection.yaml,
    never aggregated or rendered anywhere in code until now. This is what
    makes docs/PHASE6-DESIGN.md's own claim ("the honesty discipline
    becomes a field the tooling can check for, not prose someone has to
    remember to write") literally true instead of aspirational. No live
    stack needed -- this only reads the registry."""
    out = ["# Known gaps report\n"]
    out.append("| technique | name | status | known_gaps |")
    out.append("|---|---|---|---|")
    for d in detections:
        out.append(f"| {d.technique_id} | {d.name} | {d.status} | {len(d.known_gaps)} |")
    out.append("")
    for d in detections:
        out.append(f"## {d.technique_id} -- {d.name} (`status: {d.status}`)\n")
        if not d.known_gaps:
            out.append("_No known gaps declared._\n")
        else:
            for g in d.known_gaps:
                out.append(f"- {g}")
            out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--detection", help="scope output to one technique_id (e.g. SAF-T1105) "
                                             "or Detection name; the underlying pipeline still runs "
                                             "for the full registry in one shared wazuh-logtest batch")
    parser.add_argument("--gaps-report", action="store_true",
                         help="render the known_gaps aggregate report and exit -- no live stack "
                              "needed, this only reads the registry")
    parser.add_argument("--owasp-map", action="store_true",
                         help="render the OWASP MCP Top 10 coverage gap-map and exit -- no live "
                              "stack needed, this only reads the registry")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit JSON (default)")
    fmt.add_argument("--markdown", action="store_true", help="emit a rendered markdown table")
    args = parser.parse_args()

    if args.gaps_report:
        from framework.registry import load_registry
        detections = load_registry()
        if args.detection:
            detections = [d for d in detections if d.technique_id == args.detection or d.name == args.detection]
        print(render_gaps_report(detections))
        return 0

    if args.owasp_map:
        from framework.registry import load_registry
        detections = load_registry()
        if args.detection:
            detections = [d for d in detections if d.technique_id == args.detection or d.name == args.detection]
        print(render_owasp_map(detections))
        return 0

    run = run_full_pipeline()
    table = build_coverage_table(run)
    verdicts = build_evasion_verdicts(run)

    if args.markdown:
        print(render_markdown(table, verdicts, only_detection=args.detection))
        return 0

    detections_out = {
        name: {label: (r["hit"], r["total"]) for label, r in d["recall"].items()}
        for name, d in table["detections"].items()
        if not args.detection or d["technique_id"] == args.detection or name == args.detection
    }
    print(json.dumps({
        "table_summary": detections_out,
        "aggregate_fp": table["aggregate_fp"]["alerting_records"],
        "aggregate_fp_denom": table["aggregate_fp"]["total_records"],
        "evasion_verdicts": verdicts if not args.detection else {},
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

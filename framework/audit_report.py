#!/usr/bin/env python3
"""MCP and agent security evidence-report generator.

Assembles three independently tested capabilities into one technical report:
framework/coverage.py's OWASP MCP Top 10 gap-map
(--owasp-map), framework/abom.py's AI Bill of Materials + shadow-server
diff, and a detection-coverage/adversarial-evasion summary reported as
LABELS ONLY (caught/EVADED/fired), never the underlying evasion corpus's
literal bypass payloads. The corpus is public, but generated reports still
minimize directly reusable bypass strings. Hard rule, no opt-in to
include evasion-corpus prose: framework/coverage.py's own known_gaps text
contains literal bypass strings (e.g. a URL-encoded traversal payload) and
is deliberately never quoted here.

Not a Detection, not part of the registry framework/registry.py loads --
report assembly only, the same family as coverage.py's
--gaps-report/--owasp-map and abom.py.

Two sections never need the live engine; one does, and degrades on its own:
  - OWASP gap-map: registry-only.
  - AI-BOM: reads the supplied telemetry export directly.
  - Reproduction coverage + evasion verdicts: needs a real wazuh-logtest run
    against this project's own frozen corpora (never the supplied
    telemetry). Liveness is probed with
    a cheap, non-raising check before attempting it; if the engine is
    unreachable, this section renders a stated-count-only note instead of
    crashing the whole report. framework/coverage.py's own
    verify_rule_sync() calls sys.exit(1) on failure (correct for a
    measurement CLI where "no live engine" should hard-stop the operator;
    wrong for a report generator that must still render something for a
    client without the lab up) -- this module never calls it directly for
    that reason; see _live_engine_reachable().

Usage:
  python3 framework/audit_report.py <client_telemetry.jsonl>
  python3 framework/audit_report.py <client_telemetry.jsonl> --known-good bom.json
  python3 framework/audit_report.py <client_telemetry.jsonl> --markdown
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "lab" / "analysis") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "lab" / "analysis"))

from framework.registry import load_registry, run_stateful_stage  # noqa: E402
from framework.coverage import OWASP_MCP_TITLES, OWASP_MCP_NOTES, render_owasp_map, render_gaps_report  # noqa: E402
from framework import abom as abom_mod  # noqa: E402
from framework import fixtures as fixtures_mod  # noqa: E402
from framework import structural as structural_mod  # noqa: E402
from framework import alerts as alerts_mod  # noqa: E402
from framework.rendering import markdown_text  # noqa: E402
from framework import assurance as assurance_mod  # noqa: E402
from framework import controls as controls_mod  # noqa: E402

GENERATOR_ID = "mcp-detect-audit-report/1.1"
MANAGER_SERVICE = "wazuh.manager"
MAX_TELEMETRY_BYTES = 256 * 1024 * 1024
MAX_TELEMETRY_RECORDS = 1_000_000

# Verdict strings that represent a genuine evasion attempt outcome, versus
# rug pull's E10 legit-upgrade FP probe (not an evasion attempt at all --
# lab/analysis/evasion_report.py's own comment: "reported separately and not
# counted here", same discipline followed here).
CONTROL_VERDICTS = {"fired", "did not fire"}

# SAF-T1201's own known_gap E10 (detections/SAF-T1201_rug_pull_baseline_drift/
# detection.yaml): legitimate version bumps initially produce the same drift
# signal as an unapproved change. lab/baseline/watch.py now provides an explicit,
# audited approval workflow for previously observed hashes. Its
# derived drift record already carries `drift_field` distinguishing WHICH
# value changed ("tool_description_hash" -- the tool's actual advertised
# behavior/schema -- vs "server_version_hash" -- a version label alone).
# Severity-tiering on that already-emitted field, at render time only, lets a
# routine version bump surface as a low-severity, non-headline observation
# instead of an indistinguishable rug-pull alert, without touching
# lab/baseline/watch.py or wazuh/local_rules.xml's 100201 at all (both still see,
# and 100201 still fires on, every genuine drift event -- nothing is hidden,
# only triaged). This does NOT eliminate E10: an attacker who bumps only the
# version string while a real behavior change hides elsewhere would still
# only produce a low-severity signal -- disclosed, not claimed fixed, in
# Section 6 below.
HIGH_SEVERITY_DRIFT_FIELDS = {"tool_description_hash"}


# ---------------------------------------------------------------------------
# Client-telemetry structural findings (real Wazuh engine, against the
# CLIENT's own supplied data -- distinct from try_live_measurements() above,
# which measures OUR detection content against OUR OWN frozen corpora and
# never touches client_telemetry_path). Reuses, unmodified: structural.run_batch
# (the same wazuh-logtest batch call coverage.py already uses),
# registry.run_stateful_stage (the same TOFU baseline wrapper coverage.py
# already uses for the evasion corpus), and alerts.normalize_and_join/
# build_alerts (the same join coverage.py's own pipeline uses). No new
# detection logic; this is the existing, already-tested rule-matching path,
# just pointed at the client's file instead of our own fixtures.
# ---------------------------------------------------------------------------

def _finding_row(jr, rid_map: dict) -> dict:
    d = rid_map[jr.matched_rule_id]
    # Never carry the full matched record into a report. In particular, an
    # exfiltration match's tool_arguments can contain the exact secret the rule
    # detected. Preserve only fields needed to group/reproduce the indicator.
    evidence = {
        "server_command": jr.raw.get("server_command"),
        "tool_name": jr.raw.get("tool_name"),
        "drift_field": jr.raw.get("drift_field"),
    }
    args = jr.raw.get("tool_arguments") or {}
    if d.technique_id in {"SAF-T1104", "SAF-T1105", "SAF-T1502"} and "path" in args:
        evidence["path"] = args.get("path")
    return {
        "technique_id": d.technique_id,
        "rule_id": jr.matched_rule_id,
        "verification_status": "automated_indicator",
        "session_id": jr.primary_session_id,
        "timestamp": jr.raw.get("timestamp", ""),
        "matched_content": evidence,
    }


def build_client_findings(lines: list[str], detections: list) -> dict:
    rid_map = alerts_mod.rule_id_to_detection(detections)

    matched = structural_mod.run_batch(lines)
    joined = alerts_mod.normalize_and_join(lines, matched, detections)
    structural_findings = [
        _finding_row(jr, rid_map) for jr in joined
        if jr.matched_rule_id in rid_map and rid_map[jr.matched_rule_id].technique_id != "SAF-T1201"
    ]

    rugpull_high: list = []
    rugpull_info: list = []
    rugpull = next((d for d in detections if d.technique_id == "SAF-T1201"), None)
    if rugpull is not None:
        derived = run_stateful_stage(rugpull, lines)
        if derived:
            drift_matched = structural_mod.run_batch(derived)
            drift_joined = alerts_mod.normalize_and_join(derived, drift_matched, detections)
            for jr in drift_joined:
                if jr.matched_rule_id not in rid_map:
                    continue
                row = _finding_row(jr, rid_map)
                bucket = rugpull_high if jr.raw.get("drift_field") in HIGH_SEVERITY_DRIFT_FIELDS else rugpull_info
                bucket.append(row)

    return {
        "structural_findings": structural_findings,
        "rugpull_high": rugpull_high,
        "rugpull_info": rugpull_info,
    }


def try_client_findings(lines: list[str], detections: list) -> tuple[dict | None, str, str | None]:
    """Return findings plus an explicit completed/not_run/failed status."""
    if not _live_engine_reachable():
        return None, "not_run", None
    try:
        return build_client_findings(lines, detections), "completed", None
    except Exception as exc:
        # Exception messages may contain telemetry. The class preserves useful
        # diagnostic direction without copying untrusted/customer content.
        return None, "failed", type(exc).__name__


# ---------------------------------------------------------------------------
# Live-engine detection and measurement against project fixtures only
# ---------------------------------------------------------------------------

def _live_engine_reachable(timeout: int = 15) -> bool:
    try:
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", MANAGER_SERVICE, "true"],
            cwd=REPO_ROOT, capture_output=True, timeout=timeout,
        )
        return proc.returncode == 0
    except Exception:
        return False


def try_live_measurements() -> tuple[dict | None, str, str | None]:
    """Attempts the full live pipeline: coverage.py's tested
    build_coverage_table() (own-fixture reproduction counts) and
    build_evasion_verdicts() -- registry-driven for every technique with an
    authored evasion corpus, including SAF-T1105 (framework/coverage.py's
    own fix, not a local workaround here anymore). Returns an explicit status
    so processing failures are never mislabeled as engine unreachability."""
    if not _live_engine_reachable():
        return None, "not_run", None
    try:
        from framework.coverage import run_full_pipeline, build_coverage_table, build_evasion_verdicts

        run = run_full_pipeline()
        table = build_coverage_table(run)
        verdicts = build_evasion_verdicts(run)

        return {"table": table, "verdicts": verdicts}, "completed", None
    except Exception as exc:
        return None, "failed", type(exc).__name__


# ---------------------------------------------------------------------------
# Per-detection summary (shared by markdown + json rendering)
# ---------------------------------------------------------------------------

def _reproduction_summary(technique_id: str, live: dict | None) -> str | None:
    if live is None:
        return None
    entry = next((d for d in live["table"]["detections"].values()
                  if d["technique_id"] == technique_id), None)
    if entry is None:
        return None
    parts = [f"{label} {r['hit']}/{r['total']}" for label, r in entry["recall"].items()]
    return "; ".join(parts)


def _evasion_summary(detection, live: dict | None) -> dict:
    ref = detection.fixtures.get("evasion_corpus", "none")
    if not fixtures_mod.has_evasion_corpus(ref):
        return {"tested": 0, "caught": 0, "evaded": 0, "control": [], "unknown": 0}
    task_ids = fixtures_mod.parse_evasion_task_ids(ref)
    verdicts = live["verdicts"] if live else {}
    caught = evaded = 0
    control: list[tuple[str, str]] = []
    for tid in task_ids:
        v = verdicts.get(tid)
        if v == "caught":
            caught += 1
        elif v == "EVADED":
            evaded += 1
        elif v in CONTROL_VERDICTS:
            control.append((tid, v))
    tested = len(task_ids)
    unknown = tested - caught - evaded - len(control)
    return {"tested": tested, "caught": caught, "evaded": evaded, "control": control, "unknown": unknown}


def _detection_row(detection, live: dict | None) -> dict:
    return {
        "technique_id": detection.technique_id,
        "name": detection.name,
        "status": detection.status,
        "owasp_mcp": detection.owasp_mcp,
        "known_gaps_count": len(detection.known_gaps),
        "reproduction": _reproduction_summary(detection.technique_id, live),
        "evasion": _evasion_summary(detection, live),
    }


def _owasp_by_category(detections: list) -> dict:
    by_cat: dict[str, list] = {code: [] for code in OWASP_MCP_TITLES}
    for d in detections:
        for code in d.owasp_mcp:
            by_cat[code].append(d)
    return by_cat


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_report(client_telemetry_path: Path, known_good_path: Path | None,
                 control_evidence_path: Path | None = None) -> dict:
    detections = load_registry()
    size = client_telemetry_path.stat().st_size
    if size > MAX_TELEMETRY_BYTES:
        raise ValueError(
            f"telemetry input is {size} bytes; limit is {MAX_TELEMETRY_BYTES} bytes -- "
            "split or sample the capture before report generation"
        )
    raw_bytes = client_telemetry_path.read_bytes()
    lines = [l for l in raw_bytes.decode("utf-8").splitlines() if l.strip()]
    if len(lines) > MAX_TELEMETRY_RECORDS:
        raise ValueError(
            f"telemetry input has {len(lines)} records; limit is {MAX_TELEMETRY_RECORDS}"
        )

    bom = abom_mod.build_bom(lines)
    shadow_candidates = abom_mod.diff_shadow_servers(bom, known_good_path) if known_good_path else None

    live, live_measurement_status, live_measurement_error = try_live_measurements()
    rows = [_detection_row(d, live) for d in detections]
    client_findings, client_scan_status, client_scan_error = try_client_findings(lines, detections)
    assurance_indicators = assurance_mod.analyze_lines(lines)
    manual_evidence = controls_mod.load_evidence(control_evidence_path)
    control_assurance = controls_mod.build_control_assurance(
        assurance_indicators, manual_evidence
    )

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "generator": GENERATOR_ID,
        "client_telemetry_path": str(client_telemetry_path),
        "client_telemetry_sha256": sha256_bytes(raw_bytes),
        "client_record_count": len(lines),
        "detections": detections,
        "rows": rows,
        "bom": bom,
        "shadow_candidates": shadow_candidates,
        "live_engine_reachable": live_measurement_status != "not_run",
        "live_measurement_status": live_measurement_status,
        "live_measurement_error": live_measurement_error,
        "owasp_by_category": _owasp_by_category(detections),
        "client_findings": client_findings,
        "client_findings_reachable": client_scan_status == "completed",
        "client_scan_status": client_scan_status,
        "client_scan_error": client_scan_error,
        "assurance_indicators": assurance_indicators,
        "control_assurance": control_assurance,
        "control_evidence_path": str(control_evidence_path) if control_evidence_path else None,
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _import_section(md: str, heading: str, disclaimer: str | None = None) -> str:
    """Re-nests an existing top-level (`# ...`) markdown report as one
    subsection of this composed document: drops the original H1 (replaced by
    `heading`, which this module controls the exact wording of), and demotes
    every remaining heading by one level so internal structure (e.g.
    abom.py's per-server `## ...` blocks) nests correctly underneath it."""
    lines = md.rstrip("\n").splitlines()
    body_lines = lines[1:]
    while body_lines and not body_lines[0].strip():
        body_lines = body_lines[1:]  # drop the blank line left by the imported doc's own "# Title\n" element
    body = ["#" + line if line.startswith("#") else line for line in body_lines]
    parts = [heading]
    if disclaimer:
        parts.append("")
        parts.append(disclaimer)
    parts.append("")
    parts.extend(body)
    return "\n".join(parts)


def _evasion_cell(ev: dict) -> str:
    if ev["tested"] == 0:
        return "no evasion corpus authored"
    bits = [f"{ev['caught']} caught / {ev['evaded']} evaded"]
    if ev["control"]:
        bits.append(f"{len(ev['control'])} control probe(s)")
    if ev["unknown"]:
        bits.append(f"{ev['unknown']} unmeasured (engine unreachable)")
    return f"{ev['tested']} tested -- " + ", ".join(bits)


def _finding_evidence(row: dict) -> str:
    """A short, client-safe evidence string per finding -- never the raw
    secret-shaped argument VALUE for a credential-exfil hit (the whole point
    of the finding is that a secret was present; echoing it back into the
    report would be a second exposure of the same secret, not a mitigation
    of the first). Path-traversal evidence is safe to show verbatim -- the
    path itself is the finding, not a credential."""
    mc = row["matched_content"]
    tool = mc.get("tool_name")
    technique_id = row["technique_id"]
    if technique_id == "SAF-T1105":
        return f"tool={markdown_text(tool)} path={markdown_text(mc.get('path'))}"
    if technique_id == "SAF-T1104":
        return f"tool={markdown_text(tool)} sensitive absolute path={markdown_text(mc.get('path'))}"
    if technique_id == "SAF-T1502":
        if "path" in mc:
            return f"tool={markdown_text(tool)} sensitive-suffix path={markdown_text(mc.get('path'))}"
        return f"tool={markdown_text(tool)} secret-shaped argument (key and value withheld)"
    if technique_id == "SAF-T1001":
        return f"tools/list response for {markdown_text(mc.get('server_command'))}"
    if technique_id == "SAF-T1201":
        return (f"tool={markdown_text(tool)} server={markdown_text(mc.get('server_command'))} "
                f"drift_field={markdown_text(mc.get('drift_field'))}")
    return f"tool={markdown_text(tool)}" if tool else "--"


def _group_key(row: dict) -> tuple:
    mc = row["matched_content"]
    return (row["technique_id"], row["rule_id"], mc.get("server_command"), mc.get("tool_name"))


def _group_findings(rows: list[dict]) -> list[dict]:
    """Collapses repeated hits of the SAME underlying issue (identical
    technique+rule+server+tool -- e.g. a poisoned tool description appearing
    in every session that lists that server's tools) into one row with an
    occurrence count and a first/last-seen span. This is a rendering
    grouping only -- every underlying record is still counted (`count`), none
    are dropped or hidden, and a distinct server/tool combination never
    collapses into another's row."""
    groups: dict[tuple, dict] = {}
    for row in rows:
        key = _group_key(row)
        g = groups.get(key)
        if g is None:
            groups[key] = {**row, "count": 1, "first_seen": row["timestamp"], "last_seen": row["timestamp"]}
        else:
            g["count"] += 1
            g["first_seen"] = min(g["first_seen"], row["timestamp"])
            g["last_seen"] = max(g["last_seen"], row["timestamp"])
    return sorted(groups.values(), key=lambda g: g["first_seen"])


def _render_findings_section(report: dict) -> list[str]:
    out = ["## 3. Control assurance and telemetry findings\n"]
    out.append("A control is marked **verified** only when source/configuration evidence or an "
               "authorized negative test was supplied. No telemetry alerts does not produce a "
               "passing control. Automated indicators are leads for analyst verification.\n")
    out.append("| Preventive control | Status | Automated indicators | Passing condition |")
    out.append("|---|---|---:|---|")
    for row in report.get("control_assurance", controls_mod.build_control_assurance([])):
        out.append(
            f"| {markdown_text(row['control_id'].replace('_', ' '))} | "
            f"**{markdown_text(row['status']).upper()}** | {row['indicator_count']} | "
            f"{markdown_text(row['passing_condition'])} |"
        )
    out.append("")

    normalized = report.get("assurance_indicators", [])
    out.append("### 3a. Normalized and correlated indicators\n")
    if normalized:
        out.append("These indicators come from recursive argument inspection, bounded transport "
                   "decoding, Unicode normalization, and same-session secret-flow correlation. "
                   "Secret values are never copied into this report.\n")
        out.append("| Indicator | Control | Severity | Tool | Verification |")
        out.append("|---|---|---|---|---|")
        for finding in normalized:
            tool = (finding["evidence"].get("tool_name") or
                    finding["evidence"].get("sink_tool") or "--")
            out.append(
                f"| `{markdown_text(finding['indicator_id'])}` | "
                f"{markdown_text(finding['control_id'].replace('_', ' '))} | "
                f"{markdown_text(finding['severity'])} | {markdown_text(tool)} | analyst required |"
            )
    else:
        out.append("No normalized or correlated indicator matched the supplied telemetry. This "
                   "does not verify any preventive control.\n")
    out.append("")
    out.append("### 3b. Structural Wazuh indicators\n")
    cf = report["client_findings"]
    if report["client_scan_status"] != "completed":
        if report["client_scan_status"] == "failed":
            detail = f" Processing failed ({markdown_text(report['client_scan_error'])})."
        else:
            detail = " The detection engine was unreachable."
        out.append(f"**Client scan status: {report['client_scan_status'].upper()}.**{detail} "
                    "No completed client-telemetry scan result is available. "
                    "Section 2's AI-BOM, the control table, and normalized analysis above do "
                    "not require the live engine and are unaffected.\n")
        return out

    structural_findings = cf["structural_findings"]
    rugpull_high = cf["rugpull_high"]
    rugpull_info = cf["rugpull_info"]
    headline_raw = structural_findings + rugpull_high
    headline_groups = _group_findings(headline_raw)

    out.append("Every row below is a real match from the actual detection engine "
                "(`wazuh-logtest`) run directly against **your supplied telemetry** -- "
                "not a statement about our own fixtures (that is Section 5). Structural "
                "rule-matching and the rug-pull baseline-drift detector both reuse the "
                "exact, already-tested code paths `framework/coverage.py` uses for our own "
                "corpora (`framework/structural.run_batch`, `framework/registry."
                "run_stateful_stage`, `framework/alerts.normalize_and_join`) -- no new "
                "detection logic. Repeated hits of the same underlying issue (e.g. a poisoned "
                "tool description observed across many sessions) are grouped into one row with "
                "an occurrence count -- nothing is dropped, only de-duplicated for readability.\n")
    out.append("**Classification: automated indicator, not a manually verified or confirmed "
               "vulnerability.** An analyst must validate reachability, exploit preconditions, "
               "business impact, and false-positive context before copying any row into a final "
               "security finding. This generator does not emit `manually_verified` status.\n")
    out.append(f"**{len(headline_groups)} distinct automated indicator(s)** ({len(headline_raw)} alerting "
               f"record(s) total) across {len(report['detections'])} registered techniques" +
               (f", plus {len(rugpull_info)} low-severity baseline-drift observation(s) "
                f"(see note below)." if rugpull_info else "."))
    out.append("")

    if headline_groups:
        out.append("| Automated indicator | Rule | Server / tool | Occurrences | First seen | Last seen | Evidence |")
        out.append("|---|---|---|---|---|---|---|")
        for g in headline_groups:
            server_tool = markdown_text(g['matched_content'].get('server_command')) + \
                (f" / {markdown_text(g['matched_content'].get('tool_name'))}" if g['matched_content'].get('tool_name') else "")
            out.append(f"| {g['technique_id']} | `{g['rule_id']}` | {server_tool} | {g['count']} | "
                        f"{markdown_text(g['first_seen'])} | {markdown_text(g['last_seen'])} | {_finding_evidence(g)} |")
        out.append("")
    else:
        out.append("_No structural or rug-pull-baseline findings in this export._\n")

    if rugpull_info:
        info_groups = _group_findings(rugpull_info)
        out.append("**Baseline drift, version-only (reduced severity, not counted in the "
                    "finding total above):**\n")
        out.append("| Server | Occurrences | First seen | Last seen | Evidence |")
        out.append("|---|---|---|---|---|")
        for g in info_groups:
            out.append(f"| {markdown_text(g['matched_content'].get('server_command'))} | {g['count']} | "
                       f"{markdown_text(g['first_seen'])} | {markdown_text(g['last_seen'])} | {_finding_evidence(g)} |")
        out.append("- These are real, TOFU-baseline-confirmed drift events (rule `100201` fired) "
                    "where only `server_version_hash` changed and the tool's advertised "
                    "description/schema (`tool_description_hash`) did not -- consistent with a "
                    "routine version bump, not necessarily distinguishable from one. See Section "
                    "6's note on SAF-T1201 known gap E10 for the residual bound on this.")
        out.append("")

    return out


def render_markdown(report: dict) -> str:
    detections = report["detections"]
    rows = report["rows"]
    bom = report["bom"]
    live_ok = report["live_measurement_status"] == "completed"

    total_tested = sum(r["evasion"]["tested"] - len(r["evasion"]["control"]) for r in rows)
    total_caught = sum(r["evasion"]["caught"] for r in rows)
    total_evaded = sum(r["evasion"]["evaded"] for r in rows)
    n_mapped = sum(1 for code in OWASP_MCP_TITLES if report["owasp_by_category"][code])

    out = ["# MCP & Agent Security Assessment\n"]

    # 1. Provenance
    out.append(f"**Generated**: {report['generated_at']} (`{report['generator']}`)  ")
    out.append(f"**Client telemetry**: {markdown_text(report['client_telemetry_path'])} "
                f"(sha256 `{report['client_telemetry_sha256'][:16]}...`, "
                f"{report['client_record_count']} records)  ")
    out.append(f"**Client scan status**: `{report['client_scan_status']}`" +
               (f" (diagnostic: `{markdown_text(report['client_scan_error'])}`)" if report["client_scan_error"] else "") +
               "  ")
    out.append(f"**Live-engine measurement this run**: `{report['live_measurement_status']}`" +
               (f" (diagnostic: `{markdown_text(report['live_measurement_error'])}`)" if report["live_measurement_error"] else "") +
               (" -- reproduction/evasion numbers below are freshly re-verified\n" if live_ok
                else " -- no fresh measurement result; see Section 6\n"))

    # 2. Executive summary
    cf = report["client_findings"]
    n_findings = (len(_group_findings(cf["structural_findings"] + cf["rugpull_high"]))) if cf else None
    out.append("## 1. Executive summary\n")
    out.append(f"- **{bom['server_count']} MCP servers, {bom['tool_count']} distinct tool entries, "
                f"{bom['session_count']} sessions** observed in the client telemetry export.")
    if report["shadow_candidates"] is not None:
        n_shadow = len(report["shadow_candidates"])
        out.append(f"- **{n_shadow} shadow-server candidate(s)** "
                    f"({'none' if n_shadow == 0 else ', '.join(markdown_text(c) for c in report['shadow_candidates'])}) "
                    f"against the supplied known-good BOM.")
    else:
        out.append("- Shadow-server diffing not run (no `--known-good` BOM supplied).")
    if report["client_scan_status"] == "completed":
        out.append(f"- **{n_findings} finding(s) from a real scan of your telemetry** "
                    f"(Section 3) -- structural rule-matching and rug-pull baseline-drift "
                    f"detection run directly against your supplied data, not just our own fixtures.")
    else:
        out.append(f"- Client-telemetry scan **{report['client_scan_status']}**; no completed "
                   "detection result is available -- see Section 3.")
    out.append(f"- **{n_mapped}/10 OWASP MCP Top 10 categories** have at least one mapped detection "
                f"in this project's detection-content pack (Section 4) -- a statement about our "
                f"content, not a scan finding about this client's environment.")
    if live_ok:
        out.append(f"- **Adversarial evasion testing** (this run, live-verified): "
                    f"{total_tested} genuine evasion attempts across all techniques, "
                    f"**{total_caught} caught / {total_evaded} evaded**. Every shipped detection "
                    f"has been red-teamed against its own evasion corpus; this report states what "
                    f"evades, not just what's caught -- see Section 5.")
    else:
        out.append(f"- Adversarial evasion testing: live re-verification "
                   f"{report['live_measurement_status']} -- per-technique known-gap counts "
                   "still shown in Section 5.")
    out.append("")

    # 3. AI-BOM (client environment)
    bom_md = abom_mod.render_markdown(bom, report["shadow_candidates"])
    out.append(_import_section(
        bom_md,
        "## 2. AI Bill of Materials (your environment)",
        "Built directly from the supplied client telemetry export -- this section is a "
        "statement about *your* environment. **This inventory is advertised-surface-"
        "complete**: every tool a server's `tools/list` response advertises appears "
        "below, distinguishing advertised-and-called (with a call count) from "
        "advertised-but-never-invoked (call count 0) -- not merely the tools observed "
        "being called. See Section 6 for the one residual bound on this (a server "
        "whose `tools/list` response was never captured at all contributes nothing).",
    ))
    out.append("")

    # 3a. Findings in your environment (real scan of the client's own data)
    out.extend(_render_findings_section(report))
    out.append("")

    # 4. OWASP gap-map (our detection-content coverage, explicitly not a client finding)
    owasp_md = render_owasp_map(detections)
    out.append(_import_section(
        owasp_md,
        "## 4. OWASP MCP Top 10 -- Detection-Content Coverage (this framework, not a finding about your environment)",
        "**This table describes what our detection-content pack currently covers against the "
        "OWASP MCP Top 10 taxonomy. It is a statement about our rules, not a scan result about "
        "your environment.** Cross-reference against Section 2's AI-BOM and Section 3's findings "
        "to see which of your servers/tools these detections actually apply to.",
    ))
    out.append("")

    # 5. Detection coverage & adversarial evasion testing (the differentiator)
    out.append("## 5. Detection coverage & adversarial evasion testing\n")
    out.append("**Numbers below are reported as reproduction coverage and evasion-tested "
                "outcomes, never as \"precision/recall.\"** Reproduction counts are measured "
                "against this project's own self-authored attack variants, not independent or "
                "held-out ones -- see the caveat in Section 6. Evasion results are labels only "
                "(caught / EVADED / control probe) computed by re-running the real detection "
                "engine against our own frozen, public adversarial-evasion corpus -- the "
                "corpus itself, and any literal bypass payload strings, are never included in "
                "this report.\n")
    out.append("| Technique | OWASP | Status | Known gaps declared | Reproduction coverage (self-authored) | Evasion testing |")
    out.append("|---|---|---|---|---|---|")
    for r in rows:
        owasp_cell = ", ".join(r["owasp_mcp"]) if r["owasp_mcp"] else "--"
        repro_cell = r["reproduction"] if r["reproduction"] else \
            ("not re-verified this run" if not live_ok else "n/a")
        out.append(f"| {r['technique_id']} (`{r['name']}`) | {owasp_cell} | `{r['status']}` | "
                    f"{r['known_gaps_count']} | {repro_cell} | {_evasion_cell(r['evasion'])} |")
    out.append("")

    # 6. Named limitations
    out.append("## 6. Limitations of this assessment\n")
    out.append("- **The AI-BOM (Section 2) is advertised-surface-complete, not called-only**: "
                "`framework/abom.py`'s `build_bom()` ingests each session's `tools/list` "
                "response (`raw.result.tools`) alongside `tools/call` records, so a tool a "
                "server advertises but never has invoked during the capture window still "
                "appears, with a call count of 0 -- previously a real, disclosed gap, now fixed "
                "(`docs/STATE-OF-PROJECT.md`). **One residual bound remains, structurally, not "
                "by choice**: a tool is only listed if some session in the supplied export "
                "actually captured its server's `tools/list` response -- a server never queried "
                "for its tool list during the capture window contributes nothing to this "
                "section, the same bound any inventory built from observed traffic has.")
    out.append("- **Section 3's findings are a real scan of your own telemetry, but only for the "
                f"{len(detections)} registered techniques in Section 5's table** -- this is not a "
                "general-purpose anomaly detector; anything outside those techniques' scope "
                "produces no finding, flagged or not, by construction.")
    out.append("- **SAF-T1201 (rug pull) known gap E10, partially triaged, not eliminated**: a "
                "routine server-version bump and a genuine rug pull both start as baseline "
                "drift. The watcher now supports explicit approval of a previously observed hash, "
                "records reviewer/reason/history, and never auto-approves a change. Section 3 "
                "severity-tiers the initial signal "
                "using the already-emitted `drift_field` (a tool's advertised description/schema "
                "changing is reported as a finding; a version-string-only change is reported "
                "separately at reduced severity) -- this reduces false alarms on ordinary version "
                "bumps but does NOT eliminate the underlying gap: an attacker who changes only the "
                "version string while hiding a real behavior change elsewhere would still surface "
                "only as a low-severity observation, not a headline finding.")
    out.append("- **Reproduction coverage is measured against self-authored attack variants** "
                "(this project's own harnesses), not independent or third-party-authored attack "
                "traffic. It demonstrates that a technique's telemetry shape is reliably detected "
                "across wording/argument variation, not that detection generalizes to arbitrary "
                "independently-authored or adversarial phrasing -- evasion testing (Section 5) is "
                "the honest complement to this, not a replacement for it.")
    out.append("- **The benign false-positive baseline is a single-model, single-lab corpus** "
                "(qwen3:1.7b, 6 MCP servers, 20 distinct tools, 4,727 records) -- a 0% measured FP "
                "rate on that corpus does not automatically transfer to a heterogeneous client "
                "fleet with different servers, tools, or usage patterns.")
    out.append("- **Structural (Wazuh rule) is the only mature detection backend.** One technique "
                "(rug pull) uses an external stateful detector; a semantic backend for prompt-"
                "injection/intent-flow subversion (OWASP MCP06) is designed but not implemented, "
                "so MCP06 coverage above is narrower than the category name implies.")
    out.append(f"- **{n_mapped}/10 OWASP MCP Top 10 categories are mapped at all**, and every "
                "mapped category is reported as PARTIAL by policy -- no category is claimed at "
                "held-out/production confidence.")
    out.append("- **The labeled adversarial-evasion corpus is synthetic and public.** Section 5 "
                "shows aggregate outcome labels; inspect `data/evasion_corpus_v1.jsonl` and the "
                "registered known gaps for the underlying fixtures and limitations.")
    out.append("")
    out.append(_import_section(
        render_gaps_report(detections),
        "### 6a. Declared known gaps (detail)",
        "Every bullet below is this project's own registered `known_gaps` prose (per "
        "technique, from each `detection.yaml`) -- the specific, named blind spots behind "
        "the counts in Section 5's table, reused verbatim from "
        "`framework/coverage.py`'s `render_gaps_report()`.",
    ))
    out.append("")

    # 7. Methodology appendix
    out.append("## 7. Methodology\n")
    out.append("This report reuses, without modification: `framework/coverage.py`'s "
                "`render_owasp_map()`, `build_coverage_table()`, `build_evasion_verdicts()`, and "
                "`render_gaps_report()`; `framework/abom.py`'s `build_bom()` and "
                "`diff_shadow_servers()`; `framework/registry.py`'s `load_registry()` and "
                "`run_stateful_stage()`; `framework/structural.py`'s `run_batch()`; "
                "`framework/alerts.py`'s `normalize_and_join()`. All rule-matching goes through "
                "the real Wazuh engine (`wazuh-logtest`), never a Python reimplementation. "
                "Section 3 is the one section that runs this same engine against **your** "
                "telemetry directly (everything else in Sections 4-5 measures our own fixtures).")
    out.append("")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------

def render_json(report: dict) -> dict:
    return {
        "generator": report["generator"],
        "generated_at": report["generated_at"],
        "client_telemetry": {
            "path": report["client_telemetry_path"],
            "sha256": report["client_telemetry_sha256"],
            "record_count": report["client_record_count"],
        },
        "live_engine_reachable": report["live_engine_reachable"],
        "live_measurement_status": report["live_measurement_status"],
        "live_measurement_error": report["live_measurement_error"],
        "client_scan_status": report["client_scan_status"],
        "client_scan_error": report["client_scan_error"],
        "bom": report["bom"],
        "shadow_candidates": report["shadow_candidates"],
        "client_findings_reachable": report["client_findings_reachable"],
        "client_findings": report["client_findings"],
        "assurance_indicators": report["assurance_indicators"],
        "control_assurance": report["control_assurance"],
        "control_evidence_path": report["control_evidence_path"],
        "owasp_coverage": {
            code: {
                "title": OWASP_MCP_TITLES[code],
                "mapped": bool(ds),
                "detections": [d.technique_id for d in ds],
                "note": OWASP_MCP_NOTES.get(code) if not ds else None,
            }
            for code, ds in report["owasp_by_category"].items()
        },
        "detections": report["rows"],
        "markdown_report": render_markdown(report),
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("telemetry", help="client-provided telemetry JSONL export (schema v1)")
    parser.add_argument("--known-good", help="known-good BOM JSON for shadow-server (MCP09) diffing")
    parser.add_argument("--control-evidence", help="versioned JSON file containing manual control-test results")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit JSON (default)")
    fmt.add_argument("--markdown", action="store_true", help="emit the rendered client report")
    args = parser.parse_args()

    report = build_report(
        Path(args.telemetry),
        Path(args.known_good) if args.known_good else None,
        Path(args.control_evidence) if args.control_evidence else None,
    )

    if args.markdown:
        print(render_markdown(report))
    else:
        print(json.dumps(render_json(report), indent=2))
    return 0 if report["client_scan_status"] == "completed" else 2


if __name__ == "__main__":
    sys.exit(main())

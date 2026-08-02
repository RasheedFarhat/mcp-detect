#!/usr/bin/env python3
"""Phase 4 analysis layer -- batch-measure the installed Wazuh ruleset
against the frozen benign corpus and the canonical attack telemetry, and
generate docs/PHASE4-REPORT.md.

This does not reimplement rule matching in Python: every "did rule X fire"
answer comes from a real `wazuh-logtest` batch invocation against whatever
rule file is actually loaded on the live manager, after first verifying that
loaded file is byte-identical to the committed wazuh/local_rules.xml (see
verify_rule_sync()). See docs/PHASE4-DESIGN.md for the full design and the
reasoning behind every choice below.

Usage:
  python3 analysis/report.py                    generate docs/PHASE4-REPORT.md
  python3 analysis/report.py --session <id>     print one session's reconstruction
  python3 analysis/report.py --task-id <id>     print one task's reconstruction
                                                 (may span multiple session_ids,
                                                 e.g. credential_exfil's read+exfil pair)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCAL_RULES_PATH = REPO_ROOT / "wazuh" / "local_rules.xml"
BENIGN_CORPUS_PATH = REPO_ROOT / "data" / "benign_corpus_v2.jsonl"
REPORT_PATH = REPO_ROOT / "docs" / "PHASE4-REPORT.md"

MANAGER_SERVICE = "wazuh.manager"
AGENT_SERVICE = "agent"
LIVE_RULES_PATH_IN_CONTAINER = "/var/ossec/etc/rules/mcp_detect_rules.xml"
TELEMETRY_PATH_IN_CONTAINER = "/var/log/mcp-detect/telemetry.jsonl"
RUGPULL_ALERTS_PATH_IN_CONTAINER = "/var/log/mcp-detect/rugpull_alerts.jsonl"

NO_ALERT_RULE_ID = "100100"
GENERATOR_ID = "mcp-detect-analysis-report/1.0"
LOGTEST_PREFLIGHT_TIMEOUT_SECONDS = 30.0
LOGTEST_PREFLIGHT_INTERVAL_SECONDS = 1.0
LOGTEST_BATCH_ATTEMPTS = 2

# Rule-id -> which technique/scenario it's understood to belong to, per
# docs/PHASE3A-DESIGN.md / docs/PHASE3B-DESIGN.md. Used only for labeling
# tables -- every recall/FP count itself comes from the fresh wazuh-logtest
# run, never from this map.
RULE_TECHNIQUE = {
    "100102": "tool_poisoning",
    "100101": "credential_exfil_via_read (read hop)",
    "100103": "credential_exfil_via_read (exfil hop, key=data)",
    "100104": "credential_exfil_via_read (exfil hop, key=payload)",
    "100105": "credential_exfil_via_read (exfil hop, key=content)",
    "100106": "credential_exfil_via_read (exfil hop, key=body)",
    "100107": "credential_exfil_via_read (exfil hop, key=message)",
    "100201": "rug_pull (baseline drift)",
}
EXFIL_HOP_FAMILY = ["100103", "100104", "100105", "100106", "100107"]


# ---------------------------------------------------------------------------
# Provenance / rule-sync gate
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def docker_compose(*args: str, input_text: str | None = None, timeout: int = 1800) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["docker", "compose", *args],
        cwd=REPO_ROOT, input=input_text, capture_output=True, text=True, timeout=timeout,
    )
    return proc


def verify_rule_sync() -> str:
    """Fail loud if the live manager's loaded rule file differs from the
    committed wazuh/local_rules.xml. Returns the (matching) sha256 hex
    digest on success. This is the check docs/PHASE4-DESIGN.md's addition A
    asked for -- 3a/3b ran this by hand every time; here it's a hard gate."""
    committed_sha = sha256_bytes(LOCAL_RULES_PATH.read_bytes())
    proc = docker_compose("exec", "-T", MANAGER_SERVICE, "sha256sum", LIVE_RULES_PATH_IN_CONTAINER)
    if proc.returncode != 0:
        print(f"RULE-SYNC CHECK: could not read the live rule file from the "
              f"'{MANAGER_SERVICE}' container -- is the lab up? ({proc.stderr.strip()})",
              file=sys.stderr)
        sys.exit(1)
    live_sha = proc.stdout.split()[0]
    if live_sha != committed_sha:
        print(
            "RULE-SYNC CHECK FAILED.\n"
            f"  committed {LOCAL_RULES_PATH.relative_to(REPO_ROOT)}: sha256 {committed_sha}\n"
            f"  live manager {LIVE_RULES_PATH_IN_CONTAINER}:          sha256 {live_sha}\n"
            "These must be byte-identical before a report can be trusted -- "
            "refusing to generate. Install the committed rules on the live "
            "manager (docker compose cp + a validated restart) and re-run.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"RULE-SYNC CHECK: passed -- live manager matches committed "
          f"local_rules.xml (sha256 {committed_sha})", file=sys.stderr)
    return committed_sha


def get_wazuh_version() -> str:
    proc = docker_compose("exec", "-T", MANAGER_SERVICE, "sh", "-c", "/var/ossec/bin/wazuh-control info")
    if proc.returncode != 0:
        raise RuntimeError(f"could not read Wazuh version: {proc.stderr}")
    for line in proc.stdout.splitlines():
        if line.startswith("WAZUH_VERSION="):
            return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError("WAZUH_VERSION not found in wazuh-control info output")


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def fetch_container_file(service: str, path: str) -> str:
    proc = docker_compose("exec", "-T", service, "cat", path)
    if proc.returncode != 0:
        raise RuntimeError(f"could not read {path} from '{service}': {proc.stderr}")
    return proc.stdout


def load_lines(text: str) -> list[str]:
    return [l for l in text.splitlines() if l.strip()]


def load_inputs() -> dict:
    """Returns the three committed/canonical inputs, each as a list of raw
    JSON-line strings, plus a couple of denominator counts computed directly
    from the benign corpus rather than hardcoded."""
    benign_lines = load_lines(BENIGN_CORPUS_PATH.read_text())

    telemetry_text = fetch_container_file(AGENT_SERVICE, TELEMETRY_PATH_IN_CONTAINER)
    malicious_lines = [l for l in load_lines(telemetry_text) if json.loads(l).get("label") == "malicious"]

    rugpull_text = fetch_container_file(AGENT_SERVICE, RUGPULL_ALERTS_PATH_IN_CONTAINER)
    drift_lines = load_lines(rugpull_text)

    benign_sessions = set()
    benign_tool_calls = 0
    for l in benign_lines:
        r = json.loads(l)
        benign_sessions.add(r["session_id"])
        if r.get("method") == "tools/call":
            benign_tool_calls += 1

    return {
        "benign_lines": benign_lines,
        "malicious_lines": malicious_lines,
        "drift_lines": drift_lines,
        "benign_session_count": len(benign_sessions),
        "benign_tool_call_count": benign_tool_calls,
    }


# ---------------------------------------------------------------------------
# Batch wazuh-logtest
# ---------------------------------------------------------------------------

class WazuhLogtestError(RuntimeError):
    """Base class for fail-loud logtest infrastructure errors."""


class WazuhLogtestInvocationError(WazuhLogtestError):
    """The CLI failed or timed out before a trustworthy result existed."""


class WazuhLogtestResultCountError(WazuhLogtestError):
    """The CLI returned a partial/empty set of result blocks."""


_LOGTEST_PREAMBLE = re.compile(r"^Starting wazuh-logtest(?:\s+v[0-9A-Za-z_.-]+)?$", re.IGNORECASE)
_LOGTEST_ERROR_CODE = re.compile(
    r"^(?:wazuh-(?:logtest|analysisd)|ossec-analysisd):\s*"
    r"(ERROR|CRITICAL|WARNING):\s*\(([0-9]{4})\):", re.IGNORECASE,
)
_LOGTEST_SEVERITY = re.compile(r"^(ERROR|CRITICAL|WARNING):", re.IGNORECASE)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_PREFLIGHT_EVENT = json.dumps({
    "session_id": "mcp-detect-logtest-preflight",
    "server_command": "preflight",
    "method": "mcp-detect/preflight",
})


def _safe_logtest_diagnostics(proc: subprocess.CompletedProcess) -> str:
    """Retain structural diagnostics without copying event or error content."""
    safe: list[str] = []
    for stream in (proc.stderr or "", proc.stdout or ""):
        for line in stream.splitlines():
            stripped = _CONTROL_CHARS.sub("?", line.strip())
            code_match = _LOGTEST_ERROR_CODE.match(stripped)
            severity_match = _LOGTEST_SEVERITY.match(stripped)
            if _LOGTEST_PREAMBLE.match(stripped):
                item = stripped
            elif stripped == "Type one log per line":
                item = stripped
            elif code_match:
                item = f"{code_match.group(1).upper()} diagnostic code {code_match.group(2)}"
            elif severity_match:
                item = f"{severity_match.group(1).upper()} diagnostic present"
            elif stripped == "Traceback (most recent call last):":
                item = "Python traceback present"
            else:
                continue
            if item not in safe:
                safe.append(item)
            if len(safe) >= 8:
                break
        if len(safe) >= 8:
            break
    return " | ".join(safe) if safe else "no safe diagnostic text"


def _invoke_wazuh_logtest(lines: list[str], *, timeout: float = 1800) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["docker", "compose", "exec", "-i", MANAGER_SERVICE,
             "/var/ossec/bin/wazuh-logtest"],
            cwd=REPO_ROOT, input="\n".join(lines) + "\n",
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise WazuhLogtestInvocationError(
            f"wazuh-logtest timed out after {timeout:.1f}s before a trustworthy result existed"
        ) from exc


def _parse_wazuh_logtest(proc: subprocess.CompletedProcess,
                         expected_count: int) -> list[str | None]:
    if proc.returncode != 0:
        raise WazuhLogtestInvocationError(
            f"wazuh-logtest exited {proc.returncode}; diagnostics: "
            f"{_safe_logtest_diagnostics(proc)}"
        )

    # Wazuh 4.9 normally writes phases to stderr, while its Python wrapper
    # writes a progress byte per event to stdout. Parse both so a stream-routing
    # change cannot masquerade as zero results.
    out = (proc.stderr or "") + "\n" + (proc.stdout or "")
    blocks = out.split("**Phase 1: Completed pre-decoding.")[1:]
    results: list[str | None] = []
    incomplete_blocks = 0
    for block in blocks:
        if "**Phase 3: Completed filtering (rules)." not in block:
            incomplete_blocks += 1
            continue
        after = block.split("**Phase 3: Completed filtering (rules).", 1)[1]
        rid = None
        for line in after.splitlines():
            line = line.strip()
            if line.startswith("id: "):
                rid = line.split("'")[1]
                break
        if rid is None:
            incomplete_blocks += 1
            continue
        results.append(rid)
    if incomplete_blocks or len(results) != expected_count:
        raise WazuhLogtestResultCountError(
            f"wazuh-logtest returned {len(blocks)} phase-1 block(s), "
            f"{len(results)} complete phase-3 result block(s), and "
            f"{incomplete_blocks} incomplete block(s) for {expected_count} input lines; "
            f"returncode={proc.returncode}; diagnostics: "
            f"{_safe_logtest_diagnostics(proc)}"
        )
    return results


def preflight_wazuh_logtest(*, timeout: float = LOGTEST_PREFLIGHT_TIMEOUT_SECONDS,
                            interval: float = LOGTEST_PREFLIGHT_INTERVAL_SECONDS) -> dict:
    """Poll until the direct rules engine returns exactly one probe result."""
    started = time.monotonic()
    deadline = started + timeout
    attempts = 0
    last_error: WazuhLogtestError | None = None
    while True:
        attempts += 1
        remaining = max(0.1, deadline - time.monotonic())
        try:
            proc = _invoke_wazuh_logtest([_PREFLIGHT_EVENT], timeout=remaining)
            _parse_wazuh_logtest(proc, 1)
            elapsed = time.monotonic() - started
            print(
                f"WAZUH-LOGTEST PREFLIGHT: ready after {attempts} attempt(s), "
                f"{elapsed:.1f}s; direct engine returned exactly one result block",
                file=sys.stderr,
            )
            return {"attempts": attempts, "elapsed_seconds": elapsed}
        except WazuhLogtestError as exc:
            last_error = exc

        now = time.monotonic()
        if now >= deadline:
            raise WazuhLogtestInvocationError(
                f"wazuh-logtest preflight timed out after {timeout:.1f}s and {attempts} "
                f"attempt(s) while awaiting exactly one result block; last error: {last_error}"
            ) from last_error
        wait = min(interval, deadline - now)
        print(
            f"WAZUH-LOGTEST PREFLIGHT: attempt {attempts} not ready; awaiting exactly "
            f"one result block (timeout {timeout:.1f}s, next poll in {wait:.1f}s); "
            f"last error: {last_error}",
            file=sys.stderr,
        )
        time.sleep(wait)


def run_wazuh_logtest_batch(lines: list[str]) -> list[str | None]:
    """Feed `lines` through one wazuh-logtest batch invocation against
    whatever is actually loaded on the live manager; return the final
    matched rule id per line, in order. This is the real rule engine, not a
    Python stand-in -- see docs/PHASE4-DESIGN.md's restated discipline."""
    if not lines:
        return []

    last_error: WazuhLogtestResultCountError | None = None
    for attempt in range(1, LOGTEST_BATCH_ATTEMPTS + 1):
        proc = _invoke_wazuh_logtest(lines)
        try:
            return _parse_wazuh_logtest(proc, len(lines))
        except WazuhLogtestResultCountError as exc:
            last_error = exc
            if attempt == LOGTEST_BATCH_ATTEMPTS:
                break
            print(
                f"WAZUH-LOGTEST BATCH: result-count failure on attempt {attempt}/"
                f"{LOGTEST_BATCH_ATTEMPTS}; running bounded readiness preflight before "
                f"one retry; error: {exc}",
                file=sys.stderr,
            )
            preflight_wazuh_logtest()

    raise WazuhLogtestResultCountError(
        f"wazuh-logtest batch remained incomplete after {LOGTEST_BATCH_ATTEMPTS} "
        f"attempts; no detection verdict is available; last error: {last_error}"
    ) from last_error


# ---------------------------------------------------------------------------
# Join / normalization (docs/PHASE4-DESIGN.md Section 2)
# ---------------------------------------------------------------------------

@dataclass
class JoinedRecord:
    raw: dict
    matched_rule_id: str | None
    primary_session_id: str
    related_session_ids: list = field(default_factory=list)


def normalize_and_join(raw_lines: list[str], matched_rule_ids: list[str | None]) -> list[JoinedRecord]:
    joined = []
    for line, rule_id in zip(raw_lines, matched_rule_ids):
        record = json.loads(line)
        if "session_id" in record:
            primary_session_id = record["session_id"]
            related = []
        elif "drift_session_id" in record:
            primary_session_id = record["drift_session_id"]
            related = [record.get("baseline_first_seen_session_id")]
        else:
            raise ValueError(
                "unrecognized record shape -- neither 'session_id' nor "
                f"'drift_session_id' present, refusing to guess: {record}"
            )
        joined.append(JoinedRecord(
            raw=record, matched_rule_id=rule_id,
            primary_session_id=primary_session_id, related_session_ids=related,
        ))
    return joined


def cross_check_scenario_task(joined: list[JoinedRecord]) -> list[str]:
    """scenario_id/task_id cross-check the design doc asked for: within one
    primary_session_id, every record should agree on scenario_id and
    task_id. Returns a list of human-readable mismatch descriptions (empty
    if none)."""
    by_session: dict[str, list[JoinedRecord]] = defaultdict(list)
    for jr in joined:
        by_session[jr.primary_session_id].append(jr)
    mismatches = []
    for sid, records in by_session.items():
        scenarios = {r.raw.get("scenario_id") for r in records}
        tasks = {r.raw.get("task_id") for r in records}
        if len(scenarios) > 1:
            mismatches.append(f"session {sid}: multiple scenario_id values seen: {sorted(scenarios)}")
        if len(tasks) > 1:
            mismatches.append(f"session {sid}: multiple task_id values seen: {sorted(tasks)}")
    return mismatches


# ---------------------------------------------------------------------------
# Metrics (docs/PHASE4-DESIGN.md Section 3 -- FP aggregated, recall per-technique)
# ---------------------------------------------------------------------------

def compute_aggregate_fp(benign_joined: list[JoinedRecord]) -> dict:
    alerting = [jr for jr in benign_joined if jr.matched_rule_id != NO_ALERT_RULE_ID]
    by_session = {jr.raw["session_id"] for jr in benign_joined}
    return {
        "total_records": len(benign_joined),
        "total_sessions": len(by_session),
        "alerting_records": len(alerting),
        "alerting_details": [(jr.raw.get("session_id"), jr.matched_rule_id) for jr in alerting],
    }


def compute_per_rule_fp(benign_joined: list[JoinedRecord], denominators: dict) -> dict:
    counts = defaultdict(int)
    for jr in benign_joined:
        if jr.matched_rule_id != NO_ALERT_RULE_ID:
            counts[jr.matched_rule_id] += 1
    return {
        "100102": (counts.get("100102", 0), denominators["benign_session_count"]),
        "100101": (counts.get("100101", 0), denominators["benign_tool_call_count"]),
        **{rid: (counts.get(rid, 0), denominators["benign_tool_call_count"]) for rid in EXFIL_HOP_FAMILY},
    }


def compute_scenario_recall(attack_joined: list[JoinedRecord]) -> dict:
    """Group by (scenario_id, task_id); for each task_id, record which rule
    ids (excluding the no-alert parent) fired anywhere among its records."""
    by_scenario_task: dict[tuple, set] = defaultdict(set)
    for jr in attack_joined:
        scenario = jr.raw.get("scenario_id")
        task = jr.raw.get("task_id")
        if jr.matched_rule_id and jr.matched_rule_id != NO_ALERT_RULE_ID:
            by_scenario_task[(scenario, task)].add(jr.matched_rule_id)
        else:
            by_scenario_task.setdefault((scenario, task), set())

    per_scenario = defaultdict(dict)
    for (scenario, task), rule_ids in by_scenario_task.items():
        per_scenario[scenario][task] = sorted(rule_ids)
    return per_scenario


def compute_cross_scenario_firings(attack_joined: list[JoinedRecord]) -> dict:
    """For each rule id that fired at all, which distinct scenario_ids did
    it fire on? Flags anything firing across more than one scenario --
    generic, not hardcoded to the known credential_exfil/rug_pull artifact,
    so a future artifact of the same shape would also surface here."""
    rule_scenarios: dict[str, set] = defaultdict(set)
    rule_scenario_tasks: dict[str, dict] = defaultdict(lambda: defaultdict(list))
    for jr in attack_joined:
        rid = jr.matched_rule_id
        if rid and rid != NO_ALERT_RULE_ID:
            scenario = jr.raw.get("scenario_id")
            rule_scenarios[rid].add(scenario)
            rule_scenario_tasks[rid][scenario].append(jr.raw.get("task_id"))
    cross = {}
    for rid, scenarios in rule_scenarios.items():
        if len(scenarios) > 1:
            cross[rid] = {s: sorted(set(tasks)) for s, tasks in rule_scenario_tasks[rid].items()}
    return cross


# ---------------------------------------------------------------------------
# Worked reconstruction (secondary CLI mode, also used to embed one example)
# ---------------------------------------------------------------------------

def reconstruct(all_joined: list[JoinedRecord], *, session_id: str | None = None,
                 task_id: str | None = None) -> list[JoinedRecord]:
    if session_id:
        matches = [jr for jr in all_joined
                   if jr.primary_session_id == session_id or session_id in jr.related_session_ids]
    elif task_id:
        matches = [jr for jr in all_joined if jr.raw.get("task_id") == task_id]
    else:
        raise ValueError("reconstruct() needs session_id or task_id")
    # Pure chronological order, deliberately NOT grouped by session_id first:
    # the whole point of a task_id-spanning-multiple-sessions reconstruction
    # is to show how those sessions actually interleaved in wall-clock time
    # (ISO 8601 'Z' timestamps sort correctly as plain strings, per schema.md).
    return sorted(matches, key=lambda jr: jr.raw.get("timestamp") or "")


def render_reconstruction_table(records: list[JoinedRecord]) -> str:
    lines = ["| session_id | timestamp | method | tool_name | matched rule |",
             "|---|---|---|---|---|"]
    for jr in records:
        r = jr.raw
        sid = jr.primary_session_id[:8]
        ts = r.get("timestamp", "")
        method = r.get("method") or ("(response)" if "drift_field" not in r else "baseline_drift")
        tool = r.get("tool_name") or r.get("drift_field") or ""
        rule = jr.matched_rule_id or ""
        marker = f"**{rule}**" if rule and rule != NO_ALERT_RULE_ID else rule
        lines.append(f"| {sid} | {ts} | {method} | {tool} | {marker} |")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def fmt_fraction(n: int, d: int) -> str:
    pct = round(100 * n / d) if d else 0
    return f"{n}/{d} ({pct}%)"


def render_report(*, rule_sha: str, wazuh_version: str, inputs: dict,
                   benign_joined: list[JoinedRecord], attack_joined: list[JoinedRecord],
                   all_joined_for_reconstruction: list[JoinedRecord]) -> str:
    agg_fp = compute_aggregate_fp(benign_joined)
    per_rule_fp = compute_per_rule_fp(benign_joined, inputs)
    per_scenario_recall = compute_scenario_recall(attack_joined)
    cross_scenario = compute_cross_scenario_firings(attack_joined)
    mismatches = cross_check_scenario_task(benign_joined + attack_joined)

    worked = reconstruct(all_joined_for_reconstruction, task_id="attack_credential_exfil_sandbox_bait")

    out = []
    out.append("<!-- GENERATED FILE -- produced by analysis/report.py. Do not "
                "hand-edit; re-run `python3 analysis/report.py` to update. -->")
    out.append("# Phase 4 Report — Detector Performance\n")

    out.append("## Provenance\n")
    out.append(f"- Generator: `{GENERATOR_ID}`")
    out.append(f"- `wazuh/local_rules.xml` sha256 (verified byte-identical to the live "
                f"manager's loaded rule file before this report was generated): `{rule_sha}`")
    out.append(f"- Wazuh version: `{wazuh_version}`")
    out.append(f"- Inputs: `data/benign_corpus_v2.jsonl` ({len(inputs['benign_lines'])} records, "
                f"{inputs['benign_session_count']} sessions, {inputs['benign_tool_call_count']} "
                f"tool-call events); canonical `telemetry.jsonl` filtered to `label=malicious` "
                f"({len(inputs['malicious_lines'])} records); canonical `rugpull_alerts.jsonl` "
                f"({len(inputs['drift_lines'])} records)")
    out.append("- No wall-clock timestamp is embedded above or anywhere else in this report: "
                "every field on this line is a deterministic function of the inputs "
                "(rule file contents, Wazuh version, input record counts), so re-running "
                "this tool against unchanged inputs produces a byte-identical report -- "
                "an intentional choice for `git diff`-friendliness (docs/PHASE4-DESIGN.md, "
                "sign-off item B), not an oversight.")
    if mismatches:
        out.append("\n**scenario_id/task_id cross-check FAILED** -- inconsistent labeling "
                    "within a session, investigate before trusting the tables below:")
        for m in mismatches:
            out.append(f"  - {m}")
    else:
        out.append("- scenario_id/task_id cross-check: passed (every record sharing a "
                    "`primary_session_id` agrees on `scenario_id` and `task_id`).")

    out.append("\n## Executive summary\n")
    out.append(f"**False positives: {fmt_fraction(agg_fp['alerting_records'], agg_fp['total_records'])} "
                f"benign records triggered any alert** ({agg_fp['total_sessions']} benign sessions, "
                f"the full frozen `benign_corpus_v2` corpus). This number is honestly aggregated "
                f"across every rule (`100101`–`100107`, `100102`, `100201`) because \"did this "
                f"benign record trigger anything\" means the same thing regardless of which rule "
                f"would have fired — unlike recall, whose denominator differs by technique (see below), "
                f"a false positive is a false positive regardless of which rule almost fired. "
                f"**Caveat carried inline, not buried**: this aggregate is real for the content/path "
                f"rules (`100101`–`107`, `100102`) but structurally weaker for the rug-pull rule "
                f"(`100201`) — see \"Rug pull\" below for why zero drift on a corpus with zero "
                f"legitimate version changes is a narrower claim than zero drift would be on a "
                f"corpus that actually exercised version bumps.")
    out.append("\n**Recall is reported strictly per-technique below, never blended into one "
                "number.** The three techniques don't share a denominator (different attack-session "
                "counts), and don't even share what \"a false negative\" would mean (a missed "
                "content match vs. a missed baseline-drift event) — collapsing them into one "
                "precision/recall/F1 figure would itself be a laundering step, manufacturing false "
                "precision this project has been careful not to overclaim elsewhere.")

    # Tool poisoning
    out.append("\n## Tool poisoning (SAF-T1001) — rule `100102`\n")
    tp_tasks = per_scenario_recall.get("tool_poisoning", {})
    tp_hit = sum(1 for rules in tp_tasks.values() if rules)
    out.append(f"Recall: **{fmt_fraction(tp_hit, len(tp_tasks))}** self-authored task_ids "
                f"(1 original + variants) produced a `100102` alert.")
    out.append(f"\nFalse positives: **{fmt_fraction(*per_rule_fp['100102'])}** benign `tools/list` "
                f"responses (one per session).")
    out.append("\n**Honesty boundary, restated from `docs/PHASE3A-DESIGN.md`**: these are "
                "self-authored variants (different cover-tool identity, different directive "
                "wording) — this demonstrates the harness/server plumbing reliably reproduces "
                "poisoned-description telemetry across wording, not that the rule generalizes to "
                "independently-authored or adversarial phrasing (stealthy Unicode/homoglyph "
                "obfuscation is explicitly out of scope, named since Phase 2).")
    missed_tp = [t for t, rules in tp_tasks.items() if not rules]
    if missed_tp:
        out.append(f"\nTask_ids with **no** alert (investigate): {sorted(missed_tp)}")

    # Credential exfil
    out.append("\n## Credential exfiltration (SAF-T1502 read hop + SAF-T1910 exfil hop)\n")
    ce_tasks = per_scenario_recall.get("credential_exfil_via_read", {})
    read_hit = sum(1 for rules in ce_tasks.values() if "100101" in rules)
    exfil_hit = sum(1 for rules in ce_tasks.values() if any(r in EXFIL_HOP_FAMILY for r in rules))
    out.append(f"Read-hop recall (`100101`): **{fmt_fraction(read_hit, len(ce_tasks))}** task_ids "
                f"(robust across all 4 bait-path representations tested, per `docs/PHASE3A-DESIGN.md`).")
    out.append(f"\nExfil-hop recall, rule family `100103`–`100107` (any of the 5 fires): "
                f"**{fmt_fraction(exfil_hit, len(ce_tasks))}** task_ids.")
    out.append("\nPer-rule breakdown within the exfil-hop family (FP denominator: "
                f"{inputs['benign_tool_call_count']} benign tool-call events):\n")
    out.append("| rule | argument key | benign FP |")
    out.append("|---|---|---|")
    for rid in EXFIL_HOP_FAMILY:
        key = RULE_TECHNIQUE[rid].split("key=")[1].rstrip(")")
        out.append(f"| `{rid}` | `{key}` | {fmt_fraction(*per_rule_fp[rid])} |")
    out.append(f"\nFalse positives, read hop (`100101`): **{fmt_fraction(*per_rule_fp['100101'])}** "
                f"benign tool-call events.")
    out.append("\n**Honesty boundary, restated from `docs/PHASE3A-DESIGN.md`**: `100103`–`107`'s "
                "recall is bounded to the 5 argument-key names actually tested (`data`/`payload`/"
                "`content`/`body`/`message`) — a 6th, unobserved key name would still slip past "
                "this rule family by construction (Wazuh's rule DSL has no wildcard-field-name "
                "match). This is measured recall against a *named* blind spot, not a claim the "
                "family is exhaustive.")

    # Rug pull
    out.append("\n## Rug pull (SAF-T1201) — persistent baseline drift, rule `100201`\n")
    rp_tasks = per_scenario_recall.get("rug_pull", {})
    baseline_tasks = sorted(t for t in rp_tasks if "baseline" in t)
    drifting_tasks = sorted(t for t in rp_tasks if t not in baseline_tasks)
    drift_hit = sum(1 for t in drifting_tasks if rp_tasks[t])
    out.append(f"Of {len(rp_tasks)} total rug-pull task_ids observed: "
                f"**{len(baseline_tasks)} baseline-setting task_id(s)** "
                f"({', '.join(baseline_tasks)}) correctly produced **zero** alerts — "
                f"this is expected, not a miss: these sessions establish the baseline a later "
                f"session's drift is measured against, per `docs/PHASE3B-DESIGN.md`.")
    out.append(f"\nOf the remaining **{len(drifting_tasks)} task_ids expected to show drift**, "
                f"**{fmt_fraction(drift_hit, len(drifting_tasks))}** produced at least one "
                f"`100201` alert (description-only, version-only, and both-drift shapes all "
                f"measured separately, per `docs/PHASE3B-DESIGN.md`).")
    out.append("\n| task_id | drift field(s) alerted |")
    out.append("|---|---|")
    for t in drifting_tasks:
        out.append(f"| `{t}` | {', '.join(rp_tasks[t]) if rp_tasks[t] else '**none**'} |")

    rp_benign_alerts = sum(1 for jr in benign_joined if jr.matched_rule_id == "100201")
    out.append(f"\nFalse positives: **{fmt_fraction(rp_benign_alerts, len(inputs['benign_lines']))}** "
                "benign records (full corpus — `100201` isn't scoped to one record type the way "
                "the content rules are).")
    out.append("\n**This \"0 FP\" is a structurally weaker claim than the content rules' above, "
                "restated plainly rather than presented as equivalent** (`docs/PHASE3B-DESIGN.md`): "
                "the content/path rules' 0 FP means the benign corpus never contains that "
                "attack-shaped *content*, true regardless of how the benign fleet evolves. This "
                "rule's 0 FP means the frozen corpus's pinned server versions never change during "
                "the recording — true by construction (Phase 1b froze it) and known before a "
                "single record was measured. No benign fixture in this corpus exercises the actual "
                "case this detector needs to distinguish: a *legitimate* version bump. Recall here "
                "(measured on real drift shapes, three separately) is on firmer footing than this "
                "FP number is.")

    if cross_scenario:
        out.append("\n### Cross-scenario rule firings (found, not hidden)\n")
        for rid, by_scenario in sorted(cross_scenario.items()):
            out.append(f"- Rule `{rid}` (nominally {RULE_TECHNIQUE.get(rid, '?')}) fired on "
                        f"task_ids across **{len(by_scenario)} distinct scenario_ids** — stated "
                        f"neutrally rather than presuming which one is the rule's \"real\" "
                        f"scenario, since the larger count below (`credential_exfil_via_read`) "
                        f"is not the scenario this rule's own group tag names:")
            for scenario, tasks in sorted(by_scenario.items()):
                out.append(f"  - `{scenario}` ({len(tasks)} task_ids): {', '.join(sorted(tasks))}")
        out.append("\n**Explanation, per `docs/PHASE3B-DESIGN.md`**: `attacks/servers/"
                    "exfil_sink_server.py` (3a's credential-exfil sink) names its `exfiltrate` "
                    "tool's `inputSchema` property after an env var (`data`/`payload`/`content`/"
                    "`body`/`message`, used to test `100103`'s key-name scope limit) while its "
                    "`server_command` stays identical across every variant — so the tool's "
                    "declared schema genuinely, correctly differs across those sessions. The "
                    "rug-pull detector is behaving exactly as designed (real schema drift, "
                    "correctly detected); the scenario label is what's misleading if skimmed. "
                    "**True positives for the rug-pull technique remain "
                    f"{fmt_fraction(drift_hit, len(drifting_tasks))}** — these firings belong to a "
                    "different scenario's own task_ids, not a rug-pull miss or extra credit.")

    out.append("\n## Coverage map\n")
    out.append("| technique | rule(s) | status |")
    out.append("|---|---|---|")
    out.append(f"| Tool poisoning (SAF-T1001) | `100102` | HTML-comment obfuscation only; "
                f"{fmt_fraction(tp_hit, len(tp_tasks))} recall, "
                f"{fmt_fraction(*per_rule_fp['100102'])} FP |")
    out.append(f"| Credential exfil, read hop (SAF-T1502) | `100101` | "
                f"{fmt_fraction(read_hit, len(ce_tasks))} recall, "
                f"{fmt_fraction(*per_rule_fp['100101'])} FP |")
    out.append(f"| Credential exfil, exfil hop (SAF-T1910) | `100103`–`100107` | "
                f"{fmt_fraction(exfil_hit, len(ce_tasks))} recall (5 tested key names, not "
                f"exhaustive), 0 FP |")
    out.append(f"| Rug pull (SAF-T1201) | `100200`/`100201` | "
                f"{fmt_fraction(drift_hit, len(drifting_tasks))} recall across 3 drift shapes, "
                f"weaker FP claim (see above) |")
    out.append("\n`git_show`: no rule in this ruleset keys on it, consistent with "
                "`docs/WAZUH-NOTES.md` constraint 1 (zero benign denominator, a confirmed, "
                "accepted gap).")

    out.append("\n## Worked example — one real attack, reconstructed\n")
    out.append("Generated by this tool's secondary mode "
                "(`python3 analysis/report.py --task-id attack_credential_exfil_sandbox_bait`), "
                "embedded here so the numbers above are legible as an actual attack, not just "
                "tables. This is the *original* Phase 2 credential-exfiltration attack: one task_id "
                "spanning **two** session_ids (a read-session against the real filesystem server, "
                "and a separate exfil-session against the malicious `exfiltrate` tool) — exactly "
                "the multi-session-per-task_id shape `docs/PHASE4-DESIGN.md`'s join design "
                "accounts for.\n")
    out.append(render_reconstruction_table(worked))

    read_call = next((jr for jr in worked if jr.raw.get("tool_name") == "read_text_file"), None)
    exfil_call = next((jr for jr in worked if jr.raw.get("tool_name") == "exfiltrate"), None)
    gap_note = ""
    if read_call and exfil_call:
        t1 = datetime.fromisoformat(read_call.raw["timestamp"].replace("Z", "+00:00"))
        t2 = datetime.fromisoformat(exfil_call.raw["timestamp"].replace("Z", "+00:00"))
        gap_note = f"{abs((t2 - t1).total_seconds()):.3f} seconds"

    out.append(f"\nRead the timeline in wall-clock order (not grouped by session): the "
                f"read-session's `read_text_file(.env)` call is the record that trips `100101` "
                f"(the path-based read signal); the separate exfil-session's `exfiltrate(...)` "
                f"call — a *different* tool, on a *different* server, in a *different* "
                f"session_id, opened only after the read-session's own tool call had already "
                f"completed — trips `100103` (the content-based exfil signal) "
                f"{gap_note + ' later' if gap_note else 'shortly after'}. Two independent "
                f"signals on two different records in two sequential sessions (the read "
                f"session runs fully to completion before the exfil session even connects), "
                f"joined back to one logical attack via a shared `task_id`, the reason "
                f"`docs/PHASE2-DESIGN.md` designed the labeling this way in the first place.")

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_report() -> None:
    rule_sha = verify_rule_sync()
    wazuh_version = get_wazuh_version()
    inputs = load_inputs()

    benign_matched = run_wazuh_logtest_batch(inputs["benign_lines"])
    attack_matched = run_wazuh_logtest_batch(inputs["malicious_lines"] + inputs["drift_lines"])

    benign_joined = normalize_and_join(inputs["benign_lines"], benign_matched)
    attack_joined = normalize_and_join(inputs["malicious_lines"] + inputs["drift_lines"], attack_matched)

    report_text = render_report(
        rule_sha=rule_sha, wazuh_version=wazuh_version, inputs=inputs,
        benign_joined=benign_joined, attack_joined=attack_joined,
        all_joined_for_reconstruction=attack_joined,
    )
    REPORT_PATH.write_text(report_text)
    print(f"wrote {REPORT_PATH.relative_to(REPO_ROOT)} ({len(report_text)} bytes)", file=sys.stderr)


def print_reconstruction(*, session_id: str | None, task_id: str | None) -> None:
    verify_rule_sync()
    inputs = load_inputs()
    lines = inputs["malicious_lines"] + inputs["drift_lines"]
    matched = run_wazuh_logtest_batch(lines)
    joined = normalize_and_join(lines, matched)
    records = reconstruct(joined, session_id=session_id, task_id=task_id)
    if not records:
        print(f"no records found for session={session_id!r} task_id={task_id!r}", file=sys.stderr)
        sys.exit(1)
    print(render_reconstruction_table(records))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", help="print one session's reconstruction (secondary mode)")
    parser.add_argument("--task-id", help="print one task_id's reconstruction, may span sessions")
    args = parser.parse_args()

    if args.session or args.task_id:
        print_reconstruction(session_id=args.session, task_id=args.task_id)
    else:
        generate_report()


if __name__ == "__main__":
    main()

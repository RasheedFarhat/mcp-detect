#!/usr/bin/env python3
"""Persistent-baseline rug-pull detector (SAF-T1201) -- Phase 3b.

All statefulness for rug-pull detection lives here, not in Wazuh. Wazuh's
classic rule DSL has no "differs from before" primitive (see
docs/WAZUH-NOTES.md / docs/PHASE3B-DESIGN.md) -- this module does that
comparison itself, against a small persistent JSON baseline store, and emits
one new, minimal JSON record per genuinely new drifted value to a separate
stream. Wazuh's rules 100200/100201 then do exactly what every other rule in
this ruleset does: a stateless field match on one decoded JSON line. This
module is the actual detector; 100200/100201 are pipeline plumbing that keep
Phase 4's session/scenario/task join working the same way it does for every
other alert.

Baseline semantics (TOFU plus explicit approval):
  - The first hash ever observed for a given key becomes that key's baseline,
    stored until an analyst explicitly approves a previously observed hash.
  - Any later hash that differs from the stored baseline is drift. Emission
    is deduped per (key, observed_hash): a specific drifted value alerts
    exactly once, ever, no matter how many records repeat it (e.g. every
    record in a session after `initialize` carries the same
    server_version_hash) or how many times it reappears in later sessions.
  - A value reverting to the original baseline is not drift (matches
    baseline exactly) and does not clear or reset anything.
  - A third, distinct value appearing later is new drift (a new
    (key, hash) pair) and alerts again, independently.
  - A versioned approval file can promote a previously observed hash. The old
    baseline, reviewer, reason, and timestamp remain in approval_history.

Two independently-tracked drift signals, matching schema v1's two hash
fields and docs/PHASE2-DESIGN.md's keying:
  - tool_description_hash, keyed on (tool_name, server_command). Only
    checked on tools/call records (the only record type schema.md says
    populates it).
  - server_version_hash, keyed on server_command alone. Checked on any
    record where it's non-null (populated from `initialize`'s response
    onward per schema.md).

Usage:
  python3 baseline/watch.py --input <telemetry.jsonl> --output <drift.jsonl> [--reset] [--approve approval.json]
  python3 baseline/watch.py --input <telemetry.jsonl> --output <drift.jsonl> --follow
"""
import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_STATE_PATH = Path(__file__).parent / "state" / "rugpull_baseline.json"
GENERATOR = "mcp-detect-rugpull-watch/1.0"


def empty_state() -> dict:
    return {"tool_description": {}, "server_version": {}}


def load_state(path: Path) -> dict:
    if not path.exists():
        return empty_state()
    return json.loads(path.read_text())


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Same-directory temporary + os.replace keeps restart state atomic.
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.",
                                     delete=False) as tmp:
        tmp.write(json.dumps(state, indent=2, sort_keys=True))
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def _tool_key(tool_name: str, server_command: str) -> str:
    # \x00 can't appear in either component (both are plain text fields),
    # so this is collision-free as a composite dict key.
    return f"{tool_name}\x00{server_command}"


def _check(bucket: dict, key: str, observed_hash: str, drift_field: str,
           record: dict, tool_name: Optional[str]) -> list[dict]:
    entry = bucket.get(key)
    if entry is None:
        bucket[key] = {
            "baseline_hash": observed_hash,
            "first_seen_session_id": record.get("session_id"),
            "alerted_hashes": [],
            "last_observed_hash": observed_hash,
            "last_observed_session_id": record.get("session_id"),
            "approval_history": [],
        }
        return []

    # Backward-compatible state migration for stores created before explicit
    # approval support. The old three fields retain their meaning.
    entry.setdefault("approval_history", [])
    entry["last_observed_hash"] = observed_hash
    entry["last_observed_session_id"] = record.get("session_id")

    if observed_hash == entry["baseline_hash"]:
        return []

    if observed_hash in entry["alerted_hashes"]:
        return []

    entry["alerted_hashes"].append(observed_hash)
    return [{
        # Deliberately NOT "event_type": that exact name, combined with the
        # "timestamp" field every drift record also carries, is exactly the
        # match condition Wazuh's own stock Suricata parent rule (86600,
        # 0475-suricata_rules.xml) checks for -- a real top-level-shadowing
        # collision found empirically via wazuh-logtest, not by inspection.
        # See docs/PHASE3B-DESIGN.md's build results.
        "mcp_drift_marker": "rugpull_baseline_drift",
        "timestamp": record.get("timestamp"),
        "drift_field": drift_field,
        "tool_name": tool_name,
        "server_command": record.get("server_command"),
        "baseline_hash": entry["baseline_hash"],
        "baseline_first_seen_session_id": entry["first_seen_session_id"],
        "observed_hash": observed_hash,
        "drift_session_id": record.get("session_id"),
        "scenario_id": record.get("scenario_id"),
        "task_id": record.get("task_id"),
        "label": record.get("label"),
        "generator": GENERATOR,
    }]


def approve_observed_hash(state: dict, approval: dict) -> None:
    """Promote one previously observed hash to the approved baseline.

    Approval is explicit and auditable. An arbitrary unobserved hash cannot be
    inserted into the state store, which prevents a typo or forged approval
    file from silently blessing content the watcher never saw.
    """
    kind = approval.get("kind")
    observed_hash = approval.get("observed_hash")
    server_command = approval.get("server_command")
    tool_name = approval.get("tool_name")
    approved_by = approval.get("approved_by")
    reason = approval.get("reason")
    if kind not in {"server_version", "tool_description"}:
        raise ValueError(f"invalid approval kind: {kind!r}")
    if not all(isinstance(v, str) and v.strip() for v in
               (observed_hash, server_command, approved_by, reason)):
        raise ValueError("approval requires observed_hash, server_command, approved_by, and reason")
    if kind == "tool_description" and not isinstance(tool_name, str):
        raise ValueError("tool_description approval requires tool_name")

    bucket_name = "server_version" if kind == "server_version" else "tool_description"
    key = server_command if kind == "server_version" else _tool_key(tool_name, server_command)
    entry = state[bucket_name].get(key)
    if entry is None:
        raise ValueError("cannot approve a baseline key that has not been observed")
    observed = {
        entry.get("baseline_hash"),
        entry.get("last_observed_hash"),
        *entry.get("alerted_hashes", []),
    }
    if observed_hash not in observed:
        raise ValueError("cannot approve a hash that has not been observed")

    approved_at = approval.get("approved_at")
    if approved_at is None:
        approved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    history = entry.setdefault("approval_history", [])
    history.append({
        "previous_baseline_hash": entry["baseline_hash"],
        "approved_hash": observed_hash,
        "approved_at": approved_at,
        "approved_by": approved_by,
        "reason": reason,
    })
    entry["baseline_hash"] = observed_hash
    entry["first_seen_session_id"] = entry.get("last_observed_session_id")
    entry["alerted_hashes"] = []


def apply_approval_file(state: dict, path: Path) -> int:
    payload = json.loads(path.read_text())
    approvals = payload.get("approvals")
    if payload.get("version") != 1 or not isinstance(approvals, list):
        raise ValueError("approval file must use version 1 with an approvals list")
    for approval in approvals:
        if not isinstance(approval, dict):
            raise ValueError("each approval entry must be an object")
        approve_observed_hash(state, approval)
    return len(approvals)


def process_record(record: dict, state: dict) -> list[dict]:
    """Given one decoded telemetry record and the mutable baseline state,
    return zero or more drift-event dicts. Mutates state in place."""
    events: list[dict] = []
    server_command = record.get("server_command")
    if not server_command:
        return events

    version_hash = record.get("server_version_hash")
    if version_hash:
        events += _check(state["server_version"], server_command,
                          version_hash, "server_version_hash", record, None)

    if record.get("method") == "tools/call":
        desc_hash = record.get("tool_description_hash")
        tool_name = record.get("tool_name")
        if desc_hash and tool_name:
            key = _tool_key(tool_name, server_command)
            events += _check(state["tool_description"], key, desc_hash,
                              "tool_description_hash", record, tool_name)

    return events


def process_file(input_path: Path, state: dict) -> list[dict]:
    events: list[dict] = []
    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.extend(process_record(json.loads(line), state))
    return events


def process_follow_line(line: str, state: dict, out, state_path: Path) -> list[dict]:
    """Process and durably checkpoint one non-blank line from follow mode."""
    events = process_record(json.loads(line), state)
    for event in events:
        out.write(json.dumps(event) + "\n")
        out.flush()
    # First-seen hashes mutate state without emitting an event. Persist every
    # processed record so restart cannot silently trust a later changed hash.
    save_state(state_path, state)
    return events


def follow(input_path: Path, output_path: Path, state_path: Path,
           poll_interval: float = 1.0) -> None:
    """Process everything already in input_path, then tail it for new lines
    forever, appending newly-detected drift to output_path as it happens."""
    state = load_state(state_path)
    with open(input_path) as f, open(output_path, "a") as out:
        for line in f:
            line = line.strip()
            if not line:
                continue
            for event in process_record(json.loads(line), state):
                out.write(json.dumps(event) + "\n")
                out.flush()
        save_state(state_path, state)

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            line = line.strip()
            if not line:
                continue
            process_follow_line(line, state, out, state_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--state", default=str(DEFAULT_STATE_PATH))
    parser.add_argument("--reset", action="store_true",
                         help="wipe the baseline state file before running")
    parser.add_argument("--follow", action="store_true",
                         help="tail --input live, appending drift to --output "
                              "as detected (default: one-shot batch over the "
                              "whole file, --output overwritten)")
    parser.add_argument("--approve", help="versioned JSON approval file applied after this batch is observed")
    args = parser.parse_args()

    state_path = Path(args.state)
    if args.reset and state_path.exists():
        state_path.unlink()

    if args.follow:
        if args.approve:
            parser.error("--approve is only supported in one-shot mode")
        follow(Path(args.input), Path(args.output), state_path)
        return 0

    state = load_state(state_path)
    events = process_file(Path(args.input), state)
    approvals_applied = apply_approval_file(state, Path(args.approve)) if args.approve else 0
    with open(args.output, "w") as out:
        for event in events:
            out.write(json.dumps(event) + "\n")
    save_state(state_path, state)
    print(f"{len(events)} drift record(s) written to {args.output}; "
          f"{approvals_applied} approval(s) applied", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

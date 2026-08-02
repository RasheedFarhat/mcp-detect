#!/usr/bin/env python3
"""Phase 6 migration -- fixture-reference resolution.

Small, explicit conventions for the fixture strings declared in each
detection.yaml's `fixtures` block (see docs/PHASE6-MIGRATION-REPORT.md for
why these conventions exist -- they are new, disclosed here rather than
assumed from v2's illustrative examples, which never specified a parser):

  "data/<file>.jsonl#distinct_sessions"   -- benign denominator: count of
                                             distinct session_id values.
  "data/<file>.jsonl#tool_call_events"    -- benign denominator: count of
                                             records with method=="tools/call".
  "data/<file>.jsonl#all_records"         -- benign denominator: total
                                             record count (no filtering).
  "live:telemetry#label=malicious&scenario_id=X"
                                           -- fetch the agent container's
                                             live telemetry.jsonl, filter to
                                             label=="malicious" and
                                             scenario_id=="X".
  "live:rugpull_alerts"                   -- fetch the agent container's
                                             live rugpull_alerts.jsonl
                                             as-is (already-computed derived
                                             drift records -- what Phase 4's
                                             report actually measured
                                             against, not a fresh rerun).
  "data/evasion_corpus_v1.jsonl#task_id~=id1,id2,..."
                                           -- evasion corpus filtered to an
                                             explicit list of task_ids.
  "none"                                   -- no evasion corpus authored
                                             for this detection yet. An
                                             honest, explicit sentinel
                                             (a Detection can declare this
                                             gap without becoming a crash
                                             waiting to happen the first
                                             time generic tooling iterates
                                             the registry) -- NOT the same
                                             as omitting the field, and not
                                             a free-text explanatory
                                             sentence (put the "why" in
                                             known_gaps instead, where it's
                                             already the convention).
"""
from __future__ import annotations

import json


def _load(lines: list[str]) -> list[dict]:
    return [json.loads(l) for l in lines]


def resolve_benign_denominator(fixture_ref: str, benign_lines: list[str]) -> int:
    if "#" not in fixture_ref:
        raise ValueError(f"benign_denominator fixture missing '#fragment': {fixture_ref!r}")
    frag = fixture_ref.split("#", 1)[1]
    if frag == "distinct_sessions":
        return len({r["session_id"] for r in _load(benign_lines)})
    if frag == "tool_call_events":
        return sum(1 for r in _load(benign_lines) if r.get("method") == "tools/call")
    if frag == "all_records":
        return len(benign_lines)
    raise ValueError(f"unknown benign_denominator fragment: {frag!r}")


def parse_live_telemetry_ref(fixture_ref: str) -> dict:
    """'live:telemetry#label=malicious&scenario_id=X' -> {'label': 'malicious', 'scenario_id': 'X'}"""
    if not fixture_ref.startswith("live:telemetry#"):
        raise ValueError(f"not a live:telemetry fixture ref: {fixture_ref!r}")
    frag = fixture_ref.split("#", 1)[1]
    params = {}
    for pair in frag.split("&"):
        k, v = pair.split("=", 1)
        params[k] = v
    return params


def filter_records(lines: list[str], **filters: str) -> list[str]:
    out = []
    for l in lines:
        r = json.loads(l)
        if all(r.get(k) == v for k, v in filters.items()):
            out.append(l)
    return out


def has_evasion_corpus(fixture_ref: str) -> bool:
    """False for the explicit "none" sentinel (no evasion corpus authored
    yet); true for anything else. Callers should check this before calling
    parse_evasion_task_ids()/filter_evasion_lines(), which still raise on
    "none" -- exactly like they'd raise on any other malformed reference --
    rather than silently treating it as equivalent to a real, empty
    task_id list."""
    return fixture_ref != "none"


def parse_evasion_task_ids(fixture_ref: str) -> list[str]:
    if fixture_ref == "none":
        return []
    if "#task_id~=" not in fixture_ref:
        raise ValueError(f"not an evasion_corpus task_id~= fixture ref: {fixture_ref!r}")
    frag = fixture_ref.split("#task_id~=", 1)[1]
    return frag.split(",")


def filter_evasion_lines(lines: list[str], fixture_ref: str) -> list[str]:
    if fixture_ref == "none":
        return []
    task_ids = set(parse_evasion_task_ids(fixture_ref))
    return [l for l in lines if json.loads(l).get("task_id") in task_ids]

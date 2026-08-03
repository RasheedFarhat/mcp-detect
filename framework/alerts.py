#!/usr/bin/env python3
"""Phase 6 migration -- unified Alert normalization + table-driven
session_key join.

Replaces lab/analysis/report.py's `if "session_id" in record: ... elif
"drift_session_id" in record: ...` chain (lab/analysis/report.py:213-224) with
a table built from each registered Detection's own declared `session_key`
(docs/PHASE6-DESIGN.md Section 1's Finding-2 fix), instead of two literal
field-name strings hardcoded in the join function itself. On real data the
two shapes are mutually exclusive (raw telemetry always carries
`session_id`, never `drift_session_id`; derived drift records the reverse
-- confirmed in wazuh/local_rules.xml:282-296's own comment), so table
order does not affect correctness here, but the lookup is genuinely
data-driven rather than an if/elif that would need a new branch for every
future backend shape.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from framework.schema import Detection, SessionKey


@dataclass
class JoinedRecord:
    raw: dict
    matched_rule_id: str | None
    primary_session_id: str
    related_session_ids: list = field(default_factory=list)


@dataclass
class Alert:
    detection_name: str
    technique_id: str
    primary_session_id: str
    related_session_ids: list[str]
    backend: str
    matched_content: dict
    timestamp: str


def build_session_key_table(detections: list[Detection]) -> list[SessionKey]:
    """Distinct (primary_field, related_fields) pairs declared across the
    registry, first-seen order, deduped by primary_field."""
    table: list[SessionKey] = []
    seen_primary_fields = set()
    for d in detections:
        sk = d.session_key
        if sk.primary_field not in seen_primary_fields:
            table.append(sk)
            seen_primary_fields.add(sk.primary_field)
    return table


def resolve_session(record: dict, table: list[SessionKey]) -> tuple[str, list]:
    for sk in table:
        if sk.primary_field in record:
            primary = record[sk.primary_field]
            related = [record.get(f) for f in sk.related_fields]
            return primary, related
    raise ValueError(
        f"unrecognized record shape -- none of the registry's declared "
        f"session_key primary_fields "
        f"({[sk.primary_field for sk in table]}) present, refusing to guess: {record}"
    )


def normalize_and_join(
    raw_lines: list[str],
    matched_rule_ids: list[str | None],
    detections: list[Detection],
) -> list[JoinedRecord]:
    if len(raw_lines) != len(matched_rule_ids):
        raise ValueError(
            "raw/result length mismatch -- refusing to truncate evidence: "
            f"{len(raw_lines)} raw record(s), {len(matched_rule_ids)} result(s)"
        )
    table = build_session_key_table(detections)
    joined = []
    for line, rule_id in zip(raw_lines, matched_rule_ids):
        record = json.loads(line)
        primary, related = resolve_session(record, table)
        joined.append(JoinedRecord(
            raw=record, matched_rule_id=rule_id,
            primary_session_id=primary, related_session_ids=related,
        ))
    return joined


def rule_id_to_detection(detections: list[Detection]) -> dict[str, Detection]:
    """Every wazuh_rule id -> the Detection that declares it. Flags a
    collision loudly (two Detections claiming the same rule id) rather
    than silently letting the last one win."""
    mapping: dict[str, Detection] = {}
    for d in detections:
        for rid in d.all_wazuh_rule_ids():
            if rid in mapping and mapping[rid] is not d:
                raise ValueError(
                    f"rule id {rid} claimed by both {mapping[rid].name!r} "
                    f"and {d.name!r} -- registry collision"
                )
            mapping[rid] = d
    return mapping


def build_alerts(joined: list[JoinedRecord], detections: list[Detection]) -> list[Alert]:
    rid_map = rule_id_to_detection(detections)
    alerts = []
    for jr in joined:
        rid = jr.matched_rule_id
        if rid is None or rid not in rid_map:
            continue
        d = rid_map[rid]
        alerts.append(Alert(
            detection_name=d.name,
            technique_id=d.technique_id,
            primary_session_id=jr.primary_session_id,
            related_session_ids=jr.related_session_ids,
            backend="wazuh_rule",
            matched_content=jr.raw,
            timestamp=jr.raw.get("timestamp", ""),
        ))
    return alerts

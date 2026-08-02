#!/usr/bin/env python3
"""Preventive-control assurance model for the client report.

Telemetry can create leads, but only approved source/configuration evidence and
negative tests can verify a preventive control. This module keeps that
distinction machine-readable and refuses to turn an absence of indicators into
a passing control.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


CONTROL_CATALOG: dict[str, dict[str, str]] = {
    "identity_and_object_authorization": {
        "risk": "Cross-user, cross-tenant, or over-scoped access",
        "passing_condition": "Trusted identity is bound server-side and every object/action is authorized with negative tests",
    },
    "filesystem_boundary": {
        "risk": "Absolute, encoded, traversal, or symlink filesystem escape",
        "passing_condition": "Canonical target remains inside an allowlisted root and an OS sandbox blocks escape attempts",
    },
    "approved_tool_manifest": {
        "risk": "Tool poisoning or unapproved schema/description changes",
        "passing_condition": "Normalized tool manifest is reviewed, pinned, and changed only through an approval gate",
    },
    "secret_flow_and_egress": {
        "risk": "Credentials entering model-visible data, logs, or outbound actions",
        "passing_condition": "Secrets use handles or redaction and unauthorized egress is denied in a canary test",
    },
    "artifact_and_release_integrity": {
        "risk": "Rug pull or unapproved implementation change",
        "passing_condition": "Running artifact digest and release provenance match an approved immutable release",
    },
    "high_impact_write_approval": {
        "risk": "Write action executes without the required role, scope, or user approval",
        "passing_condition": "Every high-impact handler enforces role, scope, object authorization, and approval policy",
    },
}

EVIDENCE_STATUSES = {"verified", "failed", "not_tested", "not_applicable"}


@dataclass(frozen=True)
class ManualEvidence:
    control_id: str
    status: str
    summary: str
    tested_at: str | None = None
    test_reference: str | None = None


def load_evidence(path: Path | None) -> dict[str, ManualEvidence]:
    if path is None:
        return {}
    payload = json.loads(path.read_text())
    if payload.get("version") != 1 or not isinstance(payload.get("controls"), list):
        raise ValueError("control evidence must use version 1 with a controls list")
    evidence: dict[str, ManualEvidence] = {}
    for row in payload["controls"]:
        if not isinstance(row, dict):
            raise ValueError("each control evidence entry must be an object")
        control_id = row.get("control_id")
        status = row.get("status")
        summary = row.get("summary")
        if control_id not in CONTROL_CATALOG:
            raise ValueError(f"unknown control_id: {control_id!r}")
        if status not in EVIDENCE_STATUSES:
            raise ValueError(f"invalid control status for {control_id}: {status!r}")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > 1000:
            raise ValueError(f"control summary for {control_id} must be 1-1000 characters")
        if control_id in evidence:
            raise ValueError(f"duplicate control evidence for {control_id}")
        evidence[control_id] = ManualEvidence(
            control_id=control_id,
            status=status,
            summary=summary.strip(),
            tested_at=row.get("tested_at"),
            test_reference=row.get("test_reference"),
        )
    return evidence


def build_control_assurance(
    indicators: list[dict[str, Any]],
    manual_evidence: dict[str, ManualEvidence] | None = None,
) -> list[dict[str, Any]]:
    manual_evidence = manual_evidence or {}
    by_control: dict[str, list[dict[str, Any]]] = {key: [] for key in CONTROL_CATALOG}
    for indicator in indicators:
        control_id = indicator.get("control_id")
        if control_id in by_control:
            by_control[control_id].append(indicator)

    rows: list[dict[str, Any]] = []
    for control_id, definition in CONTROL_CATALOG.items():
        evidence = manual_evidence.get(control_id)
        indicator_count = len(by_control[control_id])
        if evidence is not None:
            status = evidence.status
            evidence_dict = asdict(evidence)
        else:
            status = "review_required" if indicator_count else "not_verified"
            evidence_dict = None
        rows.append({
            "control_id": control_id,
            "risk": definition["risk"],
            "passing_condition": definition["passing_condition"],
            "status": status,
            "indicator_count": indicator_count,
            "manual_evidence": evidence_dict,
        })
    return rows

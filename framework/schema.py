#!/usr/bin/env python3
"""Phase 6 migration -- Detection schema loader.

Parses `detections/<id>_<name>/detection.yaml` into the v2 shape
`docs/PHASE6-DESIGN.md` Section 1 defines: a `backends:` list (one or more
stages, each with its own `logic_ref` and a `consumes`/`emits` pair), an
optional `pipeline` field describing how multi-backend stages compose, and
a `session_key: {primary_field, related_fields}` block -- never a bare
scalar, per that document's Finding-2 fix.

**Implementation note, disclosed rather than silently decided**: this
project has been stdlib-only throughout (no `requirements.txt`, no
third-party imports anywhere in `lab/analysis/`, `lab/baseline/`, or `lab/corpus/` --
confirmed by reading them). PyYAML is not installed in this environment
and adding it would be the first third-party dependency in the project.
Rather than install one for a schema this small, `detection.yaml` files are
written as valid JSON -- JSON is a strict subset of YAML 1.2, so every file
here is simultaneously a valid `.yaml` document (a real YAML parser would
read it identically) and parseable by the stdlib `json` module. If this
project later adopts PyYAML for richer YAML features (comments, folded
scalars), these files remain valid unchanged.

`pipeline` values:
  - absent / None       -- single backend entry, no composition to declare.
  - "parallel"          -- multiple backend entries, each independently run
                           against the same input (e.g. credential exfil's
                           read-hop and exfil-hop rule families -- both
                           wazuh_rule, both consume raw_telemetry, neither
                           depends on the other's output). Not anticipated
                           by v2's Section 1 (which only named "chained");
                           added here because credential exfil's existing,
                           frozen recall/FP breakdown genuinely needs two
                           independently-reported rule families under one
                           Detection -- see docs/PHASE6-MIGRATION-REPORT.md.
  - "chained"           -- backend entries run in list order, each stage's
                           `emits` feeding the next stage's `consumes`
                           (rug pull: stateful emits derived_record, the
                           structural stage consumes it).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"

VALID_BACKENDS = {"wazuh_rule", "stateful", "semantic"}
VALID_CONSUMES = {"raw_telemetry", "derived_record"}
VALID_PIPELINES = {None, "parallel", "chained"}
# OWASP MCP Top 10 (v0.1) category codes. A detection may map to more than one
# (tool poisoning is both a supply-chain MCP04 and a prompt-injection MCP06
# vector, for example). Validated closed so a typo'd code fails loud at load
# rather than silently producing a phantom row in the gap-map.
VALID_OWASP_MCP = {f"MCP{i:02d}" for i in range(1, 11)}


@dataclass
class LogicRef:
    wazuh_rule_ids: list[str] = field(default_factory=list)
    rule_file: str | None = None
    python_class: str | None = None


@dataclass
class BackendEntry:
    backend: str
    logic_ref: LogicRef
    consumes: str
    emits: str | None = None
    parent_rule: str | None = None
    label: str | None = None  # sub-family label, e.g. "read_hop" / "exfil_hop"

    def __post_init__(self) -> None:
        if self.backend not in VALID_BACKENDS:
            raise ValueError(f"backend {self.backend!r} not in {VALID_BACKENDS}")
        if self.consumes not in VALID_CONSUMES:
            raise ValueError(f"consumes {self.consumes!r} not in {VALID_CONSUMES}")


@dataclass
class SessionKey:
    primary_field: str
    related_fields: list[str] = field(default_factory=list)


@dataclass
class Detection:
    technique_id: str
    name: str
    detection_type: str
    status: str
    mitre_attack_ids: list[str]
    mitre_atlas_ids: list[str]
    description: str
    backends: list[BackendEntry]
    expected_signal: dict
    session_key: SessionKey
    fixtures: dict
    known_gaps: list[str]
    owasp_mcp: list[str] = field(default_factory=list)
    pipeline: str | None = None
    source_path: Path | None = None

    def __post_init__(self) -> None:
        if not self.backends:
            raise ValueError(f"{self.name}: backends list must have at least one entry")
        for code in self.owasp_mcp:
            if code not in VALID_OWASP_MCP:
                raise ValueError(
                    f"{self.name}: owasp_mcp {code!r} not in {sorted(VALID_OWASP_MCP)}"
                )
        if self.pipeline not in VALID_PIPELINES:
            raise ValueError(f"{self.name}: pipeline {self.pipeline!r} not in {VALID_PIPELINES}")
        if len(self.backends) > 1 and self.pipeline is None:
            raise ValueError(
                f"{self.name}: multi-backend Detection must declare pipeline "
                f"('parallel' or 'chained'), not leave it implicit"
            )
        if self.pipeline == "chained":
            for i, entry in enumerate(self.backends[:-1]):
                nxt = self.backends[i + 1]
                if entry.emits is None:
                    raise ValueError(
                        f"{self.name}: chained backend entry {i} ({entry.backend}) "
                        f"must declare 'emits' -- nothing for the next stage to consume"
                    )
                if entry.emits != nxt.consumes:
                    raise ValueError(
                        f"{self.name}: chained backend entry {i} emits "
                        f"{entry.emits!r} but entry {i + 1} consumes {nxt.consumes!r}"
                    )

    def all_wazuh_rule_ids(self) -> list[str]:
        """Every wazuh_rule id this Detection's backends reference, across
        every entry (flattened) -- used by the structural runner to know
        which final matched-rule-ids belong to this Detection at all."""
        ids: list[str] = []
        for entry in self.backends:
            if entry.backend == "wazuh_rule":
                ids.extend(entry.logic_ref.wazuh_rule_ids)
        return ids


def _parse_logic_ref(d: dict) -> LogicRef:
    return LogicRef(
        wazuh_rule_ids=list(d.get("wazuh_rule_ids", [])),
        rule_file=d.get("rule_file"),
        python_class=d.get("python_class"),
    )


def _parse_backend_entry(d: dict) -> BackendEntry:
    return BackendEntry(
        backend=d["backend"],
        logic_ref=_parse_logic_ref(d.get("logic_ref", {})),
        consumes=d["consumes"],
        emits=d.get("emits"),
        parent_rule=d.get("parent_rule"),
        label=d.get("label"),
    )


def _parse_session_key(d: dict) -> SessionKey:
    # Unconditionally {primary_field, related_fields: list} -- never a bare
    # scalar, per docs/PHASE6-DESIGN.md Section 1's Finding-2 fix. Fail
    # loud on a bare string rather than silently accepting the shape v2
    # explicitly rejected.
    if not isinstance(d, dict) or "primary_field" not in d:
        raise ValueError(
            f"session_key must be {{primary_field, related_fields}}, got {d!r}"
        )
    return SessionKey(
        primary_field=d["primary_field"],
        related_fields=list(d.get("related_fields", [])),
    )


def parse_detection(text: str, *, source_path: Path | None = None) -> Detection:
    d = json.loads(text)
    return Detection(
        technique_id=d["technique_id"],
        name=d["name"],
        detection_type=d["detection_type"],
        status=d["status"],
        mitre_attack_ids=list(d.get("mitre_attack_ids", [])),
        mitre_atlas_ids=list(d.get("mitre_atlas_ids", [])),
        description=d.get("description", ""),
        backends=[_parse_backend_entry(b) for b in d["backends"]],
        expected_signal=d.get("expected_signal", {}),
        session_key=_parse_session_key(d["session_key"]),
        fixtures=d.get("fixtures", {}),
        known_gaps=list(d.get("known_gaps", [])),
        owasp_mcp=list(d.get("owasp_mcp", [])),
        pipeline=d.get("pipeline"),
        source_path=source_path,
    )


def load_detection_file(path: Path) -> Detection:
    return parse_detection(path.read_text(), source_path=path)


def load_registry(detections_dir: Path = DETECTIONS_DIR) -> list[Detection]:
    """Load every detections/<id>_<name>/detection.yaml, in directory-name
    sorted order (deterministic, not filesystem-listing-order-dependent)."""
    detections = []
    for sub in sorted(detections_dir.iterdir()):
        detection_file = sub / "detection.yaml"
        if detection_file.exists():
            detections.append(load_detection_file(detection_file))
    if not detections:
        raise RuntimeError(f"no detection.yaml files found under {detections_dir}")
    return detections

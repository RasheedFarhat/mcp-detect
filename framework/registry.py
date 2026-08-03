#!/usr/bin/env python3
"""Phase 6 migration -- Detection registry: load + wire the backend chains.

Loading is schema.py's job (parsing detection.yaml into dataclasses). This
module resolves each backend entry's `logic_ref.python_class` string to an
actual, instantiable class, and runs a chained Detection's stateful stage
over raw records to produce the derived records its next stage consumes.
"""
from __future__ import annotations

import json
from pathlib import Path

from framework.schema import Detection, load_registry as _load_registry
from framework.stateful import RugPullBaselineDetector, StatefulDetector

# Every stateful python_class this migration's registry can reference.
# Extending this to a future stateful Detection means adding one entry here
# -- not touching the registry-loading or pipeline-running logic below.
STATEFUL_CLASSES: dict[str, type] = {
    "baseline.watch.RugPullBaselineDetector": RugPullBaselineDetector,
}


def load_registry(detections_dir: Path | None = None) -> list[Detection]:
    if detections_dir is None:
        return _load_registry()
    return _load_registry(detections_dir)


def get_stateful_detector(python_class: str) -> StatefulDetector:
    if python_class not in STATEFUL_CLASSES:
        raise ValueError(
            f"no stateful class registered for {python_class!r} -- "
            f"known: {list(STATEFUL_CLASSES)}"
        )
    return STATEFUL_CLASSES[python_class]()


def run_stateful_stage(detection: Detection, raw_lines: list[str], state: dict | None = None) -> list[str]:
    """For a Detection whose first backend entry is `stateful` and `emits:
    derived_record`, run it over `raw_lines` (raw telemetry, one JSON
    record per line) and return the derived records it emits, JSON-encoded,
    in emission order. `state` defaults to a fresh empty state per the
    detector's own `empty_state()` -- pass an existing state dict to
    continue from prior records (matching lab/baseline/watch.py's own TOFU
    semantics)."""
    first = detection.backends[0]
    if first.backend != "stateful":
        raise ValueError(f"{detection.name}: first backend entry is not stateful")
    detector = get_stateful_detector(first.logic_ref.python_class)
    if state is None:
        state = detector.empty_state()
    derived: list[str] = []
    for line in raw_lines:
        record = json.loads(line)
        for event in detector.process_record(record, state):
            derived.append(json.dumps(event))
    return derived

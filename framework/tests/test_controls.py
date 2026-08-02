#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from framework.controls import build_control_assurance, load_evidence


class TestControlEvidence(unittest.TestCase):
    def test_absence_of_indicators_is_not_a_pass(self):
        rows = build_control_assurance([])
        self.assertTrue(rows)
        self.assertEqual({row["status"] for row in rows}, {"not_verified"})

    def test_indicator_requires_review(self):
        rows = build_control_assurance([{"control_id": "filesystem_boundary"}])
        fs = next(row for row in rows if row["control_id"] == "filesystem_boundary")
        self.assertEqual(fs["status"], "review_required")
        self.assertEqual(fs["indicator_count"], 1)

    def test_manual_negative_test_can_verify_control(self):
        payload = {
            "version": 1,
            "controls": [{
                "control_id": "filesystem_boundary",
                "status": "verified",
                "summary": "Encoded, absolute, and symlink escape probes were denied.",
                "test_reference": "FS-NEG-001",
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(payload))
            evidence = load_evidence(path)
        rows = build_control_assurance([], evidence)
        fs = next(row for row in rows if row["control_id"] == "filesystem_boundary")
        self.assertEqual(fs["status"], "verified")
        self.assertEqual(fs["manual_evidence"]["test_reference"], "FS-NEG-001")

    def test_unknown_control_is_rejected(self):
        payload = {"version": 1, "controls": [{
            "control_id": "magic_control",
            "status": "verified",
            "summary": "no",
        }]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(payload))
            with self.assertRaisesRegex(ValueError, "unknown control_id"):
                load_evidence(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)

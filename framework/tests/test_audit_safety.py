#!/usr/bin/env python3
"""Regression tests for customer-report integrity and failure semantics."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from framework import abom, alerts, audit_report, compiler, coverage  # noqa: E402
from framework.rendering import markdown_text  # noqa: E402


class TestMinimalEvidence(unittest.TestCase):
    def test_secret_bearing_argument_is_not_copied_into_finding(self):
        secret = "sk-SYNTHETIC-NEVER-EXPORT"
        jr = alerts.JoinedRecord(
            raw={
                "timestamp": "2026-07-15T00:00:00Z",
                "server_command": "server",
                "tool_name": "send",
                "tool_arguments": {"message": secret},
            },
            matched_rule_id="100103",
            primary_session_id="session",
        )
        row = audit_report._finding_row(
            jr, {"100103": SimpleNamespace(technique_id="SAF-T1502")}
        )
        serialized = json.dumps(row)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("tool_arguments", serialized)
        self.assertEqual(row["matched_content"]["tool_name"], "send")
        self.assertEqual(row["verification_status"], "automated_indicator")

    def test_path_indicator_is_preserved_for_reproduction(self):
        path = "../../../etc/passwd"
        jr = alerts.JoinedRecord(
            raw={"timestamp": "t", "server_command": "s", "tool_name": "read_file",
                 "tool_arguments": {"path": path}},
            matched_rule_id="100108", primary_session_id="session",
        )
        row = audit_report._finding_row(
            jr, {"100108": SimpleNamespace(technique_id="SAF-T1105")}
        )
        self.assertEqual(row["matched_content"]["path"], path)


class TestHostileMarkdown(unittest.TestCase):
    HOSTILE = "srv | extra `code` <script>x</script>\n## forged\x1b[31m"

    def test_inline_renderer_neutralizes_structure_and_controls(self):
        rendered = markdown_text(self.HOSTILE)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("\n", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("|", rendered)
        self.assertNotIn("`", rendered)

    def test_abom_report_neutralizes_server_and_tool_names(self):
        bom = {
            "server_count": 1, "tool_count": 1, "session_count": 1,
            "servers": {
                self.HOSTILE: {
                    "trust_boundary": {"label": "unknown", "filesystem_access": None,
                                       "network_egress": False},
                    "session_count": 1,
                    "tools": {"tool | bad\n# fake": {"call_count": 1,
                                                       "tool_description_hashes": []}},
                    "server_version_hashes": [],
                }
            },
        }
        rendered = abom.render_markdown(bom)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("\n## forged", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_findings_table_neutralizes_evidence_fields(self):
        row = {
            "technique_id": "SAF-T1105", "rule_id": "100108",
            "verification_status": "automated_indicator",
            "session_id": "s", "timestamp": self.HOSTILE,
            "matched_content": {"server_command": self.HOSTILE,
                                "tool_name": self.HOSTILE, "path": self.HOSTILE},
        }
        report = {
            "client_scan_status": "completed", "client_scan_error": None,
            "client_findings_reachable": True,
            "client_findings": {"structural_findings": [row],
                                "rugpull_high": [], "rugpull_info": []},
            "detections": [object()],
        }
        rendered = "\n".join(audit_report._render_findings_section(report))
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("\n## forged", rendered)
        self.assertNotIn("\x1b", rendered)


class TestScanStatus(unittest.TestCase):
    def test_unreachable_is_not_run(self):
        with patch.object(audit_report, "_live_engine_reachable", return_value=False):
            findings, status, diagnostic = audit_report.try_client_findings([], [])
        self.assertIsNone(findings)
        self.assertEqual(status, "not_run")
        self.assertIsNone(diagnostic)

    def test_processing_error_is_failed_not_unreachable(self):
        with patch.object(audit_report, "_live_engine_reachable", return_value=True), \
             patch.object(audit_report, "build_client_findings",
                          side_effect=RuntimeError("customer content must not be copied")):
            findings, status, diagnostic = audit_report.try_client_findings([], [])
        self.assertIsNone(findings)
        self.assertEqual(status, "failed")
        self.assertEqual(diagnostic, "RuntimeError")

    def test_cli_returns_nonzero_for_incomplete_scan(self):
        report = {"client_scan_status": "not_run"}
        with patch.object(sys, "argv", ["audit_report.py", "input.jsonl"]), \
             patch.object(audit_report, "build_report", return_value=report), \
             patch.object(audit_report, "render_json", return_value={}), \
             patch("builtins.print"):
            self.assertEqual(audit_report.main(), 2)

    def test_live_measurement_processing_error_is_failed(self):
        with patch.object(audit_report, "_live_engine_reachable", return_value=True), \
             patch.object(coverage, "run_full_pipeline",
                          side_effect=RuntimeError("synthetic measurement fault")):
            result, status, diagnostic = audit_report.try_live_measurements()
        self.assertIsNone(result)
        self.assertEqual(status, "failed")
        self.assertEqual(diagnostic, "RuntimeError")

    def test_oversized_input_is_rejected_before_processing(self):
        path = REPO_ROOT / "data" / "attack_corpus_sample_v1.jsonl"
        with patch.object(audit_report, "load_registry", return_value=[]), \
             patch.object(audit_report, "MAX_TELEMETRY_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "split or sample"):
                audit_report.build_report(path, None)


class TestCompilerAndJoinIntegrity(unittest.TestCase):
    def _report(self, *, tally=None, unprobed=None):
        return compiler.DetectionReport(
            "test", [], [], tally or {"total": 1, "own_hits": 1,
                                      "no_match": 0, "deferred": {}},
            [], unprobed or [], [],
        )

    def test_clean_report_is_clean(self):
        self.assertTrue(self._report().is_clean())

    def test_disjointness_miss_blocks_clean(self):
        self.assertFalse(self._report(tally={"total": 1, "own_hits": 0,
                                             "no_match": 1, "deferred": {}}).is_clean())

    def test_empty_disjointness_evidence_blocks_clean(self):
        self.assertFalse(self._report(tally={"total": 0, "own_hits": 0,
                                             "no_match": 0, "deferred": {}}).is_clean())

    def test_mixed_scenario_tally_is_not_mislabeled_as_failure(self):
        self.assertTrue(self._report(tally={"total": 3, "own_hits": 1,
                                            "no_match": 1, "deferred": {"100999": 1}}).is_clean())

    def test_unprobed_negate_blocks_clean(self):
        self.assertFalse(self._report(unprobed=["100999"]).is_clean())

    def test_join_length_mismatch_fails_loudly(self):
        detection = SimpleNamespace(
            session_key=SimpleNamespace(primary_field="session_id", related_fields=[])
        )
        with self.assertRaisesRegex(ValueError, "refusing to truncate evidence"):
            alerts.normalize_and_join(
                [json.dumps({"session_id": "a"}), json.dumps({"session_id": "b"})],
                [None], [detection],
            )

        with self.assertRaisesRegex(ValueError, "refusing to truncate evidence"):
            alerts.normalize_and_join(
                [json.dumps({"session_id": "a"})], [None, None], [detection],
            )

    def test_equal_length_join_preserves_every_record(self):
        detection = SimpleNamespace(
            session_key=SimpleNamespace(primary_field="session_id", related_fields=[])
        )
        joined = alerts.normalize_and_join(
            [json.dumps({"session_id": "a"}), json.dumps({"session_id": "b"})],
            [None, "100999"], [detection],
        )
        self.assertEqual([row.primary_session_id for row in joined], ["a", "b"])
        self.assertEqual([row.matched_rule_id for row in joined], [None, "100999"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

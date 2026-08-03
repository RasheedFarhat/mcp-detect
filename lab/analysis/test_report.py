#!/usr/bin/env python3
"""Unit tests for lab/analysis/report.py's pure counting/join logic -- no
Docker/Wazuh involved (that path is already covered by the live
rule-sync-gated wazuh-logtest run; this is the piece with no other
regression guard, since the arithmetic here IS the report's deliverable).

Run: python3 -m unittest test_report -v   (from inside lab/analysis/)
"""
import json
import subprocess
import unittest
from unittest.mock import patch

import report as report_mod

from report import (
    JoinedRecord,
    NO_ALERT_RULE_ID,
    compute_aggregate_fp,
    compute_cross_scenario_firings,
    compute_per_rule_fp,
    compute_scenario_recall,
    cross_check_scenario_task,
    normalize_and_join,
)


def logtest_proc(*, blocks=0, returncode=0, stdout="", diagnostic=""):
    block = (
        "**Phase 1: Completed pre-decoding.\n"
        "**Phase 3: Completed filtering (rules).\n"
        "\tid: '100100'\n"
    )
    stderr = diagnostic + (block * blocks)
    return subprocess.CompletedProcess(["wazuh-logtest"], returncode, stdout, stderr)


class TestWazuhLogtestReliability(unittest.TestCase):
    def test_empty_batch_needs_no_environment(self):
        with patch.object(report_mod, "_invoke_wazuh_logtest") as invoke:
            self.assertEqual(report_mod.run_wazuh_logtest_batch([]), [])
        invoke.assert_not_called()

    def test_result_count_failure_gets_one_preflighted_retry(self):
        responses = [
            logtest_proc(diagnostic="Starting wazuh-logtest v4.9.0\n"),
            logtest_proc(blocks=1),  # bounded readiness preflight
            logtest_proc(blocks=1),  # one retry of the real batch
        ]
        with patch.object(report_mod, "_invoke_wazuh_logtest", side_effect=responses) as invoke:
            result = report_mod.run_wazuh_logtest_batch(["synthetic-event"])
        self.assertEqual(result, ["100100"])
        self.assertEqual(invoke.call_count, 3)

    def test_nonzero_invocation_failure_is_not_retried(self):
        proc = logtest_proc(returncode=7, diagnostic="ERROR: socket unavailable\n")
        with patch.object(report_mod, "_invoke_wazuh_logtest", return_value=proc) as invoke:
            with self.assertRaisesRegex(report_mod.WazuhLogtestInvocationError,
                                        "exited 7.*ERROR diagnostic present"):
                report_mod.run_wazuh_logtest_batch(["synthetic-event"])
        invoke.assert_called_once()

    def test_diagnostics_never_copy_event_content(self):
        secret = "SYNTHETIC-SECRET-MUST-NOT-LEAK"
        proc = logtest_proc(
            returncode=9,
            diagnostic=(
                "ERROR: engine unavailable\n"
                f"full event (1234): '{secret}'\n"
            ),
        )
        with self.assertRaises(report_mod.WazuhLogtestInvocationError) as caught:
            report_mod._parse_wazuh_logtest(proc, 1)
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("engine unavailable", str(caught.exception))
        self.assertIn("ERROR diagnostic present", str(caught.exception))

    def test_preflight_timeout_is_distinct(self):
        proc = logtest_proc(diagnostic="WARNING: not ready\n")
        with patch.object(report_mod, "_invoke_wazuh_logtest", return_value=proc), \
             patch.object(report_mod.time, "monotonic", side_effect=[0.0, 0.0, 2.0]):
            with self.assertRaisesRegex(report_mod.WazuhLogtestInvocationError,
                                        "preflight timed out.*awaiting exactly one"):
                report_mod.preflight_wazuh_logtest(timeout=1.0, interval=0.1)

    def test_phase_blocks_on_stdout_are_accepted(self):
        proc = logtest_proc(stdout=(
            "**Phase 1: Completed pre-decoding.\n"
            "**Phase 3: Completed filtering (rules).\n"
            "id: '100100'\n"
        ))
        self.assertEqual(report_mod._parse_wazuh_logtest(proc, 1), ["100100"])

    def test_phase_one_without_completed_filtering_is_incomplete(self):
        proc = logtest_proc(diagnostic="**Phase 1: Completed pre-decoding.\n")
        with self.assertRaisesRegex(report_mod.WazuhLogtestResultCountError,
                                    "1 incomplete block"):
            report_mod._parse_wazuh_logtest(proc, 1)

    def test_parent_rule_is_a_legitimate_non_match_and_is_not_retried(self):
        proc = logtest_proc(blocks=1)
        with patch.object(report_mod, "_invoke_wazuh_logtest", return_value=proc) as invoke:
            self.assertEqual(report_mod.run_wazuh_logtest_batch(["synthetic-event"]), ["100100"])
        invoke.assert_called_once()

    def test_completed_filtering_without_rule_id_is_incomplete(self):
        proc = logtest_proc(diagnostic=(
            "**Phase 1: Completed pre-decoding.\n"
            "**Phase 3: Completed filtering (rules).\n"
        ))
        with self.assertRaisesRegex(report_mod.WazuhLogtestResultCountError,
                                    "1 incomplete block"):
            report_mod._parse_wazuh_logtest(proc, 1)


def telemetry_line(*, session_id, scenario_id="benign", task_id="task",
                    label="benign", method="tools/call", **extra):
    record = {
        "session_id": session_id, "scenario_id": scenario_id, "task_id": task_id,
        "label": label, "method": method, "timestamp": "2026-01-01T00:00:00.000Z",
        **extra,
    }
    return json.dumps(record)


def drift_line(*, drift_session_id, baseline_first_seen_session_id="baseline-sid",
               scenario_id="rug_pull", task_id="task", label="malicious", **extra):
    record = {
        "drift_session_id": drift_session_id,
        "baseline_first_seen_session_id": baseline_first_seen_session_id,
        "scenario_id": scenario_id, "task_id": task_id, "label": label,
        "drift_field": "tool_description_hash", "timestamp": "2026-01-01T00:00:00.000Z",
        **extra,
    }
    return json.dumps(record)


def jr(rule_id, *, session_id=None, scenario_id="benign", task_id="task", **extra):
    """Build a JoinedRecord directly, bypassing normalize_and_join, for tests
    that only care about the metrics functions downstream of the join."""
    raw = {"session_id": session_id or "sid", "scenario_id": scenario_id,
           "task_id": task_id, **extra}
    return JoinedRecord(raw=raw, matched_rule_id=rule_id,
                         primary_session_id=raw["session_id"], related_session_ids=[])


class TestNormalizeAndJoin(unittest.TestCase):
    def test_session_id_present_used_directly(self):
        lines = [telemetry_line(session_id="s1")]
        joined = normalize_and_join(lines, ["100100"])
        self.assertEqual(joined[0].primary_session_id, "s1")
        self.assertEqual(joined[0].related_session_ids, [])
        self.assertEqual(joined[0].matched_rule_id, "100100")

    def test_drift_session_id_fallback(self):
        lines = [drift_line(drift_session_id="s2", baseline_first_seen_session_id="s1")]
        joined = normalize_and_join(lines, ["100201"])
        self.assertEqual(joined[0].primary_session_id, "s2")
        self.assertEqual(joined[0].related_session_ids, ["s1"])

    def test_session_id_takes_priority_if_somehow_both_present(self):
        # Defends the documented precedence: a record with a real session_id
        # is never treated as drift-shaped even if it also carried a
        # drift_session_id key (shouldn't happen in practice, but the
        # normalization must not silently pick the wrong one).
        record = json.loads(telemetry_line(session_id="s1"))
        record["drift_session_id"] = "s2"
        joined = normalize_and_join([json.dumps(record)], ["100100"])
        self.assertEqual(joined[0].primary_session_id, "s1")

    def test_unrecognized_shape_raises(self):
        line = json.dumps({"scenario_id": "x", "task_id": "y"})
        with self.assertRaises(ValueError):
            normalize_and_join([line], ["100100"])


class TestCrossCheckScenarioTask(unittest.TestCase):
    def test_consistent_labels_no_mismatch(self):
        joined = [
            jr("100100", session_id="s1", scenario_id="benign", task_id="t1"),
            jr("100101", session_id="s1", scenario_id="benign", task_id="t1"),
        ]
        self.assertEqual(cross_check_scenario_task(joined), [])

    def test_conflicting_scenario_id_within_one_session_flagged(self):
        joined = [
            jr("100100", session_id="s1", scenario_id="benign", task_id="t1"),
            jr("100101", session_id="s1", scenario_id="credential_exfil_via_read", task_id="t1"),
        ]
        mismatches = cross_check_scenario_task(joined)
        self.assertEqual(len(mismatches), 1)
        self.assertIn("s1", mismatches[0])


class TestAggregateFP(unittest.TestCase):
    def test_counts_alerting_records_only(self):
        benign = [
            jr(NO_ALERT_RULE_ID, session_id="s1"),
            jr(NO_ALERT_RULE_ID, session_id="s2"),
            jr("100101", session_id="s3"),  # a false positive
        ]
        result = compute_aggregate_fp(benign)
        self.assertEqual(result["total_records"], 3)
        self.assertEqual(result["total_sessions"], 3)
        self.assertEqual(result["alerting_records"], 1)
        self.assertEqual(result["alerting_details"], [("s3", "100101")])

    def test_zero_fp_case(self):
        benign = [jr(NO_ALERT_RULE_ID, session_id=f"s{i}") for i in range(5)]
        result = compute_aggregate_fp(benign)
        self.assertEqual(result["alerting_records"], 0)


class TestPerRuleFP(unittest.TestCase):
    def test_counts_and_denominators(self):
        benign = [
            jr(NO_ALERT_RULE_ID, session_id="s1"),
            jr("100102", session_id="s2"),
            jr("100102", session_id="s3"),
            jr("100104", session_id="s4"),
        ]
        denominators = {"benign_session_count": 100, "benign_tool_call_count": 200}
        result = compute_per_rule_fp(benign, denominators)
        self.assertEqual(result["100102"], (2, 100))
        self.assertEqual(result["100101"], (0, 200))
        self.assertEqual(result["100104"], (1, 200))
        self.assertEqual(result["100103"], (0, 200))


class TestScenarioRecall(unittest.TestCase):
    def test_task_with_alert_recorded(self):
        attack = [
            jr(NO_ALERT_RULE_ID, session_id="s1", scenario_id="tool_poisoning", task_id="t1"),
            jr("100102", session_id="s1", scenario_id="tool_poisoning", task_id="t1"),
        ]
        result = compute_scenario_recall(attack)
        self.assertEqual(result["tool_poisoning"]["t1"], ["100102"])

    def test_task_with_only_no_alert_records_shows_empty_list(self):
        # This is the "miss" case: every record for this task_id only ever
        # matched the parent (no-alert) rule.
        attack = [
            jr(NO_ALERT_RULE_ID, session_id="s1", scenario_id="tool_poisoning", task_id="t1"),
        ]
        result = compute_scenario_recall(attack)
        self.assertEqual(result["tool_poisoning"]["t1"], [])

    def test_cross_scenario_firing_does_not_count_toward_wrong_scenario(self):
        """The exact case the user flagged: a 100201 (rug-pull) alert on a
        credential_exfil_via_read-labeled task must be tallied under
        credential_exfil_via_read's own task_id -- it must NOT inflate
        rug_pull's recall count, and rug_pull's own task_ids must be
        unaffected by it."""
        attack = [
            # three genuine rug_pull task_ids, each correctly alerting
            jr("100201", session_id="s1", scenario_id="rug_pull", task_id="rp1"),
            jr("100201", session_id="s2", scenario_id="rug_pull", task_id="rp2"),
            jr("100201", session_id="s3", scenario_id="rug_pull", task_id="rp3"),
            # the cross-scenario artifact: 100201 fires on a
            # credential_exfil_via_read task, per its OWN scenario_id/task_id
            jr("100201", session_id="s4", scenario_id="credential_exfil_via_read", task_id="ce1"),
            jr(NO_ALERT_RULE_ID, session_id="s4", scenario_id="credential_exfil_via_read", task_id="ce1"),
        ]
        result = compute_scenario_recall(attack)

        # rug_pull recall must be exactly the 3 genuine task_ids -- 3/3, not 4/4.
        self.assertEqual(set(result["rug_pull"].keys()), {"rp1", "rp2", "rp3"})
        self.assertEqual(len(result["rug_pull"]), 3)
        for task in result["rug_pull"]:
            self.assertEqual(result["rug_pull"][task], ["100201"])

        # the cross-scenario firing lands under its own scenario/task, not rug_pull.
        self.assertIn("ce1", result["credential_exfil_via_read"])
        self.assertEqual(result["credential_exfil_via_read"]["ce1"], ["100201"])
        self.assertNotIn("ce1", result["rug_pull"])


class TestCrossScenarioFirings(unittest.TestCase):
    def test_single_scenario_rule_not_flagged(self):
        attack = [
            jr("100102", session_id="s1", scenario_id="tool_poisoning", task_id="t1"),
            jr("100102", session_id="s2", scenario_id="tool_poisoning", task_id="t2"),
        ]
        self.assertEqual(compute_cross_scenario_firings(attack), {})

    def test_multi_scenario_rule_flagged_with_correct_task_breakdown(self):
        attack = [
            jr("100201", session_id="s1", scenario_id="rug_pull", task_id="rp1"),
            jr("100201", session_id="s2", scenario_id="rug_pull", task_id="rp2"),
            jr("100201", session_id="s3", scenario_id="credential_exfil_via_read", task_id="ce1"),
            jr("100201", session_id="s4", scenario_id="credential_exfil_via_read", task_id="ce2"),
            jr("100102", session_id="s5", scenario_id="tool_poisoning", task_id="t1"),  # unrelated, single-scenario
        ]
        result = compute_cross_scenario_firings(attack)
        self.assertEqual(set(result.keys()), {"100201"})
        self.assertEqual(set(result["100201"].keys()), {"rug_pull", "credential_exfil_via_read"})
        self.assertEqual(result["100201"]["rug_pull"], ["rp1", "rp2"])
        self.assertEqual(result["100201"]["credential_exfil_via_read"], ["ce1", "ce2"])


if __name__ == "__main__":
    unittest.main()

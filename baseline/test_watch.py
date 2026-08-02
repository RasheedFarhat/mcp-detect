#!/usr/bin/env python3
"""Unit tests for baseline/watch.py -- the persistent rug-pull detector.

These test the detector logic in isolation, against hand-built records, with
no proxy/Wazuh/Docker involved. Corpus/attack-telemetry replay (real hashes
computed by proxy/hashing.py, real sessions) is integration validation, done
separately via wazuh-logtest -- see docs/PHASE3B-DESIGN.md's validation plan.
This file exists specifically because Q1 of that plan made the detector's
correctness a Python testing concern, not something to only prove by example
against real telemetry.

Run: python3 -m unittest baseline/test_watch.py -v
"""
import tempfile
import unittest
from io import StringIO
from pathlib import Path

from watch import (empty_state, load_state, process_file, process_follow_line,
                   process_record, save_state, approve_observed_hash,
                   apply_approval_file)

SERVER_CMD = "python3 attacks/servers/rugpull_email_server.py"
TOOL = "send_email"


def record(*, session_id, server_command=SERVER_CMD, method="tools/call",
           tool_name=TOOL, tool_description_hash=None, server_version_hash=None,
           scenario_id="rug_pull", task_id="task", label="malicious",
           timestamp="2026-07-09T00:00:00Z"):
    return {
        "session_id": session_id,
        "timestamp": timestamp,
        "method": method,
        "tool_name": tool_name,
        "server_command": server_command,
        "tool_description_hash": tool_description_hash,
        "server_version_hash": server_version_hash,
        "scenario_id": scenario_id,
        "task_id": task_id,
        "label": label,
    }


class TestFirstSeenBaseline(unittest.TestCase):
    def test_first_record_sets_baseline_no_alert(self):
        state = empty_state()
        events = process_record(
            record(session_id="s1", tool_description_hash="sha256:D0",
                   server_version_hash="sha256:V0"),
            state,
        )
        self.assertEqual(events, [])
        self.assertEqual(state["tool_description"][f"{TOOL}\x00{SERVER_CMD}"]["baseline_hash"], "sha256:D0")
        self.assertEqual(state["server_version"][SERVER_CMD]["baseline_hash"], "sha256:V0")

    def test_repeated_same_hash_never_alerts(self):
        state = empty_state()
        for _ in range(5):
            events = process_record(
                record(session_id="s1", tool_description_hash="sha256:D0",
                       server_version_hash="sha256:V0"),
                state,
            )
            self.assertEqual(events, [])

    def test_missing_fields_do_not_crash_or_alert(self):
        state = empty_state()
        # tools/list response: no tool_description_hash, no server_version_hash yet.
        events = process_record(
            {"session_id": "s1", "method": "tools/list", "server_command": SERVER_CMD,
             "tool_name": None, "tool_description_hash": None, "server_version_hash": None},
            state,
        )
        self.assertEqual(events, [])
        self.assertEqual(state, empty_state())


class TestDriftDetectionAndAttribution(unittest.TestCase):
    def setUp(self):
        self.state = empty_state()
        # baseline session establishes D0/V0.
        process_record(
            record(session_id="s-baseline", tool_description_hash="sha256:D0",
                   server_version_hash="sha256:V0"),
            self.state,
        )

    def test_both_drift_emits_two_correctly_attributed_events(self):
        events = process_record(
            record(session_id="s-pulled", tool_description_hash="sha256:D1",
                   server_version_hash="sha256:V1"),
            self.state,
        )
        self.assertEqual(len(events), 2)
        by_field = {e["drift_field"]: e for e in events}

        desc = by_field["tool_description_hash"]
        self.assertEqual(desc["baseline_hash"], "sha256:D0")
        self.assertEqual(desc["observed_hash"], "sha256:D1")
        self.assertEqual(desc["baseline_first_seen_session_id"], "s-baseline")
        self.assertEqual(desc["drift_session_id"], "s-pulled")
        self.assertEqual(desc["tool_name"], TOOL)

        ver = by_field["server_version_hash"]
        self.assertEqual(ver["baseline_hash"], "sha256:V0")
        self.assertEqual(ver["observed_hash"], "sha256:V1")
        self.assertEqual(ver["baseline_first_seen_session_id"], "s-baseline")
        self.assertEqual(ver["drift_session_id"], "s-pulled")
        self.assertIsNone(ver["tool_name"])  # server-level, not tool-level

    def test_description_only_drift(self):
        events = process_record(
            record(session_id="s-desc-only", tool_description_hash="sha256:D2",
                   server_version_hash="sha256:V0"),  # version unchanged
            self.state,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["drift_field"], "tool_description_hash")
        self.assertEqual(events[0]["observed_hash"], "sha256:D2")

    def test_version_only_drift(self):
        events = process_record(
            record(session_id="s-version-only", tool_description_hash="sha256:D0",  # unchanged
                   server_version_hash="sha256:V3"),
            self.state,
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["drift_field"], "server_version_hash")
        self.assertEqual(events[0]["observed_hash"], "sha256:V3")


class TestDedup(unittest.TestCase):
    def test_one_alert_per_newly_drifted_hash_not_per_record(self):
        state = empty_state()
        process_record(record(session_id="s0", tool_description_hash="sha256:D0",
                               server_version_hash="sha256:V0"), state)

        # A session with many records all carrying the SAME drifted
        # server_version_hash (realistic: schema.md says it's populated on
        # every record from `initialize` onward) must alert exactly once,
        # not once per record.
        total_events = []
        for i in range(6):
            total_events += process_record(
                record(session_id="s-pulled", server_version_hash="sha256:V1"),
                state,
            )
        self.assertEqual(len(total_events), 1)

    def test_revert_to_baseline_then_redrift_is_new_alert(self):
        state = empty_state()
        process_record(record(session_id="s0", server_version_hash="sha256:V0"), state)

        drift1 = process_record(record(session_id="s1", server_version_hash="sha256:V1"), state)
        self.assertEqual(len(drift1), 1)

        # revert to the original baseline value -- must not alert.
        no_alert = process_record(record(session_id="s2", server_version_hash="sha256:V0"), state)
        self.assertEqual(no_alert, [])

        # the exact same already-alerted drifted value reappearing -- must
        # not re-alert (dedup survives across sessions, not just within one).
        no_repeat = process_record(record(session_id="s3", server_version_hash="sha256:V1"), state)
        self.assertEqual(no_repeat, [])

        # a THIRD, distinct value -- new drift, new alert.
        drift2 = process_record(record(session_id="s4", server_version_hash="sha256:V2"), state)
        self.assertEqual(len(drift2), 1)
        self.assertEqual(drift2[0]["observed_hash"], "sha256:V2")
        self.assertEqual(drift2[0]["baseline_hash"], "sha256:V0")  # baseline never overwritten


class TestIndependentKeys(unittest.TestCase):
    def test_different_tool_names_tracked_independently(self):
        state = empty_state()
        process_record(record(session_id="s0", tool_name="tool_a",
                               tool_description_hash="sha256:A0"), state)
        process_record(record(session_id="s1", tool_name="tool_b",
                               tool_description_hash="sha256:B0"), state)

        # drift on tool_a must not affect tool_b's baseline or alert state.
        events_a = process_record(record(session_id="s2", tool_name="tool_a",
                                          tool_description_hash="sha256:A1"), state)
        events_b = process_record(record(session_id="s3", tool_name="tool_b",
                                          tool_description_hash="sha256:B0"), state)
        self.assertEqual(len(events_a), 1)
        self.assertEqual(events_b, [])

    def test_different_server_commands_tracked_independently(self):
        state = empty_state()
        process_record(record(session_id="s0", server_command="cmd-A",
                               server_version_hash="sha256:V0"), state)
        process_record(record(session_id="s1", server_command="cmd-B",
                               server_version_hash="sha256:V0"), state)

        events_a = process_record(record(session_id="s2", server_command="cmd-A",
                                          server_version_hash="sha256:V9"), state)
        events_b = process_record(record(session_id="s3", server_command="cmd-B",
                                          server_version_hash="sha256:V0"), state)
        self.assertEqual(len(events_a), 1)
        self.assertEqual(events_b, [])


class TestIdempotentReplay(unittest.TestCase):
    def test_replaying_the_same_file_twice_from_a_fresh_state_matches(self):
        lines = [
            record(session_id="s0", tool_description_hash="sha256:D0",
                   server_version_hash="sha256:V0"),
            record(session_id="s1", tool_description_hash="sha256:D1",
                   server_version_hash="sha256:V1"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.jsonl"
            path.write_text("\n".join(__import__("json").dumps(r) for r in lines) + "\n")

            state1 = empty_state()
            events1 = process_file(path, state1)

            state2 = empty_state()
            events2 = process_file(path, state2)

            self.assertEqual(events1, events2)
            self.assertEqual(state1, state2)

    def test_replaying_the_same_file_against_persisted_state_is_a_no_op(self):
        # Simulates re-running the watcher a second time over telemetry it
        # already saw once -- the persisted state file already has the
        # baseline AND has already alerted on the drifted value, so a second
        # pass over identical input must emit nothing new.
        lines = [
            record(session_id="s0", server_version_hash="sha256:V0"),
            record(session_id="s1", server_version_hash="sha256:V1"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "telemetry.jsonl"
            input_path.write_text("\n".join(__import__("json").dumps(r) for r in lines) + "\n")
            state_path = Path(tmp) / "state.json"

            state = load_state(state_path)
            first_pass = process_file(input_path, state)
            save_state(state_path, state)
            self.assertEqual(len(first_pass), 1)

            reloaded = load_state(state_path)
            second_pass = process_file(input_path, reloaded)
            self.assertEqual(second_pass, [])


class TestFollowPersistence(unittest.TestCase):
    def test_no_event_baseline_survives_restart_and_detects_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            state = empty_state()
            first = record(session_id="first", server_version_hash="sha256:V0")
            events = process_follow_line(__import__("json").dumps(first), state,
                                         StringIO(), state_path)
            self.assertEqual(events, [])
            self.assertTrue(state_path.exists())

            reloaded = load_state(state_path)
            changed = record(session_id="changed", server_version_hash="sha256:V1")
            drift = process_record(changed, reloaded)
            self.assertEqual(len(drift), 1)
            self.assertEqual(drift[0]["baseline_hash"], "sha256:V0")


class TestExplicitApproval(unittest.TestCase):
    def test_observed_drift_can_be_approved_and_is_audited(self):
        state = empty_state()
        process_record(record(session_id="s0", server_version_hash="sha256:V0"), state)
        drift = process_record(record(session_id="s1", server_version_hash="sha256:V1"), state)
        self.assertEqual(len(drift), 1)

        approve_observed_hash(state, {
            "kind": "server_version",
            "server_command": SERVER_CMD,
            "observed_hash": "sha256:V1",
            "approved_by": "reviewer@example.test",
            "reason": "Reviewed release 1.1",
            "approved_at": "2026-07-20T00:00:00Z",
        })
        entry = state["server_version"][SERVER_CMD]
        self.assertEqual(entry["baseline_hash"], "sha256:V1")
        self.assertEqual(entry["approval_history"][0]["previous_baseline_hash"], "sha256:V0")
        self.assertEqual(process_record(
            record(session_id="s2", server_version_hash="sha256:V1"), state
        ), [])

    def test_unobserved_hash_cannot_be_approved(self):
        state = empty_state()
        process_record(record(session_id="s0", server_version_hash="sha256:V0"), state)
        with self.assertRaisesRegex(ValueError, "has not been observed"):
            approve_observed_hash(state, {
                "kind": "server_version",
                "server_command": SERVER_CMD,
                "observed_hash": "sha256:FORGED",
                "approved_by": "reviewer@example.test",
                "reason": "Should fail",
            })

    def test_versioned_approval_file(self):
        state = empty_state()
        process_record(record(session_id="s0", tool_description_hash="sha256:D0"), state)
        process_record(record(session_id="s1", tool_description_hash="sha256:D1"), state)
        payload = {
            "version": 1,
            "approvals": [{
                "kind": "tool_description",
                "server_command": SERVER_CMD,
                "tool_name": TOOL,
                "observed_hash": "sha256:D1",
                "approved_by": "reviewer@example.test",
                "reason": "Schema diff reviewed",
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "approval.json"
            path.write_text(__import__("json").dumps(payload))
            self.assertEqual(apply_approval_file(state, path), 1)
        self.assertEqual(
            state["tool_description"][f"{TOOL}\x00{SERVER_CMD}"]["baseline_hash"],
            "sha256:D1",
        )


if __name__ == "__main__":
    unittest.main()

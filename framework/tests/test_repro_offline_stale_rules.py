#!/usr/bin/env python3
"""Proves framework/repro_offline.py's build_run() refuses to replay a
golden capture whose rule_sha256 doesn't match the rules it's being
checked against -- the "stale golden" guard added after a rule change,
not caught, could otherwise report numbers for a rule set that no longer
exists.

Uses a TEMP COPY of wazuh/local_rules.xml, mutated, never the real
committed file -- build_run() accepts an optional `rules_path` override
for exactly this reason (see its own docstring). No live stack needed;
this only exercises the sha-comparison guard, not wazuh-logtest itself.

Run: python3 framework/tests/test_repro_offline_stale_rules.py
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from framework import repro_offline  # noqa: E402


class TestStaleGoldenRefused(unittest.TestCase):
    def test_matching_sha_does_not_raise(self):
        """Sanity check: the guard doesn't false-positive against the real,
        unmutated committed rule file -- if this fails, the guard itself is
        broken, not the thing it's supposed to catch."""
        run = repro_offline.build_run("sample")
        self.assertIn("detections", run)

    def test_mutated_rule_file_is_refused(self):
        """A temp copy of local_rules.xml with different content has a
        different sha256 than what data/attack_corpus_sample_v1.golden_matches.json
        (and benign_corpus_v2.golden_matches.json) were captured against --
        build_run() must refuse, loudly, not replay stale numbers."""
        real_rules_text = repro_offline.RULES_PATH.read_text()
        mutated_text = real_rules_text + "\n<!-- test mutation -- simulates a rule change since golden capture -->\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            mutated_path = Path(tmpdir) / "mutated_local_rules.xml"
            mutated_path.write_text(mutated_text)

            with self.assertRaises(RuntimeError) as ctx:
                repro_offline.build_run("sample", rules_path=mutated_path)

            message = str(ctx.exception)
            self.assertIn("REFUSING TO REPLAY STALE GOLDEN RESULTS", message)
            self.assertIn("capture-golden", message)

    def test_current_rules_sha256_changes_with_content(self):
        """Direct check on the hashing helper itself, isolated from
        build_run()'s other checks."""
        real_sha = repro_offline.current_rules_sha256()

        with tempfile.TemporaryDirectory() as tmpdir:
            mutated_path = Path(tmpdir) / "mutated_local_rules.xml"
            mutated_path.write_text(repro_offline.RULES_PATH.read_text() + "\n<!-- mutated -->\n")
            mutated_sha = repro_offline.current_rules_sha256(mutated_path)

        self.assertNotEqual(real_sha, mutated_sha)


if __name__ == "__main__":
    unittest.main(verbosity=2)

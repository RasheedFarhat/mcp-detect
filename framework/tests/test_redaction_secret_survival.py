#!/usr/bin/env python3
"""Proves lab/redaction/redact.py's core promise: DATA MINIMIZATION, not
blocklist redaction. Two separate claims, both checked here:

1. None of the six credential-shape literals (`DATABASE_URL=`/`API_KEY=`
   assignments, `BEGIN ... PRIVATE KEY`, `sk-` keys, `postgres(ql)?://`,
   `AKIA...` ids) survive anywhere in the minimized export, while a fixed,
   non-recoverable marker for whichever shape was present DOES survive (so
   100101/100103-107 still fire) -- `TestRedactionSecretSurvival`.
2. Realistic secrets/PII with NONE of those six shapes (a plaintext
   password, an email+SSN pair, a JWT-shaped token, an internal hostname)
   ALSO do not survive -- not because this pass recognizes their shape (it
   doesn't try to; that would be the same open-ended blocklist problem
   lab/redaction/DESIGN.md explains is unwinnable), but because the field they
   live in (a tool-call argument other than `path`, or a tool response's
   free-text content) is not on the allowlist at all and is minimized
   regardless of shape -- `TestNonCredentialShapePIIMinimized`. This is the
   test the prior blocklist-only design silently lacked.

Structural fields required for detection/BOM correctness
(`tool_arguments.path`, `tool_description_hash`, `server_version_hash`,
`raw.result.tools`/`serverInfo`) are checked as untouched. No live stack
needed -- pure Python string/JSON processing over the already-committed
examples/northwindpay/telemetry.jsonl corpus, offline-safe like every other file in
this directory.

The literal secret/PII substrings checked here are fixed values planted by
examples/northwindpay/generate_corpus.py -- hardcoded here deliberately, not
imported from the generator, so this test independently verifies the
shipped corpus rather than trusting the generator's own self-consistency.

Run: python3 framework/tests/test_redaction_secret_survival.py
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "lab"))

from redaction.redact import (GENERIC_CONTENT_PLACEHOLDER, minimize_server_command,
                              minimize_string, redact_lines)  # noqa: E402

CORPUS_PATH = REPO_ROOT / "examples" / "northwindpay" / "telemetry.jsonl"

# The exact planted six-shape secret literals (examples/northwindpay/generate_corpus.py,
# build_production_ledger()/build_support_ticket_bot()) -- any ONE of these
# surviving anywhere in the minimized export is a bug.
PLANTED_SECRET_LITERALS = [
    "R7!qLmXo2z",                                    # the connection-string password
    "nwp_svc:R7!qLmXo2z@ledger-db.internal:5432",     # full credential-bearing span
    "AKIAIOSFODNN7EXAMPLE",                           # the literal AWS access key id
]

# The shape markers this specific corpus's minimized output MUST still
# contain somewhere (proof this is a marker, not deletion -- 100103-107/
# 100101 still need these to fire). Note "postgresql://" is NOT listed here:
# in this corpus every occurrence is embedded inside a `DATABASE_URL=...`
# assignment, and minimize_string() deliberately collapses a value matching
# multiple shapes into markers for each shape found -- but the DATABASE_URL
# marker alone is sufficient for the rule to fire, and this corpus's own
# postgres:// occurrences never appear independent of a DATABASE_URL=
# assignment. Standalone postgres:// preservation is covered by
# test_all_six_shapes_preserved_in_isolation.
REQUIRED_SURVIVING_MARKERS = [
    "DATABASE_URL=",
    "AKIA",
]

# Planted in build_fs_workspace()'s "legacy system notes" benign read
# (examples/northwindpay/generate_corpus.py) -- none of these match any of the six
# credential shapes wazuh/local_rules.xml keys on, and none are attacks;
# they are the kind of real content an actual client's docs legitimately
# contain. None may survive the minimized export.
PLANTED_NON_SHAPE_PII_LITERALS = [
    "Tr0ub4dor&3-legacy",                              # plaintext password
    "jane.doe@northwindpay.example",                   # email (also appears in a path elsewhere -- see below)
    "123-45-6789",                                     # SSN-shaped
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",             # JWT header segment
    "admin-legacy.northwindpay.corp",                  # internal hostname
]


class TestRedactionSecretSurvival(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw_lines = [l for l in CORPUS_PATH.read_text().splitlines() if l.strip()]
        cls.redacted_lines = redact_lines(cls.raw_lines)
        cls.redacted_text = "\n".join(cls.redacted_lines)

    def test_raw_corpus_actually_contains_the_planted_secrets(self):
        """Sanity check on the fixture itself -- if this fails, the corpus
        changed and PLANTED_SECRET_LITERALS is stale, not that minimization
        works."""
        raw_text = "\n".join(self.raw_lines)
        for literal in PLANTED_SECRET_LITERALS:
            self.assertIn(literal, raw_text, f"planted literal {literal!r} missing from raw corpus")

    def test_no_planted_secret_survives_redaction(self):
        for literal in PLANTED_SECRET_LITERALS:
            self.assertNotIn(literal, self.redacted_text,
                              f"planted secret {literal!r} survived minimization")

    def test_detection_shape_markers_still_present(self):
        """Minimization must not have deleted the signal outright -- the
        fixed markers still contain the literal substrings 100101/100103-107
        key on."""
        for marker in REQUIRED_SURVIVING_MARKERS:
            self.assertIn(marker, self.redacted_text,
                          f"shape marker {marker!r} missing after minimization -- detection would break")

    def test_record_count_unchanged(self):
        self.assertEqual(len(self.raw_lines), len(self.redacted_lines))

    def test_hashes_unchanged(self):
        """tool_description_hash / server_version_hash must be byte-identical
        before/after -- minimization never touches raw.result.tools/
        serverInfo, the fields these hashes are computed from
        (lab/redaction/DESIGN.md)."""
        mismatches = 0
        for raw_line, red_line in zip(self.raw_lines, self.redacted_lines):
            raw = json.loads(raw_line)
            red = json.loads(red_line)
            if raw.get("tool_description_hash") != red.get("tool_description_hash"):
                mismatches += 1
            if raw.get("server_version_hash") != red.get("server_version_hash"):
                mismatches += 1
        self.assertEqual(mismatches, 0)

    def test_tool_arguments_path_preserved_verbatim(self):
        """The path-traversal/sensitive-read signal (100101/100108) is the
        path string itself -- must never be minimized. This is the one
        argument value that survives in full, a disclosed residual (a path
        can itself embed something like a username -- see
        lab/redaction/DESIGN.md and the residual-disclosure report)."""
        checked = 0
        for raw_line, red_line in zip(self.raw_lines, self.redacted_lines):
            raw = json.loads(raw_line)
            red = json.loads(red_line)
            raw_args = raw.get("tool_arguments") or {}
            red_args = red.get("tool_arguments") or {}
            if "path" in raw_args:
                self.assertEqual(raw_args["path"], red_args.get("path"))
                checked += 1
        self.assertGreater(checked, 0, "no tool_arguments.path records found -- test fixture assumption broke")

    def test_tool_poisoning_and_homoglyph_content_untouched(self):
        """SAF-T1001/100102's signal (and the class-C homoglyph plant that
        must stay exactly as unmatchable as before) live in raw.result.tools
        -- protected, never scanned."""
        raw_text = "\n".join(self.raw_lines)
        self.assertIn("CONFIDENTIAL ADMIN OVERRIDE", raw_text)
        self.assertIn("CONFIDENTIAL ADMIN OVERRIDE", self.redacted_text)

    def test_all_six_shapes_preserved_in_isolation(self):
        """Direct, corpus-independent proof that each of the six secret
        shapes wazuh/local_rules.xml 100103-107 matches still matches its
        OWN identical regex after minimization -- exercised standalone so
        collapsing behavior for compound cases (e.g. a postgres:// URL
        embedded in a DATABASE_URL= value) can't hide a broken pattern."""
        cases = {
            "postgres_bare": ("postgres://user:pass@host/db", r"postgres(?:ql)?://"),
            "postgresql_bare": ("postgresql://user:pass@host/db", r"postgres(?:ql)?://"),
            "private_key": ("-----BEGIN RSA PRIVATE KEY-----\nabc123\n-----END RSA PRIVATE KEY-----",
                             r"BEGIN RSA PRIVATE KEY"),
            "sk_key": ("sk-abcDEF1234567890xyz", r"\bsk-[A-Za-z0-9_-]{6,}"),
            "api_key": ("API_KEY=supersecretvalue", r"API_KEY\s*="),
            "database_url": ("DATABASE_URL=postgres://user:pass@host/db", r"DATABASE_URL\s*="),
            "akia": ("AKIAABCDEFGHIJKLMNOP", r"AKIA[0-9A-Z]{16}"),  # AKIA + exactly 16 chars
        }
        for name, (original, must_still_match) in cases.items():
            minimized = minimize_string(original)
            with self.subTest(case=name):
                self.assertNotEqual(original, minimized, f"{name}: minimization had no effect at all")
                self.assertRegex(minimized, re.compile(must_still_match, re.IGNORECASE),
                                  f"{name}: minimized form {minimized!r} no longer matches its own detection shape")

    def test_non_path_benign_content_minimized_to_placeholder(self):
        """Correcting a prior test's stale assumption: under data
        minimization (not blocklist redaction), ordinary benign content in a
        non-path argument is NOT preserved verbatim -- it is reduced to the
        generic placeholder, same as anything else not on the allowlist,
        regardless of whether it happens to be benign. This IS the fix, not
        a regression: the old blocklist design's "benign content survives
        untouched" was exactly the property that let arbitrary non-six-shape
        secrets/PII through too (see TestNonCredentialShapePIIMinimized)."""
        benign_marker = "Confirmed refund eligible per policy 4.2"
        raw_text = "\n".join(self.raw_lines)
        self.assertIn(benign_marker, raw_text, "fixture assumption broke -- benign marker missing from raw corpus")
        self.assertNotIn(benign_marker, self.redacted_text,
                          "benign non-path content survived verbatim -- minimization is not being applied")
        self.assertIn(GENERIC_CONTENT_PLACEHOLDER, self.redacted_text)


class TestNonCredentialShapePIIMinimized(unittest.TestCase):
    """Closes the gap TestRedactionSecretSurvival alone left open: proves
    realistic secrets/PII that DON'T match any of the six recognized
    credential shapes still don't survive minimization, because the field
    they live in isn't on the allowlist at all -- not because this pass
    tries to recognize passwords/PII shapes (it doesn't, deliberately;
    see lab/redaction/DESIGN.md)."""

    @classmethod
    def setUpClass(cls):
        cls.raw_lines = [l for l in CORPUS_PATH.read_text().splitlines() if l.strip()]
        cls.redacted_lines = redact_lines(cls.raw_lines)
        cls.redacted_text = "\n".join(cls.redacted_lines)

    def test_raw_corpus_contains_the_planted_pii(self):
        raw_text = "\n".join(self.raw_lines)
        for literal in PLANTED_NON_SHAPE_PII_LITERALS:
            self.assertIn(literal, raw_text, f"planted PII literal {literal!r} missing from raw corpus")

    def test_none_of_these_match_any_recognized_credential_shape(self):
        """Sanity check on the premise: these literals must NOT accidentally
        collide with one of the six shapes -- if they did, they'd survive as
        a marker for a different (correct) reason, not prove the
        minimization-of-unrecognized-content path at all."""
        for literal in PLANTED_NON_SHAPE_PII_LITERALS:
            with self.subTest(literal=literal):
                self.assertEqual(minimize_string(literal), GENERIC_CONTENT_PLACEHOLDER,
                                  f"{literal!r} matched a recognized shape -- rewrite the fixture, this proves the wrong thing")

    def test_no_planted_pii_survives_minimization(self):
        for literal in PLANTED_NON_SHAPE_PII_LITERALS:
            self.assertNotIn(literal, self.redacted_text,
                              f"non-credential-shape PII {literal!r} survived minimization")

    def test_email_in_path_is_the_one_disclosed_exception(self):
        """tool_arguments.path IS preserved verbatim by design (lab/redaction/
        DESIGN.md's disclosed residual) -- this specific email appears in a
        path argument (a per-user backup directory name) and DOES survive,
        deliberately. This is the one planted literal excluded from the
        blanket 'nothing survives' claim above, and it's exactly why
        lab/redaction/redact.py --report's residual-disclosure pass exists: to
        flag it for manual review, not to hide that it happens."""
        self.assertIn("backups/alex.smith@northwindpay.example/settings.json", self.redacted_text)


class TestServerCommandMinimization(unittest.TestCase):
    def test_common_credential_flags_and_assignments_are_minimized(self):
        commands = [
            "node server --api-key SYNTHETIC_ONE --safe yes",
            "node server --access-token=SYNTHETIC_TWO",
            "MCP_CLIENT_SECRET=SYNTHETIC_THREE node server",
        ]
        for command in commands:
            with self.subTest(command=command):
                minimized = minimize_server_command(command)
                self.assertNotIn("SYNTHETIC_", minimized)
                self.assertIn("[REDACTED]", minimized)

    def test_benign_command_is_unchanged(self):
        command = "npx -y @modelcontextprotocol/server-filesystem /workspace"
        self.assertEqual(minimize_server_command(command), command)


if __name__ == "__main__":
    unittest.main(verbosity=2)

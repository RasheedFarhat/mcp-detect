#!/usr/bin/env python3
"""Tests for proxy.py's proxy_anomaly marker records (schema.md's "v1 ->
v1.1" addition) -- confirms an unparseable line and a valid-but-non-object
JSON line both produce a proxy_anomaly record, and that neither ever
carries the original line's actual content, only metadata (reason +
byte_length). Stdlib-only (unittest), no live proxy subprocess needed --
parse_line_to_record() is pure and directly testable.

Inputs are real `bytes`, matching exactly what pump() actually reads off
the stream (asyncio's StreamReader never decodes) -- not `str`. An
earlier draft of this test suite used `str` literals, which passed
cleanly while the function under test actually crashed on live bytes
(`stripped_line.encode()` on an already-bytes object) -- caught only by
a live end-to-end smoke test against a real subprocess, not by this
suite, because the suite was testing the wrong input type. Fixed here so
the same class of gap can't hide again.

Run: python3 proxy/test_proxy.py
"""
from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))

from proxy import Session, parse_line_to_record, pump, STREAM_LIMIT  # noqa: E402
from hashing import sanitize_server_command, sanitize_server_command_parts  # noqa: E402


def make_session() -> Session:
    return Session(
        session_id="11111111-1111-1111-1111-111111111111",
        server_command="fake-server --arg value",
        label="benign",
        scenario_id="benign",
        task_id="test_proxy_anomaly",
    )


class TestInvalidJson(unittest.TestCase):
    def test_unparseable_line_produces_anomaly_record(self):
        garbage = b"not json at all { unbalanced"
        record = parse_line_to_record(garbage, make_session(), "server_to_client")
        self.assertIsNotNone(record)
        self.assertIn("proxy_anomaly", record)
        self.assertEqual(record["proxy_anomaly"]["reason"], "invalid_json")
        self.assertEqual(record["proxy_anomaly"]["byte_length"], len(garbage))

    def test_invalid_utf8_bytes_produce_anomaly_record_not_a_crash(self):
        # json.loads() on bytes can raise UnicodeDecodeError for a genuinely
        # malformed byte sequence, not just JSONDecodeError -- an
        # unhandled exception here would crash the whole proxy process
        # mid-session. Regression test for exactly that bug.
        garbage = b"\x80\x81\x82 not valid utf-8"
        record = parse_line_to_record(garbage, make_session(), "server_to_client")
        self.assertIsNotNone(record)
        self.assertEqual(record["proxy_anomaly"]["reason"], "invalid_json")
        self.assertEqual(record["proxy_anomaly"]["byte_length"], len(garbage))

    def test_truncated_multibyte_utf8_sequence_produces_anomaly_record(self):
        garbage = b"\xc3"  # a lone leading byte of a 2-byte UTF-8 sequence
        record = parse_line_to_record(garbage, make_session(), "client_to_server")
        self.assertIsNotNone(record)
        self.assertEqual(record["proxy_anomaly"]["reason"], "invalid_json")

    def test_anomaly_record_never_contains_original_content(self):
        garbage = b"SECRET_TOKEN_abc123_should_never_appear_anywhere { unbalanced"
        record = parse_line_to_record(garbage, make_session(), "server_to_client")
        import json as json_mod
        serialized = json_mod.dumps(record)
        self.assertNotIn("SECRET_TOKEN_abc123", serialized)
        self.assertNotIn(garbage.decode("utf-8"), serialized)

    def test_anomaly_record_shape_is_schema_consistent(self):
        record = parse_line_to_record(b"{{{", make_session(), "server_to_client")
        # Every other field stays null/session-derived, exactly like a
        # record with no real message content -- never repurposed to carry
        # anything about the anomalous line itself.
        self.assertIsNone(record["method"])
        self.assertIsNone(record["message_id"])
        self.assertIsNone(record["tool_name"])
        self.assertIsNone(record["tool_arguments"])
        self.assertIsNone(record["result_summary"])
        self.assertIsNone(record["tool_description_hash"])
        self.assertEqual(record["raw"], {"jsonrpc": "2.0"})
        self.assertEqual(record["session_id"], "11111111-1111-1111-1111-111111111111")
        self.assertEqual(record["server_command"], "fake-server --arg value")

    def test_byte_length_is_real_byte_count_not_character_count(self):
        # "é" as a single precomposed character is 1 Python str char but 2 UTF-8 bytes.
        garbage = "café-not-valid-json {".encode("utf-8")
        record = parse_line_to_record(garbage, make_session(), "client_to_server")
        self.assertEqual(record["proxy_anomaly"]["byte_length"], len(garbage))
        self.assertNotEqual(record["proxy_anomaly"]["byte_length"], len("café-not-valid-json {"))


class TestNonObjectJson(unittest.TestCase):
    def test_bare_array_produces_anomaly_record(self):
        line = b"[1, 2, 3]"
        record = parse_line_to_record(line, make_session(), "server_to_client")
        self.assertIsNotNone(record)
        self.assertIn("proxy_anomaly", record)
        self.assertEqual(record["proxy_anomaly"]["reason"], "non_object_json")
        self.assertEqual(record["proxy_anomaly"]["byte_length"], len(line))

    def test_bare_array_never_contains_original_content(self):
        line = b'["SECRET_VALUE_xyz789", 42, true]'
        record = parse_line_to_record(line, make_session(), "server_to_client")
        import json as json_mod
        serialized = json_mod.dumps(record)
        self.assertNotIn("SECRET_VALUE_xyz789", serialized)

    def test_bare_number_and_bare_string_also_produce_anomaly_record(self):
        for line in [b"42", b'"just a string"', b"null", b"true"]:
            record = parse_line_to_record(line, make_session(), "server_to_client")
            self.assertIsNotNone(record, f"line {line!r} should still produce a record")
            self.assertEqual(record["proxy_anomaly"]["reason"], "non_object_json")


class TestNormalMessagesUnaffected(unittest.TestCase):
    def test_server_command_sanitizer_removes_common_credential_values(self):
        command = "node server --api-key SYNTHETIC_SECRET --safe yes"
        sanitized = sanitize_server_command(command)
        self.assertNotIn("SYNTHETIC_SECRET", sanitized)
        self.assertEqual(sanitized, "node server --api-key [REDACTED] --safe yes")

    def test_server_argv_sanitizer_preserves_boundaries_for_spaced_secret(self):
        parts = ["node", "server", "--password", "synthetic secret with spaces", "--safe"]
        sanitized = sanitize_server_command_parts(parts)
        self.assertEqual(sanitized, ["node", "server", "--password", "[REDACTED]", "--safe"])
        self.assertNotIn("synthetic secret", " ".join(sanitized))

    def test_blank_line_produces_no_record(self):
        self.assertIsNone(parse_line_to_record(b"", make_session(), "server_to_client"))

    def test_real_jsonrpc_object_produces_a_normal_record_with_no_anomaly_field(self):
        line = (b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", '
                b'"params": {"name": "echo", "arguments": {"message": "hi"}}}')
        record = parse_line_to_record(line, make_session(), "client_to_server")
        self.assertNotIn("proxy_anomaly", record)
        self.assertEqual(record["method"], "tools/call")
        self.assertEqual(record["tool_name"], "echo")
        self.assertEqual(record["tool_arguments"], {"message": "hi"})


class _RecordingLogger:
    """Stand-in for JsonlLogger: keeps records in memory, no file I/O."""

    def __init__(self):
        self.records = []

    def write(self, record):
        self.records.append(record)

    def close(self):
        pass


class _RecordingWriter:
    """Stand-in for the forwarding side of pump(): keeps every byte written,
    so byte-transparency can be asserted directly against the input."""

    def __init__(self):
        self.data = bytearray()

    def write(self, chunk):
        self.data.extend(chunk)

    async def drain(self):
        pass


class TestPumpOverLimitLine(unittest.IsolatedAsyncioTestCase):
    """Regression test: asyncio.StreamReader's readline() raises a bare
    ValueError -- crashing pump() and the whole proxy task mid-capture --
    on any single line longer than its configured limit. A real MCP tool
    result (a file dump, a base64 image) can legitimately be that long on
    one line; this must not crash the proxy or drop the line's bytes.
    """

    async def test_line_within_new_limit_but_over_old_64kb_default_is_forwarded_and_logged_normally(self):
        # 200 KB: would have crashed pump() under asyncio's old 64 KiB
        # StreamReader default, comfortably under the proxy's own STREAM_LIMIT.
        big = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"blob": "A" * 200_000}})
        line = (big + "\n").encode()
        reader = asyncio.StreamReader(limit=STREAM_LIMIT)
        reader.feed_data(line)
        reader.feed_eof()

        logger = _RecordingLogger()
        writer = _RecordingWriter()
        session = make_session()
        await pump(reader, writer, logger, session, "server_to_client")

        self.assertEqual(bytes(writer.data), line, "line must be forwarded byte-for-byte")
        self.assertEqual(len(logger.records), 1)
        self.assertNotIn("proxy_anomaly", logger.records[0])
        self.assertEqual(logger.records[0]["message_id"], 1)
        self.assertIsNotNone(logger.records[0]["result_summary"])

    async def test_line_exceeding_stream_limit_does_not_crash_and_is_still_forwarded(self):
        # Bigger than even the raised STREAM_LIMIT -- must not crash the
        # task, must still forward every byte (transparency > logging), and
        # must produce a line_too_long proxy_anomaly instead of a normal
        # record (the line is too large to safely buffer whole for logging).
        tail = json.dumps({"marker": "END"}) + "\n"
        giant = b"X" * (STREAM_LIMIT + 5000) + tail.encode()
        reader = asyncio.StreamReader(limit=STREAM_LIMIT)
        reader.feed_data(giant)
        reader.feed_eof()

        logger = _RecordingLogger()
        writer = _RecordingWriter()
        session = make_session()
        await pump(reader, writer, logger, session, "server_to_client")

        self.assertEqual(bytes(writer.data), giant, "every byte must still reach the other side")
        anomalies = [r for r in logger.records if r.get("proxy_anomaly")]
        self.assertGreaterEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["proxy_anomaly"]["reason"], "line_too_long")
        self.assertGreaterEqual(anomalies[0]["proxy_anomaly"]["byte_length"], STREAM_LIMIT)
        # Never the line's actual content, same discipline as every other
        # proxy_anomaly marker.
        serialized = json.dumps(logger.records)
        self.assertNotIn("X" * 100, serialized)
        schema = json.loads((Path(__file__).resolve().parent.parent / "schema" / "schema.json").read_text())
        errors = list(jsonschema.Draft202012Validator(schema).iter_errors(anomalies[0]))
        self.assertEqual(errors, [], f"generated line_too_long marker violated schema: {errors}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

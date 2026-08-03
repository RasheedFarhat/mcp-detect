#!/usr/bin/env python3
"""Hand-authored deterministic benign sessions -- no LLM.

lab/corpus/agent.py's qwen3:1.7b drives realistic *structural* JSON-RPC telemetry,
but its behavioral distribution (tool sequences, argument choices) is that of
a small, sometimes-clumsy model, not a frontier-class agent. This module
fills that gap with scripted, deterministic multi-step sessions -- the kind
of tool-call sequence a real production agent reliably produces (chaining
across servers, using one call's real result to inform the next) but a 1.4GB
model does not reliably produce on its own.

Every session here runs through the exact same proxy.py as agent.py and
client.py, so it carries identical schema-v1 fields. task_id is always
prefixed "handauthored_" so the dataset is transparent about provenance --
anyone consuming the corpus can filter these in or out.

Deterministic == fast and reliable: this also works as regression coverage,
similar in spirit to `make smoke`, just spanning more servers/patterns.
"""
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

WORKSPACE = "/app/workspace"

FILESYSTEM_CMD = ["npx", "-y", "@modelcontextprotocol/server-filesystem@2026.7.4", WORKSPACE]
GIT_CMD = ["mcp-server-git", "--repository", WORKSPACE]
FETCH_CMD = ["mcp-server-fetch"]
MEMORY_CMD = ["npx", "-y", "@modelcontextprotocol/server-memory@2026.7.4"]
TIME_CMD = ["mcp-server-time"]


def open_session(server_command: list[str], log_path: str, task_id: str):
    proxy_command = [
        "python3", "lab/proxy/proxy.py",
        "--log-path", log_path,
        "--label", "benign",
        "--scenario-id", "benign",
        "--task-id", f"handauthored_{task_id}",
        "--",
    ] + server_command
    server_params = StdioServerParameters(command=proxy_command[0], args=proxy_command[1:])
    return stdio_client(server_params)


async def call(session: ClientSession, tool_name: str, arguments: dict) -> str:
    result = await session.call_tool(tool_name, arguments)
    if result.isError:
        return f"ERROR: {result.content}"
    for block in result.content:
        if getattr(block, "type", None) == "text":
            return block.text
    return ""


async def run_one(server_command: list[str], task_id: str, log_path: str, steps):
    """steps: list of (tool_name, arguments_fn) where arguments_fn(prev_result) -> dict.
    prev_result is None for the first step."""
    print(f"[handauthored] === {task_id} ===", file=sys.stderr)
    async with open_session(server_command, log_path, task_id) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.list_tools()
            prev = None
            for tool_name, args_fn in steps:
                args = args_fn(prev)
                print(f"[handauthored]   {tool_name}({args})", file=sys.stderr)
                prev = await call(session, tool_name, args)
    print(f"[handauthored] {task_id} complete.", file=sys.stderr)


async def scenario_readme_then_fetch_spec(log_path: str):
    """Read README (fs) -> fetch the MCP spec README it references (fetch)."""
    await run_one(FILESYSTEM_CMD, "readme_step1_fs", log_path, [
        ("read_text_file", lambda _: {"path": "README.md"}),
    ])
    await run_one(FETCH_CMD, "readme_step2_fetch", log_path, [
        ("fetch", lambda _: {
            "url": "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md"
        }),
    ])


async def scenario_gitlog_then_read_file(log_path: str):
    """git log (git) -> read a file referenced by the project's docs (fs)."""
    await run_one(GIT_CMD, "gitlog_step1_git", log_path, [
        ("git_log", lambda _: {"repo_path": WORKSPACE, "max_count": 5}),
    ])
    await run_one(FILESYSTEM_CMD, "gitlog_step2_fs", log_path, [
        ("read_text_file", lambda _: {"path": "lab/schema/schema.md"}),
    ])


async def scenario_fetch_then_memory_note(log_path: str):
    """Fetch a page (fetch) -> store a memory note referencing what was found (memory)."""
    await run_one(FETCH_CMD, "fetchmem_step1_fetch", log_path, [
        ("fetch", lambda _: {"url": "https://example.com"}),
    ])
    await run_one(MEMORY_CMD, "fetchmem_step2_memory", log_path, [
        ("create_entities", lambda _: {"entities": [
            {"name": "example.com", "entityType": "website", "observations": []},
        ]}),
        ("add_observations", lambda _: {"observations": [
            {"entityName": "example.com",
             "contents": ["example.com is IANA's reserved documentation domain, confirmed by fetching it."]},
        ]}),
    ])


async def scenario_time_survey_three_zones(log_path: str):
    """Three sequential time lookups across different zones in one session."""
    await run_one(TIME_CMD, "time_survey", log_path, [
        ("get_current_time", lambda _: {"timezone": "Etc/UTC"}),
        ("get_current_time", lambda _: {"timezone": "Asia/Tokyo"}),
        ("get_current_time", lambda _: {"timezone": "America/New_York"}),
    ])


async def scenario_read_multiple_docs(log_path: str):
    """One session, one call: read_multiple_files across 3 real docs at once."""
    await run_one(FILESYSTEM_CMD, "read_multiple_docs", log_path, [
        ("read_multiple_files", lambda _: {
            "paths": ["README.md", "docs/PHASE0.md", "docs/PHASE1.md"],
        }),
    ])


async def scenario_memory_build_small_graph(log_path: str):
    """Deterministic multi-step knowledge graph build: create entities, relate, observe."""
    await run_one(MEMORY_CMD, "build_graph", log_path, [
        ("create_entities", lambda _: {"entities": [
            {"name": "mcp-detect", "entityType": "project", "observations": []},
            {"name": "Phase1", "entityType": "milestone", "observations": []},
        ]}),
        ("create_relations", lambda _: {"relations": [
            {"from": "mcp-detect", "to": "Phase1", "relationType": "completed"},
        ]}),
        ("add_observations", lambda _: {"observations": [
            {"entityName": "Phase1",
             "contents": ["Phase 1 delivered a containerized lab, schema v1, and a benign corpus."]},
        ]}),
    ])


async def scenario_git_survey(log_path: str):
    """git status -> git log -> git branch, in one deterministic sequence."""
    await run_one(GIT_CMD, "git_survey", log_path, [
        ("git_status", lambda _: {"repo_path": WORKSPACE}),
        ("git_log", lambda _: {"repo_path": WORKSPACE, "max_count": 3}),
        ("git_branch", lambda _: {"repo_path": WORKSPACE, "branch_type": "local"}),
    ])


async def scenario_fetch_compare_two_sources(log_path: str):
    """Fetch two different real sources sequentially within one session."""
    await run_one(FETCH_CMD, "fetch_compare", log_path, [
        ("fetch", lambda _: {"url": "https://www.python.org/about/"}),
        ("fetch", lambda _: {"url": "https://www.iana.org/help/example-domains"}),
    ])


async def scenario_near_boundary_config_read(log_path: str):
    """FIX 4: pin a near-boundary benign read permanently as deterministic regression
    coverage, not just LLM-generated volume. Reads all 3 fixtures whose paths contain
    "config"/"env"/"keys"-adjacent terms but do not match the sensitive-read rule --
    see lab/corpus/fixtures/README.md and lab/corpus/tasks.py's docstring for why these are
    safe. Looped BOUNDARY_REPEAT times below (same weight as the fs boundary tasks
    in tasks.py): these events are what the false-positive claim rests on and must
    not be a rounding error."""
    await run_one(FILESYSTEM_CMD, "near_boundary_config_read", log_path, [
        ("read_text_file", lambda _: {"path": "lab/corpus/fixtures/example.env.txt"}),
        ("read_text_file", lambda _: {"path": "lab/corpus/fixtures/config/app_settings.json"}),
        ("read_text_file", lambda _: {"path": "lab/corpus/fixtures/keys/keys_directory_readme.md"}),
    ])


# (scenario_fn, repeat_count) -- everything defaults to 1 run except the
# near-boundary case, which carries the same repeat weight as its LLM-driven
# counterparts in tasks.py (see DEFAULT_REPEAT / the 5 fs_read_* boundary tasks).
BOUNDARY_REPEAT = 25
SCENARIOS = [
    (scenario_readme_then_fetch_spec, 1),        # 2 sessions
    (scenario_gitlog_then_read_file, 1),         # 2 sessions
    (scenario_fetch_then_memory_note, 1),        # 2 sessions
    (scenario_time_survey_three_zones, 1),       # 1 session
    (scenario_read_multiple_docs, 1),            # 1 session
    (scenario_memory_build_small_graph, 1),      # 1 session
    (scenario_git_survey, 1),                    # 1 session
    (scenario_fetch_compare_two_sources, 1),     # 1 session
    (scenario_near_boundary_config_read, BOUNDARY_REPEAT),  # 25 sessions
]
# Total: 12 base sessions across 9 scenarios, + 24 extra near-boundary repeats = 36 sessions.


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True)
    args = parser.parse_args()

    total = sum(n for _, n in SCENARIOS)
    print(f"[handauthored] run plan: {total} sessions across {len(SCENARIOS)} scenarios",
          file=sys.stderr)
    for scenario, count in SCENARIOS:
        for _ in range(count):
            asyncio.run(scenario(args.log_path))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Ollama-backed MCP agent: the benign corpus generator.

Unlike lab/client/client.py (deterministic, scripted, no LLM -- the fast `make
smoke` pipeline check), this drives a real local LLM that autonomously
decides which tools to call and with what arguments, across whichever MCP
server a task names. Realistic multi-server tool use is the point: this is
what generates the labeled benign telemetry corpus.

Corpus reproducibility framing (confirmed with the project owner): the
PUBLISHED corpus is the frozen, checksummed capture -- bit-stable and
versioned. This generator (lab + task list + pinned model + temperature=0) is
open and re-runnable, but an LLM is not deterministic even at temperature=0
across hardware/driver/quantization differences, so re-running this script
produces statistically similar, not identical, telemetry. Do not treat a
fresh run as reproducing the frozen corpus byte-for-byte.
"""
import argparse
import asyncio
import json
import os
import sys

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
MODEL = "qwen3:1.7b"
MAX_TURNS = 6
TOOL_CALL_TIMEOUT = 90  # seconds. Phase 1 had no timeout at all here and hit a
# git call that looked hung for 20+ minutes (it wasn't, in the end, but there
# was no way to tell short of watching it) -- a genuinely stuck subprocess
# must not be able to wedge a whole corpus run. On timeout we abandon this
# session (can't safely trust the transport after that) and move on, same
# fault-isolation posture as the Ollama-500 retry below.
SYSTEM_PROMPT = (
    "You are a helpful assistant with access to tools. Use the tools provided "
    "to accomplish the user's request. When you have the information needed to "
    "answer, respond with a final natural-language answer and do not call any "
    "more tools."
)


def mcp_tools_to_ollama(tools) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema or {"type": "object", "properties": {}},
            },
        }
        for t in tools
    ]


def extract_text(call_result) -> str:
    if call_result.isError:
        return f"ERROR: {call_result.content}"
    parts = []
    for block in call_result.content:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts) if parts else "(no text content)"


async def chat(client: httpx.AsyncClient, messages: list[dict], tools: list[dict],
               retries: int = 2) -> dict:
    """Call Ollama's /api/chat, retrying on transient 5xx errors.

    Observed empirically during corpus generation: Ollama's llama-server
    backend occasionally throws a bare 500 ("completion error ... EOF") under
    this environment's CPU-only inference, with no apparent pattern -- a
    retry of the exact same request succeeds. Not something our code can fix;
    just needs to not take the whole corpus run down with it.
    """
    last_exc = None
    for attempt in range(retries + 1):
        try:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/chat",
                json={
                    "model": MODEL,
                    "messages": messages,
                    "tools": tools,
                    "stream": False,
                    "options": {"temperature": 0},
                },
                timeout=300,
            )
            resp.raise_for_status()
            return resp.json()["message"]
        except httpx.HTTPStatusError as exc:
            last_exc = exc
            if exc.response.status_code < 500 or attempt == retries:
                raise
            print(f"[agent] Ollama {exc.response.status_code}, retrying "
                  f"({attempt + 1}/{retries})...", file=sys.stderr)
            await asyncio.sleep(2)
    raise last_exc


async def run_task(task: dict, log_path: str, scenario_id: str) -> None:
    task_id = task["task_id"]
    print(f"[agent] === task: {task_id} ===", file=sys.stderr)

    proxy_command = [
        "python3", "lab/proxy/proxy.py",
        "--log-path", log_path,
        "--label", "benign",
        "--scenario-id", scenario_id,
        "--task-id", task_id,
        "--",
    ] + task["server_command"]

    server_params = StdioServerParameters(command=proxy_command[0], args=proxy_command[1:])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            ollama_tools = mcp_tools_to_ollama(tools_result.tools)
            print(f"[agent] tools available: {[t.name for t in tools_result.tools]}", file=sys.stderr)

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task["prompt"]},
            ]

            async with httpx.AsyncClient() as http_client:
                for turn in range(MAX_TURNS):
                    message = await chat(http_client, messages, ollama_tools)
                    tool_calls = message.get("tool_calls") or []

                    if not tool_calls:
                        print(f"[agent] final answer: {message.get('content', '')!r}", file=sys.stderr)
                        break

                    messages.append(message)
                    for call in tool_calls:
                        fn = call["function"]
                        name, arguments = fn["name"], fn.get("arguments") or {}
                        print(f"[agent] turn {turn}: calling {name}({arguments})", file=sys.stderr)
                        try:
                            call_result = await asyncio.wait_for(
                                session.call_tool(name, arguments), timeout=TOOL_CALL_TIMEOUT
                            )
                            result_text = extract_text(call_result)
                        except asyncio.TimeoutError:
                            print(f"[agent] tool call {name} TIMED OUT after "
                                  f"{TOOL_CALL_TIMEOUT}s -- abandoning this session",
                                  file=sys.stderr)
                            raise
                        except Exception as exc:  # a tool call *erroring* (not hanging) is not fatal to the task
                            result_text = f"ERROR: {exc}"
                        messages.append({"role": "tool", "content": result_text})
                else:
                    print(f"[agent] WARNING: task {task_id} hit MAX_TURNS without a final answer",
                          file=sys.stderr)

    print(f"[agent] task {task_id} complete.", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True)
    parser.add_argument("--scenario-id", default="benign")
    parser.add_argument("--task-id", help="Run only this task (default: run all tasks in tasks.py)")
    parser.add_argument("--repeat", type=int, default=1,
                         help="With --task-id: run that task exactly this many times. "
                              "Without --task-id: global multiplier on top of each task's "
                              "own per-task 'repeat' weight from tasks.py (default 1x).")
    args = parser.parse_args()

    from tasks import DEFAULT_REPEAT, TASKS

    selected = [t for t in TASKS if args.task_id is None or t["task_id"] == args.task_id]
    if not selected:
        parser.error(f"no task with task_id={args.task_id!r}")

    # Build the run plan up front so per-task repeat weights (tasks.py's
    # "repeat" field -- the near-boundary fs tasks carry a much higher one)
    # are honored on a full run, while a single --task-id run still just
    # uses --repeat directly for quick, predictable manual testing.
    if args.task_id is not None:
        run_plan = [(task, rep) for task in selected for rep in range(args.repeat)]
    else:
        run_plan = [
            (task, rep)
            for task in selected
            for rep in range(task.get("repeat", DEFAULT_REPEAT) * args.repeat)
        ]

    print(f"[agent] run plan: {len(run_plan)} sessions across {len(selected)} task(s)",
          file=sys.stderr)

    failures = []
    for task, rep in run_plan:
        try:
            asyncio.run(run_task(task, args.log_path, args.scenario_id))
        except Exception as exc:
            print(f"[agent] task {task['task_id']} (rep {rep}) FAILED, "
                  f"continuing with remaining tasks: {exc}", file=sys.stderr)
            failures.append((task["task_id"], rep, str(exc)))

    if failures:
        print(f"[agent] {len(failures)} task run(s) failed out of "
              f"{len(run_plan)}:", file=sys.stderr)
        for task_id, rep, err in failures:
            print(f"  - {task_id} (rep {rep}): {err}", file=sys.stderr)
    else:
        print(f"[agent] all {len(run_plan)} sessions completed with no failures.", file=sys.stderr)


if __name__ == "__main__":
    main()

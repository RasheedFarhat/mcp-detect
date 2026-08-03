#!/usr/bin/env python3
"""Distribution summary for a frozen telemetry corpus.

Usage: python3 lab/corpus/summarize.py <telemetry.jsonl>

Prints session count, total tool calls, and breakdowns by tool/server/method/
task_id, PLUS per-tool argument cardinality (how many distinct whole-argument
sets, and how many distinct values per individual argument key, e.g. how many
distinct file paths were read). Call count alone can't tell you whether a
benign false-positive baseline is meaningful -- a rule keys on argument
shapes (paths, URLs, git ops), so the argument-space spread is what actually
proves the baseline characterizes what "benign" looks like, not just how much
of it there is.
"""
import json
import sys
from collections import Counter, defaultdict


def canonical(value) -> str:
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <telemetry.jsonl>", file=sys.stderr)
        return 2

    sessions = set()
    methods = Counter()
    tool_calls = Counter()
    servers = Counter()
    task_ids = Counter()
    labels = Counter()
    total_records = 0
    total_tool_calls = 0

    tool_arg_sets = defaultdict(set)                       # tool_name -> {canonical whole-arg-dict}
    tool_key_values = defaultdict(lambda: defaultdict(set))  # tool_name -> arg_key -> {canonical value}

    for line in open(sys.argv[1]):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        total_records += 1
        sessions.add(r["session_id"])
        methods[r["method"] or "(response)"] += 1
        servers[r["server_command"]] += 1
        task_ids[r["task_id"]] += 1
        labels[r["label"]] += 1
        if r["method"] == "tools/call":
            total_tool_calls += 1
            tool_name = r["tool_name"]
            tool_calls[tool_name] += 1
            args = r.get("tool_arguments") or {}
            tool_arg_sets[tool_name].add(canonical(args))
            if isinstance(args, dict):
                for key, value in args.items():
                    tool_key_values[tool_name][key].add(canonical(value))

    print(f"# Corpus distribution summary: {sys.argv[1]}\n")
    print(f"- Sessions: {len(sessions)}")
    print(f"- Total records: {total_records}")
    print(f"- Total tool calls: {total_tool_calls}")
    print()
    print("## By label")
    for k, v in labels.most_common():
        print(f"- {k}: {v}")
    print()
    print("## By task_id")
    for k, v in task_ids.most_common():
        print(f"- {k}: {v}")
    print()
    print("## By server_command")
    for k, v in servers.most_common():
        print(f"- {k}: {v}")
    print()
    print("## By JSON-RPC method")
    for k, v in methods.most_common():
        print(f"- {k}: {v}")
    print()
    print("## By tool_name (tools/call only)")
    for k, v in tool_calls.most_common():
        print(f"- {k}: {v}")
    print()
    print("## Argument cardinality (tools/call only)")
    print("Distinct whole-argument-set count, and distinct values per individual")
    print("argument key, per tool -- this is what proves the benign argument-space")
    print("has real spread rather than being a few near-identical calls repeated.\n")
    for tool, n_calls in tool_calls.most_common():
        n_distinct_sets = len(tool_arg_sets[tool])
        print(f"- **{tool}**: {n_calls} calls, {n_distinct_sets} distinct argument set(s)")
        for key, values in tool_key_values[tool].items():
            print(f"    - `{key}`: {len(values)} distinct value(s)")

    return 0


if __name__ == "__main__":
    sys.exit(main())

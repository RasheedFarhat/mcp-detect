# MCP-DETECT benign corpus v1

**File**: `benign_corpus_v1.jsonl` (273 lines, JSONL, schema v1 — see `schema/schema.md`)
**SHA-256**: `ec94698a4e52c46c9087799a96904f74a1ee6c8c4547652d862b5f4b2a74d675` (see `benign_corpus_v1.jsonl.sha256`)
**Generated**: 2026-07-08, via `make corpus` (`corpus/agent.py --repeat 3`, no failures across the full run)
**Generator**: `mcp-detect-proxy/1.1`, Ollama `qwen3:1.7b` (temperature=0), 11 task templates × 3 repeats = 33 sessions

## Reproducibility note

This file is the **frozen, checksummed artifact** — treat it as immutable and
versioned; do not regenerate it in place. The generator (`corpus/agent.py` +
`corpus/tasks.py`, pinned model, temperature=0) is open and re-runnable, but
an LLM is not bit-deterministic even at temperature=0 across
hardware/driver/quantization differences — re-running `make corpus` will
produce a **statistically similar, not identical**, telemetry set. If you
need to extend this corpus, generate a new versioned file
(`benign_corpus_v2.jsonl`, etc.) rather than overwriting this one.

## Distribution

- **Sessions**: 33
- **Total records**: 273
- **Total tool calls**: 54
- **Task failures**: 0 (Ollama occasionally returned a transient 5xx during
  generation; `corpus/agent.py` retries those automatically — see its
  docstring/comments)

### By label

| label | count |
|---|---|
| benign | 273 |

All records in this file are benign — this is the Phase 1 false-positive
baseline. Malicious-labeled telemetry is Phase 2's job.

### By task_id

| task_id | records |
|---|---|
| fs_list_and_read_readme | 41 |
| memory_store_project_fact | 35 |
| git_recent_log | 27 |
| git_status_check | 23 |
| fs_read_schema_doc | 21 |
| fs_directory_tree_docs | 21 |
| fetch_and_summarize_example | 21 |
| fetch_mcp_spec_readme | 21 |
| memory_recall_project_fact | 21 |
| time_current_utc | 21 |
| time_convert_tokyo | 21 |

Every task template ran exactly 3 times (11 × 3 = 33 sessions); record counts
per task vary because sessions differ in how many tool calls the agent chose
to make (e.g. the filesystem "list and read" task typically drives 4 tool
calls per session, while a time-conversion task drives 1).

### By server (server_command)

| server | records |
|---|---|
| filesystem (`server-filesystem@2026.7.4`) | 83 |
| memory (`server-memory@2026.7.4`) | 56 |
| git (`mcp-server-git`) | 50 |
| fetch (`mcp-server-fetch`) | 42 |
| time (`mcp-server-time`) | 42 |

All 5 pinned benign servers are represented — this is not a filesystem-only
corpus.

### By JSON-RPC method

| method | records |
|---|---|
| (response, method=null) | 120 |
| tools/call | 54 |
| initialize | 33 |
| notifications/initialized | 33 |
| tools/list | 33 |

### By tool_name (tools/call only)

| tool_name | calls |
|---|---|
| add_observations | 10 |
| list_directory | 6 |
| read_text_file | 6 |
| git_log | 6 |
| fetch | 6 |
| git_status | 4 |
| list_allowed_directories | 3 |
| get_file_info | 3 |
| search_nodes | 3 |
| get_current_time | 3 |
| convert_time | 3 |
| edit_file | 1 |

12 distinct tools called across the 5 servers — a real, if modest, spread of
agent behavior rather than a handful of repeated calls.

## Notable behavior observed during generation (informs the Phase 1 writeup)

- The agent occasionally made an **incorrect or malformed tool call** it then
  recovered from or gave a degraded answer around — e.g. guessing a
  nonexistent relative path for `list_directory`, calling `git_log`/`git_status`
  with `repo_path: "."` (rejected, outside the server's configured allowed
  directory) before sometimes retrying with the correct path, and retrying
  `add_observations` with varying argument shapes (`entityName` vs. implicit)
  before succeeding. This is realistic small-model behavior, not a pipeline
  bug — every one of these sessions still produced clean, schema-valid
  telemetry end to end.
- One session (`fs_list_and_read_readme`) had the agent attempt an `edit_file`
  (write) call against the read-only-mounted workspace, using placeholder
  text that didn't match real file content — the call failed on a content
  mismatch inside the filesystem server itself, before ever reaching the
  read-only filesystem layer. No write occurred either way; the read-only
  mount (`docker-compose.yml`'s `agent` service, `.:/app/workspace:ro`) is
  the actual backstop if a future run's placeholder text happens to match.

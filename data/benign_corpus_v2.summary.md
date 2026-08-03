# MCP-DETECT benign corpus v2

**File**: `benign_corpus_v2.jsonl` (4727 lines, JSONL, schema v1 — see `lab/schema/schema.md`)
**SHA-256**: `6800a275518d8eced53c3e0583bede118eac6c71786fdf33cc5c623caa105e41` (see `benign_corpus_v2.jsonl.sha256`)
**Generated**: 2026-07-08
**Generator**: `mcp-detect-proxy/1.1`, Ollama `qwen3:1.7b` (temperature=0)

## Reproducibility note

This file is the **frozen, checksummed artifact** — treat it as immutable and
versioned; do not regenerate it in place. An LLM is not bit-deterministic even
at temperature=0 across hardware/driver/quantization differences, so
re-running the generator will produce a **statistically similar, not
identical**, telemetry set. If you need to extend this corpus, generate a new
versioned file (`benign_corpus_v3.jsonl`, etc.) rather than overwriting this
one.

## How this file was built

Unlike v1 (a single `make corpus` pass), v2 was assembled in three passes over
`lab/corpus/agent.py` + `lab/corpus/tasks.py`, merged with `cat` and re-verified with
`lab/corpus/summarize.py` after each merge:

1. **Full run** (`agent.py`, no `--task-id` filter) — every task template in
   `tasks.py` at its configured `repeat` weight, including the five
   near-boundary filesystem reads at `repeat=12` (the false-positive-rate
   probes — see the `repeat` comment in `tasks.py`).
2. **Targeted top-up, round 1** (`agent.py --task-id X --repeat N`, run
   per-tool) — v1's mistake was treating call-count alone as sufficient; after
   pass 1, several tools sat at single-digit-to-teens call counts
   (`list_directory`, `get_file_info`, `list_allowed_directories`,
   `edit_file`, `git_branch`, `git_status`, `search_nodes`,
   `create_relations`, `read_graph`, `get_current_time`, `convert_time`) — a
   per-detection false-positive rate is meaningless with a denominator that
   small (one FP reads as a 10-50% FP rate). Ten new task templates were
   added, each targeting one thin tool with a genuinely new argument value
   (new paths, new timezones, a new memory query, a new git-branch type),
   not just repeat padding of an existing prompt.
3. **Targeted top-up, round 2** — round 1 incidentally introduced two *new*,
   even-thinner tools (`create_directory`: 4 calls, `move_file`: 1 call) as a
   side effect of the model improvising a workaround after an `edit_file`
   rejection. Six more task templates were added, scoped to the writable
   `/app/sandbox` volume (not the read-only project mount), asking the agent
   to organize its own output files — a legitimate, realistic benign use of
   both tools, with varied directory/file names for real argument spread.

Passes 2 and 3 only ran the specific new/thin `task_id`s, not a full re-run —
the near-boundary reads and every other already-well-represented task from
pass 1 were left untouched.

## Distribution

- **Sessions**: 541
- **Total records**: 4727
- **Total benign tool-call events**: 1011

### By label

| label | count |
|---|---|
| benign | 4727 |

### By server (server_command)

| server | records |
|---|---|
| filesystem, `/app/workspace` (ro) | 1415 |
| memory (`server-memory@2026.7.4`) | 946 |
| git (`mcp-server-git`) | 815 |
| filesystem, `/app/sandbox` (rw) | 758 |
| time (`mcp-server-time`) | 462 |
| fetch (`mcp-server-fetch`) | 331 |

### By JSON-RPC method

| method | records |
|---|---|
| (response, method=null) | 2093 |
| tools/call | 1011 |
| initialize | 541 |
| notifications/initialized | 541 |
| tools/list | 541 |

### By tool_name (tools/call only)

| tool_name | calls | tool_name | calls |
|---|---|---|---|
| create_directory | 113 | git_branch | 39 |
| add_observations | 99 | convert_time | 36 |
| git_log | 95 | list_directory | 34 |
| read_text_file | 87 | get_file_info | 30 |
| git_diff | 56 | edit_file | 30 |
| create_relations | 55 | git_status | 30 |
| fetch | 53 | search_nodes | 30 |
| move_file | 48 | get_current_time | 30 |
| write_file | 47 | read_graph | 29 |
| list_allowed_directories | 45 | search_files | 25 |

**20 distinct tools called across 6 server sessions.** Every tool sits at 25+
benign events except `git_show` (see Limitations) — the floor this corpus was
specifically built to clear, not just an aggregate count.

## Argument cardinality (tools/call only)

Distinct whole-argument-set count, and distinct values per individual
argument key, per tool — this is what proves the benign argument-space has
real spread rather than being a few near-identical calls repeated. Full
detail: run `python3 lab/corpus/summarize.py data/benign_corpus_v2.jsonl`.

Notable spreads: `read_text_file` (14 distinct paths), `fetch` (9 distinct
URLs), `create_directory` (13 distinct paths), `move_file` (6 distinct
sources / 5 distinct destinations), `git_branch` (3 repo_path values × 2
branch_types).

## Near-boundary false-positive-rate probes (unchanged from pass 1)

The five near-boundary filesystem reads that Phase 4's false-positive claim
rests on — each at the full `repeat=12` weight, none regenerated across the
top-up passes:

| task_id | sessions | tool calls | path read |
|---|---|---|---|
| fs_read_gitignore | 12/12 | 14 | `.gitignore` (+2 malformed-path retries — realistic small-model noise, kept as-is) |
| fs_read_schema_json | 12/12 | 12 | `lab/schema/schema.json` |
| fs_read_example_env_fixture | 12/12 | 12 | `lab/corpus/fixtures/example.env.txt` |
| fs_read_config_dir_settings | 12/12 | 12 | `lab/corpus/fixtures/config/app_settings.json` |
| fs_read_keys_dir_readme | 12/12 | 12 | `lab/corpus/fixtures/keys/keys_directory_readme.md` |

## Limitations

**1. Small-model behavioral noise.** `qwen3:1.7b` occasionally makes an
incorrect or malformed tool call it then recovers from, substitutes a
different (but topically valid) tool for the one a prompt implied, or drifts
into a tangential answer — e.g. guessing a nonexistent relative path before
retrying with the correct one, or answering a git question by reading an
unrelated config file it had recently seen. This is realistic small-model
behavior the corpus intentionally preserves, not a pipeline defect — every
one of these sessions still produced clean, schema-valid telemetry end to
end. Do not read stray or unexpected argument values in this file as
generation bugs without checking whether they're this kind of authentic
model noise first.

**2. `git_show` has no benign baseline (0 calls, by design).** A dedicated
task (`git_show_head_commit`) explicitly asked for "the diff introduced by
the most recent commit" — the one framing that should bias tool choice
toward `git_show` — across 28 attempts. The model answered every single time
with `git_log` + `git_diff` instead, never once calling `git_show`. This
was confirmed as consistent model behavior, not sampling noise, and is
accepted as a named limitation rather than chased further: forcing the
literal tool call would require an unnaturally leading prompt that
manufactures unrealistic traffic, which would undermine the point of a
*benign baseline* more than an absent one does. **A detection rule that keys
on the literal tool name `git_show` has no benign denominator in this corpus
and needs a supplemental baseline before its false-positive rate can be
trusted.** The underlying *behavior* (inspecting a commit's diff) is well
represented via `git_diff` (56 calls, 4 distinct argument sets).

# Phase 1b — Benign Corpus v2: Distribution Fix + Mutate-Tool Baseline

Status: **v2 frozen.** `data/benign_corpus_v2.jsonl` supersedes v1 as the
corpus Phase 3/4's false-positive-rate work should build on; v1 stays
immutable as historical gate evidence, not deleted or overwritten.

## Why a second pass was needed

v1 (33 sessions, 273 records, 54 tool calls) satisfied Phase 1's gate — a
labeled corpus across ≥3 servers, frozen and checksummed — but call-count
alone doesn't make a false-positive-rate denominator meaningful. A per-tool
detection's FP rate is `false positives / benign calls to that tool`; v1's
per-tool breakdown had several tools at single-digit-to-teens counts
(`get_current_time`: 3, `edit_file`: 1, several others under 10). At n=5-10, one
false positive reads as a 10-20% FP rate regardless of how good the rule
actually is. v1's corpus was real and correctly generated; it just wasn't
*sized* per-tool for the claim Phase 4 needs to make.

## What v2 changed

**Distribution fix.** After an initial full generation run (`run5`: 240
sessions, 415 tool calls), `corpus/summarize.py`'s per-tool breakdown showed
the same problem at larger scale: `add_observations` (99) and `read_text_file`
(87) were half the corpus while a dozen other tools sat at the repeat floor
(10, 10, 10, 10, 10, 5, 3). Two targeted top-up passes followed —
`corpus/agent.py --task-id X --repeat N` runs against specific under-
represented tools only, not a full regeneration — adding new task templates
with genuinely new argument values (new paths, timezones, queries, git-branch
types) rather than just repeating an existing prompt. Merged and
re-measured, every tool landed at 25-55 benign events. Final: 541 sessions,
4727 records, 1011 tool-call events, 20 distinct tools. Full breakdown in
`data/benign_corpus_v2.summary.md`.

**Mutate-tool baseline (`create_directory`, `move_file`).** Round 1's top-up
had an unplanned side effect: the model, after an `edit_file` rejection,
improvised a recovery attempt using `create_directory`/`move_file` against
the still-read-only workspace mount — introducing two *new*, even-thinner
tools (4 and 1 calls) that hadn't existed in v1 at all. These are write/
mutate operations a future MCP-abuse detection plausibly keys on (unexpected
file creation/movement), so they got their own small round-2 top-up: six new
task templates scoped to the writable `/app/sandbox` volume (not the
read-only project mount), asking the agent to organize its own output files
— a legitimate, realistic benign use of both tools. Landed at 113 and 48
calls respectively, with real path/filename cardinality (13 and 6+5 distinct
values), not padding.

**The `git_show` finding.** A dedicated task (`git_show_head_commit`)
explicitly asked for "the diff introduced by the most recent commit" — the
framing that should bias tool choice toward `git_show` over `git_log`.
Across 28 attempts, the model answered every single time with `git_log` +
`git_diff` instead, never once calling `git_show`. This was confirmed
consistent (not sampling noise) and accepted as a named limitation rather
than chased with an increasingly unnatural prompt: forcing the literal tool
call would manufacture traffic this model doesn't actually produce, which
undermines the point of a *benign baseline* more than an absent one does.
**`git_show` has zero benign representation in this corpus.** A detection
keyed on that literal tool name has no denominator here and needs a
supplemental baseline before its FP rate can be trusted; the underlying
*behavior* (inspecting a commit's diff) is well covered via `git_diff` (56
calls).

## The operational saga (for the next person who hits this)

Generating v2 surfaced three failure modes, each initially misdiagnosed once
before the real cause was found:

1. **Ollama reload churn / mid-run 500s**, initially assumed to be idle
   `keep_alive` eviction (Ollama's default 5m). Fixing it to `KEEP_ALIVE=-1`
   (never evict) didn't change the failure rate at all — the actual cause was
   `signal: killed` (SIGKILL) in Ollama's own logs, i.e. the `llama-server`
   subprocess was being OOM-killed, not idling out. Root cause: the lab's
   Colima VM (6GiB) had `wazuh.indexer` + `wazuh.dashboard` + `wazuh.manager`
   + `ollama` all resident simultaneously, leaving well under 1GiB headroom
   for Ollama's runner to work with. **Fix**: stop `wazuh.indexer`/
   `wazuh.dashboard` for the duration of generation (not needed for capturing
   telemetry — only `wazuh.manager`'s `<localfile>` tail is). Confirmed via
   `docker stats` before/after: freed ~2.1GiB, zero kills over the next
   several hours of generation.
2. **Unbounded prompt-cache growth**, a second-order consequence of the fix
   above. `KEEP_ALIVE=-1` stopped the reload-churn 500s, but with the runner
   permanently resident, llama.cpp's on-disk prompt cache accumulated one
   entry per distinct task prompt with nothing ever clearing it — memory
   climbed for the life of the runner (~2.2GiB → ~2.9GiB over ~50min/40
   sessions) until it got OOM-killed anyway, just on a slower fuse. **Fix**:
   `OLLAMA_KEEP_ALIVE=10m` (finite, not infinite) — a periodic reload that
   drops the accumulated cache is a small, bounded cost; unbounded growth
   isn't. Confirmed clean for the remainder of the run (238/240 sessions,
   zero kills, zero unexpected 500s).
3. **Disk-full mid-run**, unrelated to either memory fix. `docker cp` itself
   started failing ("no space left on device") — Colima's 40GB VM disk had
   filled completely. Root cause: `wazuh.manager`'s vulnerability-detection
   module (`<vulnerability-detection><enabled>yes</enabled>`) downloads and
   maintains a CVE feed; its cache (`queue/vd_updater` + `queue/vd`) had grown
   to 23GB, unrelated to anything corpus-generation was doing. **Fix**:
   `<vulnerability-detection><enabled>no</enabled>` in
   `wazuh/config/wazuh_cluster/wazuh_manager.conf`, pushed live via
   `docker compose cp` + manager restart (this repo's config isn't a direct
   bind mount to `/var/ossec/etc/ossec.conf` — see the docker-compose.yml
   comment on why — so a config edit needs an explicit post-boot copy, same
   pattern as installing the detection rule). This lab doesn't use
   vulnerability-detection alerts, so disabling it has no detection-coverage
   cost.

None of these three needed the same fix, and two of the three initial
hypotheses (idle eviction; "it's the memory fix's fault") were wrong on
inspection of the actual logs (`signal: killed`, not a timeout log line;
`queue/vd_updater`, not `queue/indexer`'s filebeat-shipping buffer). The
throughline: **judge a live process's health from log evidence and
multi-sample trends, not a plausible-sounding first theory** — same lesson
`docs/PHASE1.md` drew from the earlier stale-snapshot kill, applied here one
level up (to diagnosis, not just liveness).

## Forward to Phase 2/3/4

- `wazuh.indexer`/`wazuh.dashboard` are currently stopped. Phase 2/3 will
  need them back up for real alert visibility — restarting them re-shrinks
  the memory headroom this phase depended on; budget for that before running
  Ollama-backed generation and the full Wazuh stack concurrently again.
- Vulnerability-detection stays disabled; re-enabling it (if some later phase
  wants CVE-correlation alerts) means budgeting real disk for its feed cache,
  not just re-flipping the flag.
- `git_show` needs a supplemental baseline (a different model, or a
  hand-authored session via `corpus/handauthored.py`) before any detection
  keyed on that literal tool name can claim a trustworthy FP rate.
- `data/archive/` holds three partial telemetry dumps from the failed
  attempts above (pre-reload-fix, memory-creep, disk-full) as recovery
  provenance. They are not part of the published dataset and should not be
  merged into any future corpus version.

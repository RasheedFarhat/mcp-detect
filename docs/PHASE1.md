# Phase 1 — Reproducible Lab, Schema v1, Benign Corpus

Status: **gate passed.** All four conditions verified on this machine (macOS,
Apple Silicon, Colima + Docker).

## The gate

1. `docker compose up` (via `make lab-up`) brings up the full lab from a
   clean state with no host-side repair; `docs/REPRO.md` records the exact
   steps and honest limits. The manual `docker cp`/append path is gone;
   ingestion is continuous via a native bind-mounted tail. **Verified**:
   proven from a genuinely clean state (no volumes, no certs, no containers)
   — `make lab-up` then `make smoke` fired the detection rule on the very
   first real session, no manual intervention.
2. Schema v1 is documented as an adoptable spec (`lab/schema/schema.md` +
   `schema.json`), with `tool_description_hash` and `server_version_hash`
   computed and stable, and `label`/`scenario_id`/`task_id`/`generator`
   fields present. **Verified**: hash stability proven by a self-test
   (`lab/proxy/hashing.py`) asserting identical hashes across key-order and
   Unicode-normalization-form differences; all fields confirmed populated
   correctly end to end via `make smoke` and cross-checked in real Wazuh
   alerts.
3. The LLM agent produces a labeled benign corpus across ≥3 servers, frozen
   and checksummed, with a distribution summary; `make smoke` still proves
   the pipeline deterministically without the LLM. **Verified**:
   `data/benign_corpus_v1.jsonl` — 33 sessions, 273 records, 54 tool calls,
   5 servers, 12 distinct tools, zero task failures. See
   `data/benign_corpus_v1.summary.md` for the full breakdown.
4. `docs/WAZUH-NOTES.md` resolves (or safely constrains) the `decoded_as`-only
   behavior, with a test backing the conclusion. **Verified**: five
   controlled tests show it was never a real bug — ordinary first-match-wins
   evaluation among sibling rules, with load order that is neither
   alphabetical-by-filename nor numeric-by-rule-ID. Hard constraint derived
   for Phase 3: every compiled detection must chain via `<if_sid>` to one
   shared parent rule, and overlapping rules under that parent will still
   shadow each other silently — this needs regression-testing per rule pair,
   not just "it loaded without error."

## What worked

- **The Part 1 infrastructure fixes held up under real load.** The native
  bind-mounted ingestion path (proxy → shared Docker volume → Wazuh
  `<localfile>`) handled 33 real agent sessions across 5 servers with zero
  manual intervention and zero lost records — the entire benign corpus
  landed correctly on the first full run after the pre-touch fix, with no
  repeat of Phase 0's dedup/inode gotchas.
- **Hash canonicalization is genuinely stable.** `lab/proxy/hashing.py`'s
  self-test (stability under key reordering and NFC-normalization
  differences) caught nothing wrong because the recipe was designed
  correctly the first time — NFC-normalize, then sort-keys/compact-separator/
  ASCII-only JSON, then SHA-256. Both hashes populated exactly where designed
  (server_version_hash from `initialize`'s response onward; tool_description_hash
  only on `tools/call` records, mirroring `tool_name`) across every session
  of the real corpus run, no exceptions.
- **The agent loop is robust to realistic small-model imperfection.** `qwen3:1.7b`
  made plenty of small mistakes during corpus generation — guessing wrong
  relative paths, retrying `add_observations` with varying argument shapes,
  attempting an `edit_file` write against a read-only mount with a
  placeholder that didn't match real content — and every single one of these
  sessions still produced complete, schema-valid telemetry. The pipeline
  doesn't care whether the agent's task attempt succeeds; it only needs the
  JSON-RPC traffic to be real, which it always was.
- **Fault isolation in the corpus generator was the right call.** Ollama's
  backend threw sporadic bare 500s during the real run (see below); the
  per-call retry plus per-task exception isolation added after the first
  attempt's crash meant the full 33-session run finished with **zero**
  task failures despite those transient errors, instead of the whole batch
  dying on the first one (which is exactly what happened before that fix).

## What was fragile

- **Ollama's backend threw sporadic bare 500s under sustained CPU-only
  inference**, logged server-side as `"llama-server completion error" ...
  EOF`, with no discernible pattern — a retry of the exact same request
  reliably succeeded. Root cause not chased further (it's upstream, in
  `ollama/ollama:0.31.1`'s bundled llama.cpp server, not our code); the
  practical fix is what's in `lab/corpus/agent.py` now: retry transient 5xx up
  to twice with a short backoff, and isolate failures per task so one flaky
  call can't take down an entire corpus run.
- **A real self-inflicted mistake during this phase: I killed a live,
  progressing corpus-generation process because a single snapshot made it
  look permanently hung.** A `git_log` tool call was mid-flight (git's own
  `cat-file --batch`/`--batch-check` helpers, slow but not stuck) when I
  checked; I concluded "deadlocked" from one `ps aux` snapshot and killed the
  process tree, losing ~17 sessions of real work. The process was, in fact,
  progressing normally — CPU-only inference on this model is just genuinely
  slow (roughly 1–3 minutes per task depending on how many tool-call turns
  it takes), and a single point-in-time snapshot of a long-running step is
  not evidence of a hang. Lesson applied immediately afterward: judge
  liveness from *trend across two checks separated by real time*, not one
  snapshot; and run long unattended jobs fully detached
  (`docker compose exec -d`, not a tracked foreground shell) precisely so
  that killing my own tracking process can never affect the real work again.
- **No timeout on individual MCP tool calls in `lab/corpus/agent.py`.** If a
  wrapped server's tool call genuinely hangs (not just "slow," but actually
  stuck), the agent loop has no way to notice and move on — it will await
  that call forever. Didn't bite this run (the git_log call above eventually
  returned), but it's a real gap: worth adding a per-call timeout before
  Phase 2 introduces attack scenarios, where a hung tool call could plausibly
  be the attack itself.
- **Colima's default disk allocation (40GB) filled up completely mid-phase**,
  surfacing as `docker cp` failing with a misleading "no space left on
  device" — misleading because `df -h /` inside the VM showed 94% free; the
  actual full filesystem was `/mnt/lima-colima`, the separate disk image
  backing Docker's own data-root, not the VM's root filesystem. A large
  chunk (6.4GB) turned out to be entirely reclaimable: named volumes from the
  **original Phase 0 `wazuh-docker/single-node` compose project**, torn down
  early in Part 1 but never volume-pruned, sitting unused. Removed them and
  had headroom again (4GB free after cleanup) — tight, but sufficient to
  finish. This is a real capacity-planning gap for Phase 2: attack scenarios
  and more corpus generation will keep consuming disk (Wazuh's own queue/log
  volumes grow with sustained activity), and 40GB was already borderline for
  Phase 1 alone.
- **Ingesting a mid-schema-migration telemetry file produces exactly the
  validation errors you'd expect, which is correct but easy to
  misdiagnose in the moment.** Continuous ingestion means old (schema v0)
  and new (schema v1) records can coexist in the same accumulated file
  across a schema change mid-testing — `lab/schema/validate.py` correctly flags
  the old ones as invalid (missing `label`/`scenario_id`/etc.), which looks
  alarming until you remember the file is append-only and spans a schema
  version boundary. Not a bug; just something to remember before panicking
  at a validation failure count that doesn't match the records you just
  generated.

## Reasons to reconsider anything before Phase 2 — or not

Nothing here demands an architecture change. The schema, proxy, hash
recipe, and detection-rule mechanics all held up under real multi-server,
multi-session load exactly as designed. The friction was: one upstream
Ollama flakiness (mitigated, not eliminated, by retries), one operator
mistake on my part (corrected, and the underlying "how do I judge if a
background job is actually stuck" lesson is now applied), and one capacity-
planning gap (Colima's disk headroom) that Phase 2 needs to actively budget
for rather than discover the hard way again. Concretely, before Phase 2:

- **Budget more disk for Colima**, or add a `make prune` target that clears
  reclaimable Docker build cache/dangling volumes as routine hygiene — Phase
  2's attack scenarios plus continued benign corpus growth will use more,
  not less, disk than Phase 1 did.
- **Add a timeout to `session.call_tool()` in the agent loop** before attack
  scenarios exist, since a hung tool call and an attack that hangs a tool
  call on purpose are not effectively distinguishable without one.
- **Carry forward `docs/WAZUH-NOTES.md`'s hard constraint** into whatever
  Phase 3's Sigma-compiled rules look like: chain to one shared parent, and
  regression-test every pair of rules whose match conditions could overlap.

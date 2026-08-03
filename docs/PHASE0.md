# Phase 0 — Feasibility Spike

Status: **gate passed.** All three conditions below are verified on this machine
(macOS, Apple Silicon, Colima + Docker, existing `wazuh-docker/single-node`
deployment at `/Users/rasheedfarhat/wazuh-docker/single-node`).

## The gate

1. `make spike` produces a JSONL telemetry log where `initialize`, `tools/list`,
   and the sensitive `tools/call` are all visible as clean structured records
   matching `lab/schema/schema.json`.
   **Verified**: a clean run produces 7 records (initialize + response,
   `notifications/initialized`, tools/list + response, tools/call + response),
   all 7 validate against `lab/schema/schema.json` with `lab/schema/validate.py`.

2. The MCP session completes normally through the proxy (transparent forwarding).
   **Verified**: `client.py` exits 0 every run; the filesystem server's own
   stdout banner ("Secure MCP Filesystem Server running on stdio") and the
   real file content it returns both pass through the proxy untouched. An
   isolated echo-subprocess test (proxy wrapping `cat`-like echo instead of
   the real server) confirmed byte-for-byte round-trip of both directions
   independently — see "What was fragile" below for a real bug this caught.

3. Wazuh ingests the log and exactly one rule fires on the sensitive read,
   visible in Wazuh alerts.
   **Verified**: with the `wazuh/local_rules.xml` rules and
   `wazuh/ossec_localfile.xml` config loaded into the existing single-node
   manager, feeding a real `make spike` output through the actual
   `localfile` → `logcollector` → `wazuh-analysisd` pipeline (not
   `wazuh-logtest` simulation) produced exactly one alert:
   `rule.id 100101, level 12, "MCP sensitive file read via tool call:
   tool=read_text_file path=.../.env"`. The other 6 records in the same
   batch matched only the level-0 parent rule (100100) or nothing, and
   generated no alert — confirmed by grepping `alerts.json` for the batch's
   `session_id` and content markers.

## How to reproduce

```
cd mcp-detect
make spike                      # generates logs/telemetry.jsonl, validates against schema
```

To wire it into an existing Wazuh single-node deployment:

```
# 1. Copy the rule and localfile config in (adjust container name as needed)
docker cp wazuh/local_rules.xml <manager-container>:/var/ossec/etc/rules/mcp_detect_rules.xml
docker exec <manager-container> chown wazuh:wazuh /var/ossec/etc/rules/mcp_detect_rules.xml

# 2. Add the <localfile> block from wazuh/ossec_localfile.xml to the manager's
#    ossec.conf (see "Fragile: config persistence" below — for wazuh-docker,
#    edit the HOST file config/wazuh_cluster/wazuh_manager.conf, not the
#    in-container /var/ossec/etc/ossec.conf, or your edit will be discarded).

# 3. Restart the manager, then feed a telemetry log to the watched path:
docker exec <manager-container> mkdir -p /var/log/mcp-detect
cat logs/telemetry.jsonl | docker exec -i <manager-container> sh -c 'cat >> /var/log/mcp-detect/telemetry.jsonl'

# 4. Check alerts:
docker exec <manager-container> grep '"id":"100101"' /var/ossec/logs/alerts/alerts.json
```

## What worked

- **Proxy design**: a stdio JSON-RPC logging proxy in ~200 lines of stdlib
  Python (asyncio, no dependencies) is enough to capture clean, complete,
  schema-conformant telemetry from a real MCP session, and to prove
  byte-transparent forwarding. No need for a more complex approach for Phase 0.
- **Scripted client over a real LLM**: using the official `mcp` SDK directly
  (no agent framework) gave a fully deterministic, three-line-of-intent
  client (`initialize` → `tools/list` → `tools/call`) with no flakiness.
  Discovering the read-tool name from `tools/list` rather than hardcoding it
  paid off immediately — the actual tool is `read_text_file`, not `read_file`
  as an outdated tutorial or cached assumption might suggest.
- **The filesystem reference server**: worked with zero modification, exposes
  a clean `tools/list`, and the pinned version resolves reliably via `npx`.
- **Wazuh's generic JSON decoder**: `log_format json` with no custom decoder
  correctly flattens nested JSON (`tool_arguments.path`, `raw.params.name`,
  etc.) into dot-addressable dynamic fields usable directly in rule `<field>`
  conditions — exactly as hoped, and confirmed field-by-field via
  `wazuh-logtest`'s Phase 2 output.
- **One hand-written rule was sufficient**: no Sigma compiler, no rule pack —
  a two-rule local_rules.xml (one level-0 "this is our telemetry" parent, one
  level-12 child matching `tools/call` + a sensitive-path regex on
  `tool_arguments.path`) correctly fires once and only once on the sensitive
  read, and stays silent on `initialize`/`tools/list`/benign traffic.

## What was fragile (fix before Phase 1, or at least don't rediscover blind)

- **A real transparency bug in the first proxy draft.** The initial
  implementation used `asyncio.wait(..., return_when=FIRST_COMPLETED)` across
  the two directions and cancelled whichever pump hadn't finished when the
  other hit EOF. Since the client's stdin closes (EOF) essentially at the same
  time the server's final response is still in flight, this raced and
  silently dropped the last server→client message in an isolated test. Fixed
  by letting each direction drain to its own natural EOF independently
  (`asyncio.gather`, no cross-cancellation). **This is exactly the kind of bug
  that "prove transparency explicitly" was meant to catch — do not skip that
  test in future phases**, especially if the proxy design changes.
- **Wazuh's default field-matching dialect is not what it looks like.**
  `<field name="x">.+</field>` (no `type` attribute) did **not** match a
  non-empty UUID string — Wazuh's default is its own "osregex" dialect, not
  PCRE, and its semantics for `.` are not what a PCRE-literate reader assumes.
  Explicit `type="pcre2"` on every `<field>`/`<match>` fixed it immediately
  and is what `local_rules.xml` uses throughout. **Always specify
  `type="pcre2"` explicitly in future rules** — do not rely on the default.
  Also: a rule with only `<decoded_as>json</decoded_as>` and no other
  condition did not appear in `wazuh-logtest -v`'s "Trying rule" list at all
  in one test — not fully root-caused, avoided rather than explained. Rules
  that combine `<decoded_as>` with at least one `<field>` condition worked
  reliably; a bare `<decoded_as>`-only rule should be treated as unproven.
- **`docker cp` replaces the file's inode; a tailing log collector may not
  notice.** Re-delivering telemetry into the watched path with `docker cp`
  (which does an atomic replace, changing the inode) did not reliably trigger
  re-reading. Truncating and appending in place (`sh -c 'cat >> file'` over a
  stdin redirect) is the reliable way to deliver incremental content to a
  tailed file inside a container.
- **Wazuh's own offset/content tracking will silently no-op on byte-identical
  content.** Re-feeding a previously-ingested telemetry file (even after
  truncating and rewriting it with the exact same bytes) produced zero new
  alerts — Wazuh's logcollector state (`/var/ossec/queue/logcollector/file_status.json`)
  tracks a hash/offset and correctly treats identical content as "nothing
  new," even across a truncate+rewrite cycle. Real-world implication: replay
  testing against Wazuh needs genuinely new content (new session_id/timestamps
  from a fresh spike run), not naive replay of a saved fixture.
- **This `wazuh-docker/single-node` image does not re-apply container-internal
  config edits across a `wazuh-control restart`, and does not restart its own
  internal daemons after a full container restart.** Two surprising behaviors
  stacked here: (a) editing `/var/ossec/etc/ossec.conf` inside the running
  container and calling `wazuh-control restart` silently discarded the edit,
  because the container's init flow re-mounts `ossec.conf` from the
  `docker-compose.yml`-mounted host file
  (`config/wazuh_cluster/wazuh_manager.conf`) every time — edits must go
  in that **host** file, then `docker compose restart wazuh.manager`. (b) After
  a full container restart, the internal Wazuh daemons (analysisd,
  logcollector, etc.) are launched once via a `cont-init.d` script and are
  **not** supervised by s6 as persistent services in this image — they did not
  come back up automatically and needed a manual
  `docker exec <container> /var/ossec/bin/wazuh-control start`. Custom rule
  files dropped into `/var/ossec/etc/rules/` (a Docker named volume, not a
  host bind mount) *did* survive container restarts fine — only the
  bind-mounted `ossec.conf` had this gotcha.
- **`wazuh-logtest` occasionally stops after "Phase 2: Completed decoding"**
  with no error and no Phase 3, for reasons not fully root-caused (observed
  right after certain restarts / rule reloads; resolved itself after the next
  clean restart). Don't trust a missing Phase 3 as proof a rule doesn't match
  — cross-check against a real ingested alert before concluding a rule is
  broken, which is what surfaced the actual `type="pcre2"` bug above.
- **This dev machine's Homebrew Python 3.14 (and, after an accidental
  `autoremove`, its 3.12 and 3.13 bottles too) had a broken `pyexpat` ↔
  system `libexpat.1.dylib` symbol mismatch on macOS 26.0**, breaking
  `ensurepip`/`venv` entirely for every prebuilt Homebrew Python bottle
  tried. This is a host environment issue, not an MCP-DETECT issue, but it
  blocked `make spike` cold until resolved. Fixed by
  `brew reinstall python@3.13 --build-from-source`, which compiles against
  the actual local libraries instead of a mismatched prebuilt bottle. The
  Makefile's `SYSTEM_PYTHON` auto-detection logic exists specifically to
  route around this without hardcoding a fix that may not apply on other
  machines. Also note: my own `brew install colima docker docker-compose`
  step is what triggered the `autoremove` that took out the previously-working
  `python@3.13` keg as an "orphaned" dependency — a reminder that `brew
  install`'s cleanup pass has real, sometimes-surprising blast radius on
  unrelated formulae.
- **Colima was not installed** despite being the stated normal environment;
  only Docker Desktop was present (and stopped). Installed Colima
  fresh (`brew install colima docker docker-compose`) per user confirmation.
  `wazuh-docker/single-node`'s images are `linux/amd64`-only (no arm64 build
  for Wazuh 4.9.0), so they run under Colima's QEMU x86_64 emulation on Apple
  Silicon — functional but slow, and `wazuh-monitord` segfaulted once under
  emulation (non-critical daemon; did not affect the rule-firing gate, and
  came back clean on the next restart). If Phase 1 does sustained work
  against this stack, expect emulation overhead and occasional flaky crashes
  in less-exercised daemons.
- **Indexer/dashboard TLS is broken in this deployment** (filebeat →
  wazuh.indexer fails with "certificate signed by unknown authority"), traced
  to the certificate generator failing with `Permission denied` on
  `root-ca-manager.pem/key` during `generate-indexer-certs.yml` (leftover
  restrictive permissions from a prior run, unrelated to this spike). This
  does **not** affect the gate — `wazuh-analysisd` writes local
  `alerts.json` regardless of whether filebeat can ship it to the indexer —
  but it means the Wazuh **dashboard** currently shows nothing for this
  data. Fine for Phase 0 (gate only requires alerts.json); worth fixing
  before any phase that wants visual triage in the dashboard.

## Reasons to reconsider the architecture before Phase 1 — or not

Nothing here rises to "reconsider the architecture." The core bet — capture
at the JSON-RPC/stdio layer, keep the client scripted and deterministic, use
Wazuh's generic JSON decoder plus a hand-rolled rule — held up completely.
The friction encountered was either host-environment noise (Python/Colima)
or shallow, well-understood gotchas in Wazuh's field-matching dialect and
this particular Docker image's restart semantics, all now documented above
so Phase 1 doesn't rediscover them blind. The one item worth carrying forward
as an open question rather than a settled fact: the unexplained
`<decoded_as>`-only rule not appearing in `wazuh-logtest -v"`'s rule list —
worth a deeper look if Phase 1's rule pack leans on `decoded_as` alone as a
matching condition anywhere.

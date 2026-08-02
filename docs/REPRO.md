# Reproducing the lab from a clean machine

## What "clean" means here, and its honest limit

This was tested by tearing down the Phase 0 host state on the same machine:
removing the old `wazuh-docker/single-node` compose project, and building this
repo's compose project from scratch (no pre-existing certs, no pre-existing
named volumes, no `.venv`). That is the strongest clean-state test available
without a second physical machine — **I have not verified this on a genuinely
different host**, and there is one class of bug that kind of testing can't
rule out: something this exact machine's Docker/Colima install happens to
paper over silently. If you run this on a different machine and it doesn't
work, that gap is the first place to look.

What *is* verified: the only things this repo assumes about the host are
**Docker Desktop or Docker Engine with Compose v2, and enough disk/RAM** to
run five containers (three Wazuh services, Ollama, one agent image) plus a
~1.4GB model download. No host Python. No host Node. No host `uv`. No
`SYSTEM_PYTHON` detection, no Homebrew repair, no manual package installation
of any kind — Phase 0's entire "heavy host repair" chapter (rebuilding
Homebrew Python from source, installing Colima by hand, hand-starting Wazuh
daemons after restarts) does not recur here because none of that machinery is
load-bearing anymore. Everything that used to run on the host now runs inside
the `agent` image.

## Bootstrap steps (exactly what to run)

```
git clone <this repo>
cd mcp-detect
make lab-up
```

`make lab-up` does, in order:
1. `make certs` — generates fresh Wazuh indexer/manager/dashboard TLS certs
   via `wazuh/generate-indexer-certs.yml`, then self-heals a real bug in
   `wazuh-certs-generator:0.0.2` (see below) that leaves two cert files
   missing on every single run, clean machine or not.
2. `docker compose up -d --build` — builds the `agent` image (Python 3.12 +
   Node 20 + `uv`, with `mcp==1.28.1` and every MCP server package listed in
   the README pre-installed/pre-warmed at build time) and starts all five
   services: `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`, `ollama`,
   `agent`.
3. Waits for the Wazuh manager's API to respond (proves `wazuh-analysisd` and
   friends are actually up, not just the container).
4. `docker compose exec ollama ollama pull qwen3:1.7b` — pulls the pinned
   tool-calling model into the `ollama_models` named volume. Takes a few
   minutes on first run (~1.4GB download); cached on every run after via the
   named volume.

Then:
```
make smoke
```
runs the Phase 0 scripted client (deterministic, no LLM) *inside* the `agent`
container: `initialize` → `tools/list` → sensitive `tools/call` against the
filesystem server, through the proxy, straight into `mcp_telemetry` — the
Docker named volume the `wazuh.manager` container is *already* tailing via a
native `<localfile>` block. No `docker cp`, no manual delivery step, at any
point.

```
make alerts
```
greps the manager's real `alerts.json` for rule `100101` (the sensitive-read
rule from Phase 0, unchanged) to confirm it fired.

## What changed from Phase 0's ingestion path, concretely

Phase 0 wrote telemetry to a host path, then `docker cp`'d or `cat >>`'d it
into the manager container by hand — the source of the inode-replacement and
hash/offset dedup gotchas documented in `docs/PHASE0.md`. That path is now
gone entirely. The proxy inside the `agent` container writes directly to
`/var/log/mcp-detect/telemetry.jsonl`, which **is** the same file — same
inode, same mount — that `wazuh.manager`'s `<localfile log_format="json">`
block tails, because both containers mount the same named volume
(`mcp_telemetry`) at that path. Every `make smoke` (or, later, `make corpus`)
run simply appends more lines to a file Wazuh is already watching. There is
no copy step to get wrong.

## Fragile things found while proving this, fixed here

- **`wazuh-certs-generator:0.0.2` has a real, reproducible bug**, not a
  Phase-0-specific permissions accident as originally suspected: its internal
  script `chmod`s the certs output directory to `dr-x------` (no write bit)
  *before* it finishes copying `root-ca-manager.pem` and `root-ca-manager.key`,
  so those two files never get written, on a fresh directory, every time.
  Confirmed by reproducing on a genuinely empty cert directory during this
  test. Since `root-ca-manager.*` is meant to be identical to `root-ca.*` in
  single-node mode (no real multi-manager clustering here), `make certs`
  self-heals by `chmod`-ing the directory writable again and copying
  `root-ca.{pem,key}` over as `root-ca-manager.{pem,key}`. This is now baked
  into the Makefile (both `certs` and `lab-clean`, which needs the same
  `chmod` before it can remove the directory at all), not a manual step.
- **A self-inflicted bug, found and fixed during this phase: bind-mounting
  the rule file directly into `/var/ossec/etc/rules/` broke the manager's own
  first-boot volume seeding.** The `wazuh_etc` named volume is seeded from a
  baked-in backup by the manager image's `0-wazuh-init` script, which decides
  whether to seed at all using a single, crude signal: "is
  `/var/ossec/etc` already non-empty?" An earlier version of
  `docker-compose.yml` bind-mounted `local_rules.xml` straight to
  `/var/ossec/etc/rules/mcp_detect_rules.xml` — Docker materializes that path
  *before* any container script runs, so `0-wazuh-init` saw a non-empty
  directory and silently skipped seeding the real defaults
  (`etc/shared/`, `etc/decoders/`, etc.). Symptom: `wazuh-analysisd` refused
  to start with `Could not open file 'etc/shared/ar.conf'`. **Fix**: the rule
  file is no longer bind-mounted at all. `make lab-up` installs it with
  `docker compose cp` *after* the manager's API confirms it's up — a
  one-time config-install copy done once per bring-up, which is a
  fundamentally different thing from the continuous telemetry-delivery
  `docker cp`/append workaround this phase removes. (`wazuh-config-mount`,
  the *other* mechanism this image offers for seeding config from a
  bind-mounted host file, is confirmed from Phase 0 to handle exactly
  `ossec.conf` specifically, not arbitrary paths — not used for the rule file
  for that reason either.)
- **A real, one-time race on first discovery of a fast-growing new file.**
  The very first time `wazuh-logcollector` discovers a brand-new file at the
  watched path and that file gets many lines written to it within
  milliseconds (exactly what a fresh MCP session's telemetry looks like), it
  can silently miss part of that first batch — confirmed by reproducing it
  (the sensitive `tools/call` line from the very first `make smoke` run after
  a truly fresh volume did not alert, while a later append to the
  *already-known* file did, immediately and reliably, every time after).
  Steady-state tailing of a file logcollector already knows about is
  reliable; only true first-discovery-under-rapid-growth is not. **Fix**:
  `make lab-up` now `touch`es the (empty) telemetry file and restarts the
  manager before any session ever runs, so logcollector registers the file
  while it's empty and every subsequent write is normal incremental tailing,
  never a first-discovery race. Verified after the fix: the very first
  `make smoke` on a fresh `make lab-up` alerted immediately
  (`firedtimes: 1`), no manual retry needed.
- **The `wazuh-manager`/`wazuh-indexer`/`wazuh-dashboard` images are
  `linux/amd64`-only** (Wazuh 4.9.0 ships no arm64 build), so on Apple
  Silicon they run under Docker's/Colima's QEMU emulation. Functional, but
  slow to start (expect a couple of minutes for the manager's API to answer).
  Twice during this phase's testing, the manager container hung
  indefinitely at the very first `s6-init` stage (zero processes beyond the
  base supervisor, no forward progress for 10+ minutes) — unrelated to
  either bug above (reproduced with both present and absent). A plain
  `docker compose restart wazuh.manager` cleared it both times; the
  container's own internal daemons still needed a manual
  `wazuh-control start` afterward in earlier tests this phase, consistent
  with Phase 0's finding that this image doesn't supervise them as
  persistent services and won't auto-restart them after a container-level
  restart. **This is a known flake, not solved** — if `make lab-up` hangs
  waiting for the manager API for more than ~5 minutes, check
  `docker compose exec wazuh.manager ps aux`; if it shows only
  `s6-svscan`/`s6-fdholderd` and nothing else, `docker compose restart
  wazuh.manager` and wait again.

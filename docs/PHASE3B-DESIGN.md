# Phase 3b Design — Rug Pull Detection (SAF-T1201), Persistent Baseline

Status: **proposal — awaiting review.** No rule file, `ossec_localfile.xml`,
or telemetry has been touched. Per the Phase 1/2/3a pattern, this is the
check-in gate before any of that.

## Restating what this phase inherits, before proposing anything

**Why rug pull was deferred out of 3a — what makes it not a single-record
detection.** `docs/PHASE2-DESIGN.md`'s headline finding: the signal
(`tool_description_hash`/`server_version_hash` differing from what was
established earlier for the same `(tool_name, server_command)`) is real and
clean — zero drift across 23/23 tool+server pairs in the 4727-record benign
baseline, genuine drift confirmed in the two-session Attack 3 telemetry. But
"differs from before" is a comparison against prior state. Every rule 3a
built (`100100`–`100107`) is a `<field>`/pcre2 match against one decoded JSON
line in isolation — there is no "remember the last value" primitive in that
shape, full stop. Wazuh's one built-in stateful primitive
(`if_matched_sid`/`same_field`/`different_field` + `frequency`/`timeframe`) is
capped at `timeframe ≤ 99999` seconds (~27.7 hours) — real rug pulls unfold
over days to months (postmark-mcp: 15 published versions before the
backdoor). That primitive would demo-fire on a synthetic back-to-back test
while being structurally incapable of catching the attack it represents.
`docs/PHASE2-DESIGN.md` named the correct mechanism without building it:
architecturally identical to Wazuh's own FIM (`syscheck`) — a *persistent*
baseline, not a bounded window — keyed on `(tool_name, server_command)`
instead of a filesystem path. That infrastructure is 3b's actual job.

**Standing process rules inherited from 3a, restated because they still
apply:**

1. **`wazuh-logtest`-first iteration.** Edit via `docker compose cp` (pure
   file write, no service impact), validate via `wazuh-logtest -v` (reads
   rule files fresh from disk every invocation, no restart). Reserve real
   manager restarts for installing an already-validated candidate, never for
   testing a hypothesis.
2. **Restart budget.** A small, counted number of live-manager restarts per
   round, tracked and reported, not spent speculatively. Proposing budget 2
   for this round (see "Restart budget" below — one nuance this phase adds
   that 3a didn't have).
3. **`\x3c` not `&lt;`.** Any literal `<`/`>` in a `type="pcre2"` `<field>`
   pattern must use PCRE2's own hex escape — Wazuh's rule-XML parser does
   not reliably decode the `&lt;`/`&gt;` entity before compiling the pattern,
   and a non-matching rule doesn't error, it just silently never fires.
   Doesn't obviously apply to anything drafted below (no `<`/`>` needed in
   this phase's patterns), but restating since it's a standing landmine, not
   a 3a-specific one.
4. **Negate-on-absent-field gate.** `negate="yes"` against a field that is
   genuinely *absent* from the record does not satisfy the condition in this
   Wazuh version (4.9.0) — confirmed the hard way in 3a (`100103`'s first
   draft silently never fired on its own true positive). Any rule using
   `negate` must be checked against the record where the negated field is
   actually missing, first, before anything else is built on top of it. I
   caught a place below where this gate would have bitten a naive version of
   this design — see "Parent-disjointness" — and designed around it instead
   of needing to pass it, which seemed the more robust fix.

Two more inherited findings that specifically bear on 3b (not just restated
process, actually load-bearing for the design below):

- **Single shared parent, first-match-wins, no backtracking** — proven in
  `docs/WAZUH-NOTES.md` Tests 1–5, both at the top level and among children
  of a matched parent. Any new top-level rule risks silent shadowing against
  `100100` unless proven disjoint by construction (exactly how 3a resolved
  `100101`/`100103`'s sibling-shadowing risk) — this phase introduces a new
  top-level parent and has to clear that same bar; see below.
- **`tool_arguments.*` and other plain-object scalar fields decode cleanly
  per-key; `raw.result.tools` (an array) flattens to one string.** Not
  directly used below (this design doesn't read `tool_arguments` or
  `raw.result.tools`), but worth having in view since the new record stream
  proposed below is also a plain JSON object with scalar fields — same clean
  decoding behavior expected, to be confirmed via `wazuh-logtest` rather than
  assumed, per the standing discipline.

## The architecture question, resolved

Three ways to get a persistent-baseline detection working were on the table.
Recommending one, stating why the other two are wrong for this phase's
actual constraints — not a menu, a decision with the reasoning shown:

1. **Bounded Wazuh correlation (`if_matched_sid`/`frequency`/`timeframe`).**
   Rejected — already named as wrong in `docs/PHASE2-DESIGN.md`: the
   99999-second cap is incompatible with the technique's real timescale.
   Building it would produce a rule that only catches rug pulls that happen
   within 27.7 hours, which is not the attack.
2. **FIM-mediated**: maintain a small on-disk "last-known-hash-per-tool"
   state file and put it under Wazuh's native `syscheck` (FIM) watch, so a
   hash change surfaces as a native FIM alert with zero new correlation code.
   Rejected, for a reason not previously written down: FIM alerts have their
   own alert shape (`syscheck.path`, `syscheck.diff`, etc.) — they do not
   carry `session_id`/`scenario_id`/`task_id`/`label`, the fields Phase 4
   analysis joins on for every other detection in this project. Getting
   those fields into a FIM alert would mean encoding them into the
   watched file's *path* or *content* and then writing a decoder to parse
   `syscheck.diff` back apart anyway — at which point the "no new
   correlation code" benefit is gone and this is strictly more work than
   option 3, for no offsetting benefit. Naming this now since Phase 2 left
   both options open and this is the concrete reason to close off this one.
3. **External persistent-baseline watcher, emitting a stateless-matchable
   flag record.** A small standalone Python process reads telemetry as it's
   produced, maintains the actual baseline comparison itself (all
   statefulness lives here, in one small, independently-testable component,
   not inside Wazuh at all), and — only when it observes a hash that
   genuinely differs from an established baseline — emits one new,
   purpose-built JSON record to a **separate** file. Wazuh then does exactly
   what it's already good at and already does for every other rule in this
   ruleset: a single-record, stateless field match on that new record. This
   fully respects the "Wazuh's classic rule DSL has no memory" constraint by
   never asking Wazuh to have any — the comparison already happened before
   Wazuh ever sees the line.

**Recommendation: option 3.** It's the only one of the three that (a)
respects the real rug-pull timescale (no window, ever), (b) keeps
Phase 4's session/scenario/task join working the same way it already does
for every other alert, and (c) keeps 100% of Wazuh's role identical to 3a —
one parent, stateless children, `wazuh-logtest`-first iteration, same
process. All the new complexity is isolated in one small watcher script,
not smeared across the rule engine.

## Persistent baseline store

- **Location**: new `baseline/` directory (sibling to `attacks/`, `corpus/`,
  `proxy/`) — this is infrastructure, not attack-generation or corpus code,
  and the persistent-comparison pattern named in `docs/PHASE2-DESIGN.md`
  (`(tool_name, server_command) → first-seen hash`) is plausibly reusable for
  a future stateful signal beyond just rug pull, so it gets its own home
  rather than living inside `attacks/` or `wazuh/`.
- **Format**: flat JSON file (`baseline/state/rugpull_baseline.json`),
  keyed by `(tool_name, server_command)` for `tool_description_hash` and by
  `server_command` alone for `server_version_hash` — matching exactly the
  keying `docs/PHASE2-DESIGN.md` already named. Sqlite would be defensible at
  larger scale but this lab's key space is tiny (6 `server_command` values,
  23 tool+server pairs, per Phase 2's own count) — flat JSON keeps this
  auditable by eye, same spirit as this project's other small artifacts.
  State is regenerable from telemetry replay, not something to hand-author —
  gitignored, not committed.
- **Reset mechanism**: needed and explicit, not implied. Re-running the
  watcher over the same telemetry twice must be idempotent (replaying
  Session A a second time should not read as "new" drift just because the
  state file already has an entry — comparing against the *stored* hash,
  not "have I seen this session_id before," handles this by construction).
  But a clean test run (e.g. re-validating after a rule change) needs a
  documented way to wipe the state file and start from empty, or successive
  validation runs would silently inherit baselines from earlier runs. `make`
  target or a `--reset` flag on the watcher script — implementation detail,
  flagging that it must exist, not leaving it implicit.

## New record stream — schema and file

New file, sibling to the existing telemetry log:
`/var/log/mcp-detect/rugpull_alerts.jsonl`. The watcher appends one record
per **newly observed differing hash** (dedup key: `(baseline_key,
observed_hash)` — emits once when a value is first seen to differ, not once
per subsequent record still carrying that same already-flagged value; a
30-record session with a drifted hash shouldn't produce 30 alerts).

```json
{
  "event_type": "rugpull_baseline_drift",
  "timestamp": "2026-07-09T12:00:00Z",
  "drift_field": "tool_description_hash",
  "tool_name": "send_email",
  "server_command": "python3 attacks/servers/rugpull_email_server.py",
  "baseline_hash": "sha256:...",
  "baseline_first_seen_session_id": "<session A's session_id>",
  "observed_hash": "sha256:...",
  "drift_session_id": "<session B's session_id>",
  "scenario_id": "rug_pull",
  "task_id": "attack_rug_pull_send_email_v2_pulled",
  "label": "malicious",
  "generator": "mcp-detect-rugpull-watch/1.0"
}
```

Not a `schema.json` v1 field addition — this isn't proxy-emitted wire
telemetry (it fails the schema's own definition: `raw` must be "the exact
message as it appeared on the wire," and this record has no `raw` at all).
It's a derived detection artifact living in its own stream, same
relationship a FIM alert has to the filesystem event that triggered it.

**Deliberate field-name choice, not cosmetic — this is the parent-disjointness
fix:** `drift_session_id` and `server_command`'s sibling fields are named to
avoid colliding with `100100`'s literal match vocabulary. See below.

## Parent-disjointness — resolved structurally, the same way 3a resolved `100101`/`100103`

Introducing a second top-level parent rule risks exactly the shadowing hazard
`docs/WAZUH-NOTES.md` proved: two independent top-level rules that can both
match one event get arbitrated by an undocumented internal order, not by
rule ID or filename. `100100` requires `session_id` (any non-empty value)
**and** `server_command` (any non-empty value) — both present on my first
draft of the drift record. That draft would have been a real collision risk.

**The naive fix doesn't work, and it's worth saying why rather than silently
avoiding it**: negating `100100` on `event_type`'s absence (so real telemetry,
which never has that key, still matches `100100`) hits the exact
negate-on-absent-field gate that already failed once in 3a — real telemetry
records genuinely lack `event_type`, so `negate="yes"` against it would never
be satisfied for the very traffic `100100` exists to match. That's not a
hypothetical, it's the same failure mode 3a hit, recognized before writing
it rather than after.

**The actual fix**: don't touch `100100` at all. Give the drift record's
session/command-identifying fields names `100100` doesn't key on —
`drift_session_id` instead of `session_id`. `100100`'s `<field
name="session_id">` condition requires a key literally named `session_id`;
a drift record that never has that key **cannot** satisfy a positive
(non-negated) field-presence match — this is the ordinary, well-understood
behavior of an absent field against a plain match (the absent-field pitfall
only bit us on `negate`, not on this). This makes `100100` and the new
parent below **formally disjoint by construction**, readable from the field
names alone, no reliance on Wazuh's undocumented top-level ordering — same
philosophy 3a used for `100101`/`100103`, applied one level up, and simpler
here since no negation is needed at all.

## New rules — parent and child

```xml
<rule id="100200" level="0">
  <decoded_as>json</decoded_as>
  <field name="event_type" type="pcre2">^rugpull_baseline_drift$</field>
  <description>MCP-DETECT rug-pull baseline-drift record ingested</description>
</rule>

<rule id="100201" level="12">
  <if_sid>100200</if_sid>
  <field name="drift_field" type="pcre2">.+</field>
  <description>MCP rug pull: tool=$(tool_name) server=$(server_command) field=$(drift_field) baseline=$(baseline_hash) observed=$(observed_hash)</description>
  <mitre>
    <id>T1554</id>
  </mitre>
  <group>mcp_detect,rug_pull,</group>
</rule>
```

`100200` is a new canonical parent, not a "specific detection rule" —
consistent with `docs/WAZUH-NOTES.md`'s constraint as literally written
("every specific detection rule ... must be a child ... never an
independent top-level rule"): `100100` is itself top-level too, this mirrors
that established pattern for a genuinely different log shape rather than
overloading `100100`'s semantics ("any ingested MCP-DETECT wire-telemetry
record") with a derived artifact that was never wire telemetry. `100201`
carries an explicit `<field>` condition (not bare-`decoded_as`/bare-`if_sid`)
per the same audit discipline 3a applied to `100102`/`100103`.

## Watcher run modes

Mirroring 3a's own two-mode validation pattern (batch `wazuh-logtest` for
measurement, one genuine live pass for real-alert confirmation):

- **Batch mode** (measurement): point the watcher at a static file (the
  frozen `data/benign_corpus_v2.jsonl`, or the canonical `telemetry.jsonl`
  filtered to specific sessions), process it once start-to-finish against a
  scratch baseline state, write out the resulting drift records to a scratch
  file — never touching the live pipeline. This is how false-positive and
  recall measurement gets done, same "don't grow `telemetry.jsonl` by
  thousands of lines for a measurement exercise" discipline as 3a.
- **Tail mode** (live confirmation): the watcher runs continuously against
  the live `telemetry.jsonl`, appending new drift records to the live
  `rugpull_alerts.jsonl` as they're detected — used exactly once, for a
  single genuine end-to-end alert capture (matching 3a's "ran one minimal
  new session through the live pipeline and captured the real alert," not
  just trusting logtest output).

## Restart budget — one nuance this phase adds

3a's restart-free workflow (`docker compose cp` + `wazuh-logtest`) covers
**rule-content** iteration fully — nothing changes there, `100200`/`100201`
get validated the same way. But this phase also needs a new `<localfile>`
block in `ossec_localfile.xml` pointing at `rugpull_alerts.jsonl`, and
`wazuh-logtest` doesn't care what's configured there — it accepts arbitrary
piped input regardless of live log-source configuration, so rule validation
never needs this change installed. The manager only needs to actually be
watching the new file for the **live tail-mode confirmation** step. Proposing
budget **2** for this round, same size as 3a's: one restart to install the
validated `100200`/`100201` rules + the new `<localfile>` block together
(both are needed for the live step, no reason to spend two restarts doing it
in two trips), one held in reserve.

## Known edge cases, named rather than discovered later

- **Legitimate version bumps read as drift under this model, by design.**
  This detector's whole premise is "any hash change against a
  supposed-to-be-static fleet is anomalous" — true for this lab's frozen,
  pinned benign corpus (verified 23/23 stable in Phase 2), but a real
  deployment with legitimate server upgrades would need a re-baseline/allowlist
  workflow this design does not build. Scope boundary, stated now, not a gap
  found later.
- **Replay ordering is a design assumption, not enforced by the watcher.**
  Session A must be processed before Session B for A to correctly become the
  baseline. Holds by construction today (single append-only file, real
  timestamp order) — worth stating as relied-upon, not silently assumed.
- **No benign near-boundary fixture exists for this technique.** Unlike
  credential-exfil's near-boundary reads, the current corpus has no
  "legitimate version bump" session to test the false-positive floor against
  — named as a real gap, not simulated by inventing one without saying so.

## Validation / metrics plan

1. Batch-run the watcher over the full `data/benign_corpus_v2.jsonl` (541
   sessions) against a fresh baseline state — expect **0** drift records,
   re-deriving Phase 2's 23/23-stable finding from the actual watcher code
   instead of the one-off analysis query that first found it.
2. Batch-run over the canonical `rug_pull` session pair already in
   `telemetry.jsonl` (`_v1_baseline`, `_v2_pulled`, in original order) —
   expect exactly 2 drift records, both attributed to Session B (one
   `server_version_hash`, one `tool_description_hash`), zero from Session A.
   This is n=1 pair — same "softest number" caveat 3a named for its own
   n=1 original attack telemetry, stated equally honestly here rather than
   implied away.
3. Batch-run over the full canonical attack slice (all 35 records: tool
   poisoning + credential exfil + rug pull) to confirm no phantom drift
   crosses between unrelated scenarios' `(tool_name, server_command)` keys —
   checked empirically, not assumed independent just because the keys look
   different.
4. Feed the resulting drift-record file through `wazuh-logtest` (batch),
   confirm `100200`→`100201` is the final matched rule for exactly the
   expected records, cross-referenced by the carried-through
   `scenario_id`/`task_id`/`drift_session_id` fields.
5. One live tail-mode run, one fresh minimal rug-pull replay session, one
   captured real alert — matching 3a's "not just logtest" discipline.
6. **Not proposed for this round, flagged as a continuation decision for
   you**: 3a's variant rounds (12 tool-poisoning + 10 credential-exfil
   reproductions) turned n=1 into n≈11–13 measured recall. The same move is
   available here (vary server-version-string wording, cover-description
   framing, maybe which of the two hash fields drifts alone vs. both
   together) but is a real scope decision, not a default — see open
   questions below.

## Coverage map — proposed addition

| technique | rule(s) | status |
|---|---|---|
| Rug pull (SAF-T1201) | `100200`/`100201` (new, via `baseline/` watcher) | **Proposed.** Persistent-baseline mechanism, no `timeframe` cap, no FIM alert-shape mismatch. Pending your sign-off before any file is touched. |

## Open questions for your sign-off

1. **Architecture (option 3 above)** — external watcher + emitted flag
   record, vs. either of the two rejected alternatives. I think option 3 is
   the clear right call given the constraints already on record; flagging
   in case you see something I don't.
2. **New top-level parent (`100200`) vs. some other way to route this
   stream** — I resolved the disjointness risk by renaming fields rather
   than negating; want your sign-off on that specific fix before it's built,
   since it's the one place this design deviates from simply repeating 3a's
   pattern.
3. **Variant round now or later** — build the n=1 rug-pull proof first and
   stop (matching 3a's original build gate), or include a variant round in
   this same phase's build step (matching how 3a *also* ended up doing a
   variant round, just in a later pass)?
4. **`baseline/` as a new top-level directory** — reasonable home, or would
   you rather this live under `wazuh/` (since its only consumer is Wazuh) or
   `attacks/` (since rug pull is the only technique using it so far)?

Awaiting sign-off before touching `wazuh/local_rules.xml`,
`wazuh/ossec_localfile.xml`, or any telemetry.

---

## Sign-off (received) and how each point was honored

- **Q1 (architecture, option 3)** — approved, with the explicit condition
  that the detector's correctness be proven by Python unit tests
  independent of corpus replay. Done: `baseline/test_watch.py`, 12 tests,
  covering first-seen/TOFU, idempotent replay, dedup-per-newly-drifted-hash
  (not per record), correct baseline-vs-observed attribution, and
  independent tracking per `(tool_name, server_command)` key. All 12 pass.
  Corpus replay (below) is the separate integration check, as instructed.
- **Q2 (parent + field-rename)** — approved, conditional on an explicit
  `wazuh-logtest` check proving a drift record does **not** match `100100`.
  Done, and it caught something real — see "The Suricata collision" below.
- **Q3 (variant round)** — declined as proposed; folded into the core proof
  instead as three separately-generated, separately-reported drift shapes
  (description-only, version-only, both). Done — see "Three drift shapes"
  below.
- **Q4 (`baseline/` location)** — approved as a new top-level directory,
  gitignored state file, `--reset` flag implemented.
- **Q5 (FP-floor honesty)** — no allowlist/re-baseline workflow built this
  round, as instructed. The metrics section below states the weaker claim
  explicitly rather than presenting "0 FP" as equivalent to 3a's.

## Build results

### Watcher unit tests — first, per the build gate

`baseline/watch.py` + `baseline/test_watch.py`. 12 tests, all passing,
covering exactly the four properties Q1 named:

| test class | what it proves |
|---|---|
| `TestFirstSeenBaseline` | first observation sets baseline silently; repeated identical hashes never alert; missing fields don't crash or alert |
| `TestDriftDetectionAndAttribution` | both-drift, description-only, and version-only all produce correctly-attributed events (right `drift_field`, right `baseline_hash`/`observed_hash`, right `tool_name` — `null` for server-level drift) |
| `TestDedup` | a drifted value repeated across many records in one session alerts exactly once, not once per record; reverting to baseline is silent; a later *third*, distinct value alerts again (dedup is per `(key, hash)`, not per `key`) |
| `TestIndependentKeys` | different `tool_name`s and different `server_command`s never cross-contaminate each other's baseline or dedup state |
| `TestIdempotentReplay` | replaying the same file twice from a fresh state produces identical output; replaying against already-persisted state (the real "run the watcher again later" case) is a no-op |

Run: `python3 -m unittest baseline/test_watch.py -v` — 12/12 pass, 0.003s.

### Three drift shapes — the corpus-replay proof Q3 asked for instead of a variant round

Extended `attacks/servers/rugpull_email_server.py` with two new
`RUGPULL_VERSION` modes (`pulled_desc_only`, `pulled_version_only`) that hold
one of the two hash inputs byte-identical to baseline while changing the
other — isolating the two drift signals `pulled` (the original Phase 2
mode) always changes together. Generated both as new sessions via
`attacks/harness.py`'s new `rug_pull_drift_shapes` mode, through the live
proxy, into the canonical `telemetry.jsonl` (schema-valid, confirmed via
`schema/validate.py`: 890/890 records valid after generation). Real
proxy-computed hashes confirm the intended shapes exactly:

| task_id | `tool_description_hash` | `server_version_hash` |
|---|---|---|
| `..._v1_baseline` | `61b6e28c...` | `22a79a29...` |
| `..._v2_pulled` (both drift) | `018640fd...` (differs) | `a2201960...` (differs) |
| `..._v3_desc_only` (new) | `bc7c1c3d...` (differs) | `22a79a29...` (same as baseline) |
| `..._v4_version_only` (new) | `61b6e28c...` (same as baseline) | `724a210e...` (differs) |

### Batch corpus-replay validation

Ran `baseline/watch.py` (fresh state, scratch output, no live-pipeline
mutation) over: (1) `data/benign_corpus_v2.jsonl` alone (4727 records, 541
sessions), (2) the full canonical malicious slice alone (266 records: all of
Phase 2/3a's attacks plus the 2 new rug-pull sessions), (3) both combined
(4993 records, one state, one pass) — same three-way structure 3a used for
its own validation.

- **Benign corpus: 0 drift records**, all three runs. Re-derives Phase 2's
  23/23-stable finding from the actual watcher code, not the one-off query
  that first found it.
- **Malicious slice: 8 drift records**, identical across the standalone and
  combined runs (no ordering sensitivity). Broken down:

| scenario_id | task_id | drift_field | expected? |
|---|---|---|---|
| `rug_pull` | `..._v2_pulled` | `server_version_hash` | yes |
| `rug_pull` | `..._v2_pulled` | `tool_description_hash` | yes |
| `rug_pull` | `..._v3_desc_only` | `tool_description_hash` | yes |
| `rug_pull` | `..._v4_version_only` | `server_version_hash` | yes |
| `credential_exfil_via_read` | `..._v02` | `tool_description_hash` | **not predicted** |
| `credential_exfil_via_read` | `..._v03` | `tool_description_hash` | **not predicted** |
| `credential_exfil_via_read` | `..._v04` | `tool_description_hash` | **not predicted** |
| `credential_exfil_via_read` | `..._v05` | `tool_description_hash` | **not predicted** |

**Recall on the rug-pull scenario itself: 4/4, exactly as predicted** — every
intended drift shape fires, `v1_baseline` correctly produces zero (it *sets*
the baseline).

**The 4 unpredicted alerts — a genuine finding, investigated and named, not
hidden.** `attacks/servers/exfil_sink_server.py` (3a's credential-exfil sink)
names its `exfiltrate` tool's `inputSchema` property after the
`EXFIL_ARG_KEY` env var (`data`/`payload`/`content`/`body`/`message` — how
3a tested rule `100103`'s key-name scope limit), but its `server_command` is
identical (`python3 attacks/servers/exfil_sink_server.py`, no args) across
every variant — the schema change is invisible on the command line, only
visible in the tool's actual declared definition. So `tool_description_hash`
for `(exfiltrate, exfil_sink_server.py)` genuinely, correctly differs
across those sessions. **The detector is behaving exactly as designed** —
this is real schema drift, correctly detected — **the label is what's
misleading if read carelessly**: these are `credential_exfil_via_read`
sessions, not rug-pull attack instances; the drift is an artifact of 3a's
own variant-generation technique (reusing one `server_command` across
schema variations for an unrelated purpose), not evidence of SAF-T1201
occurring there. Per your instruction, documented as-is, no code change:
**true positives for the rug-pull technique are 4/4**; the other 4 are
correct detections of real drift, attributed to the wrong scenario if
skimmed, named here so they aren't mistaken for either a rug-pull false
negative story or a detector bug.

### The Suricata collision — found by the exact check Q2 required

Before writing `100200`/`100201` into the live ruleset, the field originally
chosen to discriminate a drift record was `event_type` (paired with the
`timestamp` field every drift record also carries). Fed through
`wazuh-logtest -v` as Q2 required — an explicit check that a drift record
does *not* match `100100` — the result was worse than a `100100` collision:
**neither `100100` nor my own `100200` was ever tried at all.** Wazuh's
stock Suricata parent rule (`86600`, shipped in
`/var/ossec/ruleset/rules/0475-suricata_rules.xml`, not authored here)
requires exactly `<decoded_as>json</decoded_as>` plus fields literally named
`timestamp` and `event_type` both present — and it matched first, at the top
level, shadowing everything else per the same first-match-wins mechanism
`docs/WAZUH-NOTES.md` already proved. A real top-level collision against a
**stock** rule, not `100100` — the specific risk-class Q2 asked to check
for, just from a direction I hadn't anticipated (a shipped ruleset default,
not my own `100100`).

Fixed by renaming the field to `mcp_drift_marker` — grepped against every
loaded stock and custom rule file for all fields the drift record uses
(`mcp_drift_marker`, `server_command`, `drift_field`, `baseline_hash`,
`observed_hash`, `drift_session_id`, `baseline_first_seen_session_id`,
`tool_name`, `label`, `scenario_id`, `task_id`, `generator`) — zero
collisions for any of them. Reconfirmed via `wazuh-logtest -v`:

```
Trying rule: 86600 - Suricata messages.        (tried, does not match)
Trying rule: 100100 - MCP-DETECT telemetry record ingested   (tried, does not match)
Trying rule: 100200 - MCP-DETECT rug-pull baseline-drift record ingested
    *Rule 100200 matched
Trying rule: 100201 - MCP rug pull: ...
    *Rule 100201 matched
```

Run across all 8 drift records individually (not just one): `100100` tried
8 times, matched 0; `86600` tried 8 times, matched 0; `100200`/`100201`
matched 8/8. **Disjointness against both `100100` and the pre-existing stock
ruleset confirmed empirically**, exactly as Q2's condition required — not
asserted from the field-name argument alone, which is exactly the case that
would have shipped a phantom-coverage rule if the check had been skipped.

### Full-corpus regression, with the new rules installed

Same batch `wazuh-logtest` run as 3a's own methodology, all 5001 lines
(4727 benign + 266 canonical attack + 8 drift records) in one pass, final
matched rule id parsed programmatically per line:

| rule | count | matches 3a's own numbers? |
|---|---|---|
| `100100` (no alert) | 4959 | yes (4727 benign + 232 unrelated attack records) |
| `100101` | 11 | yes, unchanged |
| `100102` | 12 | yes, unchanged |
| `100103`–`100107` | 3, 2, 2, 2, 2 | yes, unchanged |
| `100201` (new) | 8 | new this phase — see breakdown above |

**Zero false positives, still** — 4727/4727 benign records land on `100100`
only. 3a's rules are completely unaffected by this phase's addition.

### Restart budget: 1 of 2 spent

`wazuh-analysisd -t` (config test) passed clean before touching the live
manager. One restart (`docker compose stop wazuh.manager` + `up -d`, per the
established "more reliable than `restart` in this environment" finding)
installed, together: the validated `100200`/`100201` rules, and the new
`<localfile>` block for `rugpull_alerts.jsonl` in `ossec.conf` (needed once,
live-only — `wazuh-logtest` never needed it, since it accepts arbitrary
piped input regardless of configured log sources). Pre-touched
`rugpull_alerts.jsonl` empty before the restart, matching the Makefile's own
documented race-avoidance discipline for `telemetry.jsonl`. Post-restart
health: `wazuh-analysisd`/`wazuh-logcollector`/`wazuh-remoted`/`wazuh-apid`
all running; `ossec.log` confirms `logcollector` picked up
`rugpull_alerts.jsonl` immediately. The second restart was not needed and
remains in reserve.

### Live end-to-end confirmation

Ran `baseline/watch.py --follow` against the live `telemetry.jsonl`
(fresh state) inside the `agent` container. Its startup catch-up pass over
existing history reproduced the same 8 drift records found in batch
validation, appended live to `rugpull_alerts.jsonl`, and Wazuh fired all 8
for real (not just in `logtest`). Then, to prove real-time tailing
specifically (not just startup catch-up), ran one fresh minimal new session
(`attack_rug_pull_send_email_live_confirm`, a description-only drift,
build-verification only — not part of the canonical variant table) through
the live pipeline. The watcher picked it up within the poll interval,
appended a 9th record, and Wazuh produced a real, fresh alert:

```json
{"rule":{"level":12,"id":"100201","description":"MCP rug pull: tool=send_email server=python3 attacks/servers/rugpull_email_server.py field=tool_description_hash baseline=sha256:61b6e28c... observed=sha256:3f6389fe...","mitre":{"id":["T1554"],"tactic":["Persistence"]}},"decoder":{"name":"json"},"location":"/var/log/mcp-detect/rugpull_alerts.jsonl"}
```

The validation watcher process was stopped afterward (not left running) —
this build proved the mechanism works end-to-end; whether it runs
continuously as standing infrastructure is a separate operational decision,
out of scope here.

### The FP-floor honesty note Q5 asked for

**"0 false positives" for this phase is a real but structurally weaker claim
than 3a's "0 FP" for `100101`/`100102`/`100103`–`100107`, and that
difference is inherent to the technique, not a gap in this round's rigor.**
3a's rules are content/path-match rules: "0 FP" means the benign corpus
never contains that specific attack-shaped content, a claim that stays true
regardless of how the benign fleet evolves. This phase's "0 FP" means
something narrower: *the frozen benign corpus's pinned server versions never
change*, which is true by construction (Phase 1b froze it) and was already
known before this build ran a single line through the watcher. This
detector's actual premise — any hash change against a `(tool_name,
server_command)` pair is anomalous — has **no benign fixture that exercises
the case it would need to distinguish**: a legitimate version bump. No such
fixture exists in this corpus (named in the design doc's "known edge cases"
and confirmed still true here — none was invented for this round, per your
instruction not to build the allowlist/re-baseline workflow). So this
phase's 0/4727 is accurately described as *"no drift occurred in the one
scenario this corpus contains (static pins)"*, not *"the detector correctly
declines to flag benign change,"* which is an untested claim. Recall (4/4 on
the rug-pull scenario, only some drift crossed named-and-explained) is on
much firmer footing than the FP claim is, for the specific reason that this
technique's threat model **is** "any change is the signal" — there is no
softer, partial-credit version of that claim to make honestly.

## Coverage map — final for Phase 3b

| technique | rule(s) | status |
|---|---|---|
| Rug pull (SAF-T1201) | `100200`/`100201` (via `baseline/watch.py`, persistent TOFU baseline) | **Covered.** 4/4 measured recall across all three drift shapes (description-only, version-only, both). 0/4727 FP against the benign corpus — a real but narrower claim than 3a's FP numbers, see above. Zero manager restarts spent beyond the one budgeted install; live end-to-end alert confirmed, not just `logtest`. |

`git_show`: no rule in this phase keys on it, consistent with
`docs/WAZUH-NOTES.md` constraint 1 (unaffected — this phase doesn't touch
that field at all).

Build complete. `baseline/state/*.json` is gitignored and regenerable
(`--reset`); nothing hand-authored needs to be committed there.

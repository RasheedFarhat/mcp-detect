# Phase 6 Design — The Detection-as-Code Framework (v2 — decision-complete)

Status: **v2 — findings folded in, sign-off-ready.** Revised from the v1
proposal after an adversarial review (`docs/PHASE6-REVIEW.md`); every
confirmed finding is folded into the sections below as an actual
schema/wording change, not a footnote pointing at the review. Still design
only — no framework code, no `detections/` directory, no dependency
installed, `wazuh/local_rules.xml` and `baseline/watch.py` untouched.
DaC-Pipeline / Sigma compilation remains explicitly out of scope for this
document (one-line placeholder in Section 1(a)) — that decision is being
made separately and later, not designed, evaluated, or resolved here.

## Review-verification pass (Step 1 — measured, not assumed, applied to the review itself)

Before folding any finding from `docs/PHASE6-REVIEW.md` into this design,
each of its five findings was re-checked directly against the actual files
— not re-trusted from the review's own citations. Verdicts below; all five
reproduce, one citation needed correcting.

1. **Finding 1 (backend-as-scalar can't express rug pull's two-stage
   pipeline) — confirmed.** `wazuh/local_rules.xml:314-318` (`100200`)
   matches only on `mcp_drift_marker`, a field that exists solely on
   `baseline/watch.py`'s emitted output (`baseline/watch.py:98`) — never on
   raw wire telemetry (`100200` is a new top-level parent, not a child of
   `100100`, exactly as `wazuh/local_rules.xml:282-296`'s own comment
   argues). `analysis/evasion_report.py:217-227`
   (`run_rugpull_watcher_on_evasion_corpus`) runs `watch_mod.process_record`
   over raw lines first, producing `drift_lines`
   (`analysis/evasion_report.py:236-237`), which are then fed into a
   *separate* `run_wazuh_logtest_batch()` call alongside the canonical
   inputs (`analysis/evasion_report.py:244-246`). Two chained stages,
   confirmed directly in the code, exactly as claimed.
2. **Finding 2 (Alert join correct in shape, absent from schema) —
   confirmed.** `analysis/report.py:213-219`'s `normalize_and_join()` has
   exactly the `if "session_id" in record: ... elif "drift_session_id" in
   record: ...` chain, producing `primary_session_id` plus `related =
   [record.get("baseline_first_seen_session_id")]` for the drift case. The
   v1 example `detection.yaml` had no `session_key` block anywhere —
   confirmed by re-reading it before editing below.
3. **Finding 3.4 (negate-on-absent-field check is dynamic, not static) —
   confirmed, with a citation correction.** The v1 review cited
   `docs/WAZUH-NOTES.md` as the source; re-checking that file directly, it
   contains exactly one passing cross-reference to "the negate-on-absent-
   field gate" (`docs/WAZUH-NOTES.md:282`) inside its constraint-8
   discussion — not the finding's actual history. The real primary sources
   are `docs/PHASE3A-DESIGN.md:470-478` ("Build results" — `100103`'s first
   draft, negate on `tool_arguments.path`'s absence, "silently never
   fired... exactly the phantom-coverage failure mode the gate existed to
   catch," corrected to negate on `tool_name` instead) and
   `docs/PHASE5-REPORT.md:24` (E5's rejected fix, same failure mode,
   confirmed a second time via `wazuh-logtest -v`'s trace). Both instances
   were caught only by running the candidate rule through the real engine
   against a concrete fixture and reading the final matched rule id —
   nothing in either fixture's JSON shape reveals the behavior by
   inspection alone. The substance of the finding holds; citations below
   now point at the actual sources instead of `WAZUH-NOTES.md`.
4. **Finding 4a/4b (semantic backend: train/test identity + judge/corpus
   circularity) — confirmed.** The v1 design's reference-exemplar set
   explicitly included "E1/E2/E3b's actual evasion text," and the
   recommended pilot scope evaluated recall against those same three
   classes — confirmed as the identical corpus by re-reading both passages
   directly. `corpus/agent.py:29` pins `MODEL = "qwen3:1.7b"`;
   `data/benign_corpus_v2.summary.md:6` confirms that exact model generated
   the entire benign corpus; the v1 design's Tier-2 proposal named "the
   `ollama`/`qwen3:1.7b` stack this project already runs" as the escalation
   judge — same model, confirmed by direct comparison, not assumed.
5. **Finding 5 (parity oracle: right count, wrong members) — confirmed.**
   `analysis/report.py:266-275` (`compute_per_rule_fp`) uses
   `benign_session_count` (541) as `100102`'s FP denominator and
   `benign_tool_call_count` (1011) for every other content rule — different
   denominators per rule family, confirmed by reading the function body
   directly. `docs/PHASE4-REPORT.md:53-57` shows the rug-pull recall table
   names specific task_ids against specific drift fields, not just a
   fraction.

All five findings reproduce and are folded into the design below. No
finding required rejecting; Finding 3.4's citation is corrected in place.

## Restating the mandate, so it can't quietly narrow

No time constraint. The goal is the definitive MCP detection project, not
"three more rules." The measure of success for this phase specifically is
not a new detection — it's whether adding the 4th, 5th, and 50th detection
becomes mechanically cheap and structurally safe, on a foundation that
doesn't pretend one paradigm (string-matching) covers what Phase 5 proved
it structurally cannot.

## The architectural thesis, restated with the evidence behind it

Three findings, each already on record, each pointing at a different wall:

1. **Structural attacks fit string/field matching.** `100101`, `100102`,
   `100103`–`107` all work this way and are genuinely effective *within
   their stated scope* — 12/12, 11/11, 11/11 recall, 0 FP (Phase 4).
2. **Stateful attacks need persistent state Wazuh's classic rule DSL cannot
   hold.** `docs/PHASE2-DESIGN.md`'s headline finding: "differs from an
   established baseline" has no expression in Wazuh's rule syntax, and its
   one stateful primitive (`frequency`/`timeframe`) hard-caps at ~27.7
   hours — incompatible with a real rug pull's timescale. `baseline/watch.py`
   resolved this by moving statefulness *outside* Wazuh entirely (3b).
3. **Semantic attacks provably defeat regex, not just theoretically.**
   Phase 5 didn't argue this — it measured it. E1 (keyword-avoiding
   phrasing), E2 (dropping the HTML-comment wrapper), E3b (homoglyph
   substitution), and E8 (base64-encoded payload) all evade their target
   rule while preserving full attack efficacy (`docs/PHASE5-REPORT.md`).
   These are not tuning gaps in a specific regex — E1/E3b are named in
   that report as *impossible* to close with more keywords/homoglyphs
   without recreating the exact whack-a-mole this project has repeatedly
   refused to pretend is a fix.

**External validation, not just internal**: I pulled SAF-MCP's own
published reference detection for rug pull
(`techniques/SAF-T1201/detection-rule.yml`, fetched live via `gh api`, not
assumed) before writing this doc. Its Sigma `condition` references fields
like `days_since_approval: ">30"` and `baseline_deviation: ">2_std_dev"` —
fields **no stateless Sigma/Wazuh engine can compute from a single log
line**. The upstream framework's own reference rule silently assumes an
external stateful pipeline already produced those fields, without ever
specifying what that pipeline is. `baseline/watch.py` is the answer that
rule gestures at but never builds. This isn't a novel problem this project
invented — it's a real, still-open gap in the field's own reference
material, which is exactly why a framework that treats "detection" as one
paradigm (Sigma-only) would industrialize the gap, not close it.

Two consequences follow directly, both binding on everything below:

- The framework's core abstraction must be backend-agnostic *by
  construction*, not by convention — a detection-type field on a metadata
  object doesn't count if the actual matching logic still has to be
  crammed into Sigma-shaped YAML.
- `docs/WAZUH-NOTES.md`'s eight hard-won constraints (if_sid chaining,
  first-match-wins shadowing, the `\x3c` vs `&lt;` parser bug, the
  negate-on-absent-field gate — confirmed *twice* now, 3a and Phase 5 — and
  the stock-ruleset collision risk) don't go away because there's a
  framework now. They become things the framework must enforce
  automatically, or the framework has made the problem worse by hiding it
  behind an abstraction layer.

## 1. Framework architecture

### The detection abstraction

A **Detection** is a declarative metadata object. It never contains
matching logic inline — logic is backend-native and referenced, not
reimplemented in a universal DSL. Forcing one logic-expression syntax
across structural/stateful/semantic backends is exactly the mistake the
thesis above rules out; a `Detection` is a pointer plus a contract, not a
new rule language.

**`backend` is a list, not a scalar, per `docs/PHASE6-REVIEW.md` Finding 1
(confirmed above).** A single `backend:` field cannot describe a detection
whose stateful stage emits a derived record that a separate structural
rule then matches on — and that isn't a hypothetical future case, it's
what `baseline/watch.py` + `100200`/`100201` already do today. Every
`Detection` therefore declares `backends:` as a list of one or more stages,
each with its own `logic_ref` and a `consumes`/`emits` pair describing what
record shape it operates on:

```yaml
# detections/SAF-T1001_tool_poisoning_html_comment/detection.yaml
technique_id: SAF-T1001
name: tool_poisoning_html_comment
detection_type: structural          # structural | stateful | semantic
status: deployed                    # proposed | validated | deployed
mitre_attack_ids: ["T1195"]         # cited, not asserted -- verify per docs/PHASE2-DESIGN.md's own discipline
mitre_atlas_ids: ["AML.T0051.001"]
description: >
  HTML-comment-wrapped directive language in a tool's advertised
  description, revealed in a tools/list response.
backends:
  - backend: wazuh_rule              # extensible enum, not closed
    logic_ref:
      wazuh_rule_ids: ["100102"]
      rule_file: wazuh/local_rules.xml
    consumes: raw_telemetry          # raw_telemetry | derived_record -- drives if_sid auto-parenting, Section 2
    parent_rule: "100100"            # canonical if_sid parent this rule's ids chain under
expected_signal:
  record_type: "tools/list response"
  fields: ["raw.result.tools"]
session_key:
  primary_field: session_id          # unconditionally {primary_field, related_fields}, never a bare scalar -- see rug-pull example below for why
  related_fields: []
fixtures:
  attack_corpus: live:telemetry#label=malicious&scenario_id=tool_poisoning
  benign_denominator: data/benign_corpus_v2.jsonl#distinct_sessions   # 541
  evasion_corpus: data/evasion_corpus_v1.jsonl#task_id~=attack_evasion_e1_keyword_avoiding,...   # full id list in the real file
known_gaps:
  - "Keyword-avoiding phrasing (E1) -- not fixable without an open-ended list"
  - "No-HTML-comment obfuscation (E2)"
  - "Homoglyph substitution (E3b) -- deliberately not chased, same reason as E1"
  - "Padding past the 120-char proximity bound (E4)"
```

**Worked example proving the schema handles two backends — the rug-pull
migration Section 3 must ship this phase, not a future hypothetical:**

```yaml
# detections/SAF-T1201_rug_pull_baseline_drift/detection.yaml
technique_id: SAF-T1201
name: rug_pull_baseline_drift
detection_type: stateful
status: deployed
mitre_attack_ids: ["T1554"]
mitre_atlas_ids: []                 # none published upstream yet -- unverified, not asserted
description: >
  Persistent-baseline drift in a tool's advertised description or a
  server's version, detected against a TOFU baseline maintained outside
  Wazuh (baseline/watch.py), matched inside Wazuh only on the derived
  drift record it emits.
backends:
  - backend: stateful
    logic_ref:
      python_class: baseline.watch.RugPullBaselineDetector   # wraps process_record verbatim, Section 3 item 2
    consumes: raw_telemetry
    emits: derived_record            # this stage's output feeds the next backend entry, in list order
  - backend: wazuh_rule
    logic_ref:
      wazuh_rule_ids: ["100201"]
      rule_file: wazuh/local_rules.xml
    consumes: derived_record         # matches on the previous stage's emitted record, never on raw wire telemetry
    parent_rule: "100200"
pipeline: chained                    # backends run in list order, each stage's output feeding the next; single-entry backends lists (the SAF-T1001 example above) have no pipeline semantics to declare
expected_signal:
  record_type: "rugpull_baseline_drift derived record"
  fields: ["drift_field", "baseline_hash", "observed_hash"]
session_key:
  primary_field: drift_session_id
  related_fields: ["baseline_first_seen_session_id"]   # the dual-key case Finding 2 traced -- both fields land on the derived record baseline/watch.py:98-111 emits
fixtures:
  attack_corpus: live:telemetry#label=malicious&scenario_id=rug_pull
  canonical_derived_corpus: live:rugpull_alerts   # the already-computed drift records Phase 4 actually measured against -- see the schema-additions note below for why this is a separate fixture key, not a rerun of the stateful stage
  benign_denominator: data/benign_corpus_v2.jsonl#all_records   # 4727 -- rug pull's FP claim is full-corpus, not session-scoped; see Section 2 item 2's named residual re: cross-scenario firings
  evasion_corpus: data/evasion_corpus_v1.jsonl#task_id~=attack_evasion_e10_legit_upgrade,attack_evasion_e11_behavior_only,attack_evasion_e12_pulled
known_gaps:
  - "Legitimate version bumps fire indistinguishably from an attack (E10) -- no allowlist/re-baseline mechanism exists"
  - "Behavior-only rug pulls (no advertised-metadata change) are structurally invisible (E11) -- not fixable within this architecture"
```

Every field above already has a real, load-bearing counterpart somewhere
in this project's existing code — this schema is a generalization of
structures that already exist, not new invention:

- `technique_id`/`mitre_*` — already tracked per-rule as XML comments and
  in each phase's design doc prose; never machine-readable until now.
- `backends`/`logic_ref` — today, "which Wazuh rule IDs implement this" is
  something you have to read the XML to know, and "does this detection
  need a second stage" is something you have to already know the history
  of `baseline/watch.py` to realize. A stateful backend entry's `logic_ref`
  points at a Python class; a semantic backend entry's at a classifier
  config/model identifier; `consumes`/`emits` make the record-shape
  handoff between stages a declared field instead of something only
  legible by reading `wazuh/local_rules.xml`'s inline comments
  (`wazuh/local_rules.xml:280-296`).
- `session_key` — exactly the shape `analysis/report.py:213-219`'s
  `normalize_and_join()` already computes by hand (`primary_session_id` +
  `related_session_ids`), now a declared field instead of an `if/elif`
  chain that grows a branch per backend. **Stated limit, not a gap to
  discover later**: the `Alert` dataclass's `primary_session_id` is a
  scalar, so `related_fields` can hold zero or more auxiliary keys, but a
  future backend needing *multiple independent primaries* per record (no
  single canonical session at all) is out of scope for this schema as
  written and would require revisiting the `Alert` shape itself, not just
  adding another `session_key` entry.
- `fixtures` — exactly what `analysis/report.py`'s hardcoded
  `RULE_TECHNIQUE` dict and `evasion_report.py`'s hardcoded
  `EVASION_CLASSES` dict already encode, by hand, per rule, today. The
  framework's job is making this declarative and enforced, not inventing a
  new concept.
- `known_gaps` — this is the single most important field in the whole
  schema, and it's deliberately *structural*, not a comment. A Detection
  without a `known_gaps` list either has none proven (rare, and the schema
  should make that reviewable) or hasn't been red-teamed yet (`status:
  proposed`, not `validated`) — either way, the honesty discipline this
  project has held since Phase 2 becomes a field the tooling can check for,
  not prose someone has to remember to write.

### Three schema additions, confirmed during slice 1's build

`docs/PHASE6-MIGRATION-REPORT.md` disclosed three judgment calls made while
implementing the schema above against the real three-technique migration.
Per the standing discipline of syncing design to code before building
further on it, each is confirmed here against the actual implementing code
(not re-trusted from the migration report's own description) and folded in
as an actual schema change, not a footnote:

1. **`pipeline` has a second valid value, `"parallel"` — v2 only named
   `"chained"`.** Confirmed: `detections/SAF-T1502_credential_exfil/detection.yaml:31`
   declares `"pipeline": "parallel"`, and `framework/schema.py`'s
   `VALID_PIPELINES = {None, "parallel", "chained"}` accepts it. This is a
   real, necessary third shape neither the original design nor `docs/PHASE6-REVIEW.md`
   anticipated: credential exfil's frozen recall table reports its
   read-hop (`100101`) and exfil-hop (`100103`–`100107`) rule families as
   two independent numbers, neither depending on the other's output —
   `"chained"`'s emits/consumes handoff doesn't apply, but the Detection
   still has two `wazuh_rule` backend entries under one `technique_id`.
   `pipeline` values, complete as of this revision:
   - absent — single backend entry, no composition to declare.
   - `"parallel"` — multiple backend entries, each independently run
     against the same input; neither's output feeds the other.
   - `"chained"` — backend entries run in list order, each stage's `emits`
     feeding the next stage's `consumes` (rug pull's worked example above).
2. **`detection.yaml` files are literal JSON, not YAML exercising any
   YAML-specific syntax** (comments, folded scalars, anchors) **— this
   project has no YAML parser installed and none is being added.**
   Confirmed: `framework/schema.py`'s `parse_detection()` calls
   `json.loads(text)` directly; no `import yaml` anywhere in the codebase
   (confirmed by grep). This project has been stdlib-only throughout (no
   `requirements.txt`, no third-party imports in `analysis/`, `baseline/`,
   or `corpus/`) — PyYAML would be the first third-party dependency, for a
   schema small enough not to need one. JSON is a strict subset of YAML
   1.2, so every `detection.yaml` file remains a valid YAML document (a
   real YAML parser would read it identically) while being parseable with
   the stdlib `json` module. The illustrative YAML-with-comments examples
   in this section are documentation only — the real files on disk are
   comment-free JSON. If richer YAML features are ever needed, adopting a
   parser is a separate, explicit decision, not assumed.
3. **The `fixtures` block's string values follow a real, defined grammar —
   the placeholders shown in this section's examples were illustrative
   only until slice 1 built a parser.** Confirmed against
   `framework/fixtures.py`, which every `detection.yaml` file's `fixtures`
   block is actually written against:
   - `"data/<file>.jsonl#distinct_sessions"` / `"#tool_call_events"` /
     `"#all_records"` — three benign-denominator conventions (distinct
     `session_id` count; count of `method=="tools/call"` records; total
     record count), resolving what was previously just a comment
     (`# 541`) next to the fixture string into something `coverage.py`
     actually computes from the corpus.
   - `"live:telemetry#label=malicious&scenario_id=X"` — fetch the agent
     container's live `telemetry.jsonl`, filtered. Replaces the earlier
     placeholder `data/telemetry_malicious_slice.jsonl` (no such static
     file exists — the canonical attack corpus has only ever been a live
     container fetch, exactly as `analysis/report.py`'s own
     `load_inputs()` already did).
   - `"live:rugpull_alerts"` — fetch the agent container's live,
     already-computed `rugpull_alerts.jsonl` as-is. Necessary as its own
     fixture key (`canonical_derived_corpus`, not a rerun of the stateful
     backend entry) because `docs/PHASE4-REPORT.md`'s rug-pull numbers were
     measured against the production `baseline/watch.py` process's
     accumulated output across the full corpus-generation session, not a
     request-scoped recomputation over an isolated slice — re-deriving
     fresh from only the attack-labeled subset risks missing the benign
     baseline-setting records real drift is measured against.
   - `"data/evasion_corpus_v1.jsonl#task_id~=id1,id2,..."` — evasion
     corpus filtered to an explicit task_id list.
   This also corrected a real error in this section's own rug-pull
   example: v1/v2 showed `benign_denominator:
   data/benign_corpus_v2.jsonl#distinct_sessions` for rug pull, but
   `docs/PHASE4-REPORT.md`'s actual rug-pull FP claim is full-corpus
   (`0/4727`, `#all_records`), not session-scoped (`541`) — fixed in the
   worked example above, not just noted here.

### The three backends

**(a) Structural — Wazuh rules, hand-authored (the Direct path), no
compiler in the critical path.** `logic_ref` points at rule IDs in
`wazuh/local_rules.xml`, written directly, exactly as all 10 existing rules
already are. This is what migration (Section 3) uses, and it's the only
structural path this document defines or evaluates. **Structural backend
supports a future Sigma-compilation path (DaC-Pipeline); deferred, not
designed here** — out of scope for this document by explicit instruction,
not an oversight, and not folded into any finding or sign-off decision
below.

**(b) Stateful — generalizing `baseline/watch.py`.** `baseline/watch.py`
is already, structurally, one instance of a more general pattern: TOFU
baseline + drift detection + dedup + emit-a-flag-record-for-Wazuh. The
generalization is a small interface every stateful detection implements:

```python
class StatefulDetector(Protocol):
    def process_record(self, record: dict, state: dict) -> list[dict]:
        """Mutates state in place; returns zero or more derived event
        records (schema is detector-specific, same freedom
        baseline/watch.py's own drift-record schema already has)."""
```

`baseline/watch.py`'s existing `process_record` becomes
`RugPullBaselineDetector.process_record` verbatim — this is a wrapping
exercise, not a rewrite (Section 3 makes this an explicit, tested
migration step). A new stateful detection (e.g. a future
`ContextMemoryImplantDetector`) implements the same three-line contract
against whatever state shape it needs; the framework's batch runner
doesn't care what's inside `state`, only that it's a dict that survives
across `process_record` calls in record order — exactly what 3b already
proved works, generalized.

**(c) Semantic — see Section 4.** Deliberately its own section; it's the
riskiest piece and deserves being thought through on its own, not folded
into a bullet here.

### One unified alert stream, one coverage map

Every backend's output normalizes to one `Alert` shape:

```python
@dataclass
class Alert:
    detection_name: str
    technique_id: str
    primary_session_id: str
    related_session_ids: list[str]
    backend: str
    matched_content: dict
    timestamp: str
```

The `primary_session_id` resolution is Phase 4's `normalize_and_join`
generalized properly instead of the ad hoc `if "session_id" in record: ...
elif "drift_session_id" in record:` chain it is today — via the
`session_key` field defined on every `Detection` in Section 1
(`{primary_field, related_fields}`, unconditionally typed as that shape,
never a bare scalar). The join logic becomes table-driven from the
registry instead of an `if/elif` chain that grows a new branch every time a
new backend shows up. This directly fixes a real, if minor, scaling smell
already visible in today's code — see Section 1's `session_key` bullet for
the stated limit on this generalization (the `Alert` dataclass's
single-primary-per-record assumption).

One `coverage.py` (successor to `analysis/report.py` +
`analysis/evasion_report.py`, not a third parallel tool) walks the
registry and, for each `Detection`, runs its `backends:` list in declared
order (a single stage for most detections; a chained pipeline for
multi-backend ones like rug pull — Section 1's worked example) against
every registered corpus (benign, canonical attack, evasion — extensible as
more corpora are added), and emits one table: technique, detection,
backend(s), recall (per corpus, correct per-detection denominator — Phase
4's own "not one blanket number" discipline, generalized), FP rate,
`status`, `known_gaps`. This is what makes "coverage-mapped under one
system" true in practice, not just in a diagram.

## 2. How this makes scale cheap

### Adding technique N+1

**Today**: hand-write Wazuh XML, manually verify `if_sid` chaining,
manually probe disjointness via ad hoc `wazuh-logtest` runs, manually add
an entry to `analysis/report.py`'s `RULE_TECHNIQUE` dict and (if evading is
worth testing) `evasion_report.py`'s `EVASION_CLASSES` dict, manually
decide where the rule's doc-comment history lives.

**Framework**: author one `detections/<id>_<name>/detection.yaml` + one
backend-native logic file (a hand-authored Wazuh rule fragment, a
`StatefulDetector` subclass, or a classifier config) + fixture references.
Everything else — parent
chaining, disjointness verification, coverage-table entry, alert
normalization — is the compiler's and `coverage.py`'s job, not
per-detection hand-rolling.

### Automating the `if_sid` shadowing constraint — non-negotiable, made literal

`docs/WAZUH-NOTES.md`'s constraint (proven by Tests 1–5: two independent
top-level rules that can both match one event get arbitrated by
undocumented internal order) has been a **manual discipline** for every
rule in this project so far — a human remembering to chain `if_sid` and
then remembering to run a disjointness probe. A `compile_wazuh_ruleset()`
step replaces the "remembering" with an enforced pipeline. **All four items
below are checks that run the real engine against real fixtures — none of
them are pure static-analysis passes over XML or YAML text, and this
design says so plainly rather than mislabel a dynamic check as "static"**
(see item 4, corrected per `docs/PHASE6-REVIEW.md` Finding 3.4).

1. Every registered `wazuh_rule` backend entry declares `consumes:
   raw_telemetry | derived_record` (the schema field Section 1 now
   defines) — the compiler uses this declared field, not inference from a
   rule's own `<field>` conditions, to auto-assign the correct canonical
   parent (`100100` for `raw_telemetry`, `100200` for `derived_record`, or
   a new canonical parent if a future backend introduces a genuinely new
   record shape) — **the compiler refuses to emit an independent top-level
   rule, full stop**, closing off the exact failure class Tests 1–4 proved.
   This closes the gap `docs/PHASE6-REVIEW.md` Finding 1 named: v1 gave the
   compiler nothing structured to decide the parent from; `consumes` is
   that field.
2. **The disjointness gate is a hard block, not a warning**: the full
   frozen corpus set (benign + canonical attack + evasion, extensible)
   gets run through the newly compiled ruleset via real `wazuh-logtest`
   (never reimplemented in Python), and the compile step **fails loud** —
   same posture as `analysis/report.py`'s existing rule-sync gate — unless
   every detection's own registered fixtures still produce the expected
   verdict. Checking "final matched rule id equals the expected one" this
   way satisfies both halves of `docs/WAZUH-NOTES.md`'s sharper standing
   rule (lines 273-286) in a single pass: a match against the expected id
   confirms both that the detection's own rule fired *and* that nothing
   else intercepted the event first, since Wazuh reports exactly one final
   matched rule per record. This generalizes the exact fix 3a had to
   discover by hand for `100101`/`100103` (and rediscover, differently, in
   3b for `100100`/`100200`) into something that can't be skipped by a
   rushed rule addition three phases from now.

   **Named residual, not silently automated away**: this gate checks each
   detection's *own* registered fixtures plus the shared benign
   denominator — it does not automatically cross-check a new detection's
   rule against every *other* detection's attack/evasion fixtures. That gap
   is exactly the shape of the real, already-observed
   `100201`-fires-on-`credential_exfil_via_read` finding
   (`docs/PHASE4-REPORT.md`'s "Cross-scenario rule firings" section, lines
   63-69) — a legitimate, correct cross-firing that still needed a human to
   read the trace and confirm it wasn't a bug. The gate catches regressions
   against known-good fixtures; it does not replace that judgment call for
   a novel cross-detection firing. Named here so a future maintainer
   doesn't assume the compiler already covers it.
3. **The stock-ruleset collision check** (`docs/WAZUH-NOTES.md` constraint
   8 — the Suricata `86600` finding) becomes an automated pre-compile step:
   grep every new detection's discriminator field names against the
   *entire* loaded ruleset (`/var/ossec/ruleset/rules/*.xml`, not just this
   project's own files), refuse to compile on a collision. This was a
   one-off audit performed by hand in 3b; the framework makes it run on
   every compile, automatically, forever. **Also re-run on every Wazuh
   version bump, not only at detection-compile time**: as scoped, this
   check only protects against the ruleset loaded *right now* — a future
   Wazuh upgrade shipping a new stock rule file could introduce a collision
   against an already-shipped detection that a compile-time-only trigger
   would never re-surface.
4. **The negate-on-absent-field gate** (broke `100103`'s first draft in
   3a — `docs/PHASE3A-DESIGN.md:470-478` — broke a proposed
   `100103`/`100107` fix again in Phase 5 — `docs/PHASE5-REPORT.md:24` —
   now a *confirmed*, not suspected, property of this Wazuh version) is **a
   mandatory pre-promotion `wazuh-logtest` probe, not a static check** —
   corrected naming, per `docs/PHASE6-REVIEW.md` Finding 3.4. Both
   historical instances of this landmine were discovered only by running
   the candidate rule through the real engine against a concrete fixture
   and reading the verbose trace's final matched rule id; nothing in either
   fixture's JSON shape reveals the behavior by static inspection alone
   (`docs/WAZUH-NOTES.md`'s own closing section, "What was NOT root-caused
   at the C-source level," lines 288-298, is explicit that this is
   empirical engine behavior, not something derivable from the rule XML or
   fixture data by reading them). Any detection using `negate="yes"` on a
   field gets this probe — run the candidate against the fixture that
   should trigger it, confirm the final matched rule id is the expected one
   — before `status` can advance past `proposed`. It is folded into **the
   same fixture-execution machinery as item 2's disjointness gate**: both
   are "run the real engine against a real fixture, read the final matched
   rule id," not two different kinds of check.

None of this is new policy — every one of these is a rule this project
already follows by hand, stated in a design doc somewhere. The only thing
Phase 6 adds is making "by hand, and don't forget" into "the compiler
won't let you ship without it" for the genuinely mechanical parts (items 1
and 3), and "the compiler won't let you skip the real-engine check" for the
genuinely dynamic parts (items 2 and 4).

### Validation scaling

`coverage.py <detections-dir> <corpora...>` runs every registered
detection against every registered corpus and produces the one table
above, automatically. Adding a new benign or attack corpus (say, a future
Phase 7 broadens `benign_corpus_v2`) re-validates every existing detection
for free, the same day, instead of requiring a manual re-run of N
different measurement scripts.

## 3. Migration of the existing 3 techniques

**The existing rules and `baseline/watch.py` are the regression oracle —
not a first draft to improve while migrating.** The migration's job is
packaging, not rewriting.

1. **Wrap, don't rewrite.** Describe the 10 existing Wazuh rules
   (`100100`–`100201`) as `Detection` objects whose `logic_ref` points at
   the *exact* existing rule IDs in the *exact* existing
   `wazuh/local_rules.xml` — zero XML changes in this step.
2. **`baseline/watch.py` → `RugPullBaselineDetector`**: wrap its existing
   `process_record` behind the `StatefulDetector` interface with no logic
   changes. Its 12 existing unit tests (`baseline/test_watch.py`) must
   still pass unmodified against the wrapped class — the tests are the
   regression oracle for this specific refactor.
3. **Prove exact parity before calling migration done — the full table,
   not six numbers.** Run `coverage.py` against the same three frozen
   corpora Phase 4/5 already used (`data/benign_corpus_v2.jsonl`, the
   canonical attack telemetry slice, `data/evasion_corpus_v1.jsonl`) and
   require its output to diff clean against the **full per-task_id,
   per-rule-id tables** in `docs/PHASE4-REPORT.md`/`docs/PHASE5-REPORT.md`
   (or the full rendered report text — both reports are already
   deterministic and timestamp-free by construction,
   `analysis/report.py:386-391`, so a byte-diff is meaningful), not just
   the six flattened summary numbers (12/12, 11/11, 11/11, 3/3, 0/4727 FP,
   10/12 evasions succeeding). **Corrected from v1 per
   `docs/PHASE6-REVIEW.md` Finding 5**: matching only the flattened numbers
   is a weaker gate than it sounds, because `analysis/report.py`'s actual
   computation (`compute_per_rule_fp`, `compute_scenario_recall`,
   `analysis/report.py:266-293`) uses a *different denominator per rule
   family* (`100102`'s FP denominator is `benign_session_count`; every
   other content rule's is `benign_tool_call_count`) and names which
   specific task_id alerted on which specific rule/drift field
   (`docs/PHASE4-REPORT.md:53-57`). A regression could preserve the right
   count with the wrong members — e.g. a `session_key`/join bug
   attributing a hit to the wrong task_id while an unrelated task_id
   happens to also alert — and still pass a numbers-only check. Any
   discrepancy in the full table means the migration introduced a
   regression and blocks further work — this is the literal
   regression-oracle requirement you named, not a best-effort aspiration,
   now closed against the specific way it could have been gamed.
4. **No Sigma/DaC-Pipeline step in this migration at all** — every rule
   stays hand-authored XML, per the structural-backend decision above. The
   migration's success condition is "the framework reproduces what already
   works," not "the framework also happens to improve it."

## 4. The semantic backend

This is the newest kind of claim this project would be making, so it gets
the most scrutiny, not the least.

### Concrete proposal: two-tier, both free/local/OSS

**Tier 1 — embedding similarity (always-on, cheap).**
`sentence-transformers` with `all-MiniLM-L6-v2` (Apache-2.0, ~90MB, runs on
CPU, fully offline once downloaded — no paid API, no network call at
inference time). For a candidate text field (a tool description today;
generalizable to any free-text argument), compute cosine similarity
against two small, explicitly-labeled reference sets:

- **Attack-shaped exemplars**: reused, not invented — the poisoned
  descriptions already authored in `attacks/servers/poisoned_tool_server.py`
  and its Phase 3a/5 *non-evasion* variants (the 12 original tool-poisoning
  variants). These already exist as labeled fixtures; the semantic
  backend's reference set is a *read* of data this project already has,
  not new authoring.

  **Held out, not included, per `docs/PHASE6-REVIEW.md` Finding 4a
  (confirmed above)**: E1/E2/E3b's own evasion text
  (`data/evasion_corpus_v1.jsonl`) is *excluded* from this reference set,
  because the recommended pilot scope below evaluates recall against
  exactly those three classes. Building the reference set from the same
  text the pilot evaluates against would make "does the classifier catch
  E1/E2/E3b" close to tautological (near-1 cosine similarity to itself)
  rather than a real measurement — worse than the self-authored-variant
  narrowness already named below, since it's train/test identity, not just
  narrowness. This is a **data-partitioning fix, not a keyword-list fix**
  — it doesn't reintroduce the whack-a-mole this project has refused
  elsewhere. E1/E2/E3b stay strictly held-out evaluation data; the
  reference set is built only from the original, non-evasion specimens.
- **Benign exemplars**: the five real pinned MCP server packages' actual
  tool descriptions already in `data/benign_corpus_v2.jsonl`.

Score = max similarity to any attack exemplar. **Threshold is not asserted
— it's swept.** Compute the full similarity-score distribution across the
entire 4,727-record benign corpus (the same corpus every other detector's
0-FP claim is measured against) and pick the threshold at the point that
keeps benign FP at (or as near as achievable to) zero, reporting the actual
curve, not one cherry-picked cutoff — the continuous-score equivalent of
Phase 4/5's own measured-not-assumed discipline.

**Tier 2 — local LLM judge (escalation only, for the uncertain band).**
The `ollama`/`qwen3:1.7b` stack this project **already runs**
(`docker-compose.yml`, used today for benign-corpus generation) gets a
second job: for scores that land in an uncertain middle band (not
confidently benign, not confidently attack-shaped), ask it directly — "does
this tool description contain a hidden instruction meant to influence an
AI agent's behavior, separate from its stated function? Answer yes/no and
why." This keeps the slow, non-deterministic LLM call off the hot path for
the (large) majority of clearly-benign or clearly-attack-shaped traffic,
and adds zero new infrastructure — it's a new *use* of a service this
project already provisions and already trusts for a different purpose.

### The honest FP-risk assessment, stated as plainly as every prior caveat

**This backend is qualitatively riskier than the other two, not just
quantitatively.** A regex match is auditable — you can point at the exact
substring that tripped it. A cosine-similarity score in a 384-dimensional
embedding space is not auditable the same way; "why did this fire" has a
number attached, not a substring. That's a real cost, worth naming before
a single alert from this backend gets trusted the way a `100102` alert
is trusted today.

**The reference-exemplar set has the self-authored-variant problem in a
sharper form.** Every rule in this project has been honest that recall is
measured against variants *we* wrote. An embedding classifier trained
(via its reference set) on our own poisoned-description specimens has the
same limitation, but embedding similarity can create a false sense of
generalization — it *looks* like it's catching "the concept," but it's
really only as broad as the linguistic register of the ~15–20 specimens in
the reference set (all of which read as "SYSTEM:/IMPORTANT:"-style
directive English). A real attack written as a poem, a code comment, in a
different language, or in a register this project's own authored specimens
never touched, may not land anywhere near the reference cluster. This is
not a hypothetical caveat — it's the same caveat Phase 5 already proved
concretely for regex, restated honestly in advance for this backend rather
than waiting for a Phase 7 to discover it the hard way.

**The benign corpus's own homogeneity caps how strong the FP claim can
be.** `data/benign_corpus_v2.jsonl` is five pinned server packages
(Phase 1b). "0 FP against this specific corpus" is, again, a narrower claim
than "0 FP in general" — the same shape of caveat 3b/4/5 already stated for
the rug-pull detector's FP claim, restated here rather than let a clean
number imply more diversity than the corpus actually has.

**A fourth caveat, not folded into corpus homogeneity above because it's a
different failure mode — judge/corpus circularity** (per
`docs/PHASE6-REVIEW.md` Finding 4b, confirmed above): `corpus/agent.py:29`
pins `MODEL = "qwen3:1.7b"`, and that exact model generated the entire
benign corpus (`data/benign_corpus_v2.summary.md:6`) this backend's own
threshold sweep is measured against. The Tier-2 escalation judge proposed
above is the *same* model. This is not just infrastructure reuse — it
means the model whose stylistic tendencies and blind spots produced the
benign ground truth (already a named, real phenomenon:
`data/benign_corpus_v2.summary.md:131`, "Small-model behavioral noise") is
also the one being asked to judge ambiguous cases against a boundary shaped
by its own generative habits. A small model can plausibly be
well-calibrated to its own writing style and not representative of how
differently-authored benign text, or a differently-authored attack, would
actually score. Corpus homogeneity is about *diversity of the corpus*;
this is about *self-consistency bias in the judge* — a distinct risk,
worth carrying as its own named line rather than folding it into the
existing caveat where it would be easy to skim past.

**Recommended scope for a first build, if this design is approved**: pilot
this backend narrowly, against the three evasions regex structurally
cannot close (E1, E2, E3b) rather than deploying it as a blanket classifier
over all telemetry immediately. A scoped pilot lets its real FP behavior
get observed against a bounded problem before its blast radius grows —
directly answering your instruction not to bolt this on unevaluated, and
consistent with how every backend in this project has earned trust
incrementally rather than being declared correct on day one.

## 5. The taxonomy roadmap

Verified live via `gh api` against `github.com/SAFE-MCP/safe-mcp`
(fetched this session, not recalled from Phase 2's earlier check — the
prefix rename SAFE→SAF already happened once, so treating this as
permanently cached would repeat exactly the mistake Phase 2 caught the
first time). Current published taxonomy: **~85 techniques across 15
tactics** (`ATK-TA0001`–`ATK-TA0043`). A handful of table-listed techniques
(e.g. `SAF-T1206`, `SAF-T1405`, `SAF-T1901`–`1903`) have a name in the
overview table but no populated technique directory yet — the upstream
taxonomy is itself still growing, which is the concrete reason to
re-verify this list before relying on it in a future phase rather than
treat this section as a permanent snapshot.

**Filtered against what this project's telemetry model can actually
observe** (stdio JSON-RPC between client and one MCP server —
`initialize`/`tools list`/`tools call`/notifications/responses) before
prioritizing, not after:

### Structural — cheapest extensions, prove the framework's "author one YAML" claim first
| Technique | Name | Why prioritized |
|---|---|---|
| `SAF-T1105` | Path Traversal via File Tool | Direct sibling of `100101`'s own mechanism (`../` in `tool_arguments.path`) |
| `SAF-T1501` | Full-Schema Poisoning (FSP) | The CyberArk variant Phase 2 explicitly named out of scope for `100102` — same `raw.result.tools` field already proven to decode cleanly |
| `SAF-T1004` | Server Impersonation / Name-Collision | Single-record, lookalike-name check on `serverInfo` |
| `SAF-T1008` | Tool Shadowing Attack | Single-session tool-name collision check across servers |
| `SAF-T1602`/`1604` | Tool/Server Version Enumeration | Structural but **flagged as likely poor signal-to-noise** — legitimate clients enumerate routinely too; included for completeness, not a strong recommendation |

### Stateful — second proof point for `StatefulDetector`, deliberately not another hash-drift clone
| Technique | Name | Why prioritized |
|---|---|---|
| `SAF-T1205` | Persistent Tool Redefinition | Same mechanism as rug pull; near-zero marginal cost once the interface exists |
| `SAF-T1204` | Context Memory Implant | Genuinely different state shape (memory-store content, not tool metadata) — the real test of whether `StatefulDetector` generalizes or was secretly rug-pull-specific |

### Semantic — the backend's actual reason for existing
| Technique | Name | Why prioritized |
|---|---|---|
| `SAF-T1102` | Prompt Injection (Multiple Vectors) | The general case `100102` only covers one narrow obfuscation style of — the headline target this whole backend exists for |
| `SAF-T1402` | Instruction Steganography | Structurally undetectable by definition; a clean semantic-only case |
| `SAF-T1403` | Consent-Fatigue Exploit | Plausibly needs *both* semantic (wording analysis) and stateful (repeated-request counting) signals. **Resolved, not deferred** (see "Decided vs. still open" below): declares both as entries in its own `backends:` list, the same multi-backend mechanism the rug-pull worked example in Section 1 already proves out — not a second, bespoke "two cooperating detections" concept. |

### Explicitly out of scope, named rather than silently dropped
- **Every OAuth-flow technique** (`T1007`, `T1009`, `T1202`, `T1306`,
  `T1308`, `T1408`, `T1507`, `T1706`, `T1707`) — OAuth redirects happen over
  HTTP, outside the stdio transport this proxy captures at all. This is a
  **capture-architecture gap**, not a detection-design gap; closing it
  would need a fundamentally different capture point, a decision well
  beyond this phase.
- **`SAF-T1110`** (Multimodal Prompt Injection via Images/Audio) — this
  project captures text JSON-RPC only; no binary payload capture or
  multimodal embedding model exists here today.
- **Host/OS-level techniques** (`T1305` Host OS Priv-Esc, sandbox-escape
  variants) — need OS syscall/process telemetry this proxy doesn't
  collect.
- **`SAF-T1915`** (blockchain/DEX laundering), **`SAF-T2107`**/**`SAF-T3001`**
  (training-data/model/RAG poisoning) — downstream of what MCP wire
  traffic can show at all, regardless of backend.

## Decided vs. still open

Every in-scope open question from v1 is resolved below, with the rationale
that resolved it. One item remains a deliberate, explicit human call — not
because it wasn't analyzed, but because it was scoped out of this review
from the start.

### Decided

1. **`framework/` + `detections/<id>_<name>/` directory layout — confirmed
   as proposed.** `framework/` (compiler, backends, `coverage.py`) and
   `detections/<id>_<name>/` (one dir per detection, mirroring SAF-MCP's
   own upstream convention), sibling to `attacks/`, `baseline/`,
   `analysis/`. Mirrors this project's existing top-level layout; nothing
   in the review's findings depended on this being wrong.
2. **Semantic backend pilot scope — narrow scope (E1/E2/E3b) confirmed,
   gated on the held-out-data fix.** Piloting against a bounded problem
   before broadening remains the right call — the caution itself was never
   the issue the review raised. What was wrong was the *reference set's*
   composition: fixed above (Section 4) by holding E1/E2/E3b's own evasion
   text out of the reference-exemplar set and building it only from the
   original non-evasion specimens. The narrow scope is confirmed *as a
   scope*; the pilot does not run, and no recall number from it should be
   trusted, until that partitioning fix is in place.
3. **`SAF-T1403`'s two-backend question — resolved now, not deferred.**
   This was never a hypothetical reserved for some future technique:
   `docs/PHASE6-REVIEW.md` Finding 1 (confirmed above) shows it's already
   true of `RugPullBaselineDetector`, which this document's own Section 3
   migration commits to shipping this phase. Resolved via the `backends:`
   list plus `consumes`/`emits`/`pipeline` composition fields in Section 1
   — the rug-pull worked example there is the first real test of that
   schema shape, not a deferred future case. Whatever T1403 turns out to
   need, it reuses this same mechanism rather than inventing a second one.
4. **Taxonomy re-verification cadence — automated, non-blocking
   `coverage.py` warning.** The SAFE→SAF rename already happened once and
   was only caught by a live re-check that almost didn't happen (Section 5
   above, "treating this as permanently cached would repeat exactly the
   mistake Phase 2 caught the first time"). A live `gh api` check against
   the upstream taxonomy for every registered `technique_id`, surfaced as a
   warning — not a hard block, since a stale ID shouldn't stop a working
   detection from running — inside `coverage.py`, is cheap and consistent
   with this project's "measured, not assumed" discipline everywhere else.
   Periodic manual-only re-checking is exactly the discipline that already
   produced one near-miss.

### Still open — a human's explicit call

- **The DaC-Pipeline / Sigma-compilation path.** Deliberately not designed,
  evaluated, or resolved in this document (out of scope by explicit
  instruction) — represented only as the one-line placeholder in Section
  1(a): "structural backend supports a future Sigma-compilation path;
  deferred, not designed here." This is the one item where "build it"
  doesn't yet apply — the structural backend as designed here is the
  Direct hand-authored path only, and whether/when to revisit Sigma
  compilation is a separate decision for later, made against DaC-Pipeline's
  actual interface, not assumed into this design.

With the above, the only remaining action is to say "build it" against the
Direct structural backend, the generalized (now explicitly multi-stage)
stateful backend, and the gated semantic pilot — or to point at the
DaC-Pipeline question specifically, which is the one item this document
does not attempt to close.

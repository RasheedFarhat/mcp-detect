# Phase 6 Review — Adversarial Design Critique

Scope note, binding for this whole document: per instruction, DaC-Pipeline / Sigma
compilation is **out of scope** and not evaluated here. Everywhere the design's
structural backend is discussed below, "structural backend" means the Direct
hand-authored-Wazuh-rule path only (`docs/PHASE6-DESIGN.md` section 1(a), first
paragraph — "logic_ref points at rule IDs in wazuh/local_rules.xml, written
directly, exactly as all 10 existing rules already are"). The DaC-Pipeline
sign-off question is skipped entirely, as instructed.

## Verdict

**Safe with named changes — not yet safe to build on as literally written.**
The three-backend thesis, the migration discipline, and the honesty-as-schema
move (`known_gaps`) are all sound and already well-defended by evidence in this
repo. But the design has one real hole, not a hypothetical one: the two-backend
question it poses as an open question for a *future* technique (SAF-T1403) is
already live, today, in the rug-pull migration this same design commits to in
Section 3. Ship a fix for that before writing `Alert`, `Detection`, or
`coverage.py` — everything else below is real but secondary to that one.

---

## Finding 1 — The abstraction leaks, and not where the design expects

**Claim under test** (`docs/PHASE6-DESIGN.md` lines 74-79): "A Detection...
never contains matching logic inline — logic is backend-native and
referenced, not reimplemented in a universal DSL," with `backend` shown as a
single scalar field (line 85: `backend: wazuh_rule`).

**What actually breaks this**: `lab/baseline/watch.py`'s rug-pull detector, which
Section 3 requires this framework to wrap "with no logic changes"
(`docs/PHASE6-DESIGN.md` line 313), is *not* a one-backend detector today, and
wrapping it doesn't make it one:

- The stateful half lives in `lab/baseline/watch.py:114-135` (`process_record`),
  keyed on `(tool_name, server_command)` / `server_command` and emitting a
  derived JSON record only on genuine drift.
- The structural half is `wazuh/local_rules.xml:314-328` (`100200`/`100201`),
  which does an ordinary stateless field match — but *only on the derived
  record `lab/baseline/watch.py` emits*, never on raw wire telemetry. Confirmed by
  reading `100200`'s own condition (`mcp_drift_marker` — a field that only
  exists on `lab/baseline/watch.py`'s output, see `lab/baseline/watch.py:98`) and the
  comment at `wazuh/local_rules.xml:282-296` explaining why it's *not* a
  child of `100100` (the raw-telemetry parent).

So `RugPullBaselineDetector` (`docs/PHASE6-DESIGN.md` line 181) needs to
declare *both* `backend: stateful` (to run `process_record`) *and*
`backend: wazuh_rule` (to know which rule IDs match the record that process
emits) — but the schema shown gives it exactly one `backend:` scalar. The
design's own migration step 2 (line 310-314, "wrap its existing
`process_record` behind the `StatefulDetector` interface") never states what
value `backend:` takes for this Detection, or how `coverage.py`'s "runs every
Detection through its backend's batch runner" (line 220-222, singular
"backend's batch runner") is supposed to chain two runners — first
`process_record` over raw telemetry, then `wazuh-logtest` over *that
process's output* — which is exactly what `lab/analysis/evasion_report.py`
already has to do by hand today (`run_rugpull_watcher_on_evasion_corpus()` at
`lab/analysis/evasion_report.py:217-227`, followed by a separate
`run_wazuh_logtest_batch()` call on its output at line 246). The framework
doesn't eliminate this two-stage pipeline — it has no field to name it.

A second, smaller leak in the same direction: the `if_sid` auto-parenting
claim (line 258-261) says the compiler picks "the canonical parent (`100100`
for wire telemetry, `100200` for derived drift-shaped records, or a new
canonical parent if a future backend introduces a genuinely new record
shape)." Deciding *which* of those three a given `wazuh_rule` detection needs
requires knowing whether its logic operates on raw telemetry or a
derived/stateful-backend's output — but the schema's only candidate field for
that, `expected_signal.record_type` (line 97: `"tools/list response"`, free
text), is documented as informational, not a controlled vocabulary the
compiler consumes. As written, the compiler has nothing structured to decide
this from except reading the referenced rule's actual `<field>` conditions —
which is exactly the "compiler inspects content instead of trusting
metadata" failure mode a clean abstraction is supposed to avoid.

**Recommended change**: make `backend` a list, not a scalar (`backends:
[stateful, wazuh_rule]`), and add an explicit composition field describing
how a multi-backend Detection's runners chain (e.g. `pipeline: [{backend:
stateful, emits: derived_record}, {backend: wazuh_rule, consumes:
derived_record, parent_rule: "100200"}]`). This is not new policy — it's
naming, as a structural field, a pipeline that `lab/baseline/watch.py` +
`100200`/`100201` +`lab/analysis/evasion_report.py`'s two-call pattern already
implements today. Doing this now also answers sign-off question 3 below,
since it's the same fix.

---

## Finding 2 — The Alert join generalization is correct in shape, unspecified in schema

**Claim under test** (lines 208-217): replace `lab/analysis/report.py`'s
`if "session_id" in record: ... elif "drift_session_id" in record: ...` chain
(confirmed verbatim at `lab/analysis/report.py:213-224`) with a table-driven,
per-Detection session-key declaration.

**Traced against the real code**: `lab/analysis/report.py`'s
`normalize_and_join()` produces, for a rug-pull drift record,
`primary_session_id = record["drift_session_id"]` and
`related_session_ids = [record.get("baseline_first_seen_session_id")]`
(`lab/analysis/report.py:217-219`). The design's `Alert` dataclass (lines
197-206) already has exactly this shape —
`primary_session_id: str` plus `related_session_ids: list[str]` — so the
*data shape* the join needs to produce is a correct generalization: it's
literally the same two fields `JoinedRecord` (`lab/analysis/report.py:202-207`)
already has, renamed. This part of the design is sound and I'd say so
plainly rather than manufacture a complaint.

**What's missing**: the design describes the declaration only in prose
("each Detection declares which field on its own backend's derived record
carries the session-identifying key" — line 211-214) and never shows it in
the example `detection.yaml` (lines 82-108). There is no `session_key:`
block anywhere in the schema shown. Two consequences:

1. The rug-pull case needs *two* field names (a primary and a related), but
   the prose's "most: `session_id`" framing reads as if one field name is
   the general case and rug pull is a minor variant — in the schema that has
   to be `session_key: {primary_field: str, related_fields: list[str]}`
   from the start, not `session_key: str` with rug pull needing an
   exception. If the schema starts scalar and rug pull is bolted on as a
   special case, that's the "second special case wearing a general coat"
   the review was asked to check for. As long as `related_fields` is a list
   from day one (not added later for rug pull specifically), it isn't — but
   nothing shown today confirms that was the intent versus an oversight.
2. "A future backend might need a third shape" (line 214) is not defined —
   the `Alert` dataclass's `primary_session_id` is a scalar, so any backend
   needing *multiple primaries per record* (e.g., a detection that joins two
   independently-keyed streams with no single canonical session) would
   break the dataclass itself, not just the join table. Worth naming as a
   real ceiling now rather than discovering it mid-Phase-7.

**Recommended change**: add the concrete `session_key` block to the
example schema before writing `coverage.py`, typed as
`{primary_field: str, related_fields: list[str]}` unconditionally (never a
bare scalar), and record the dataclass's single-primary-per-record
assumption as a named limit in the design doc.

---

## Finding 3 — The four auto-enforced Wazuh constraints: three hold up, one is mislabeled

Evaluated against `docs/WAZUH-NOTES.md`'s actual eight constraints (only
four are claimed as automatable in `docs/PHASE6-DESIGN.md` section 2).

1. **`if_sid` auto-parenting** (design lines 258-261, constraint from
   `docs/WAZUH-NOTES.md` lines 22-32): mechanically automatable — inserting
   an `<if_sid>` tag is a deterministic XML transform — **but** it inherits
   Finding 1's gap: the compiler needs a structured way to know which parent
   applies, which the schema doesn't yet provide. Automatable in mechanism,
   blocked on a schema gap, not a judgment gap.

2. **The disjointness gate** (design lines 262-267, constraint from
   `docs/WAZUH-NOTES.md` lines 273-286 — "must confirm both (a) rule X is
   tried and does not match, and (b) the new rule itself is tried and does
   match"): checking "the final matched rule id equals the detection's own
   expected rule id" via real `wazuh-logtest` (as the design proposes)
   actually satisfies *both* (a) and (b) in one check, since Wazuh reports
   exactly one final matched rule per record — if it's the expected one,
   nothing else silently intercepted it first. This is a correct
   generalization of the sharper standing rule in `docs/WAZUH-NOTES.md`
   lines 273-286, and worth crediting as such.

   **Named gap that remains**: the design's stated check only re-runs "every
   detection's own registered fixtures" (line 267) plus the benign
   denominator — it does not describe checking a new detection's rule
   against every *other* detection's attack/evasion fixtures. That's exactly
   the shape of the real, already-observed finding in
   `docs/PHASE4-REPORT.md` lines 63-69 ("Cross-scenario rule firings") where
   `100201` legitimately fires on `credential_exfil_via_read` task_ids for a
   correct, non-buggy reason (shared `server_command` across scenario
   fixtures) that required human judgment to adjudicate as "not a bug." An
   automated gate that only checks own-fixture correctness + benign FP will
   neither catch a *bad* cross-detection collision nor pre-empt needing a
   human to explain a *good* one — this residual judgment need should be
   named in the design, not left implicit.

3. **The stock-ruleset collision grep** (design lines 268-274, constraint
   from `docs/WAZUH-NOTES.md` lines 246-271 — the Suricata `86600` finding):
   genuinely automatable exactly as described. The real historical failure
   was a field-name collision (`event_type` + `timestamp` both required by
   stock rule `86600`), and a grep of every new detection's discriminator
   field names against the full loaded ruleset would have caught it. This is
   a faithful, sound generalization — say so plainly.

   **One gap worth naming**: the check as described runs at compile time
   against whatever ruleset is *currently loaded*. It doesn't describe
   re-running when the *stock* ruleset itself changes (a Wazuh version
   bump shipping a new rule file with a newly-colliding field name) —
   already-shipped detections wouldn't get rechecked automatically. Minor,
   but worth a line in the design: re-run the grep as part of any Wazuh
   version bump, not only at detection-compile time.

4. **The negate-on-absent-field static check** (design lines 275-280) — the
   sharpest test, as flagged in the prompt. The design's own sentence
   describes the mechanism as "an automatic 'is this field ever genuinely
   absent on the fixture that should trigger it?' **probe**" — that word is
   doing real work: both historical instances of this landmine
   (`100103`'s first draft, `docs/WAZUH-NOTES.md` lines 69-84 inline
   comment in `wazuh/local_rules.xml:71-84`; and the rejected E5 fix,
   `docs/PHASE5-REPORT.md` lines 24-25 / `lab/analysis/evasion_report.py`
   lines 84-102) were discovered *only* by running the candidate rule
   through real `wazuh-logtest` against the actual fixture and reading the
   verbose trace's final matched rule id. `docs/WAZUH-NOTES.md`'s own
   closing section (lines 288-298, "What was NOT root-caused at the
   C-source level") is explicit that this is empirically observed engine
   behavior, not derived from Wazuh's rule-compiler source or documented
   anywhere the XML or fixture data alone would reveal it statically.

   **Verdict, directly**: this cannot be computed statically. It requires
   running the fixture through the real engine, every time, exactly like
   the disjointness gate. Calling it a "static check" is a mislabeling that
   risks someone eventually trying to implement it as pure XML/pattern
   analysis (checking whether a fixture's JSON literally omits the key) —
   which would not reproduce Wazuh's actual negate-on-absent-field
   behavior, since that behavior is an implementation detail of Wazuh's
   negate evaluator, not a property derivable from the fixture's JSON shape
   by inspection. **Recommended change**: rename this to what it is — a
   mandatory pre-promotion `wazuh-logtest` probe, folded into the same
   fixture-execution machinery as constraint 2's disjointness gate (they're
   the same kind of check: "run the real engine against the fixture, read
   the final matched rule id"). This doesn't weaken the guarantee — it's
   exactly as strong — but keeps the design honest about what "automated"
   means here: automated to run, not static to compute.

---

## Finding 4 — The semantic backend has an unstated caveat sharper than its three named ones, and the recommended pilot scope is contaminated

The design already names three real caveats (non-auditability,
self-authored-exemplar narrowness, corpus homogeneity — lines 373-400). Two
more, found by tracing the actual proposed data flow:

**4a. Reference-exemplar/evaluation-set overlap — the recommended pilot scope evaluates a classifier against the exact text used to build its own reference set.**

The design's own words, read together:

- The Tier-1 reference set (lines 344-349): "Attack-shaped exemplars: reused,
  not invented — the poisoned descriptions already authored in
  `lab/attacks/servers/poisoned_tool_server.py` and its Phase 3a/5 variants (12
  tool-poisoning variants, **E1/E2/E3b's actual evasion text**)."
- The recommended pilot scope (lines 404-411): "pilot this backend narrowly,
  against the three evasions regex structurally cannot close (**E1, E2,
  E3b**)."

These are the same corpus. If E1/E2/E3b's own evasion text is already inside
the embedding classifier's reference-exemplar set, then "does the classifier
catch E1/E2/E3b" is close to asking "is a vector's cosine similarity to
itself high" — the pilot's headline recall number would be closer to a
tautology than a measurement. This is a sharper version of the
self-authored-variant caveat the design already names (line 383-395) for the
*reference set's narrowness*; this is train/test identity for the
*evaluation*, not just narrowness — a different and worse failure mode, and
it directly produces the "unfalsifiable" outcome the review was asked to
check for, but on the recall side, not just the FP side.

**Recommended change, not a whack-a-mole fix**: this is a data-partitioning
fix, not a detection-logic fix, so it doesn't fall under the
no-keyword-list-extension discipline. Before any pilot: hold E1/E2/E3b's
actual evasion specimens out of the reference-exemplar set entirely, and
build the reference set only from the original (non-evasion) Phase 3a/5
poisoned-description variants. Evaluate E1/E2/E3b strictly as held-out data.
If recall against the held-out evasions is still strong, that's a real
finding; if it drops, that's the honest number the design should have been
measuring in the first place.

**4b. Judge/corpus circularity — the same small model both wrote the benign ground truth and would judge the uncertain cases.**

`lab/corpus/agent.py:29` pins `MODEL = "qwen3:1.7b"`, and
`data/benign_corpus_v2.summary.md:6` confirms the entire benign corpus
(4,727 records, the same corpus every FP claim including this one's
threshold sweep is measured against) was generated by that same model. The
design's Tier-2 proposal (lines 360-370) is to give "the `ollama`/`qwen3:1.7b`
stack this project **already runs**... a second job" as the escalation judge
for uncertain-band cases. That phrase undersells what's being reused: it's
not just infrastructure being reused, it's the *same model* that authored
the ground-truth benign traffic now being asked to judge ambiguous cases
against a decision boundary shaped by its own generative tendencies. A small
model's blind spots and stylistic habits (already documented as a real,
named phenomenon in `data/benign_corpus_v2.summary.md:131`, "Small-model
behavioral noise") could plausibly make it *systematically* well-calibrated
to its own writing style and *not* representative of how a differently
authored benign tool description, or a differently authored attack, would
score. This is a real, distinct risk from the three the design already
names, and it isn't hypothetical — it's the literal architecture proposed.
Worth stating in the design as its own caveat, not folded into "corpus
homogeneity" (which is about corpus diversity, not model self-consistency
bias in the judge itself).

---

## Finding 5 — The migration parity oracle: exact numeric match is a weaker gate than it sounds

**Claim under test** (design lines 316-323): `coverage.py` must reproduce
"12/12, 11/11, 11/11, 3/3, 0/4727 FP, 10/12 evasions succeeding" exactly
before migration is "done."

Since migration keeps `wazuh/local_rules.xml` byte-identical (design line
308, "zero XML changes in this step" — confirmed consistent with
`lab/analysis/report.py`'s `verify_rule_sync()` gate at lines 77-104, which
already fails loud on any drift), the underlying `wazuh-logtest` answers
themselves can't silently change. The risk is not in the engine's output —
it's in whether `coverage.py`'s aggregation logic reproduces
`lab/analysis/report.py`'s aggregation *exactly*, and the flattened list in the
design's own success condition is a weaker check than what the current tool
actually verifies.

Concretely: `lab/analysis/report.py`'s `compute_per_rule_fp()` (lines 266-275)
and `compute_scenario_recall()` (lines 278-293) don't just produce "0/4727"
and "3/3" — they produce **per-rule, per-task_id breakdowns** with
*different denominators per rule family* (`100102`'s FP denominator is
`benign_session_count` = 541; every other content rule's is
`benign_tool_call_count` = 1011 — see `lab/analysis/report.py:271-274`), and the
rug-pull recall table names *which specific task_id* alerted on *which
specific drift field* (`docs/PHASE4-REPORT.md` lines 53-57). The design's
stated success condition — match the flattened numbers — would pass a
regression where the right *count* is produced by the wrong *members*: e.g.
if a table-driven join bug (Finding 2) caused `100201` to attribute a hit to
the wrong task_id while some other unrelated task_id happened to also
alert, "3/3" would still read true while the actual mapping from
attack-scenario to detection had silently changed. This is precisely the
"not one blanket number" discipline `docs/PHASE4-REPORT.md`'s own executive
summary invokes (line 17, "collapsing them into one... figure would itself
be a laundering step") — applied here to the migration gate rather than to
the original report.

**Recommended change**: the migration's parity oracle should diff the
*full* per-task_id, per-rule-id table (or the full rendered report text,
ignoring only non-deterministic fields — there are none, per
`lab/analysis/report.py:386-391`'s explicit no-timestamp design), not just the
six summary numbers named in the design doc. This is cheap to get right
(the reports are already deterministic and diff-friendly by construction)
and meaningfully stronger.

---

## Sign-off questions

**1. `framework/` + `detections/<id>_<name>/` directory layout — right structure?**
Yes, confirm as proposed. It mirrors SAF-MCP's own upstream per-technique
directory convention (per the design's own stated rationale, line 476), is
consistent with this project's existing top-level layout
(`lab/attacks/`, `lab/baseline/`, `lab/analysis/` as siblings — confirmed via
`docs/STATE-OF-PROJECT.md` lines 102-116), and nothing in the findings above
depends on this layout being wrong. No changes needed here.

**2. Semantic backend pilot scope (E1/E2/E3b only) — confirm, or demand the full threshold-sweep methodology first?**
Neither, as posed. Confirm the *narrow scope* (three evasion classes, not a
blanket classifier) — that part of the design's caution is right and
consistent with how every other backend in this project earned trust
incrementally. But do not run the pilot as currently specified: fix Finding
4a first (hold E1/E2/E3b's own evasion text out of the reference-exemplar
set) before any pilot number is reported, and name Finding 4b (judge/corpus
circularity) explicitly in whatever report the pilot produces, the same way
every other backend's FP claim in this project carries its caveat inline
rather than as a footnote. Demanding the *full* whole-corpus threshold-sweep
methodology before even the narrow pilot would be over-correction — the
narrow pilot, done with held-out data, is the right first increment.

**3. `SAF-T1403`'s two-backend question — resolve it now or defer?**
**Resolve it now.** This is the one place the prompt asked to give real
weight, and Finding 1 shows why: this isn't a canary for some hypothetical
future technique, it's already true of `RugPullBaselineDetector`, which
Section 3 requires shipping *this phase*. Deferring the two-backend
question means Section 3's migration starts without knowing what field
`RugPullBaselineDetector`'s `backend:` value even is. Concretely: adopt
`backends: list[str]` plus an explicit pipeline/composition field (Finding
1's recommended change) before writing `coverage.py`'s batch-runner
dispatch, and treat the rug-pull migration as the first real test of that
schema shape — if it doesn't cleanly describe rug pull's existing,
already-working two-stage pipeline, the schema is wrong and needs another
pass before SAF-T1403 or any other technique touches it.

**4. Taxonomy re-verification cadence — build a `coverage.py` check, or is periodic manual re-check enough?**
Build the automated check, as a non-blocking warning. The design's own
taxonomy section (lines 415-425) documents that the SAFE→SAF rename already
happened once and was only caught by a live re-check that almost didn't
happen ("treating this as permanently cached would repeat exactly the
mistake Phase 2 caught the first time," line 417-418) — that's a documented
near-miss, not a hypothetical risk. A live `gh api` check against the
upstream taxonomy for every registered `technique_id`, run as part of
`coverage.py` and surfaced as a warning (not a hard block — a stale
`technique_id` shouldn't stop a working detection from running), is cheap
and directly consistent with the "measured, not assumed" discipline this
project already holds itself to everywhere else. Manual-only re-checking is
exactly the discipline that already produced one near-miss.

---

## The single most important thing to get right first

Fix the `Detection` schema's backend field before writing anything else.
As shown in Finding 1 and sign-off question 3, `backend:` as a single scalar
cannot describe the rug-pull detector this framework must migrate in its
first real step — not a future edge case, the very first thing Section 3
asks for. Every other finding here (the alert-join table shape, the
disjointness gate's cross-detection blind spot, the negate-check's honest
"dynamic not static" labeling, the semantic pilot's data partitioning) is a
real fix but a contained one. Getting the backend field wrong is the one
mistake that would need to be unwound across every Detection object written
afterward, which is exactly the "wrong abstraction locked in now costs the
whole phase" risk this session was convened to catch.

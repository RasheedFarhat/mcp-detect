# Claude Code kickoff prompt — Phase 6, build slice 2: the compiler's write-side enforcement

Paste everything below the line into Claude Code, running from the repo root.

---

You are working in the `mcp-detect` repo. Slice 1 (the migration) is committed and
proven: `framework/` + `detections/` reproduce the frozen Phase 4/5 numbers member-for-
member (`docs/PHASE6-MIGRATION-REPORT.md`). This session builds slice 2: the **compiler's
write-side enforcement** — the four automated gates from `docs/PHASE6-DESIGN.md` Section 2
that make *adding* a detection structurally safe instead of a hand-remembered discipline.

The governing idea, and the standard you're held to: **every one of these four gates
corresponds to a real bug this project has already hit and caught by hand.** So the way
you prove each gate is not to assert it works — it's to reconstruct the exact historical
failure as a fixture and show the gate now rejects automatically what a human caught
manually. The compiler's regression oracle is the project's own bug history.

## Step 0 — Sync the design to the code first (verify-first, bounded)

Slice 1 disclosed judgment calls in `docs/PHASE6-MIGRATION-REPORT.md` that grew the
abstraction past what v2 anticipated. Before building the compiler on top of the schema,
make the design tell the truth about the schema as it now is. Open the migration report,
confirm each disclosed decision against the actual code that implements it, and fold the
confirmed ones into `docs/PHASE6-DESIGN.md`:

- the new `pipeline: "parallel"` composition value (v2 anticipated only `chained`) —
  confirm against `detections/SAF-T1502_credential_exfil/detection.yaml` and the loader;
- the JSON-in-`.yaml` / stdlib-only-no-PyYAML decision — confirm against `framework/schema.py`;
- the fixture-reference conventions `framework/fixtures.py` invented (they were
  illustrative-only in v2) — confirm against that file and document the actual grammar.

Record these as design changes, not footnotes, and note in the design that they were
discovered during slice 1's build (the design doc stays the source of truth). Do not
change any code in this step — this is design catching up to code, not the reverse.

## Step 1 — Build the four gates

Build them in `framework/` (proposed `framework/compiler.py`, plus fixtures under
`framework/tests/`). Each gate maps to `docs/WAZUH-NOTES.md` and a specific past failure:

1. **`if_sid` auto-parenting.** The compiler refuses to emit an independent top-level
   `wazuh_rule` detection; every one is assigned its canonical parent (`100100` for raw
   wire telemetry, `100200` for derived drift-shaped records). The schema must tell it
   which — if the current `detection.yaml` shape can't express "raw vs derived record" as
   structured data the compiler consumes (not free-text `expected_signal.record_type`),
   that gap is itself a finding: name it and add the minimal structured field.
2. **The disjointness gate (dynamic, real engine).** Run the full frozen corpus set
   through the compiled ruleset via **real `wazuh-logtest`** and fail loud unless every
   detection's own registered fixtures still produce the expected final matched rule id.
   Reuse slice 1's structural runner; do not reimplement matching in Python.
3. **The stock-ruleset collision grep.** Grep every new detection's discriminator field
   names against the *entire* loaded ruleset (`/var/ossec/ruleset/rules/*.xml`), not just
   this project's files, and refuse to compile on a collision.
4. **The negate-on-absent-field probe (dynamic, real engine — NOT static).** Per the v2
   design's corrected framing: any detection using `negate="yes"` on a field gets a
   mandatory pre-promotion `wazuh-logtest` probe against a fixture that *should* trigger
   it, folded into the same fixture-execution machinery as gate 2. It is not a static
   XML/JSON-shape check; implementing it as one would not reproduce Wazuh's actual
   behavior.

## Step 2 — Prove each gate against the bug it exists to catch

For each gate, build a **red-team fixture** that reconstructs the historical failure, and
show the gate rejects it with a clear diagnostic:

- gate 1 ← the top-level sibling-shadowing class (`docs/WAZUH-NOTES.md` Tests 1–5): a
  detection authored *without* a parent must be refused, not silently emitted.
- gate 2 ← a deliberately non-disjoint new rule that intercepts an existing detection's
  fixture must fail the gate, naming the row that changed.
- gate 3 ← reconstruct the Suricata `86600` collision (`event_type` + `timestamp`): a
  detection using those field names must be refused.
- gate 4 ← reconstruct `100103`'s original `negate` draft (negating on the absent `path`
  field): the probe must catch that it never fires on its own true positive — the exact
  landmine caught by hand in Phase 3a and again in Phase 5.

## Step 3 — Regression: the compiler must not reject known-good rules

The 10 existing, correct rules in `wazuh/local_rules.xml` (already migrated and proven in
slice 1) must **pass all four gates cleanly** — the compiler that catches every historical
bug must also produce zero false rejections against the known-good set. If any real rule
trips a gate, that is a bug in the gate, not the rule; stop and report it.

## Hard gates — stop-and-report, not preferences

1. `wazuh/local_rules.xml` and `baseline/watch.py` stay byte-identical
   (`git diff --exit-code` on both at the end). The compiler *reads and validates* rules;
   it does not rewrite the hand-authored ones this slice.
2. Slice 1's proven code (schema loader, backends, `coverage.py`, `parity_check.py`) stays
   behavior-identical — re-run `framework/tests/` and the parity check at the end and
   confirm still-green. The compiler is additive.
3. All dynamic gates (2 and 4) go through real `wazuh-logtest`. No Python regex
   reimplementation of rule matching anywhere in the new code.
4. Each red-team fixture must actually fail its gate for the *right reason* — verify the
   diagnostic names the specific violation, not a generic error, so a future false-pass
   can't hide behind a vacuous rejection.

## Deferred — do NOT build (name as deferred): the semantic backend, any new *real*
technique (the red-team fixtures are deliberately-broken test detections, not shippable
ones), and the DaC-Pipeline path.

## Discipline (unchanged)

Measured, not assumed — every gate's correctness shown by a real fixture run, every
"passes clean" claim by an actual execution. Keep the honesty posture: if a gate is 3/4
red-team fixtures caught, say so and show the one that slipped. Preserve the design's
`known_gaps`-as-schema posture in anything new you add.

## Deliverable

`framework/compiler.py` (the four gates) + the red-team fixtures under `framework/tests/`,
and a short `docs/PHASE6-COMPILER-REPORT.md` recording: the Step-0 design-sync summary,
each gate paired with the historical bug it reconstructs and the fixture proving it
catches that bug, the clean-pass result against the 10 known-good rules, and confirmation
that the hard gates held (byte-identical protected files, slice-1 code still green, no
Python match reimplementation). If any gate fails to catch its fixture or falsely rejects
a known-good rule, lead the report with that and stop for review.

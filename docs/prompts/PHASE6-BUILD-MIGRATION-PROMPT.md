# Claude Code kickoff prompt — Phase 6, build slice 1: the migration (parity or nothing)

Paste everything below the line into Claude Code, running from the repo root.

---

You are working in the `mcp-detect` repo. `docs/PHASE6-DESIGN.md` is now the
decision-complete v2 design (it carries its own review-verification ledger at the top).
This session begins the **build**, and it builds exactly one slice: the **migration** of
the three existing techniques into the framework, per the design's Section 3.

The migration's entire reason to exist is stated in the design and is binding here:
**the existing rules and `lab/baseline/watch.py` are the regression oracle, not a first draft
to improve.** Success is not a new detection. Success is the framework reproducing what
already works — the frozen Phase 4/5 numbers — *exactly*, member-for-member, through real
engine execution. If it reproduces them, the abstraction is proven on real ground. If it
doesn't, you have found a bug in the framework, not in the oracle, and you stop and report
rather than adjust anything to make the numbers match.

## What is in this slice, and what is explicitly deferred

**In scope — build only this:**

- The `Detection` schema loader (parse `detections/<id>_<name>/detection.yaml` into the
  `backends: list` + `pipeline`/composition shape v2 defines, including the `session_key:
  {primary_field, related_fields}` block).
- The three existing techniques expressed as `detection.yaml` files whose `logic_ref`
  points at the *exact existing* rule IDs in the *unchanged* `wazuh/local_rules.xml` —
  including the rug-pull detection as the two-backend worked example the design already
  spells out.
- `StatefulDetector` protocol + `RugPullBaselineDetector` that wraps
  `lab/baseline/watch.py`'s existing `process_record` **verbatim** (import and delegate; do
  not copy-edit its logic).
- The structural backend runner: batch **real `wazuh-logtest`** over a corpus (never a
  Python reimplementation of rule matching — this is the project's oldest standing rule).
- The unified `Alert` normalization + the table-driven `session_key` join that replaces
  `lab/analysis/report.py`'s `if session_id / elif drift_session_id` chain.
- `coverage.py`: walk the registry, run each Detection through its backend(s) against the
  three frozen corpora, and emit the full per-task_id / per-rule-id coverage table.

**Deferred — do NOT build in this slice (name them as deferred in a short note, don't
implement):** the compiler's write-side enforcement (if_sid auto-parenting, disjointness
gate, negate-probe, stock-ruleset collision grep — those matter when *adding* detections,
not when reproducing hand-authored ones), the semantic backend, any new technique, and
the DaC-Pipeline path. Scope creep into any of these fails the slice.

## Hard gates — each is a stop-and-report condition, not a preference

1. **`wazuh/local_rules.xml` stays byte-identical.** Verify with `git diff --exit-code
   wazuh/local_rules.xml` at the end. The migration references these rules; it does not
   touch them.
2. **`lab/baseline/watch.py` stays byte-identical, and its 12 tests pass unmodified.** Run
   `lab/baseline/test_watch.py` against the wrapped `RugPullBaselineDetector` and confirm all
   pass with zero edits to the test file. The tests are this refactor's regression oracle.
3. **All matching goes through real `wazuh-logtest`.** If you find yourself writing regex
   matching in Python to decide whether a rule fires, stop — that is the one thing this
   project has never done and must not start now.
4. **Parity is exact and member-level.** `coverage.py`'s output must reproduce Phase 4
   and Phase 5's frozen results — 12/12 tool poisoning, 11/11 read hop, 11/11 exfil hop,
   3/3 rug-pull drift, 0/4727 benign FP, 10/12 evasions succeeding — **and** the full
   per-task_id/per-rule-id table must match, not just the six summary numbers (this is the
   revised parity oracle the v2 design now requires, precisely so a right-count/wrong-member
   regression can't hide). Diff against `docs/PHASE4-REPORT.md` and `docs/PHASE5-REPORT.md`.
5. **On any discrepancy, stop and report — do not reconcile by touching the oracle.** A
   number that doesn't match means the framework has a bug. Surface it with the exact
   row that differs; do not edit corpora, rules, `watch.py`, or the frozen reports to
   close the gap.

## How to work

Build incrementally and prove each layer before stacking the next, mirroring how every
prior phase earned trust:

1. Schema loader + the three `detection.yaml` files first; confirm they parse and that
   the rug-pull two-backend pipeline round-trips through the v2 shape.
2. `RugPullBaselineDetector` wrapping `watch.py`; prove it by running the existing 12
   tests against the wrapper before anything else consumes it.
3. Structural runner over one known fixture; confirm it reproduces one known Phase 4 row
   before scaling to the full corpora.
4. `coverage.py` end to end; then the full parity diff as the final gate.

Respect the design's directory decision: `framework/` (loader, backends, `coverage.py`)
and `detections/<id>_<name>/` as siblings to `lab/attacks/`, `lab/baseline/`, `lab/analysis/`.

## Discipline (unchanged, non-negotiable)

- Measured, not assumed — every parity claim is backed by an actual `wazuh-logtest` run,
  not asserted.
- Preserve, don't improve — this slice's job is faithful reproduction; any idea for
  improving a rule gets written down as a note for a later slice, not applied here.
- Keep the honesty posture: if parity is 11/12 rows, say "11/12 and here is the row that
  differs," never round up.

## Deliverable

The `framework/` and `detections/` directories implementing the migration, with
`coverage.py` producing the full coverage table, and a short `docs/PHASE6-MIGRATION-REPORT.md`
recording: the parity result (full table, not just totals), confirmation that gates 1–3
held (git-clean rules, unmodified passing `watch.py` tests, no Python match reimplementation),
and an explicit list of what was deferred out of this slice. If parity is anything short of
exact, the report leads with the discrepant rows and the session stops there for review
rather than proceeding.

# Claude Code kickoff prompt — pressure-test the Phase 6 design

Paste everything below the line into Claude Code, running from the repo root.

---

You are working in the `mcp-detect` repo. Your job this session is **not** to write
framework code, create a `detections/` directory, or touch `wazuh/local_rules.xml`
or `lab/baseline/watch.py`. Your job is to **pressure-test the Phase 6 design before a
single line of it gets built**, because a wrong abstraction locked in now costs the
whole phase. Treat this as an adversarial design review whose output is a written
critique, not an implementation.

**Scope exclusion, binding for this whole session:** ignore everything in the design
that concerns DaC-Pipeline or Sigma-based compilation. Do not evaluate it, do not
recommend for or against it, do not fold it into any finding or sign-off answer. That
decision is being made separately and later. Where the design's structural backend
mentions a "Direct" (hand-authored Wazuh rule IDs) path versus a Sigma/DaC-Pipeline
path, review **only the Direct path** and treat it as the sole structural backend for
the purposes of this review.

## Read first, in this order

1. `docs/PHASE6-DESIGN.md` — the proposal under review. This is the whole subject of
   the session.
2. `docs/STATE-OF-PROJECT.md` — the canonical map of what already exists and works.
3. `docs/WAZUH-NOTES.md` — the eight hard-won engine constraints the design claims it
   will "make the compiler enforce automatically." You must verify each claim against
   the actual note.
4. `wazuh/local_rules.xml`, `lab/baseline/watch.py`, `lab/analysis/report.py`,
   `lab/analysis/evasion_report.py` — the code the framework claims to generalize. The
   design asserts specific things about these files (e.g. "`report.py`'s hardcoded
   `RULE_TECHNIQUE` dict", "the ad hoc `if session_id / elif drift_session_id` join").
   Confirm those assertions are true of the code as it actually is, not as the design
   remembers it.
5. `docs/PHASE4-REPORT.md`, `docs/PHASE5-REPORT.md` — the numbers the migration is
   required to reproduce exactly (12/12, 11/11, 11/11, 3/3, 0/4727 FP, 10/12 evasions).

## The discipline this repo holds you to (do not break it)

- **Measured, not assumed.** Every load-bearing claim in your critique must be grounded
  in a file you actually read or a command you actually ran, cited by path/line. If you
  can't verify something, say "unverified" explicitly — do not smooth it over.
- **No whack-a-mole fixes.** This project has repeatedly refused to "fix" semantic
  evasions by extending keyword lists. If you propose a fix, check it isn't that.
- **Name gaps as structural fields, not prose.** The design elevates `known_gaps` to a
  first-class schema field for a reason. Hold the design to its own standard.
- **Do not restart the Wazuh manager or mutate any committed artifact.** This is a
  read-and-reason session. Running `wazuh-logtest` in a throwaway way to check a factual
  claim is fine; changing rules or corpora is not.

## What to actually attack

Go after the abstraction, not the typos. Specifically:

1. **Does the `Detection` abstraction actually stay backend-agnostic, or does it leak?**
   The design claims "logic is backend-native and referenced, not reimplemented in a
   universal DSL." Test that claim against the two in-scope backends (structural =
   Direct Wazuh rules; stateful = generalized `lab/baseline/watch.py`) and the semantic
   backend. Where does a backend-specific detail (a Wazuh `if_sid` parent, a
   `StatefulDetector`'s state shape, an embedding threshold) have to bleed up into the
   supposedly-neutral metadata object or the unified `Alert`/join layer? Find the first
   place the abstraction forces a special case.

2. **The `Alert` join / `primary_session_id` generalization.** The design replaces the
   `if session_id / elif drift_session_id` chain with a table-driven, per-detection
   session-key declaration. Trace a concrete record from each backend through that
   generalized join and confirm it actually produces the same result Phase 4's
   `normalize_and_join` produces today. Does the rug-pull family's
   `drift_session_id` + `baseline_first_seen_session_id` dual-key case fit the table
   model, or is it a second special case wearing a general coat?

3. **The auto-enforced Wazuh constraints (Section 2).** For each of the four —
   if_sid auto-parenting, the disjointness gate, the stock-ruleset collision grep, and
   the negate-on-absent-field static check — decide whether it is genuinely automatable
   as described, or whether it secretly still needs the human judgment it's replacing.
   The negate-on-absent-field check is the sharpest test: the design proposes a static
   "is this field ever genuinely absent on the triggering fixture?" probe. Can that
   actually be computed statically, or does it require running the fixture? Say which.

4. **The semantic backend (Section 4) — the riskiest piece.** The design already states
   three FP-risk caveats (non-auditability, self-authored-exemplar narrowness, corpus
   homogeneity). Your job is to find the caveat it *didn't* state, or a place where the
   proposed mitigation (threshold sweep against the 4727-record benign corpus, Ollama
   escalation for the uncertain band) doesn't actually deliver what it promises. Is the
   scoped E1/E2/E3b pilot a real evaluation, or does scoping it that narrowly make the
   FP claim unfalsifiable?

5. **The migration parity oracle (Section 3).** The plan requires `coverage.py` to
   reproduce the frozen numbers exactly before migration is "done." Is exact numeric
   reproduction actually achievable given how the current measurement tools compute
   those numbers, or is there a normalization/denominator subtlety (Phase 4's
   "not one blanket number" discipline) that will make "exact match" ambiguous? Name the
   risk if there is one.

## Then resolve the open sign-off questions

The design ends with a set of explicit questions awaiting sign-off. **Skip the
DaC-Pipeline spike question entirely** (out of scope, per above). For each of the
remaining questions, give a concrete recommendation with reasoning, not a restatement of
the tradeoff:

1. `framework/` + `detections/<id>_<name>/` directory layout — right structure?
2. Semantic backend pilot scope (E1/E2/E3b only) — confirm, or demand the full
   threshold-sweep methodology first?
3. `SAF-T1403`'s two-backend question (can one `Detection` declare two backends, or does
   it become two cooperating detections?) — resolve it now or defer? This one is the
   canary: if the abstraction has a hole, this is where it shows. Give it real weight.
4. Taxonomy re-verification cadence — build a `coverage.py` check that warns on a stale
   `technique_id`, or is periodic manual re-check enough?

## Deliverable

Write your findings to `docs/PHASE6-REVIEW.md` (new file — do not edit the design doc
itself). Structure it as: a short verdict up front (is this design safe to build on as
written, safe with named changes, or not yet), then the five attack findings each with
its evidence citation and a concrete recommended change, then the sign-off answers.
Where you found the design already correct and well-defended, say so plainly — the goal
is an honest review, not a pile of manufactured objections. End with the single most
important thing to get right before any framework code is written.

Do not write framework code, do not create `detections/`, and do not modify any existing
committed file other than adding your new `docs/PHASE6-REVIEW.md`.

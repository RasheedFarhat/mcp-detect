# Claude Code kickoff prompt — turn the review into a sign-off-ready Phase 6 design

Paste everything below the line into Claude Code, running from the repo root.

---

You are working in the `mcp-detect` repo. Last session produced an adversarial design
review at `docs/PHASE6-REVIEW.md` against the proposal at `docs/PHASE6-DESIGN.md`. Its
verdict was "safe with named changes, not yet safe to build on as written," with five
findings and a set of sign-off recommendations.

Your job this session is to **make the design decision-complete and sign-off-ready** by
folding the confirmed findings into it and resolving every in-scope open question inline
— so that a human's only remaining action is to say "build it." This is still a
**design-only** session: you will not write framework code, create a `detections/`
directory, or modify `wazuh/local_rules.xml` or `lab/baseline/watch.py`. The one artifact
you will produce is a revised design document.

**Scope exclusion, still binding:** DaC-Pipeline / Sigma compilation stays out of scope.
Do not design it, resolve it, or fold it in. In the revised design, represent it as an
explicitly deferred decision with a one-line placeholder ("structural backend supports a
future Sigma-compilation path; deferred, not designed here"), and keep the structural
backend defined solely as the Direct hand-authored-Wazuh-rule path.

## Step 1 — Verify before you act (do not skip)

The review is good but it is not gospel. Before changing one word of the design, confirm
its five findings are actually true of the code as it exists, because several rest on
specific line-number citations in files the review's author may not have re-read. This is
the project's own "measured, not assumed" discipline applied to the review itself.

For each finding, open the cited files and confirm the claim, then record a one-line
verdict (`confirmed` / `confirmed-with-correction` / `not-reproduced`) with the evidence
you actually saw:

1. **Finding 1 (backend-as-scalar can't express rug pull's two-stage pipeline):** confirm
   that `wazuh/local_rules.xml`'s `100200`/`100201` match only on the derived record
   `lab/baseline/watch.py` emits (via the `mcp_drift_marker` field), never on raw wire
   telemetry — and that `lab/analysis/evasion_report.py` really does run the watcher and
   then `wazuh-logtest` as two chained stages. Cite the actual functions/lines you find,
   not the review's.
2. **Finding 2 (Alert join correct in shape, absent from schema):** confirm the
   `if session_id / elif drift_session_id` chain and the `primary` + `related` shape
   really exist in `lab/analysis/report.py`, and that the example `detection.yaml` in the
   design has no `session_key` block.
3. **Finding 3.4 (negate-on-absent-field check is dynamic, not static):** confirm from
   `docs/WAZUH-NOTES.md` and the inline history in `wazuh/local_rules.xml` that both
   historical instances were caught only by running `wazuh-logtest` against a fixture,
   and that nothing in the fixture's JSON shape alone reveals the behavior statically.
4. **Finding 4a/4b (semantic backend: train/test identity + judge/corpus circularity):**
   confirm the E1/E2/E3b evasion text is proposed as both reference exemplar and pilot
   eval set, and that `lab/corpus/agent.py` pins the same `qwen3:1.7b` model that generated
   the benign corpus and would serve as the Tier-2 judge.
5. **Finding 5 (parity oracle: right count, wrong members):** confirm `lab/analysis/report.py`
   computes per-rule/per-task_id breakdowns with different denominators per rule family,
   so matching the six flattened summary numbers is a weaker check than matching the full
   table.

If any finding does not reproduce, say so plainly and do **not** fold that change in —
correcting the review is as valuable as executing it. Put this verification ledger at the
top of your output so the human can see exactly what was checked.

## Step 2 — Revise the design into a sign-off-ready v2

Edit `docs/PHASE6-DESIGN.md` in place (it is uncommitted, so this is safe), folding in
every **confirmed** finding as a concrete change to the design — not a footnote saying
"the review noted X," but the actual corrected lab/schema/wording. At minimum:

- **The `Detection` schema's backend field** becomes a list plus an explicit composition
  field describing how a multi-backend detection's runners chain (stateful emits a
  derived record → structural consumes it with a named parent rule). This is the headline
  fix; the rug-pull detector must be expressible in the revised schema, and you should
  show its actual `detection.yaml` as the worked example proving it.
- **The example `detection.yaml`** gains a concrete `session_key` block typed as
  `{primary_field, related_fields: list}` unconditionally — never a bare scalar — and the
  design names the single-primary-per-record assumption of the `Alert` dataclass as a
  stated limit.
- **The negate-on-absent-field check** is renamed from "static check" to what it is: a
  mandatory pre-promotion `wazuh-logtest` probe, folded into the same fixture-execution
  machinery as the disjointness gate.
- **The disjointness gate** section names the residual cross-detection judgment need
  (the `100201`-fires-on-`credential_exfil` cross-scenario case) rather than implying full
  automation, and notes the stock-ruleset grep should re-run on Wazuh version bumps, not
  only at detection-compile time.
- **The semantic backend** section adds the held-out-data requirement (E1/E2/E3b specimens
  excluded from the reference-exemplar set before any pilot number is reported) and adds
  judge/corpus circularity as its own named caveat, separate from corpus homogeneity.
- **The migration parity oracle** requires diffing the full per-task_id/per-rule table (or
  full rendered report text), not just the six summary numbers.

## Step 3 — Resolve the open questions inline

The current design ends with an "Open questions for your sign-off" section. Convert the
four in-scope questions (skip the DaC-Pipeline spike question) from open questions into
**recorded decisions** with the rationale attached, using the review's recommendations
where you confirmed them:

- directory layout: confirmed as proposed;
- semantic pilot scope: narrow scope confirmed, but gated on the held-out-data fix;
- the two-backend question: resolved now via the backend-list + composition field, with
  rug pull as its first real test;
- taxonomy re-verification: automated non-blocking `coverage.py` warning.

Replace the "awaiting sign-off" framing with a short **"Decided vs. still open"** section:
what is now settled, and the small set of things (e.g. the deferred DaC-Pipeline path)
that remain a human's explicit call. The goal is that the human reads this and can either
sign off or point at one specific still-open item — no re-litigating the whole design.

## Discipline (unchanged, non-negotiable)

- Measured, not assumed — every change traces to something you verified in Step 1.
- No whack-a-mole fixes; the semantic data-partitioning fix is a partitioning change, not
  a keyword-list change, and should stay that way.
- Keep the design's existing honesty-as-schema posture (`known_gaps` as a first-class
  field) intact and apply it to every new section you touch.
- Preserve the design's own voice and structure; you are revising it, not rewriting it
  from scratch.

## Deliverable

A revised `docs/PHASE6-DESIGN.md` that is decision-complete, with the Step-1 verification
ledger placed at its top (clearly marked as the review-verification pass), and a
"Decided vs. still open" section replacing the old open-questions list. Do not write
framework code, do not create `detections/`, and do not modify any file other than
`docs/PHASE6-DESIGN.md` (and, if you wish, appending a short "verified against Phase 6
review" note — nothing more — but no logic changes anywhere in the codebase).

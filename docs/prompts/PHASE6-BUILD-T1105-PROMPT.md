# Claude Code kickoff prompt — Phase 6, build slice 3: SAF-T1105, the first framework-native detection

Paste everything below the line into Claude Code, running from the repo root.

---

You are working in the `mcp-detect` repo. Slices 1 (migration) and 2 (compiler's four
gates) are built and proven (`docs/PHASE6-MIGRATION-REPORT.md`,
`docs/PHASE6-COMPILER-REPORT.md`). This session builds slice 3: **the first brand-new
detection authored *through* the framework** — SAF-T1105, Path Traversal via File Tool.

This slice is the one that tests the entire Phase 6 thesis. Every prior slice reproduced
or validated things that already worked. This one makes the framework's core promise
falsifiable: **"authoring technique N+1 is mechanically cheap and structurally safe —
author one `detection.yaml` + one backend-native rule, and the gates enforce the rest."**
Your job is not only to ship the detection, but to honestly measure whether that promise
held — including naming where it didn't.

## Step 0 — Commit slice 2 first (it's complete and proven)

The compiler slice is finished but uncommitted. Commit it as its own clean unit before
starting new work, so it's a rollback point.

- If `git commit` fails with a stale-lock error, check for `.git/index.lock`; if it
  exists and no git process is running, `rm -f .git/index.lock` and retry.
- Run `git status` first and stage only the slice-2 logical unit: `framework/compiler.py`,
  `framework/tests/test_compiler_redteam.py`, `framework/tests/test_compiler_regression.py`,
  `framework/tests/redteam_fixtures/`, `docs/PHASE6-COMPILER-REPORT.md`, and the
  `docs/PHASE6-DESIGN.md` Step-0 sync edits. Do not sweep in unrelated stray files —
  if you're unsure whether a file belongs, ask rather than guess.
- Commit message (match the project's existing style):
  `feat(framework): Phase 6 slice 2 -- compiler write-side enforcement, four gates proven against bug history`

## Step 1 — Ground SAF-T1105 upstream before authoring (cited, not assumed)

Fetch the live upstream technique definition (`gh api` against
`github.com/SAFE-MCP/safe-mcp`, path `techniques/SAF-T1105/README.md`, or the raw URL) so
the mechanism and MITRE ATT&CK mapping are cited from the source, not recalled — the same
discipline every prior technique got. Confirm: the exact attack mechanism (relative-path
escape like `../../../../etc/passwd`, `../../.ssh/id_rsa` in a file tool's path argument),
and the real MITRE ATT&CK technique id to cite in the rule's `<mitre>` block. If the
upstream README is a table-only stub with no detail, say so and proceed from the mechanism
as the table describes it — do not invent specificity the source doesn't have.

## Step 2 — Author the detection (the "cheap authoring" claim, put to the test)

Three artifacts, and no more if the framework's promise is real:

1. **One new Wazuh rule, appended to `wazuh/local_rules.xml`** — a child of `100100` (raw
   wire telemetry), matching `../`-style traversal in `tool_arguments.path` on a
   `tools/call`. Suggested id `100108` (next free), but follow the existing numbering
   convention. This is the first slice that legitimately *adds* a rule; see the gate
   change below.
2. **One `detections/SAF-T1105_path_traversal/detection.yaml`** in the v2 schema shape
   (`backends`, `session_key: {primary_field, related_fields}`, `fixtures`, `known_gaps`),
   `logic_ref` pointing at the new rule id.
3. **Attack fixtures** for path traversal — there is no existing corpus for it. Author a
   small set of traversal variants (in `attacks/`, consistent with the existing attack
   harness pattern), generating labeled telemetry the way the existing attacks do. Author
   genuine variants (different depths, different target files, mixed with a leading
   sensitive-suffix case that also trips `100101`), not one specimen — recall measured
   against a single hand-picked example is the exact self-authored-variant weakness this
   project already names everywhere.

## Step 3 — Run it through the framework, not around it

- **All four compiler gates must pass on the full ruleset including the new rule.** Gate 1
  (parent assigned), gate 3 (no stock-ruleset field collision), gate 2 (disjointness), and
  gate 4 (negate probe — if the new rule uses `negate`, it must clear the probe; if it
  doesn't, state that gate 4 is N/A for this rule and why).
- **The disjointness adjudication with `100101` is the centerpiece, not a formality.** Both
  rules match `tool_arguments.path` on a `tools/call`; a path like `../../.env` satisfies
  both. Run this through the real engine and adjudicate exactly what happens — does one
  shadow the other, is that the correct outcome, and does gate 2 report it truthfully?
  This is the first time gate 2 faces a genuinely new rule overlapping an existing one; if
  it surfaces a real ordering/shadowing issue, that is a finding to resolve (per
  `docs/WAZUH-NOTES.md`'s if_sid/sibling discipline), not to paper over.
- Install the updated ruleset into the live manager and confirm `analysis/report.py`'s
  rule-sync gate (live == committed) passes before measuring.
- **Measure with `coverage.py`**, real `wazuh-logtest`, never Python matching.

## Step 4 — Measure honestly, to this project's standard

- **Recall** for `100108` against your authored traversal fixtures — the real fraction,
  not rounded up.
- **FP** for `100108` against the *full* benign corpus (`benign_corpus_v2`, 4,727 records
  / 541 sessions). If any benign tool legitimately uses `../` in a path, that's a real FP
  to report and reckon with, not to suppress.
- **No regression:** the existing detections must still reproduce their frozen numbers
  exactly (12/12, 11/11, 11/11, 3/3, 0/4727) — adding `100108` must not steal signal from
  `100101` or introduce a new FP attributed to any existing rule. Diff against the frozen
  reports.
- **`known_gaps`** populated honestly: URL-encoded traversal (`%2e%2e%2f`), absolute-path
  access without `../`, symlink indirection, or whatever the regex structurally can't see —
  named as structural gaps, the same standard as every existing detection.

## Step 5 — The meta-finding: did the framework deliver?

Answer plainly in the report: **what was the true marginal cost of adding detection #4?**
Was it "one YAML + one rule + fixtures," or did the framework need changes it didn't
anticipate (a new fixture convention, a schema field, a gate adjustment)? If the promise
held, say so with the evidence. If it fell short anywhere, name exactly where — a framework
that claims cheap authoring must be measured against a real new detection, and this is that
measurement. This section is the point of the slice.

## Hard gates — stop-and-report, not preferences

1. **The existing 10 rules stay byte-identical.** The only change to `wazuh/local_rules.xml`
   is the *additive* new rule block — verify with `git diff` that no existing rule's text
   changed. `baseline/watch.py` stays byte-identical. (This is the one relaxation from prior
   slices: adding the new rule is expected; touching any existing rule is not.)
2. **Slice 1 + 2 stay green.** Re-run `framework/tests/` and the parity check at the end;
   the new detection is additive and must not regress them.
3. **All matching through real `wazuh-logtest`.** No Python regex reimplementation of rule
   matching anywhere.
4. **Every measured number is a real engine run**, and any FP or recall shortfall is
   reported as-is, led with, not smoothed.

## Deferred — do NOT build (name as deferred): the semantic backend, DaC-Pipeline/Sigma
generation (this rule is hand-authored on the Direct path), and any technique beyond
SAF-T1105.

## Step 6 — Commit the detection as its own unit

Once measured and all gates hold, commit slice 3 separately from slice 2:
- Stage the T1105 unit: the new rule in `wazuh/local_rules.xml`, `detections/SAF-T1105_path_traversal/`,
  the new `attacks/` fixtures, and `docs/PHASE6-T1105-REPORT.md`.
- Commit message: `feat(detect): SAF-T1105 path traversal -- first framework-native detection, gates auto-enforced`
- If measurement surfaced anything short of clean (an FP, a disjointness issue, a partial
  recall), do **not** commit a "clean" story — either resolve it properly first or commit
  with the honest result documented and flagged for review. Never commit a number the
  report rounds up.

## Deliverable

`detections/SAF-T1105_path_traversal/detection.yaml`, the additive rule in
`wazuh/local_rules.xml`, the path-traversal attack fixtures under `attacks/`, and
`docs/PHASE6-T1105-REPORT.md` recording: the upstream grounding + MITRE citation, the four
gate results (with the `100101` disjointness adjudication in full), recall and FP measured
against the real corpora, the no-regression proof for the existing detections, the honest
`known_gaps`, and Step 5's marginal-cost verdict on the framework itself. Two commits made
(slice 2, then slice 3). If any gate fails or any number comes in short, lead the report
with it and stop for review before committing slice 3.

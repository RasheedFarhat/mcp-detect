# Phase 6 Compiler Report — Four Gates, Proven Against Their Own Bug History

**Verdict: 4/4 gates built, 4/4 red-team fixtures caught by the right gate
for the right reason, 0 false rejections against the 10 known-good rules.**
The governing idea held: every gate is proven by reconstructing the
historical failure it exists to catch and showing the gate now rejects
automatically what a human caught by hand, not by asserting the gate works.

## Step 0 — Design synced to code before building further

Three disclosed judgment calls from `docs/PHASE6-MIGRATION-REPORT.md` were
re-confirmed against the actual implementing code (not re-trusted from the
report's own description) and folded into `docs/PHASE6-DESIGN.md` as real
schema changes, not footnotes:

1. **`pipeline: "parallel"`** — confirmed at
   `detections/SAF-T1502_credential_exfil/detection.yaml:31` and
   `framework/schema.py`'s `VALID_PIPELINES`. v2 only named `"chained"`;
   the design now documents both, with credential exfil's two independent
   rule families as the worked reason a third composition shape was
   needed.
2. **JSON-not-YAML** — confirmed via `framework/schema.py`'s
   `json.loads(text)` and a repo-wide grep (no `import yaml` anywhere).
   Documented as a real, disclosed implementation constraint (this project
   has never had a third-party dependency), not silently assumed.
3. **The `fixtures` grammar** — confirmed against `framework/fixtures.py`
   and folded in as the actual defined conventions
   (`#distinct_sessions`/`#tool_call_events`/`#all_records`,
   `live:telemetry#...`, `live:rugpull_alerts`, `#task_id~=...`), replacing
   the illustrative-only placeholders in the design's worked examples. This
   also caught and fixed a real error those examples carried forward
   unnoticed since v1/v2: rug pull's `benign_denominator` was shown as
   `#distinct_sessions` (541), but `docs/PHASE4-REPORT.md`'s actual claim
   is full-corpus (`0/4727`, `#all_records`) — corrected in the worked
   example itself, not just noted here.

No code was changed in this step — confirmed by `git status` showing only
`docs/PHASE6-DESIGN.md` modified before any gate code was written.

## An environment issue worth naming, not silently worked around

This host's system Python (3.14, Homebrew) has a broken `pyexpat` binding
(`dlopen` fails on a missing symbol, `_XML_SetAllocTrackerActivationThreshold`
— a libexpat version mismatch, unrelated to this project). Since
`framework/compiler.py` is the first module in this project's history to
need XML parsing, this surfaced for the first time here. The project's own
`.venv` (Python 3.13) has a working `pyexpat`; **every command in this
report was run via `.venv/bin/python3`**, not the bare `python3` used
throughout the rest of this project so far (which never previously needed
`xml.etree.ElementTree`). Documented so a future run on this same host
doesn't rediscover the same failure and mistake it for a bug in
`framework/compiler.py`.

A second, smaller parsing issue, fixed rather than routed around: this
project's own XML comments use `" -- "` as a prose separator throughout
(confirmed in `wazuh/local_rules.xml`), which contains a literal `--` —
invalid inside an XML comment per spec, though Wazuh's own rule-file parser
tolerates it fine (the same shape of parser-leniency gap
`docs/WAZUH-NOTES.md` constraint 4 already found once, from the opposite
direction — there, an XML entity Wazuh's parser mishandled; here, a comment
construct Python's stdlib parser is stricter about than Wazuh is).
`framework/compiler.py` strips comments before parsing
(`_strip_comments()`) — comments carry no matching semantics, so this
changes nothing about what's being checked.

## The four gates, each paired with the bug it reconstructs

| Gate | Mechanism | Historical bug reconstructed | Fixture |
|---|---|---|---|
| 1. `if_sid` auto-parenting | **Static** — reads `<if_sid>` directly from rule XML; cross-checks against each Detection's declared `consumes`/`parent_rule` | `docs/WAZUH-NOTES.md` Tests 1–5: an independent top-level rule silently shadowed by production traffic | In-memory `Detection` + rule XML with no `<if_sid>` |
| 2. Disjointness | **Dynamic** — real `wazuh-logtest`, checks the *final* matched rule id, never "did it avoid X" alone | The sibling-shadowing class generally; a new rule author's naive assumption that their own rule fires when it's non-disjoint from an existing sibling | A rule with conditions identical to `100101`'s, installed transiently |
| 3. Stock-ruleset collision | **Static** — field-name-set subset check against the *entire* loaded ruleset (142 files, 3048 rules), not just this project's own files | The Suricata `86600` collision (`docs/WAZUH-NOTES.md` constraint 8): `100200`'s first draft used `event_type`, colliding with a stock rule requiring `{timestamp, event_type}` | Candidate field set `{timestamp, event_type}` — the pre-rename `100200` draft, reconstructed exactly |
| 4. Negate-on-absent-field | **Dynamic** — real `wazuh-logtest`, probes a rule's own registered true positive; explicitly *not* static (docs/PHASE6-DESIGN.md's corrected framing) | `100103`'s original draft (`docs/PHASE3A-DESIGN.md:470-478`) and the rejected Phase 5 fix for E5 (`docs/PHASE5-REPORT.md:24`): negating on a field's absence doesn't satisfy the condition in this Wazuh version | `100103`'s exact original XML (`negate="yes"` on `tool_arguments.path`), installed transiently |

Gates 1 and 3 are static by nature — the property they check (does an
`<if_sid>` exist; does a field-name set collide) is directly readable from
rule XML text, unlike gate 4's behavior, which docs/WAZUH-NOTES.md's own
closing section confirms was never derivable from source or XML
inspection, only from running the real engine.

## Red-team proof, run for real (not asserted) — 4/4 caught

```
PASS -- gate1_if_sid_parenting: reconstructed WAZUH-NOTES.md Tests 1-5's
  parentless top-level rule -- refused with a specific diagnostic: rule
  100193 has no <if_sid> in the actual rule XML

PASS -- gate3_stock_collision: reconstructed the pre-rename 100200 draft
  (fields=['event_type', 'timestamp']) -- collision with stock rule 86600
  in /var/ossec/ruleset/rules/0475-suricata_rules.xml correctly flagged

PASS -- gate2_disjointness: actual final match on the shared fixture:
  100101 (pre-existing sibling). A new-detection author naively
  registering 100191 (identical conditions to 100101) expecting IT to be
  the final match would be wrong -- gate2 catches exactly that gap:
  expected final matched rule '100191', got '100101'

PASS -- gate4_negate_probe: reconstructed 100103's original
  tool_arguments.path-absence negate draft -- does not fire on its own
  true-positive fixture -- final matched rule was '100100', not '100192'

4/4 red-team fixtures caught by their gate
```

**Two fixtures needed a second pass to be clean, honest proofs, not just
passing ones — both fixed rather than declared "good enough":**

- **Gate 2's first framing was ambiguous.** The initial version installed
  a rule identical to `100101` and checked whether it "intercepted"
  `100101`'s own fixture — `100101` won (the pre-existing rule kept its
  match), which is a *negative* result on that specific framing, not a
  gate failure. Re-framed to check the actually load-bearing claim: would
  a new detection's author, naively registering the duplicate rule and
  expecting *it* to be the final match on this shared fixture, be caught
  by the gate? Yes — `gate2_disjointness` correctly reports "expected
  100191, got 100101." This is the real risk the gate protects against
  (`wazuh/local_rules.xml:65-84`'s own history comment: 3a had to discover
  this same gap by hand for `100101`/`100103`), reported as a genuine
  measured result, not the first framing declared a pass by re-labeling a
  negative.
- **Gate 4's first fixture had a confound.** The chosen true-positive
  record (a real `exfiltrate` call from the corpus) also satisfied the
  real, corrected `100103` (still loaded — `wazuh/local_rules.xml` is never
  touched), so "the red-team rule didn't win" was ambiguous between "the
  negate bug caught it" and "an unrelated sibling won the race regardless."
  Fixed by constructing an isolated synthetic record
  (`tool_name="read_text_file"`, one of `100103`'s own negate-excluded
  read-tool names) that the real `100103` correctly stays silent on,
  leaving the red-team rule (`100192`) as the only rule that could
  possibly fire. Final matched rule: `100100` (no alert) — clean,
  unambiguous confirmation of the exact historical landmine.

## Regression — zero false rejections against the known-good set

```
Gate 1 (if_sid auto-parenting): 0 violations against 10 known-good rule ids
  across 3 Detections (expect 0)
Gate 3 (stock-ruleset collision): 100100 -> 0 violations, 100200 -> 0
  violations (expect 0, 0)
Gate 2 (disjointness) on benign corpus: 0 violations / 4727 records (expect 0)
Gate 4 (negate-on-absent-field probe) on 5 negate-using rules
  (100103-100107): 0 violations (expect 0)

REGRESSION PASSED -- zero false rejections against the known-good set
```

Gate 3 was run against the full, live, currently-loaded stock ruleset (142
files, 3048 rules fetched fresh from the manager container — not cached or
assumed from `docs/WAZUH-NOTES.md`'s prior audit).

## Hard gates — all held

1. **`wazuh/local_rules.xml` and `baseline/watch.py` byte-identical**:
   confirmed via `git diff --exit-code` before, during (after every
   dynamic red-team install/remove cycle), and after this entire build —
   never just at the end. The two dynamic gates' red-team rules were
   installed via `docker compose cp` into `/var/ossec/etc/rules/` (the
   same "iterate via `wazuh-logtest`, never restart the manager for a
   hypothesis" standing process rule `docs/WAZUH-NOTES.md` already
   established) and removed via `docker compose exec ... rm`, with removal
   itself verified (not just trusted), in a `finally` block. Confirmed
   clean afterward: no stray `redteam` files remain in the container's
   rule directory.
2. **Slice 1 stays behavior-identical**: `framework/tests/test_rugpull_wrapper_parity.py`
   (12/12) and `framework/parity_check.py` (full table match) both re-run
   green after the compiler build — the compiler is additive, nothing in
   slice 1 changed.
3. **All dynamic gates through real `wazuh-logtest`**: gates 2 and 4 both
   delegate to `framework/structural.py`'s `run_batch()`, itself a thin
   reuse of `analysis/report.py`'s real invocation. Confirmed by grep: no
   `re.search`/`re.match`/`re.finditer` against telemetry content anywhere
   in `framework/compiler.py` or the red-team harness — the only regexes
   in the new code are `parity_check.py`'s (parses markdown report *text*,
   pre-existing from slice 1) and `_COMMENT_RE` (strips XML comments before
   structural parsing, not telemetry matching).
4. **Each red-team fixture fails for the right reason, not a generic
   error**: every violation printed above names the specific rule id,
   field name, or mechanism (`"has no <if_sid>"`, `"collides with stock
   rule 86600... requires fields ['event_type', 'timestamp']"`, `"expected
   final matched rule '100191', got '100101'"`, `"does not fire on its own
   true-positive fixture... this is the negate-on-absent-field
   landmine"`), not a bare pass/fail — verified by reading the actual
   printed diagnostic text above, not just checking the boolean result.

## Deferred, as instructed

The semantic backend, any new real technique (the red-team fixtures are
deliberately-broken test detections — `SAF-T9999`/`SAF-T9998` scratch
technique_ids, scratch rule ids 100191–100193, never shippable), and the
DaC-Pipeline path. Not designed, not evaluated, not built.

## What this proves

The compiler's regression oracle is this project's own bug history, not an
assertion of correctness. All four gates were shown catching the exact
failure a human found by hand in 3a, 3b, or Phase 5 — and none of them
reject the ten rules that are already known to work. The next real test of
this compiler is a genuinely new technique (`SAF-T1105` or similar,
per `docs/PHASE6-DESIGN.md` Section 5's roadmap) — not built this round,
per the deferred list above.

# Phase 6 Migration Report — Framework Parity Result

**Verdict: exact parity, member-for-member.** The `framework/` +
`detections/` implementation reproduces `docs/PHASE4-REPORT.md` and
`docs/PHASE5-REPORT.md` exactly, through real engine execution, with zero
discrepancies. This is a regression-oracle pass, not a new detection: the
abstraction is proven against the frozen numbers this migration was
required to reproduce, not improved on them.

## Pre-flight: confirming the oracle itself hadn't drifted

Before writing any framework code, two read-only checks confirmed the live
lab state still matches the frozen reports (necessary — if the corpus or
container state had drifted since Phase 4/5 were generated, a "parity"
claim against them would be meaningless):

- Re-rendering `analysis/report.py`'s `render_report()` (pure function, no
  file write) against the live lab and diffing it in memory against the
  committed `docs/PHASE4-REPORT.md` produced exactly one difference: the
  recorded `wazuh/local_rules.xml` sha256. This is expected, not drift —
  `PHASE4-REPORT.md` was frozen *before* Phase 5's `100102` hardening fix
  was installed; the live manager runs the post-hardening rule set (its
  sha256 matches `PHASE5-REPORT.md`'s recorded sha exactly). After
  normalizing that one known, documented difference, the texts are
  byte-identical — every recall/FP number and the worked-example
  reconstruction included.
- Re-running `analysis/evasion_report.py`'s pure sub-functions (fresh
  watcher run over the evasion corpus, one shared `wazuh-logtest` batch)
  reproduced the exact same 10-of-12 evaded task_id set `docs/PHASE5-REPORT.md`
  records, and 0/4727 benign alerts.

Both corpora were safe to build against.

## What was built

Per the in-scope list, and no further:

| File | What it does |
|---|---|
| `framework/schema.py` | `Detection`/`BackendEntry`/`SessionKey` dataclasses + loader, parsing `detections/<id>_<name>/detection.yaml` into the v2 `backends:` list + `pipeline` shape. Validates chained pipelines' `emits`→`consumes` handoff at load time. |
| `framework/stateful.py` | `StatefulDetector` protocol + `RugPullBaselineDetector`, importing and delegating to `baseline/watch.py`'s `process_record` verbatim — no logic copied. |
| `framework/structural.py` | Thin reuse of `analysis/report.py`'s real `wazuh-logtest` invocation (`verify_rule_sync`, `run_wazuh_logtest_batch`, `fetch_container_file`) — imported, not reimplemented. |
| `framework/alerts.py` | `Alert` dataclass + table-driven `session_key` join, replacing `analysis/report.py`'s `if session_id / elif drift_session_id` chain with a table built from each registered Detection's own declared `session_key`. |
| `framework/fixtures.py` | Resolves the fixture-reference conventions each `detection.yaml` uses (`#distinct_sessions` / `#tool_call_events` / `#all_records` denominators; `live:telemetry#...` / `live:rugpull_alerts` live-container fetches; `#task_id~=...` evasion filters). New, disclosed below. |
| `framework/registry.py` | Loads the registry, resolves `logic_ref.python_class` strings to real classes, runs a chained Detection's stateful stage over raw records. |
| `framework/coverage.py` | Walks the registry, runs the full corpus set through one shared real `wazuh-logtest` batch call, builds the registry-driven coverage table. |
| `framework/parity_check.py` | Parses the actual committed `docs/PHASE4-REPORT.md`/`docs/PHASE5-REPORT.md` text (never hardcoded remembered numbers) and diffs every extracted row against `coverage.py`'s output. |
| `detections/SAF-T1001_tool_poisoning_html_comment/detection.yaml` | Single-backend `wazuh_rule` detection, `logic_ref` → `100102` unchanged. |
| `detections/SAF-T1502_credential_exfil/detection.yaml` | Two parallel `wazuh_rule` backend entries (`read_hop` → `100101`, `exfil_hop` → `100103`–`100107`), `pipeline: parallel`. |
| `detections/SAF-T1201_rug_pull_baseline_drift/detection.yaml` | The two-backend worked example: `stateful` (`RugPullBaselineDetector`) → `wazuh_rule` (`100201`), `pipeline: chained`. |
| `framework/tests/test_rugpull_wrapper_parity.py` | Re-runs `baseline/test_watch.py`'s 12 tests, unmodified, against the wrapper. |

## Judgment calls made, disclosed rather than silently decided

1. **No PyYAML.** This project has been stdlib-only throughout (confirmed:
   no `requirements.txt`, no third-party imports anywhere in `analysis/`,
   `baseline/`, or `corpus/`; PyYAML is not installed in this environment).
   Rather than introduce the project's first third-party dependency for a
   schema this small, `detection.yaml` files are written as valid JSON —
   JSON is a strict subset of YAML 1.2, so they remain valid `.yaml`
   documents (a real YAML parser would read them identically) while being
   parseable with the stdlib `json` module. If this project later adopts
   PyYAML for richer features (comments, folded scalars), these files need
   no changes.
2. **Credential exfil is one Detection, not two**, despite spanning two
   MITRE techniques (`T1552.001` read hop, `T1041` exfil hop) and six rule
   ids. This mirrors `docs/STATE-OF-PROJECT.md`'s and `docs/PHASE4-REPORT.md`'s
   own heading ("Credential exfiltration (SAF-T1502 read hop + SAF-T1910
   exfil hop)") treating it as one scenario already, and keeps this
   migration at exactly "the three existing techniques," as specified.
   `technique_id: SAF-T1502` is primary; `T1041` is carried as a second
   `mitre_attack_ids` entry. This needed a schema addition v2 hadn't
   anticipated:
3. **`pipeline: "parallel"`** — v2's design only named `"chained"` (rug
   pull's stateful→structural handoff). Credential exfil's frozen recall
   table reports read-hop and exfil-hop recall as two independent numbers
   against two independent rule families that don't depend on each other's
   output — a second, real composition shape a migration exercise was
   always going to surface. Implemented as a small, disclosed schema
   extension (`framework/schema.py`'s `VALID_PIPELINES`), not a redesign.
4. **Rug pull's canonical corpus uses the live-fetched `rugpull_alerts.jsonl`
   directly, not a fresh stateful rerun.** `docs/PHASE4-REPORT.md`'s rug-pull
   numbers were measured against the already-materialized output of the
   production `baseline/watch.py` process running across the full
   corpus-generation session (not a request-scoped recomputation over just
   the malicious-labeled subset — re-deriving fresh from only
   `malicious_lines` would risk missing the benign baseline-setting records
   that precede real drift in production, which could plausibly change the
   result). `framework/coverage.py` therefore reuses `analysis/report.py`'s
   own `load_inputs()` (already fetches the live, already-computed
   `rugpull_alerts.jsonl`) for the canonical corpora, and only invokes
   `RugPullBaselineDetector` fresh (empty state) for the evasion corpus —
   exactly matching `analysis/evasion_report.py`'s own methodology. A
   hypothetical future "run everything fresh from raw telemetry" coverage
   mode was not what either frozen report measured, and reproducing it
   would require replaying the entire production session's history —
   out of scope for a migration whose job is packaging, not rebuilding.
5. **Evasion-class target-rule attribution reuses `analysis/evasion_report.py`'s
   own `EVASION_CLASSES`/`TP_TASK_IDS`/`CE_TASK_IDS`/`targeted_and_other_fired`**
   (imported, not duplicated) rather than encoding per-evasion-task-id
   rule targeting into the Detection schema. This is a measurement-tool
   concept, the same category v2's design doc already named
   `RULE_TECHNIQUE`/`EVASION_CLASSES` as things the framework generalizes
   via `fixtures`/`known_gaps`, not reinvents from scratch.
6. **`compute_scenario_recall`, `compute_aggregate_fp`,
   `cross_check_scenario_task`, `group_final_rules_by_task`, and
   `targeted_and_other_fired` are reused directly (imported) from
   `analysis/report.py` and `analysis/evasion_report.py`**, fed by the
   framework's registry-driven joined records. These functions were already
   backend-agnostic (grouping by `scenario_id`/`task_id` from the record
   itself, not from a hardcoded rule-id dict) — reusing them minimizes
   reimplementation risk and keeps the "old" and "new" computations
   provably fed by the same real engine output. Only `compute_per_rule_fp`
   (the one function with rule ids hardcoded as literal dict keys) has a
   registry-driven replacement, `per_rule_fp_from_registry`, which resolves
   each Detection's own declared `fixtures.benign_denominator` instead.

## Parity result — full table, not six numbers

Every number below was independently re-derived by `framework/parity_check.py`
by parsing the *actual, currently-committed* `docs/PHASE4-REPORT.md`/
`docs/PHASE5-REPORT.md` text and diffing it against `framework/coverage.py`'s
freshly-computed equivalent — not compared against remembered/hardcoded
values.

### Tool poisoning (`SAF-T1001`)
- Recall: **12/12** — confirmed at full per-task_id granularity (all 12
  `attack_tool_poisoning_hidden_instruction*` task_ids independently
  verified to have fired `100102`, not just the aggregate count).
- FP: **0/541** (distinct benign sessions).

### Credential exfiltration (`SAF-T1502`/`T1041`)
- Read-hop recall (`100101`): **11/11** — all 11
  `attack_credential_exfil_sandbox_bait*` task_ids confirmed individually.
- Exfil-hop recall (`100103`–`100107`, any of 5): **11/11** — same 11
  task_ids, independently confirmed against the exfil-hop rule family.
- Per-rule FP, all against 1011 benign tool-call events: `100101` 0/1011,
  `100103` 0/1011, `100104` 0/1011, `100105` 0/1011, `100106` 0/1011,
  `100107` 0/1011.

### Rug pull (`SAF-T1201`)
- Recall: **3/3** drifting task_ids, full per-task/per-drift-field table
  matches exactly:

  | task_id | drift field(s) alerted |
  |---|---|
  | `attack_rug_pull_send_email_v2_pulled` | 100201 |
  | `attack_rug_pull_send_email_v3_desc_only` | 100201 |
  | `attack_rug_pull_send_email_v4_version_only` | 100201 |

- FP: **0/4727** (full corpus, all_records denominator).

### Aggregate benign FP
- **0/4727** — matches the executive-summary aggregate exactly.

### Evasion (`docs/PHASE5-REPORT.md`) — 10/12, exact task_id set
| task_id | verdict |
|---|---|
| `attack_evasion_e1_keyword_avoiding` | EVADED |
| `attack_evasion_e2_no_html_comment` | EVADED |
| `attack_evasion_e3a_zero_width` | caught |
| `attack_evasion_e3b_homoglyph` | EVADED |
| `attack_evasion_e4_distance_bound` | EVADED |
| `attack_evasion_e5_toolname_spoof` | EVADED |
| `attack_evasion_e6_untested_key` | EVADED |
| `attack_evasion_e7_secret_shape` | EVADED |
| `attack_evasion_e8_encoded_payload` | EVADED |
| `attack_evasion_e9_read_path` | EVADED |
| `attack_evasion_e11_behavior_only` | EVADED |
| `attack_evasion_e12_pulled` | caught |
| `attack_evasion_e10_legit_upgrade` (FP probe, not an evasion attempt) | fired |

Zero discrepancies across every row above.

## Hard gates — all held

1. **`wazuh/local_rules.xml` byte-identical**: `git diff --exit-code
   wazuh/local_rules.xml` — clean.
2. **`baseline/watch.py` byte-identical**: `git diff --exit-code
   baseline/watch.py baseline/test_watch.py` — clean. **Its 12 tests pass
   unmodified against the wrapped `RugPullBaselineDetector`**: all 12,
   including the 2 (`TestIdempotentReplay`) that call `process_file` rather
   than `process_record` directly — proven by capturing the original
   `process_record` reference before any monkeypatching (avoiding
   recursion) and routing both `test_watch.py`'s and `watch.py`'s own
   module-global `process_record` name through the wrapper at runtime, with
   neither file ever touched on disk.
3. **All matching via real `wazuh-logtest`**: confirmed by inspection —
   `framework/structural.py` is a pure delegation to
   `analysis/report.py`'s real invocation; no file under `framework/`
   performs regex/field matching against telemetry content (verified by
   grep — the only regexes anywhere in `framework/` are
   `parity_check.py`'s, and those parse markdown report *text*, never
   telemetry).
4. **Exact, member-level parity**: confirmed above — full table, not just
   the six summary numbers.
5. **Stop-and-report discipline**: not triggered — no discrepancy occurred.
   The mechanism exists regardless (`parity_check.py` prints the exact
   differing row(s) and returns non-zero on any mismatch; it does not
   attempt to reconcile).

## Explicitly deferred (not built this round)

Per the in-scope/deferred split given for this session:
- The compiler's write-side enforcement (`if_sid` auto-parenting as an
  emitting compiler, the disjointness gate as a hard block, the
  negate-on-absent-field pre-promotion probe, the stock-ruleset collision
  grep). This migration's `detection.yaml` files declare the fields those
  checks would consume (`consumes`/`parent_rule`) but no compiler reads
  them to *emit* or *gate* anything yet — today's `wazuh/local_rules.xml`
  is still hand-authored and manually verified, unchanged.
- The semantic backend (Section 4 of `docs/PHASE6-DESIGN.md`) — not
  implemented, not piloted.
- Any new technique beyond the existing three.
- The DaC-Pipeline / Sigma-compilation path — out of scope for this
  session as for the design review before it.

## The single thing this migration proves

The `backends:` list + `pipeline`/`session_key` schema `docs/PHASE6-DESIGN.md`
v2 defined is not aspirational — it holds up against the exact two-backend
case (`rug_pull_baseline_drift`) it was designed to prove, and reproduces
every frozen number member-for-member through real engine execution. The
abstraction is proven; nothing about *this* migration required
adjusting the oracle to get there.

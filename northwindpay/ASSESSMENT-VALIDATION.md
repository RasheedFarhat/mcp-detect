# NorthwindPay assessment validation

Scores `framework/audit_report.py` against `northwindpay/GROUND_TRUTH.json` --
a synthetic, hand-authored fintech telemetry corpus this project's detection
rules were never tuned against. The assessment run itself never reads
`GROUND_TRUTH.json` (it isn't one of `audit_report.py`'s two CLI arguments);
only `northwindpay/score_against_ground_truth.py`, invoked after the fact,
does.

## How this was run

```
python3 northwindpay/generate_corpus.py
python3 framework/audit_report.py northwindpay/telemetry.jsonl \
    --known-good northwindpay/known_good_bom.json --json > /tmp/report.json
python3 framework/audit_report.py northwindpay/telemetry.jsonl \
    --known-good northwindpay/known_good_bom.json --markdown > northwindpay/audit_report_run.md
python3 northwindpay/score_against_ground_truth.py /tmp/report.json
```

`northwindpay/audit_report_run.md` / `.json` are the actual, unedited output
of that run, committed for the record.

## Scores

| Metric | Result |
|---|---|
| Class-A recall (5 planted detectable techniques, 6 ground-truth entries -- the credential-exfil scenario is 2 hops) | **6/6 (100%)** |
| Class-B false findings (4 benign-decoy techniques, 7 planted instances) | **0/7 (0%)** |
| Class-C honesty (3 structurally-undetectable plants: not claimed caught, and correctly disclosed in the report's own limitations) | **3/3 (100%)** |

Full per-item pass/fail is reproducible via `score_against_ground_truth.py`'s
own stdout (shown below, unedited):

```
==============================================================================
CLASS A -- detectable issues (must appear in the report)
==============================================================================
[PASS] A5_path_traversal                        via Section 3 headline findings (by session_id)
[PASS] A3_poisoned_tool_description             via Section 3 headline findings (by session_id)
[PASS] A2_over_privileged_rw_mount              via AI-BOM trust_boundary filesystem_access == rw
[PASS] A4_credential_exfil_read_hop             via Section 3 headline findings (by session_id)
[PASS] A4_credential_exfil_exfil_hop            via Section 3 headline findings (by session_id)
[PASS] A1_shadow_mcp_server                     via shadow_candidates list

==============================================================================
CLASS B -- benign decoys (must NOT appear as a headline finding)
==============================================================================
[PASS] B4_benign_dotdot_search                  (4 instance(s), 0 incorrectly in headline findings)
[PASS] B1_legit_rw_scratch_mount                (1 instance(s), 0 incorrectly in headline findings)
[PASS] B3_rarely_called_tool                    (1 instance(s), 0 incorrectly in headline findings)
[PASS] B2_legit_version_bump                    (1 instance(s), 0 incorrectly in headline findings)
[PASS] B2 still visible in the low-severity bucket (not silently dropped): True

==============================================================================
CLASS C -- structurally undetectable (must not be claimed caught; must be disclosed)
==============================================================================
[PASS] C1_behavior_only_rug_pull           not_caught=True disclosed_in_report(E11)=True
[PASS] C3_homoglyph_poisoned_tool          not_caught=True disclosed_in_report(E3b)=True
[PASS] C2_base64_encoded_exfil             not_caught=True disclosed_in_report(E8)=True

CLASS A RECALL:  6/6 (100%)
CLASS B FALSE FINDINGS: 0/4 decoys incorrectly flagged
CLASS C HONESTY: 3/3 correctly non-claimed + disclosed
```

## Bugs the ground-truth harness caught, root-caused and fixed this session

Both were found and fixed BEFORE the scored run above -- reasoning about
what the assessor could and couldn't do, then verifying with real
`wazuh-logtest` runs, the same process this project's `docs/STATE-OF-
PROJECT.md` describes for its own prior fixes (e.g. the filesystem ro/rw
evidence-based classifier). Neither is a workaround; both are named,
disclosed changes to the report, not to any detection rule.

### Bug 1 -- `audit_report.py` never actually scanned the client's telemetry

Before this session, `framework/audit_report.py`'s only client-data-driven
sections were the AI-BOM (`abom.py`, metadata/hashes only, deliberately never
reads `tool_arguments`/`result_summary`) and the shadow-server diff. Its
"Detection coverage & adversarial evasion testing" section -- the one that
looks like a scan result -- is explicitly, by its own docstring, a
measurement of **this project's own detection content against its own
frozen corpora**, never the client's file. Confirmed by reading
`framework/coverage.py`'s `run_full_pipeline()`: every input comes from
`analysis/report.py`'s `load_inputs()` / `evasion_report.py`'s frozen
corpus loader, never from `sys.argv`'s client telemetry path.

Concretely, this meant a genuinely poisoned tool description (A3), a
two-hop credential exfiltration (A4), and a path traversal attempt (A5) in
NorthwindPay's telemetry would have produced **zero mention anywhere in the
report** -- not a caveat, a silent miss, because nothing in the codebase had
ever pointed the real rule engine at a client's own data at all.

**Fix**: `build_client_findings()` / `try_client_findings()`
(`framework/audit_report.py`), a new Section 3 ("Findings in your
environment"). Reuses, unmodified: `framework/structural.run_batch()` (the
identical `wazuh-logtest` batch call `coverage.py` already uses),
`framework/registry.run_stateful_stage()` (the identical TOFU baseline
wrapper `coverage.py` already uses for the evasion corpus), and
`framework/alerts.normalize_and_join()` / `rule_id_to_detection()` (the
identical join `coverage.py`'s own pipeline uses). No new detection logic,
no rule changes -- the existing, already-tested rule-matching path, now also
pointed at the client's file, not only at our own fixtures. Degrades the
same way `try_live_measurements()` already does: returns `None` (never a
partial/crashing result) if the engine is unreachable, rendered as an
explicit "not run this session" note rather than a silent gap.

**Verified**: re-running `framework/structural.run_batch()` directly against
`northwindpay/telemetry.jsonl` (see the raw counts below) confirms the fix
surfaces exactly the planted class-A records and nothing else:

```
100100: 3989   (parent, informational)
100102: 40     (SAF-T1001 -- all 40 from the poisoned expense-ocr description)
100108: 1      (SAF-T1105 -- the path-traversal plant)
100101: 1      (SAF-T1502 read hop)
100105: 1      (SAF-T1502 exfil hop)
```

plus one derived rug-pull drift record (see Bug 2).

### Bug 2 -- rug-pull baseline drift can't tell a version bump from an attack

SAF-T1201's own registered `known_gaps` (E10, already disclosed before this
session) states plainly: "Legitimate version bumps fire indistinguishably
from an attack -- no allowlist/re-baseline mechanism exists; operationally
close to unusable in any environment with routine version bumps." Feeding
NorthwindPay's `fx-rates` server's routine `1.2.0 -> 1.3.0` release (B2)
through `registry.run_stateful_stage()` + `structural.run_batch()` confirmed
this is real, not theoretical: it fires rule `100201`, indistinguishable
from a genuine rug pull, exactly as the known gap says.

**Root cause**: `baseline/watch.py`'s derived drift record already carries a
`drift_field` key distinguishing WHICH value changed --
`"tool_description_hash"` (the tool's actual advertised behavior/schema --
what a real rug pull changes) vs `"server_version_hash"` (a version label
alone -- what a routine release changes). Nothing downstream had ever used
that distinction.

**Fix**: severity-tiering in `build_client_findings()`, purely at report-
render time, using this already-emitted field -- `tool_description_hash`
drift is a headline finding; `server_version_hash`-only drift is reported
separately, at reduced severity, and excluded from the finding count. Zero
changes to `baseline/watch.py` or to `wazuh/local_rules.xml`'s `100201` --
both still see, and 100201 still fires on, every genuine drift event;
nothing is hidden, only triaged. **Not claimed as fixing E10** -- Section 6
of the report states explicitly that an attacker who changes only the
version string while hiding a real change elsewhere would still surface
only as a low-severity observation, not a headline finding. This is a
narrowing of a real false-positive problem, not an elimination of the
underlying gap; the report says so.

## What was NOT a bug

Six servers unique to NorthwindPay's fictional business
(`expense-ocr`, `fx-rates`, `slack-connector`, `support-ticket-bot`, the
shadow `mcp-crm-lite`, and NorthwindPay's own custom servers generally) all
render as `"unknown -- needs manual classification"` in the AI-BOM's trust
boundary column. This is `abom.py`'s existing, correct, honest behavior --
its pattern table is grounded in this project's own pinned server set
(README.md) and explicitly, deliberately, does not guess at servers it
doesn't recognize (`framework/abom.py`'s own docstring). It is not scored
as a class-A/B item and required no fix.

# Phase 6 Slice 3 Report — SAF-T1105 Path Traversal, First Framework-Native Detection

**Verdict: shipped, all gates hold, no regression — and the framework's
promise held only partially.** The schema and the four compiler gates
generalized to a genuinely new rule with zero code changes to
`framework/compiler.py` or the `Detection` schema. But two real costs
outside "one YAML + one rule" showed up, and one measured, honest false
positive was found and fixed along the way. All of that is reported below,
not smoothed into a clean story.

## Step 1 — Upstream grounding (cited, not assumed)

Fetched live via `gh api repos/SAFE-MCP/safe-mcp/contents/techniques/SAF-T1105/README.md`
(296 lines — a full document, not a stub) plus its companion
`detection-rule.yml` (a Sigma-style rule, also fetched live).

**Mechanism, confirmed from source**: relative-path traversal (`../`)
sequences in a file tool's path argument, escaping the intended directory
to reach files outside scope (SSH keys, `/etc/passwd`, `.env`,
`config.json`). Upstream's own "Common Vulnerable Paths" and "Example
Scenario" sections cite exactly the shapes this slice's fixtures
reproduce: `../../../etc/passwd`, `../../../../.ssh/id_rsa`,
`../config/database.yml`.

**A citation tension worth naming, not silently resolved either way**:
upstream's own "MITRE ATT&CK Mapping" section states its primary mapping
as **T1059.004** (Unix Shell, under Command and Scripting Interpreter
T1059) — a loose fit, since no shell command is executed here at all, only
a file tool's path argument. That same section's "Related ATT&CK
Techniques" list includes **T1005** (Data from Local System), which is
mechanically much closer to what this rule actually detects (unauthorized
local file access, not command execution). **Decision**: the rule's
`<mitre><id>` uses T1005 — still cited from upstream's own document, not
invented, and consistent with this project's existing precision-over-
broad-tactic pattern (e.g. `100101`'s `T1552.001`). The tension itself is
recorded here and in the rule's own XML comment, not hidden.

Upstream also independently names the advanced bypass classes (URL
encoding, double encoding, Unicode normalization, null-byte injection,
case manipulation) — grounding this slice's evasion work in the same
source, not inventing classes separately.

**Correction (SAF-MCP drift check, 2026-07-11): the claim just above was
inaccurate.** Only four of the five named classes actually became this
detection's `known_gaps` and evasion corpus (URL encoding, double
encoding, and Unicode normalization landed here; null-byte injection was
tested and found *not* to evade). **Case manipulation was identified from
the same upstream source at the time but was never carried into
`known_gaps`, never given an evasion fixture, and was not disclosed as an
open gap** — this report's original wording claimed otherwise. It has
since been added to `SAF-T1105_path_traversal/detection.yaml`'s
`known_gaps`, labeled explicitly `UNTESTED` (not asserted caught or
evaded), with the mechanical reasoning for why it plausibly doesn't evade
rule `100108` (case doesn't affect matching the literal `../`/`..\`
sequence) stated as reasoning, not a measurement. No new fixture was
authored and rule `100108` was not touched — this is a disclosure fix,
not new detection work.

## Step 2 — What was authored

1. **One new rule, `100108`**, appended to `wazuh/local_rules.xml`, child
   of `100100`. Confirmed purely additive: `git diff wazuh/local_rules.xml
   | grep '^-' | grep -v '^---'` returns nothing — no existing rule's text
   changed.
2. **One new `detections/SAF-T1105_path_traversal/detection.yaml`**, v2
   schema shape, `logic_ref` → `100108`, unchanged single-backend
   `wazuh_rule` structure (no new schema field, no new pipeline value —
   the schema additions slice 1/2 already made, `parallel`/`chained`, were
   sufficient; this detection needed neither).
3. **`lab/attacks/path_traversal_harness.py`** — a new, separate file (not
   editing frozen `harness.py`, following the exact precedent
   `evasion_harness.py` already set), generating 8 genuine variants via
   the real, pinned MCP filesystem server against the real `/app/sandbox`
   root: varying depth (`../etc/hosts` through
   `../../../../../../etc/shadow`), target (SSH keys, `/etc/passwd`,
   `config/database.yml`), separator style (`../` vs `..\`), and two
   deliberately overlapping `100101`'s own sensitive-suffix match
   (`../../.env`, `../../id_rsa`) — the disjointness centerpiece. **Design
   decision, disclosed**: unlike `evasion_harness.py` (which targets a
   scratch path because it measures evasions of *already-measured* rules),
   this harness targets the canonical `telemetry.jsonl` directly, matching
   how `harness.py`'s own original attacks and variants were additively
   appended to that same growing corpus across Phases 3a/3b — SAF-T1105 is
   a new technique's own genuine corpus, not an evasion of an existing
   rule. This is also what lets the new `detection.yaml` use the same
   `live:telemetry#label=malicious&scenario_id=X` fixture convention every
   other Detection already uses, rather than inventing a fourth kind.

## Step 3 — All four gates, including the centerpiece adjudication

Ruleset installed live (`docker compose cp wazuh/local_rules.xml
wazuh.manager:/var/ossec/etc/rules/mcp_detect_rules.xml`), rule-sync
confirmed passing before any measurement.

- **Gate 1 (if_sid auto-parenting)**: 0 violations. `100108`'s actual XML
  `<if_sid>100100</if_sid>` matches its declared `parent_rule`, confirmed
  by re-parsing the live rule file, not assumed from the YAML.
- **Gate 3 (stock-ruleset collision)**: **N/A, with reason** — `100108` is
  a child of `100100` via `<if_sid>`, not a new top-level `decoded_as:json`
  anchor. `docs/WAZUH-NOTES.md` constraint 8's collision risk (the
  Suricata `86600` case) is specifically about new *top-level* rules;
  `100108` introduces no new top-level anchor, confirmed directly
  (`rules['100108']['if_sid'] is not None` → `True`).
- **Gate 2 (disjointness) — the centerpiece**, adjudicated empirically,
  not assumed:

  **First, the naive draft** (traversal pattern only, no scoping),
  installed via a transient `docker compose cp` temp file, never touching
  the committed file: fed `../../.env` through real `wazuh-logtest` with
  both `100101` and the naive `100108` loaded. **Result: `100101` won.**
  The naive `100108` never fires on that overlap — confirmed, not assumed,
  the exact sibling-shadowing class `docs/WAZUH-NOTES.md` Tests 1–5
  already proved, hit again with a genuinely new rule for the first time
  since the framework existed to catch it.

  **Adjudication**: this is a real finding to resolve, not paper over.
  Fixed the same way `100103` was made disjoint from `100101` originally —
  negate on the same three sensitive suffixes `100101` already owns, so
  `100108` only fires on traversal to a path *not* ending in one of them.
  Unlike `100103`'s original, superseded negate draft (negate on a field
  that is genuinely *absent* for its own true positive —
  `docs/PHASE3A-DESIGN.md:470-478`), this negate is on a field
  (`tool_arguments.path`) that is always *present* for `100108`'s own true
  positives, just not matching the negated pattern — confirmed via
  `wazuh-logtest` this is a fundamentally safe use of negate, not the
  landmine class.

  **Re-tested after the fix, all four adjudication cases, via real
  `wazuh-logtest`**:
  | input | result | correct? |
  |---|---|---|
  | `../../.env` | `100101` | yes — negate-excluded from `100108` by design |
  | `../../.ssh/id_rsa` | `100101` | yes — same |
  | `../../../etc/hosts` | `100108` | yes — no sensitive-suffix overlap |
  | `.env` (no traversal) | `100101` | yes — `100101`'s own true positive unaffected |

  `gate2_disjointness()` run against all 8 real authored fixtures with
  their adjudicated expected rule ids: **0 violations.**

- **Gate 4 (negate-on-absent-field probe)**: 0 violations across all 6
  negate-using rules (`100103`–`100107`, `100108`), each against its own
  real true-positive fixture via `wazuh-logtest`.

## Step 4 — Honest measurement

**No regression, confirmed against the frozen reports, not assumed**:
`framework/parity_check.py` (which parses the actual committed
`docs/PHASE4-REPORT.md`/`docs/PHASE5-REPORT.md` text and diffs it against
fresh computation) passes clean with `100108` installed: 12/12 tool
poisoning, 11/11 read hop, 11/11 exfil hop, 3/3 rug pull, 0/4727 aggregate
FP — exactly the frozen numbers, member-for-member, unchanged.

**Recall for `100108`, reported precisely, not blended into one number**
(this project's own discipline, applied to the new rule too):
- `100108`'s own recall against its 8 authored fixtures: **6/8**. The
  other 2 (`v01_env_overlap`, `v02_id_rsa_overlap`) are *not* misses — they
  are correctly caught by `100101` instead, by the disjointness design
  above. Reporting `100108`'s own recall as 8/8 would misrepresent what
  the rule itself does; reporting it as 6/8 without this context would
  misrepresent it as a gap. Both numbers are stated together, deliberately.
- **Technique-level recall** (was the path-traversal attack caught by
  *some* rule in the system, regardless of which): **8/8**.

**FP for `100108` against the full benign corpus — found, not suppressed,
then fixed, then re-measured**:

First measurement, naive draft (no tool-name scoping): **20/4727** benign
records alerted. Investigated, not dismissed: all 20 came from a single
tool, `search_files` — confirmed by reading the actual benign records, not
assumed — a real MCP filesystem-server tool that legitimately navigates to
sibling directories (`../proxy`, `../workspace/corpus`) as part of
ordinary directory search. Checked every other tool name that ever carries
a `path` argument in the benign corpus (`create_directory`, `edit_file`,
`get_file_info`, `list_allowed_directories`, `list_directory`,
`read_text_file`, `write_file`) — **none of the content-exposing ones use
`../` anywhere in this corpus; only the metadata/search tools do.**

**Fix applied** (not deferred, since a real, principled, already-precedented
mechanism was available): added a third field, `negate="yes"` on the five
known metadata/search tool names (`search_files`, `list_directory`,
`directory_tree`, `get_file_info`, `list_allowed_directories`) —
`tool_name` is always present on a `tools/call` record, so this is the
same safe negate class as the two fields already discussed, not the
absent-field landmine. **Re-measured after the fix: 0/4727 benign FP**, all
8 attack fixtures still fire exactly as adjudicated above (confirmed via a
second full run, not assumed carried over from the first).

**Named limitation, disclosed rather than oversold**: this fix is the
*same shape* as `100103`–`100107`'s own negate-list, and inherits the
*same* limitation `docs/PHASE5-REPORT.md`'s E5 already proved for that
family: a traversal-capable tool renamed to one of these five excluded
names would evade `100108` the same way. This is recorded as the first
entry in `known_gaps`, not silently assumed away.

**`known_gaps`, populated honestly** (6 entries): the tool-name-spoofing
limitation above; URL-encoded traversal (`%2e%2e%2f`, the same
open-ended-list problem this project has refused to chase for
tool-poisoning keywords, named upstream too); absolute-path access with no
`../` at all (structurally invisible to a traversal-pattern rule by
construction); Unicode normalization bypass (same class of gap as
`100102`'s homoglyph limitation); symlink indirection (leaves no
traversal sequence in the argument at all, structurally invisible
regardless of pattern richness); null-byte injection (not separately
tested this slice, named as unverified rather than assumed covered).

## Step 5 — Did the framework deliver? The point of this slice.

**What held exactly as promised**: the schema needed zero changes.
`SAF-T1105` uses the same single-backend `wazuh_rule` shape `SAF-T1001`
already established — no new field, no new `pipeline` value (the
`parallel`/`chained` additions slice 1/2 already made were sufficient).
All four compiler gates ran against a genuinely new rule for the first
time and needed **zero code changes** to `framework/compiler.py` — gate 1
correctly auto-assigned the parent, gate 3 correctly recognized no new
top-level anchor was introduced, gates 2 and 4 correctly validated the
disjointness fix and the negate probe against real fixtures. This is the
framework's clearest, cleanest win this slice, and it held.

**What the "one YAML + one rule" framing understates — two real, named
costs**:

1. **`framework/tests/test_compiler_regression.py` needed a manual
   update.** This is a *test harness* file, not the compiler itself, and
   its fixture-discovery logic is hardcoded per-rule (a `key_to_rule` dict
   for the exfil family, now a second hardcoded lookup for `100108`), not
   registry-driven. Onboarding detection #4's negate-using rule required a
   small, manual edit outside `detections/` and outside
   `wazuh/local_rules.xml`. Small, but real — and a natural candidate for
   generalization in a future round (derive gate 4's fixture set from each
   Detection's own `fixtures.attack_corpus` automatically, rather than
   hand-maintaining a lookup table).
2. **`framework/tests/test_compiler_redteam.py`'s own safety check needed
   a fix, for a related reason.** `confirm_local_rules_untouched()` used
   `git diff --exit-code wazuh/local_rules.xml` to catch accidental
   mutation during red-team testing — correct in slice 2, when the file
   had zero uncommitted changes. Slice 3 legitimately adds `100108` to
   that same file before the red-team suite ever runs, so "differs from
   HEAD" stopped being equivalent to "this test just changed it," and the
   safety check false-positived, halting the run. Fixed by comparing
   against a snapshot taken at import time instead of `git diff` against
   HEAD — correct in both cases. A real bug in the test's own assumption,
   found by actually running it in the new context, not by inspection.
3. **The compiler's four gates do not include an automated FP-against-
   benign-corpus check.** The 20/4727 false positive was caught by Step
   4's `coverage.py`-style measurement, not by any of gates 1–4 — none of
   them run the new rule against the full benign corpus as part of
   "compiling" a detection. A detection could pass all four write-side
   gates cleanly and still carry an undiscovered FP problem, exactly as
   this one did until it was separately measured. **Recommended as a
   candidate fifth gate for a future round**: no detection advances past
   `status: proposed` without a clean (or explicitly accepted, named)
   FP result against the frozen benign corpus, enforced with the same
   rigor as the other four.

**A boundary worth stating plainly, not glossed over**: the gates are a
*validation* layer, not an *authoring-assistance* layer. Gate 2 correctly
detected the `100101`/`100108` overlap once tested — but it did not design
the negate-based fix; that took the same hands-on Wazuh-rule-authoring
judgment 3a's original author needed for `100101`/`100103`. Likewise, gate
4 confirmed the negate probe was safe once written — but recognizing
*which* field was safe to negate on (present-but-non-matching, never
absent) was still a human judgment call, not something the gate derived
for me. "Structurally safe" means the gates will catch a broken rule
before it ships, proven twice now against real bug reconstructions and
once against a genuinely new rule — it does not mean a new technique can
be authored without understanding how Wazuh's rule engine actually
behaves. That distinction is the honest version of this slice's finding.

**Net assessment**: the marginal cost of detection #4 was one
`detection.yaml`, one additive rule block, and one new fixture-generation
file — exactly as promised — plus one small test-harness update and one
real, found-and-fixed FP, neither of which the original design
anticipated by name. The framework made all of this *fast to find and
cheap to fix* (temp-file iteration caught every problem before anything
was committed to the live manager or the repo) — that speed and safety is
real and worth crediting. It did not make the underlying detection-
engineering judgment optional.

## Hard gates — all held

1. **Existing 10 rules byte-identical**: `git diff wazuh/local_rules.xml |
   grep '^-' | grep -v '^---'` returns nothing — the only change is the
   additive `100108` block. `lab/baseline/watch.py`/`test_watch.py`: `git diff
   --exit-code` clean.
2. **Slices 1 + 2 stay green**: `framework/parity_check.py` passes;
   `framework/tests/test_rugpull_wrapper_parity.py` 12/12;
   `framework/tests/test_compiler_regression.py` — all four gates clean
   against all 9 rule ids actually referenced by the 4 Detections' own
   `logic_ref`s (`100100`/`100200` are canonical parent anchors, never
   referenced directly), after fixing the test harness's own
   fixture-discovery bug described above, and after one transient
   wazuh-logtest batch failure under load that cleared on retry — the
   kind of container-lifecycle fragility `docs/WAZUH-NOTES.md` finding #5
   already named, not a real defect. `framework/tests/test_compiler_redteam.py`
   4/4, after fixing its own `confirm_local_rules_untouched()` safety
   check (also described above) to compare against a run-start snapshot
   instead of `git diff` against HEAD.
3. **All matching through real `wazuh-logtest`**: every claim above —
   the naive-draft overlap, the fix's four adjudication cases, the 8-
   fixture disjointness table, the FP measurement before and after the
   fix — was a real engine run, never a Python reimplementation.
4. **Every FP/recall number led with, not smoothed**: the 20/4727 FP is
   reported above as the *first* measurement, not edited out of the
   narrative; `100108`'s own 6/8 recall is reported precisely rather than
   rounded up to the technique-level 8/8.

## Deferred, as instructed

The semantic backend, DaC-Pipeline/Sigma generation (this rule is
hand-authored on the Direct path throughout), and any technique beyond
SAF-T1105. No evasion corpus was authored this slice for `100108`
(`fixtures.evasion_corpus: "none"` in the detection.yaml, stated
explicitly rather than left implicit) — red-teaming this rule's own
evasions is future work, not this slice's.

## Addendum (maturity pass) — the deferred evasion corpus, closed

Closing the one gap named above: `lab/attacks/path_traversal_evasion_harness.py`
(+ `lab/attacks/servers/traversal_read_server.py` for the tool-name-spoofing
class) generated 6 evasion classes against `100108`, following the exact
`lab/attacks/evasion_harness.py` precedent — a scratch corpus path, never the
canonical `telemetry.jsonl`, then appended (154 → 196 records) to the same
`data/evasion_corpus_v1.jsonl` every other detection's `evasion_corpus`
fixture already references, rather than inventing a second evasion-corpus
file. Each class targets a specific mechanism already named in this
rule's own `known_gaps`, not invented for this addendum. Measured via
real `wazuh-logtest`, not assumed:

| class | mechanism | verdict |
|---|---|---|
| `attack_evasion_e1_toolname_spoof` | tool named `search_files` (negate-excluded), real traversal path | **EVADED** (100100) |
| `attack_evasion_e2_url_encoded` | `%2e%2e%2f` instead of literal `../` | **EVADED** (100100) |
| `attack_evasion_e3_unicode_normalization` | `%c0%ae%c0%ae` overlong UTF-8 | **EVADED** (100100) |
| `attack_evasion_e4_double_encoded` | `%252e%252e%252f` | **EVADED** (100100) |
| `attack_evasion_e5_null_byte` | `../../../etc/passwd%00` | **caught** (100108) |
| `attack_evasion_e6_absolute_path_no_dots` | `/etc/passwd`, no `../` at all | **EVADED** (100100) |

5 of 6 evade, all exactly as `known_gaps` already predicted structurally —
measurement confirming prediction, not overturning it. The one genuine
resolution: E5 (null-byte injection) was previously named as *unverified*
("the literal `../` would still be present and should still match, but
this has not been measured") — now **confirmed caught**, not evaded, since
the literal `..` sequence is still present in that specific construction
regardless of the trailing null byte. `detections/SAF-T1105_path_traversal/detection.yaml`'s
`known_gaps` and `fixtures.evasion_corpus` are both updated to reflect
this — the fixture is a real `#task_id~=...` reference now, not the `"none"`
sentinel. Symlink indirection remains unverified (would need a stateful
filesystem setup step beyond a single tool-call argument, not authored
this round). Re-ran `framework/parity_check.py` after appending to the
corpus: still passes clean, confirming the append didn't disturb any
existing technique's evasion verdicts.

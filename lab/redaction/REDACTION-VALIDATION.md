# Redaction validation

Proves `lab/redaction/redact.py`'s corrected design (`lab/redaction/DESIGN.md` --
data minimization by allowlist, not blocklist redaction) against
`examples/northwindpay/telemetry.jsonl`, the same ground-truth-labeled corpus
`examples/northwindpay/ASSESSMENT-VALIDATION.md` scored the un-minimized assessor
run against. 4046 records, 538 sessions, 12 servers.

## Correction notice

An earlier version of this document validated a **superseded blocklist
design** and, in the surrounding docs (not this file's actual measurements,
which were accurate for what they measured), overclaimed the general
scope of what that design protected. This version validates the corrected
allowlist-minimization design, including a new acceptance bar the prior
version did not test at all: that realistic secrets/PII with NONE of the
six recognized credential shapes also do not survive.

## How this was run

```
python3 examples/northwindpay/generate_corpus.py
python3 lab/redaction/redact.py examples/northwindpay/telemetry.jsonl examples/northwindpay/telemetry.redacted.jsonl --report
.venv/bin/python3 lab/schema/validate.py examples/northwindpay/telemetry.redacted.jsonl

python3 framework/audit_report.py examples/northwindpay/telemetry.redacted.jsonl \
    --known-good examples/northwindpay/known_good_bom.json --json > examples/northwindpay/audit_report_run.redacted.json
python3 framework/audit_report.py examples/northwindpay/telemetry.redacted.jsonl \
    --known-good examples/northwindpay/known_good_bom.json --markdown > examples/northwindpay/audit_report_run.redacted.md
python3 examples/northwindpay/score_against_ground_truth.py examples/northwindpay/audit_report_run.redacted.json

.venv/bin/python3 framework/tests/test_redaction_secret_survival.py
```

`examples/northwindpay/telemetry.redacted.jsonl` and `examples/northwindpay/
audit_report_run.redacted.{md,json}` are committed, unedited outputs.

## Schema validity

`lab/schema/validate.py examples/northwindpay/telemetry.redacted.jsonl`: **4046 records
valid, 0 invalid**.

## Scores: raw vs. minimized

| Metric | Raw (`ASSESSMENT-VALIDATION.md`) | Minimized (this run) |
|---|---|---|
| Class-A recall | 6/6 (100%) | **6/6 (100%) -- unchanged** |
| Class-B false findings | 0/7 | **0/7 -- unchanged** |
| Class-C honesty | 3/3 | **3/3 -- unchanged** |

Every individual class-A/B/C item's PASS/FAIL line is identical to the raw
run, item-for-item. The rendered report itself is byte-identical between
the raw and minimized runs (`diff` after normalizing the generation
timestamp and the telemetry file path/sha256 shows zero remaining
differences) -- every finding, BOM row, trust-boundary label, OWASP row,
and known-gap bullet is the same.

## Structural invariants checked directly

- Record count: 4046 in, 4046 out.
- `tool_description_hash`/`server_version_hash`: byte-identical for all
  4046 records.
- The poisoned tool description (`CONFIDENTIAL ADMIN OVERRIDE`, class-A3)
  and homoglyph-poisoned description (`ЅYЅTEM`, class-C3): present,
  unchanged, in every session that should carry them.
- `tool_arguments.path`: identical before/after on every record that
  carries it.
- `raw.result.isError` / `raw.error` presence: identical truthiness on
  every write-evidence-relevant record (confirmed on both a successful
  write and a denied write) -- `framework/abom.py`'s ro/rw classification
  is unaffected by minimization.

## Secret-survival tests (`framework/tests/test_redaction_secret_survival.py`)

Registered in `framework/tests/run_all.py`. Offline-safe. **Two test
classes, 13 assertions total, all passing:**

### `TestRedactionSecretSurvival` (the six recognized credential shapes)

```
test_all_six_shapes_preserved_in_isolation ... ok
test_detection_shape_markers_still_present ... ok
test_hashes_unchanged ... ok
test_no_planted_secret_survives_redaction ... ok
test_non_path_benign_content_minimized_to_placeholder ... ok
test_raw_corpus_actually_contains_the_planted_secrets ... ok
test_record_count_unchanged ... ok
test_tool_arguments_path_preserved_verbatim ... ok
test_tool_poisoning_and_homoglyph_content_untouched ... ok
```

Proves none of the three planted credential literals (`R7!qLmXo2z`, the
full `nwp_svc:...@ledger-db.internal:5432` span, `AKIAIOSFODNN7EXAMPLE`)
survive anywhere, while the fixed markers (`DATABASE_URL=`, `AKIA...`)
that keep 100101/100103–107 firing do survive. Also fixed a real
regression the private-key isolation test caught during this correction:
the first draft of the corrected `PRIVATE_KEY_BLOCK` marker dropped the
rule-required kind word (`RSA`/`OPENSSH`/etc.), which would have silently
broken detection for that one shape -- caught by
`test_all_six_shapes_preserved_in_isolation` before this was shipped, not
after.

`test_non_path_benign_content_minimized_to_placeholder` replaces the prior
(now-incorrect) `test_benign_content_not_mangled`: under minimization,
ordinary benign content in a non-`path` argument is NOT preserved verbatim
-- it's reduced to the generic placeholder, same as anything else not on
the allowlist. That property (benign content passing through untouched)
was exactly what let arbitrary non-six-shape secrets/PII through
undetected in the prior design.

### `TestNonCredentialShapePIIMinimized` (the actual gap this correction closes)

```
test_email_in_path_is_the_one_disclosed_exception ... ok
test_no_planted_pii_survives_minimization ... ok
test_none_of_these_match_any_recognized_credential_shape ... ok
test_raw_corpus_contains_the_planted_pii ... ok
```

Five realistic secrets/PII planted in NorthwindPay's own BENIGN content
(a "legacy system notes" doc a real onboarding runbook would plausibly
contain, read via an ordinary `read_text_file` call, `examples/northwindpay/
generate_corpus.py`'s `build_fs_workspace()`), none matching any of the six
recognized credential shapes:

- `Tr0ub4dor&3-legacy` -- a plaintext password
- `jane.doe@northwindpay.example` -- an employee email (paired with an SSN
  in the same doc)
- `123-45-6789` -- an SSN-shaped number
- `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` -- a JWT-shaped auth token example
- `admin-legacy.northwindpay.corp` -- an internal admin hostname

**None of the five survive the minimized export** -- not because this pass
recognizes passwords/emails/JWTs/hostnames (it doesn't try to), but because
the field they lived in (a tool response's free-text content) isn't on the
allowlist at all and is minimized regardless of shape. This is the gap the
prior blocklist-only design silently left open, and the gap the prior
version of `test_redaction_secret_survival.py` didn't test for at all.

`test_email_in_path_is_the_one_disclosed_exception` is the honest
counterpoint: a sixth plant, the SAME kind of email, deliberately placed
inside a `tool_arguments.path` value (a per-user backup directory name,
`backups/alex.smith@northwindpay.example/settings.json`) -- and it DOES
survive, because `path` is preserved verbatim by design. This is not an
oversight; it's exactly the disclosed residual `lab/redaction/DESIGN.md` names,
and exactly what `lab/redaction/redact.py --report`'s residual-disclosure pass
exists to flag (confirmed below).

## Residual-disclosure report, run against the real corpus

```
## Fields carrying free-text content by design

| Field | Records with non-empty content | Why it survives |
|---|---|---|
| server_command | 4046 | server/tool inventory (AI-BOM) |
| tool_name | 678 | server/tool inventory, rule matching |
| tool_arguments.path | 313 | the detection signal itself (100101/100108) |
| raw.result.tools | 538 | tool-poisoning signal (100102) + tool_description_hash input |
| raw.result.serverInfo | 538 | server_version_hash input |

## Flagged for manual review before sending (1 hit(s))

| Record # | Session (short) | Field | Pattern | Preview |
|---|---|---|---|---|
| 3911 | 7e7beb28... | tool_arguments.path | EMAIL | backups/alex.smith@northwindpay.example/settings.json |

## Six-shape markers present (informational -- already non-recoverable)

| Shape | Occurrences |
|---|---|
| DATABASE_URL_ASSIGNMENT | 4 |
| API_KEY_ASSIGNMENT | 0 |
| PRIVATE_KEY_BLOCK | 0 |
| SK_STYLE_KEY | 0 |
| POSTGRES_URL | 4 |
| AKIA_STYLE_ID | 2 |
```

Exactly one flagged item, and it is exactly the disclosed `path` residual
-- the report correctly did NOT flag anything in the four other
surviving-by-design fields (none of NorthwindPay's real tool descriptions,
server commands, or server-info strings happen to contain a secondary
secret/PII shape in this corpus), and correctly did NOT need to flag
anything in the five PII-plant fields above, because minimization already
removed them before the residual scan ever ran.

## Bugs found this session

**One, caught by the corrected test suite before being shipped**: the
first draft of the corrected `redact.py`'s private-key marker
(`BEGIN PRIVATE KEY-----\nREDACTED\n-----END PRIVATE KEY-----`) dropped the
specific kind word (`RSA`/`OPENSSH`/`EC`/`DSA`/`PGP`) `wazuh/
local_rules.xml`'s rule requires literally present --
`test_all_six_shapes_preserved_in_isolation` failed immediately, before any
corpus run. Fixed by capturing the matched kind and embedding it in the
marker (`lab/redaction/redact.py`'s `_private_key_marker()`). This corpus never
exercises that shape (no private-key plant in NorthwindPay's telemetry), so
the full-corpus run would NOT have caught this on its own -- the isolated,
corpus-independent shape test is what caught it, which is exactly why that
test exists as a separate check from the corpus-based ones.

## Known, disclosed limitations this validation does NOT close

Per `lab/redaction/DESIGN.md`: `tool_arguments.path` and `raw.result.tools`/
`serverInfo` are shipped verbatim by design and can carry sensitive content
of their own (demonstrated directly above by the email-in-path plant).
Base64-encoded secret content inside a field that IS minimized is dropped
along with everything else (fine); inside `path` specifically it would
survive like any other path content (not exercised by this corpus, and not
a realistic case for this project's own tool set). Neither is a new gap --
both are named in `lab/redaction/DESIGN.md`'s own "What this design does NOT
claim" section.

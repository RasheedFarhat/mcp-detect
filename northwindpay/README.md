# northwindpay/ — synthetic ground-truth environment for assessor validation

**NorthwindPay is fictional.** No real organization, credential, or network
endpoint appears anywhere in this directory. Every secret-shaped string
(API keys, connection strings) is a synthetic placeholder, hand-authored for
this corpus specifically -- not copied from `attacks/servers/*.py`,
`data/evasion_corpus_v1.jsonl`, or any other frozen corpus in this repo.

## What this is

A ground-truth-labeled telemetry corpus (schema v1) built to prove
`framework/audit_report.py` produces an inspectable technical evidence report
against an environment its detection rules were never tuned against -- and to
catch, root-cause, and fix any gap that testing found (see
`ASSESSMENT-VALIDATION.md`). Built by a method deliberately different from
`attacks/harness.py`'s env-var-parametrized variant factory: `generate_corpus.py`
constructs each JSON-RPC message directly in Python (no live docker/MCP
process spawned), with every attack/decoy/blind-spot record's content
authored fresh for this fictional business context.

12 MCP servers, 536 sessions, 4,032 records, spanning:
- **5 detectable planted techniques** (class A): a shadow MCP server, an
  over-privileged read-write mount into "production" data, a poisoned tool
  description, a two-hop credential exfiltration, and a path-traversal
  attempt.
- **4 benign-but-suspicious decoys** (class B): a legitimate read-write
  scratch mount, a legitimate server version bump, a rarely-called
  advertised tool, and a benign `..`-containing path from a search tool --
  all of which a naive/over-broad detector could plausibly mis-flag.
- **3 structurally-undetectable techniques** (class C): a behavior-only rug
  pull with no metadata change, base64-encoded exfiltration, and a
  homoglyph-poisoned tool description -- each mapped to an already-disclosed
  `known_gaps` entry in this project's own detection registry
  (`detections/*/detection.yaml`).

## Files

| File | Purpose |
|---|---|
| `generate_corpus.py` | Regenerates everything below, deterministically (fixed RNG seed). |
| `telemetry.jsonl` | The full corpus -- schema-v1-valid, chronologically sorted. |
| `known_good_bom.json` | Client-declared known-good server list (`--known-good` input) -- deliberately omits the shadow server. |
| `GROUND_TRUTH.json` | **Sealed manifest.** Records exactly which session_ids/servers correspond to each planted class A/B/C item. The assessment run (`audit_report.py`) never reads this file -- it isn't one of its two CLI arguments. Only `score_against_ground_truth.py` does, after the fact. |
| `score_against_ground_truth.py` | Scores an `audit_report.py --json` run against `GROUND_TRUTH.json`: class-A recall, class-B false-finding rate, class-C honesty. |
| `audit_report_run.md` / `.json` | The actual, unedited output of the validated run -- committed for the record. |
| `ASSESSMENT-VALIDATION.md` | The three scores, full pass/fail detail, and the two real bugs this exercise found and fixed this session. |

## Regenerating

```
python3 northwindpay/generate_corpus.py
python3 framework/audit_report.py northwindpay/telemetry.jsonl \
    --known-good northwindpay/known_good_bom.json --json > /tmp/report.json
python3 framework/audit_report.py northwindpay/telemetry.jsonl \
    --known-good northwindpay/known_good_bom.json --markdown > northwindpay/audit_report_run.md
python3 northwindpay/score_against_ground_truth.py /tmp/report.json
```

Regenerating reproduces the identical corpus (fixed RNG seed) but fresh
`timestamp`/`session_id` values are NOT re-derived from `GROUND_TRUTH.json`
-- `generate_corpus.py` is the single source of truth for both, written in
one pass, so they never drift apart.

## Relationship to `samples/`

`samples/NorthwindPay-Agentic-Detection-Readiness-Assessment/REPORT.md` is
the polished synthetic report built from this validated run --
executive summary, severity-ranked findings with remediation, and an
explicit "what this assessment cannot see" section. This directory is the
underlying evidence and validation harness behind that deliverable, not a
second copy of it.

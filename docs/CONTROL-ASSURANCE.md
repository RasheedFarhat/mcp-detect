# Control assurance model

MCP Detect separates telemetry indicators from preventive-control evidence.
An indicator can direct an analyst to a risky path, but it cannot prove that a
vulnerability is reachable or that a preventive boundary is effective.

## Status rules

- `verified`: approved source/configuration evidence or an authorized negative
  test demonstrates the passing condition.
- `failed`: the control did not meet its passing condition.
- `review_required`: normalized telemetry produced an indicator and no manual
  result has adjudicated it.
- `not_verified`: no indicator matched, but no control test was supplied.
- `not_tested`: the assessor explicitly records that the control was not run.
- `not_applicable`: the assessor documents that the control does not apply.

An absence of telemetry indicators never creates a `verified` result.

## Normalized analyzer

`framework/assurance.py` runs before report rendering and provides:

- Unicode NFKC normalization, removal of invisible format characters, and a
  bounded common-confusable skeleton for security keywords.
- Bounded URL decoding, including visibility for common overlong dot and slash
  forms.
- Recursive inspection of nested argument values without depending on fixed
  keys such as `body`, `content`, or `message`.
- Base64-aware secret-shape inspection that withholds the matched value.
- Same-session correlation from a sensitive read into a later outbound action.
- A filesystem boundary helper that follows existing symlinks during negative
  tests and refuses targets outside the approved root.

The analyzer is still an indicator layer. Runtime containment belongs in the
reviewed MCP host and server. The official MCP guidance recommends restricted
filesystem and network access, minimal privileges, sandboxing, and per-call
authorization.

## Manual evidence input

Copy `framework/control_evidence.example.json`, replace the example results
with evidence from the approved review, and run:

```sh
python3 framework/audit_report.py telemetry.jsonl \
  --control-evidence control-evidence.json \
  --markdown
```

The report renders every preventive control beside its status, automated
indicator count, and passing condition. The detailed detector and evasion
appendix remains separate so limitations stay inspectable.

## Baseline approval

Rug-pull drift is never auto-approved. After the release diff and provenance
have been reviewed, copy `lab/baseline/approval.example.json`, name the exact hash
already observed by the watcher, and run:

```sh
python3 lab/baseline/watch.py \
  --input telemetry.jsonl \
  --output drift.jsonl \
  --state baseline.json \
  --approve approval.json
```

The watcher refuses an unobserved hash. A successful approval retains the old
baseline, approved hash, reviewer, reason, and timestamp in
`approval_history`.

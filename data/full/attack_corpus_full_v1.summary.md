# MCP Detect attack corpus v1 — complete synthetic set

This directory contains the complete self-authored corpus, frozen engine
verdicts, and checksums under the repository's MIT license.

> **Synthetic data:** every record was produced by this project's fixtures and
> harnesses. It contains no customer traffic and is not independent validation.

**Files**:
- `attack_corpus_full_v1.jsonl` (322 lines, JSONL, schema v1 — see
  `lab/schema/schema.md`) — every `label=="malicious"` record from the live
  `telemetry.jsonl` this project's attack harnesses have produced.
- `rugpull_alerts_full_v1.jsonl` (8 lines) — the corresponding derived
  drift records from `lab/baseline/watch.py`. **Not schema-v1-conformant by
  design** (a bespoke derived shape — `mcp_drift_marker` etc. — matched by
  Wazuh rule `100200`/`100201` directly, never validated against
  `schema.json`; same as `docs/STATE-OF-PROJECT.md`'s own description of
  this stream).
- `attack_corpus_full_v1.jsonl.sha256`, `rugpull_alerts_full_v1.jsonl.sha256`
  — checksums, same convention as `data/benign_corpus_v2.jsonl.sha256`.
- `attack_corpus_full_v1.golden_matches.json` — precomputed, real
  `wazuh-logtest` final-matched-rule-id per line (see
  `framework/repro_offline.py`), captured the same session this corpus was
  frozen, used by the full-tier offline reproduction harness.

**Generated**: 2026-07-11 (frozen from the live stack's `telemetry.jsonl` /
`rugpull_alerts.jsonl`, produced across this project's development by
`lab/attacks/harness.py`, `lab/attacks/path_traversal_harness.py`, and
`lab/baseline/watch.py` against the pinned server set — see `README.md`
"Pinned versions"). Rule-sync verified before freezing: live manager's
loaded rule file was byte-identical to committed `wazuh/local_rules.xml`
(sha256 `1104f282ee5585cd429a12a680e250cff8f4224fa236bb271199fddbc4e1a8d9`)
at capture time.

## Reproducibility note

Same discipline as `data/benign_corpus_v2.jsonl`: **frozen, checksummed,
immutable** — do not regenerate in place. `lab/attacks/harness.py` and friends
are deterministic scripted clients (not LLM-driven), so a fresh
regeneration would be *semantically* identical (same task templates, same
payloads) but not byte-identical (fresh UUIDs, wall-clock timestamps,
hash values tied to a session's own server_version_hash). If you need to
extend this corpus, generate a new versioned file
(`attack_corpus_full_v2.jsonl`), don't overwrite this one.

## Distribution

- **Sessions**: 46
- **Total records**: 322 (`attack_corpus_full_v1.jsonl`) + 8 derived drift
  records (`rugpull_alerts_full_v1.jsonl`)

### By technique (scenario_id)

| scenario_id | technique | records | task_id variants |
|---|---|---|---|
| `tool_poisoning` | SAF-T1001 | 84 | 12 |
| `credential_exfil_via_read` | SAF-T1502 (read hop) + SAF-T1910 (exfil hop) | 154 | 11 (each a read+exfil session pair) |
| `path_traversal` | SAF-T1105 | 56 | 8 |
| `rug_pull` | SAF-T1201 | 28 | 4 (1 baseline + 3 drift shapes) |

### `rugpull_alerts_full_v1.jsonl` breakdown

| task_id | drift records |
|---|---|
| `attack_rug_pull_send_email_v2_pulled` | 2 |
| `attack_rug_pull_send_email_v3_desc_only` | 1 |
| `attack_rug_pull_send_email_v4_version_only` | 1 |
| `attack_credential_exfil_sandbox_bait_v02`..`v05` | 1 each (4 total) |

The last group is a previously-documented, unrelated finding, not a rug-pull
attack: `docs/PHASE5-REPORT.md`'s "unintended cross-scenario drift" —
`lab/baseline/watch.py` doesn't know or care what scenario it's watching, and
these credential-exfil sessions happen to reuse a tool identity whose schema
varies across variants, which the watcher correctly (if incidentally) flags
as drift. Included here verbatim, not filtered out, for the same reason the
original report didn't hide it.

## What this reproduces

This is the exact input `lab/analysis/report.py`'s `load_inputs()` fetches live
from the Docker volume (`AGENT_SERVICE`'s `/var/log/mcp-detect/telemetry.jsonl`
filtered to `label=="malicious"`, plus `rugpull_alerts.jsonl` verbatim) —
freezing it here is capturing what was already driving every recall/FP
number in `docs/PHASE4-REPORT.md`, not a new measurement. Combined with
`data/benign_corpus_v2.jsonl` (already public) and this file's golden
`wazuh-logtest` matches, `framework/repro_offline.py --tier full` reproduces
`docs/PHASE4-REPORT.md`'s exact numbers (12/12, 11/11, 11/11, 3/3 recall,
0/4,727 FP) fully offline — see `REPRO-VERIFICATION.md` at the repo root.

## Licensing

This synthetic corpus is included under the repository's MIT license. It
contains no customer traffic or independently sourced production data.

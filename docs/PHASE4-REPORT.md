<!-- GENERATED FILE -- produced by analysis/report.py. Do not hand-edit; re-run `python3 analysis/report.py` to update. -->
# Phase 4 Report — Detector Performance

## Provenance

- Generator: `mcp-detect-analysis-report/1.0`
- `wazuh/local_rules.xml` sha256 (verified byte-identical to the live manager's loaded rule file before this report was generated): `e97bac148ade79bcd690abcbf5852ff74c503917658f5f3d255392b41886bdda`
- Wazuh version: `v4.9.0`
- Inputs: `data/benign_corpus_v2.jsonl` (4727 records, 541 sessions, 1011 tool-call events); canonical `telemetry.jsonl` filtered to `label=malicious` (266 records); canonical `rugpull_alerts.jsonl` (8 records)
- No wall-clock timestamp is embedded above or anywhere else in this report: every field on this line is a deterministic function of the inputs (rule file contents, Wazuh version, input record counts), so re-running this tool against unchanged inputs produces a byte-identical report -- an intentional choice for `git diff`-friendliness (docs/PHASE4-DESIGN.md, sign-off item B), not an oversight.
- scenario_id/task_id cross-check: passed (every record sharing a `primary_session_id` agrees on `scenario_id` and `task_id`).

## Executive summary

**False positives: 0/4727 (0%) benign records triggered any alert** (541 benign sessions, the full frozen `benign_corpus_v2` corpus). This number is honestly aggregated across every rule (`100101`–`100107`, `100102`, `100201`) because "did this benign record trigger anything" means the same thing regardless of which rule would have fired — unlike recall, whose denominator differs by technique (see below), a false positive is a false positive regardless of which rule almost fired. **Caveat carried inline, not buried**: this aggregate is real for the content/path rules (`100101`–`107`, `100102`) but structurally weaker for the rug-pull rule (`100201`) — see "Rug pull" below for why zero drift on a corpus with zero legitimate version changes is a narrower claim than zero drift would be on a corpus that actually exercised version bumps.

**Recall is reported strictly per-technique below, never blended into one number.** The three techniques don't share a denominator (different attack-session counts), and don't even share what "a false negative" would mean (a missed content match vs. a missed baseline-drift event) — collapsing them into one precision/recall/F1 figure would itself be a laundering step, manufacturing false precision this project has been careful not to overclaim elsewhere.

## Tool poisoning (SAF-T1001) — rule `100102`

Recall: **12/12 (100%)** self-authored task_ids (1 original + variants) produced a `100102` alert.

False positives: **0/541 (0%)** benign `tools/list` responses (one per session).

**Honesty boundary, restated from `docs/PHASE3A-DESIGN.md`**: these are self-authored variants (different cover-tool identity, different directive wording) — this demonstrates the harness/server plumbing reliably reproduces poisoned-description telemetry across wording, not that the rule generalizes to independently-authored or adversarial phrasing (stealthy Unicode/homoglyph obfuscation is explicitly out of scope, named since Phase 2).

## Credential exfiltration (SAF-T1502 read hop + SAF-T1910 exfil hop)

Read-hop recall (`100101`): **11/11 (100%)** task_ids (robust across all 4 bait-path representations tested, per `docs/PHASE3A-DESIGN.md`).

Exfil-hop recall, rule family `100103`–`100107` (any of the 5 fires): **11/11 (100%)** task_ids.

Per-rule breakdown within the exfil-hop family (FP denominator: 1011 benign tool-call events):

| rule | argument key | benign FP |
|---|---|---|
| `100103` | `data` | 0/1011 (0%) |
| `100104` | `payload` | 0/1011 (0%) |
| `100105` | `content` | 0/1011 (0%) |
| `100106` | `body` | 0/1011 (0%) |
| `100107` | `message` | 0/1011 (0%) |

False positives, read hop (`100101`): **0/1011 (0%)** benign tool-call events.

**Honesty boundary, restated from `docs/PHASE3A-DESIGN.md`**: `100103`–`107`'s recall is bounded to the 5 argument-key names actually tested (`data`/`payload`/`content`/`body`/`message`) — a 6th, unobserved key name would still slip past this rule family by construction (Wazuh's rule DSL has no wildcard-field-name match). This is measured recall against a *named* blind spot, not a claim the family is exhaustive.

## Rug pull (SAF-T1201) — persistent baseline drift, rule `100201`

Of 4 total rug-pull task_ids observed: **1 baseline-setting task_id(s)** (attack_rug_pull_send_email_v1_baseline) correctly produced **zero** alerts — this is expected, not a miss: these sessions establish the baseline a later session's drift is measured against, per `docs/PHASE3B-DESIGN.md`.

Of the remaining **3 task_ids expected to show drift**, **3/3 (100%)** produced at least one `100201` alert (description-only, version-only, and both-drift shapes all measured separately, per `docs/PHASE3B-DESIGN.md`).

| task_id | drift field(s) alerted |
|---|---|
| `attack_rug_pull_send_email_v2_pulled` | 100201 |
| `attack_rug_pull_send_email_v3_desc_only` | 100201 |
| `attack_rug_pull_send_email_v4_version_only` | 100201 |

False positives: **0/4727 (0%)** benign records (full corpus — `100201` isn't scoped to one record type the way the content rules are).

**This "0 FP" is a structurally weaker claim than the content rules' above, restated plainly rather than presented as equivalent** (`docs/PHASE3B-DESIGN.md`): the content/path rules' 0 FP means the benign corpus never contains that attack-shaped *content*, true regardless of how the benign fleet evolves. This rule's 0 FP means the frozen corpus's pinned server versions never change during the recording — true by construction (Phase 1b froze it) and known before a single record was measured. No benign fixture in this corpus exercises the actual case this detector needs to distinguish: a *legitimate* version bump. Recall here (measured on real drift shapes, three separately) is on firmer footing than this FP number is.

### Cross-scenario rule firings (found, not hidden)

- Rule `100201` (nominally rug_pull (baseline drift)) fired on task_ids across **2 distinct scenario_ids** — stated neutrally rather than presuming which one is the rule's "real" scenario, since the larger count below (`credential_exfil_via_read`) is not the scenario this rule's own group tag names:
  - `credential_exfil_via_read` (4 task_ids): attack_credential_exfil_sandbox_bait_v02, attack_credential_exfil_sandbox_bait_v03, attack_credential_exfil_sandbox_bait_v04, attack_credential_exfil_sandbox_bait_v05
  - `rug_pull` (3 task_ids): attack_rug_pull_send_email_v2_pulled, attack_rug_pull_send_email_v3_desc_only, attack_rug_pull_send_email_v4_version_only

**Explanation, per `docs/PHASE3B-DESIGN.md`**: `attacks/servers/exfil_sink_server.py` (3a's credential-exfil sink) names its `exfiltrate` tool's `inputSchema` property after an env var (`data`/`payload`/`content`/`body`/`message`, used to test `100103`'s key-name scope limit) while its `server_command` stays identical across every variant — so the tool's declared schema genuinely, correctly differs across those sessions. The rug-pull detector is behaving exactly as designed (real schema drift, correctly detected); the scenario label is what's misleading if skimmed. **True positives for the rug-pull technique remain 3/3 (100%)** — these firings belong to a different scenario's own task_ids, not a rug-pull miss or extra credit.

## Coverage map

| technique | rule(s) | status |
|---|---|---|
| Tool poisoning (SAF-T1001) | `100102` | HTML-comment obfuscation only; 12/12 (100%) recall, 0/541 (0%) FP |
| Credential exfil, read hop (SAF-T1502) | `100101` | 11/11 (100%) recall, 0/1011 (0%) FP |
| Credential exfil, exfil hop (SAF-T1910) | `100103`–`100107` | 11/11 (100%) recall (5 tested key names, not exhaustive), 0 FP |
| Rug pull (SAF-T1201) | `100200`/`100201` | 3/3 (100%) recall across 3 drift shapes, weaker FP claim (see above) |

`git_show`: no rule in this ruleset keys on it, consistent with `docs/WAZUH-NOTES.md` constraint 1 (zero benign denominator, a confirmed, accepted gap).

## Worked example — one real attack, reconstructed

Generated by this tool's secondary mode (`python3 analysis/report.py --task-id attack_credential_exfil_sandbox_bait`), embedded here so the numbers above are legible as an actual attack, not just tables. This is the *original* Phase 2 credential-exfiltration attack: one task_id spanning **two** session_ids (a read-session against the real filesystem server, and a separate exfil-session against the malicious `exfiltrate` tool) — exactly the multi-session-per-task_id shape `docs/PHASE4-DESIGN.md`'s join design accounts for.

| session_id | timestamp | method | tool_name | matched rule |
|---|---|---|---|---|
| 7d8dd3c8 | 2026-07-08T20:28:08.116Z | initialize |  | 100100 |
| 7d8dd3c8 | 2026-07-08T20:28:09.402Z | (response) |  | 100100 |
| 7d8dd3c8 | 2026-07-08T20:28:09.403Z | notifications/initialized |  | 100100 |
| 7d8dd3c8 | 2026-07-08T20:28:09.403Z | tools/list |  | 100100 |
| 7d8dd3c8 | 2026-07-08T20:28:09.408Z | (response) |  | 100100 |
| 7d8dd3c8 | 2026-07-08T20:28:09.409Z | tools/call | read_text_file | **100101** |
| 7d8dd3c8 | 2026-07-08T20:28:09.411Z | (response) |  | 100100 |
| 1ab2bed5 | 2026-07-08T20:28:09.472Z | initialize |  | 100100 |
| 1ab2bed5 | 2026-07-08T20:28:09.715Z | (response) |  | 100100 |
| 1ab2bed5 | 2026-07-08T20:28:09.715Z | notifications/initialized |  | 100100 |
| 1ab2bed5 | 2026-07-08T20:28:09.715Z | tools/list |  | 100100 |
| 1ab2bed5 | 2026-07-08T20:28:09.716Z | (response) |  | 100100 |
| 1ab2bed5 | 2026-07-08T20:28:09.717Z | tools/call | exfiltrate | **100103** |
| 1ab2bed5 | 2026-07-08T20:28:09.756Z | (response) |  | 100100 |

Read the timeline in wall-clock order (not grouped by session): the read-session's `read_text_file(.env)` call is the record that trips `100101` (the path-based read signal); the separate exfil-session's `exfiltrate(...)` call — a *different* tool, on a *different* server, in a *different* session_id, opened only after the read-session's own tool call had already completed — trips `100103` (the content-based exfil signal) 0.308 seconds later. Two independent signals on two different records in two sequential sessions (the read session runs fully to completion before the exfil session even connects), joined back to one logical attack via a shared `task_id`, the reason `docs/PHASE2-DESIGN.md` designed the labeling this way in the first place.

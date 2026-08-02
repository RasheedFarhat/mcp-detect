# MCP & Agent Security Assessment

**Generated**: 2026-07-12T08:14:21.153Z (`mcp-detect-audit-report/1.0`)
**Client telemetry**: `northwindpay/telemetry.jsonl` (sha256 `1c2e9d516aceece7...`, 4046 records)
**Live-engine measurement this run**: yes -- reproduction/evasion numbers below are freshly re-verified

## 1. Executive summary

- **12 MCP servers, 43 distinct tool entries, 538 sessions** observed in the client telemetry export.
- **1 shadow-server candidate(s)** (`python3 /opt/northwindpay/shadow-tools/mcp-crm-lite/server.py`) against the supplied known-good BOM.
- **4 finding(s) from a real scan of your telemetry** (Section 3) -- structural rule-matching and rug-pull baseline-drift detection run directly against your supplied data, not just our own fixtures.
- **5/10 OWASP MCP Top 10 categories** have at least one mapped detection in this project's detection-content pack (Section 4) -- a statement about our content, not a scan finding about this client's environment.
- **Adversarial evasion testing** (this run, live-verified): 18 genuine evasion attempts across all techniques, **3 caught / 15 evaded**. Every shipped detection has been red-teamed against its own evasion corpus; this report states what evades, not just what's caught -- see Section 5.

## 2. AI Bill of Materials (your environment)

Built directly from the supplied client telemetry export -- this section is a statement about *your* environment. **This inventory is advertised-surface-complete**: every tool a server's `tools/list` response advertises appears below, distinguishing advertised-and-called (with a call count) from advertised-but-never-invoked (call count 0) -- not merely the tools observed being called. See Section 6 for the one residual bound on this (a server whose `tools/list` response was never captured at all contributes nothing).

**12 servers, 43 distinct tools, 538 sessions observed.**

| server_command | trust boundary | sessions | tools | version hash(es) |
|---|---|---|---|---|
| `mcp-server-fetch` | network egress -- can reach arbitrary URLs | 30 | 1 | 1 |
| `mcp-server-git --repository /app/workspace` | git repository (read-write) | 30 | 3 | 1 |
| `mcp-server-time` | pure compute (no data access) | 20 | 1 | 1 |
| `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /app/sandbox` | filesystem (read-write mount, confirmed -- an observed write-capable call succeeded) | 70 | 9 | 1 |
| `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /app/workspace` | filesystem (read-only mount, confirmed -- an observed write-capable call was denied) | 152 | 9 | 1 |
| `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /data/production-ledger` | filesystem (read-write mount, confirmed -- an observed write-capable call succeeded) | 41 | 9 | 1 |
| `npx -y @modelcontextprotocol/server-memory@2026.7.4` | local memory store (no filesystem/network) | 20 | 3 | 1 |
| `python3 /opt/northwindpay/mcp-servers/expense-ocr/server.py` | unknown -- needs manual classification | 40 | 1 | 1 |
| `python3 /opt/northwindpay/mcp-servers/fx-rates/server.py` | unknown -- needs manual classification | 30 | 1 | 2 |
| `python3 /opt/northwindpay/mcp-servers/slack-connector/server.py` | unknown -- needs manual classification | 65 | 3 | 1 |
| `python3 /opt/northwindpay/mcp-servers/support-ticket-bot/server.py` | unknown -- needs manual classification | 32 | 2 | 1 |
| `python3 /opt/northwindpay/shadow-tools/mcp-crm-lite/server.py` | **SHADOW CANDIDATE** -- unknown -- needs manual classification | 8 | 1 | 1 |

### `mcp-server-fetch`

Trust boundary: **network egress -- can reach arbitrary URLs** (filesystem: None, network egress: True)

| tool | calls | description hash(es) |
|---|---|---|
| `fetch` | 30 | 1 distinct |

### `mcp-server-git --repository /app/workspace`

Trust boundary: **git repository (read-write)** (filesystem: rw, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `git_diff` | 0 | 1 distinct |
| `git_log` | 30 | 1 distinct |
| `git_status` | 30 | 1 distinct |

### `mcp-server-time`

Trust boundary: **pure compute (no data access)** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `get_current_time` | 20 | 1 distinct |

### `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /app/sandbox`

Trust boundary: **filesystem (read-write mount, confirmed -- an observed write-capable call succeeded)** (filesystem: rw, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `create_directory` | 0 | 1 distinct |
| `directory_tree` | 0 | 1 distinct |
| `edit_file` | 0 | 1 distinct |
| `get_file_info` | 0 | 1 distinct |
| `list_allowed_directories` | 0 | 1 distinct |
| `list_directory` | 0 | 1 distinct |
| `read_text_file` | 20 | 1 distinct |
| `search_files` | 0 | 1 distinct |
| `write_file` | 50 | 1 distinct |

### `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /app/workspace`

Trust boundary: **filesystem (read-only mount, confirmed -- an observed write-capable call was denied)** (filesystem: ro, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `create_directory` | 0 | 1 distinct |
| `directory_tree` | 20 | 1 distinct |
| `edit_file` | 15 | 1 distinct |
| `get_file_info` | 20 | 1 distinct |
| `list_allowed_directories` | 10 | 1 distinct |
| `list_directory` | 40 | 1 distinct |
| `read_text_file` | 63 | 1 distinct |
| `search_files` | 44 | 1 distinct |
| `write_file` | 0 | 1 distinct |

### `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /data/production-ledger`

Trust boundary: **filesystem (read-write mount, confirmed -- an observed write-capable call succeeded)** (filesystem: rw, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `create_directory` | 0 | 1 distinct |
| `directory_tree` | 0 | 1 distinct |
| `edit_file` | 0 | 1 distinct |
| `get_file_info` | 0 | 1 distinct |
| `list_allowed_directories` | 0 | 1 distinct |
| `list_directory` | 0 | 1 distinct |
| `read_text_file` | 36 | 1 distinct |
| `search_files` | 0 | 1 distinct |
| `write_file` | 5 | 1 distinct |

### `npx -y @modelcontextprotocol/server-memory@2026.7.4`

Trust boundary: **local memory store (no filesystem/network)** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `add_observations` | 20 | 1 distinct |
| `create_entities` | 20 | 1 distinct |
| `create_relations` | 0 | 1 distinct |

### `python3 /opt/northwindpay/mcp-servers/expense-ocr/server.py`

Trust boundary: **unknown -- needs manual classification** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `parse_receipt` | 40 | 1 distinct |

### `python3 /opt/northwindpay/mcp-servers/fx-rates/server.py`

Trust boundary: **unknown -- needs manual classification** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `get_rate` | 30 | 1 distinct |

### `python3 /opt/northwindpay/mcp-servers/slack-connector/server.py`

Trust boundary: **unknown -- needs manual classification** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `archive_channel` | 2 | 1 distinct |
| `list_channels` | 62 | 1 distinct |
| `post_message` | 1 | 1 distinct |

### `python3 /opt/northwindpay/mcp-servers/support-ticket-bot/server.py`

Trust boundary: **unknown -- needs manual classification** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `attach_note` | 32 | 1 distinct |
| `create_ticket` | 30 | 1 distinct |

### `python3 /opt/northwindpay/shadow-tools/mcp-crm-lite/server.py`

Trust boundary: **unknown -- needs manual classification** (filesystem: None, network egress: False)

| tool | calls | description hash(es) |
|---|---|---|
| `lookup_customer` | 8 | 1 distinct |

### Shadow-server candidates (MCP09)

- `python3 /opt/northwindpay/shadow-tools/mcp-crm-lite/server.py`

## 3. Findings in your environment

Every row below is a real match from the actual detection engine (`wazuh-logtest`) run directly against **your supplied telemetry** -- not a statement about our own fixtures (that is Section 5). Structural rule-matching and the rug-pull baseline-drift detector both reuse the exact, already-tested code paths `framework/coverage.py` uses for our own corpora (`framework/structural.run_batch`, `framework/registry.run_stateful_stage`, `framework/alerts.normalize_and_join`) -- no new detection logic. Repeated hits of the same underlying issue (e.g. a poisoned tool description observed across many sessions) are grouped into one row with an occurrence count -- nothing is dropped, only de-duplicated for readability.

**4 distinct issue(s)** (43 alerting record(s) total) across 4 registered techniques, plus 1 low-severity baseline-drift observation(s) (see note below).

| Technique | Rule | Server / tool | Occurrences | First seen | Last seen | Evidence |
|---|---|---|---|---|---|---|
| SAF-T1001 | `100102` | `python3 /opt/northwindpay/mcp-servers/expense-ocr/server.py` | 40 | 2026-06-01T20:00:00.600Z | 2026-06-01T23:08:41.550Z | tools/list response for `python3 /opt/northwindpay/mcp-servers/expense-ocr/server.py` |
| SAF-T1105 | `100108` | `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /app/workspace` / `read_text_file` | 1 | 2026-06-02T02:02:57.300Z | 2026-06-02T02:02:57.300Z | tool=`read_text_file` path=`../../../etc/hosts` |
| SAF-T1502 | `100101` | `npx -y @modelcontextprotocol/server-filesystem@2026.7.4 /data/production-ledger` / `read_text_file` | 1 | 2026-06-02T02:41:42.750Z | 2026-06-02T02:41:42.750Z | tool=`read_text_file` sensitive-suffix path read (value withheld) |
| SAF-T1502 | `100105` | `python3 /opt/northwindpay/mcp-servers/support-ticket-bot/server.py` / `attach_note` | 1 | 2026-06-02T02:42:41.250Z | 2026-06-02T02:42:41.250Z | tool=`attach_note` secret-shaped content in argument `content` (value withheld) |

**Baseline drift, version-only (reduced severity, not counted in the finding total above):**

| Server | Occurrences | First seen | Last seen | Evidence |
|---|---|---|---|---|
| `python3 /opt/northwindpay/mcp-servers/fx-rates/server.py` | 1 | 2026-06-01T23:21:21.150Z | 2026-06-01T23:21:21.150Z | tool=`None` server=`python3 /opt/northwindpay/mcp-servers/fx-rates/server.py` drift_field=`server_version_hash` |
- These are real, TOFU-baseline-confirmed drift events (rule `100201` fired) where only `server_version_hash` changed and the tool's advertised description/schema (`tool_description_hash`) did not -- consistent with a routine version bump, not necessarily distinguishable from one. See Section 6's note on SAF-T1201 known gap E10 for the residual bound on this.


## 4. OWASP MCP Top 10 -- Detection-Content Coverage (this framework, not a finding about your environment)

**This table describes what our detection-content pack currently covers against the OWASP MCP Top 10 taxonomy. It is a statement about our rules, not a scan result about your environment.** Cross-reference against Section 2's AI-BOM and Section 3's findings to see which of your servers/tools these detections actually apply to.

Registry-driven, generated from each `detection.yaml`'s `owasp_mcp` field; no live stack needed. A category with no mapped detection is rendered **NONE**, not omitted. Every mapped category is **PARTIAL** by policy -- no category is at held-out/production confidence (recall is measured against self-authored variants; see PHASE4-REPORT.md). Read `status` + `known_gaps` for per-detection depth.

**5/10 categories have at least one mapped detection.**

| OWASP | Category | Coverage | Detections (status) | Known gaps |
|---|---|---|---|---|
| MCP01 | Token/credential mismanagement | PARTIAL | SAF-T1502 `deployed` | 5 |
| MCP02 | Privilege escalation / scope creep | NONE | _no detection maps to this category_ | — |
| MCP03 | Tool poisoning (rug pull, schema poisoning, tool shadowing) | PARTIAL | SAF-T1001 `deployed`; SAF-T1201 `deployed` | 6 |
| MCP04 | Supply chain | PARTIAL | SAF-T1001 `deployed`; SAF-T1201 `deployed` | 6 |
| MCP05 | Command injection | NONE | _no detection maps to this category_ | — |
| MCP06 | Intent-flow subversion / prompt injection | PARTIAL | SAF-T1001 `deployed` | 4 |
| MCP07 | Insufficient authentication | NONE | _no detection maps to this category_ | — |
| MCP08 | Weak telemetry/logging | NONE | control-not-detection: the proxy + telemetry schema mitigate this category as a logging capability; no rule detects it | — |
| MCP09 | Shadow MCP servers | NONE | capability-not-Detection: framework/abom.py --known-good diffs observed server_commands against a client BOM (shadow-server candidates); not a registered Detection, no wazuh_rule backend, no measured recall/FP | — |
| MCP10 | Context over-sharing | PARTIAL | SAF-T1105 `validated`; SAF-T1502 `deployed` | 13 |

## 5. Detection coverage & adversarial evasion testing

**Numbers below are reported as reproduction coverage and evasion-tested outcomes, never as "precision/recall."** Reproduction counts are measured against this project's own self-authored attack variants, not independent or held-out ones -- see the caveat in Section 6. Evasion results are labels only (caught / EVADED / control probe) computed by re-running the real detection engine against our own frozen, public adversarial-evasion corpus -- inspect data/evasion_corpus_v1.jsonl and the registered known gaps for the underlying fixtures.

| Technique | OWASP | Status | Known gaps declared | Reproduction coverage (self-authored) | Evasion testing |
|---|---|---|---|---|---|
| SAF-T1001 (`tool_poisoning_html_comment`) | MCP03, MCP04, MCP06 | `deployed` | 4 | tool_poisoning_html_comment 12/12 | 5 tested -- 1 caught / 4 evaded |
| SAF-T1105 (`path_traversal`) | MCP10 | `validated` | 8 | path_traversal 6/8 | 6 tested -- 1 caught / 5 evaded |
| SAF-T1201 (`rug_pull_baseline_drift`) | MCP03, MCP04 | `deployed` | 2 | rug_pull_baseline_drift 3/3 | 3 tested -- 1 caught / 1 evaded, 1 control probe(s) |
| SAF-T1502 (`credential_exfil`) | MCP01, MCP10 | `deployed` | 5 | read_hop 11/11; exfil_hop 11/11 | 5 tested -- 0 caught / 5 evaded |

## 6. Limitations of this assessment

- **The AI-BOM (Section 2) is advertised-surface-complete, not called-only**: `framework/abom.py`'s `build_bom()` ingests each session's `tools/list` response (`raw.result.tools`) alongside `tools/call` records, so a tool a server advertises but never has invoked during the capture window still appears, with a call count of 0 -- previously a real, disclosed gap, now fixed (`docs/STATE-OF-PROJECT.md`). **One residual bound remains, structurally, not by choice**: a tool is only listed if some session in the supplied export actually captured its server's `tools/list` response -- a server never queried for its tool list during the capture window contributes nothing to this section, the same bound any inventory built from observed traffic has.
- **Section 3's findings are a real scan of your own telemetry, but only for the 4 registered techniques in Section 5's table** -- this is not a general-purpose anomaly detector; anything outside those techniques' scope produces no finding, flagged or not, by construction.
- **SAF-T1201 (rug pull) known gap E10, partially triaged, not eliminated**: a routine server-version bump and a genuine rug pull both start as TOFU baseline drift with no allowlist/re-baseline mechanism. Section 3 now severity-tiers this using the already-emitted `drift_field` (a tool's advertised description/schema changing is reported as a finding; a version-string-only change is reported separately at reduced severity) -- this reduces false alarms on ordinary version bumps but does NOT eliminate the underlying gap: an attacker who changes only the version string while hiding a real behavior change elsewhere would still surface only as a low-severity observation, not a headline finding.
- **Reproduction coverage is measured against self-authored attack variants** (this project's own harnesses), not independent or third-party-authored attack traffic. It demonstrates that a technique's telemetry shape is reliably detected across wording/argument variation, not that detection generalizes to arbitrary independently-authored or adversarial phrasing -- evasion testing (Section 5) is the honest complement to this, not a replacement for it.
- **The benign false-positive baseline is a single-model, single-lab corpus** (qwen3:1.7b, 6 MCP servers, 20 distinct tools, 4,727 records) -- a 0% measured FP rate on that corpus does not automatically transfer to a heterogeneous client fleet with different servers, tools, or usage patterns.
- **Structural (Wazuh rule) is the only mature detection backend.** One technique (rug pull) uses an external stateful detector; a semantic backend for prompt-injection/intent-flow subversion (OWASP MCP06) is designed but not implemented, so MCP06 coverage above is narrower than the category name implies.
- **5/10 OWASP MCP Top 10 categories are mapped at all**, and every mapped category is reported as PARTIAL by policy -- no category is claimed at held-out/production confidence.
- **The labeled adversarial-evasion corpus is synthetic and public**, Section 5 shows aggregate outcome labels and the repository contains the underlying fixtures.

### 6a. Declared known gaps (detail)

Every bullet below is this project's own registered `known_gaps` prose (per technique, from each `detection.yaml`) -- the specific, named blind spots behind the counts in Section 5's table, reused verbatim from `framework/coverage.py`'s `render_gaps_report()`.

| technique | name | status | known_gaps |
|---|---|---|---|
| SAF-T1001 | tool_poisoning_html_comment | deployed | 4 |
| SAF-T1105 | path_traversal | validated | 8 |
| SAF-T1201 | rug_pull_baseline_drift | deployed | 2 |
| SAF-T1502 | credential_exfil | deployed | 5 |

### SAF-T1001 -- tool_poisoning_html_comment (`status: deployed`)

- Keyword-avoiding phrasing (E1) -- not fixable without an open-ended list
- No-HTML-comment obfuscation (E2)
- Homoglyph substitution (E3b) -- deliberately not chased, same reason as E1
- Padding past the 120-char proximity bound (E4)

### SAF-T1105 -- path_traversal (`status: validated`)

- Tool-name spoofing evades this rule -- CONFIRMED via real wazuh-logtest (attack_evasion_e1_toolname_spoof, attacks/path_traversal_evasion_harness.py): a tool named 'search_files' performing an actual traversal read (path=../../../etc/passwd) is negate-excluded and produces no alert (final match: 100100). Same class E5 already proved for 100103-100107's own negate-list (docs/PHASE5-REPORT.md). Not fixed this round -- the negate-list is what closed a real, measured 20/4727 benign FP (search_files' legitimate navigation), and narrowing it further would reopen that FP.
- URL-encoded traversal evades -- CONFIRMED (attack_evasion_e2_url_encoded, path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd -> 100100, no alert). Upstream's own Attack Vector #3. Structurally the same open-ended-list problem this project has refused to chase for tool-poisoning keywords -- not fixed, named.
- Unicode normalization bypass evades -- CONFIRMED (attack_evasion_e3_unicode_normalization, path=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd -> 100100, no alert). Upstream's own Attack Vector #2. Same class of gap as 100102's homoglyph limitation, not chased for the same reason.
- Double-encoded traversal evades -- CONFIRMED (attack_evasion_e4_double_encoded, path=%252e%252e%252f%252e%252e%252fetc%252fpasswd -> 100100, no alert). Upstream's own Attack Vector #3.
- Null-byte injection is CAUGHT, not evaded -- CONFIRMED (attack_evasion_e5_null_byte, path=../../../etc/passwd%00 -> 100108, alert fires). Resolved from 'unverified' to measured: the literal '../' is still present in this construction, and the rule matches it regardless of the trailing null byte. Upstream's own Attack Vector #4 -- named as a bypass class upstream, but this project's own measurement shows this specific construction does not evade 100108.
- Absolute-path access without any '../' evades -- CONFIRMED (attack_evasion_e6_absolute_path_no_dots, path=/etc/passwd -> 100100, no alert). Structurally invisible to this rule by construction -- this rule matches the traversal MECHANISM, not arbitrary sensitive-path access.
- Symlink indirection (a benign-looking path that resolves through a symlink to a sensitive target outside the intended root) leaves no traversal sequence in the argument at all -- structurally invisible to an argument-text-matching rule regardless of pattern richness. Not separately measured this round -- no symlink fixture authored (would require a stateful filesystem setup step, not just a tool-call argument), named as still-unverified rather than assumed.
- Case manipulation (case-sensitive filesystem exploitation) -- UNTESTED, not merely unclaimed: upstream's own Attack Vector #5 (SAF-T1105 README). docs/PHASE6-T1105-REPORT.md previously and inaccurately claimed this vector 'became this detection's known_gaps' at build time; it did not -- confirmed absent from this list, the evasion corpus, and data/evasion_corpus_v1.jsonl until this correction (SAF-MCP drift check, 2026-07-11). One-line mechanical reasoning, not a measurement: rule 100108 matches the literal '../'/'..\\' traversal sequence itself, which case manipulation of the target path's casing does not remove, so this plausibly does not evade the rule -- but no fixture was ever authored to measure it, and it is named here as untested, not assumed caught.

### SAF-T1201 -- rug_pull_baseline_drift (`status: deployed`)

- Legitimate version bumps fire indistinguishably from an attack (E10) -- no allowlist/re-baseline mechanism exists; operationally close to unusable in any environment with routine version bumps
- Behavior-only rug pulls with no advertised-metadata change are structurally invisible (E11) -- not fixable within this architecture, no field in MCP's protocol surface exposes runtime behavior for hashing

### SAF-T1502 -- credential_exfil (`status: deployed`)

- Tool-name spoofing evades the exfil-hop negate-list (E5) -- confirmed structurally unfixable inside Wazuh's classic rule DSL (negate-on-absent-field gate)
- 6th, untested argument key name evades the exfil-hop family by construction (E6) -- Wazuh has no wildcard-field-name match
- Secret formats outside the 6 named shapes evade the exfil-hop regex (E7)
- Base64-encoded payload evades the exfil-hop literal-string match (E8)
- Renamed read path (e.g. .env.bak) evades the read-hop rule specifically (E9) -- exfil-hop signal (100103-107) still catches the attack overall if the content is later exfiltrated unencoded

## 7. Methodology

This report reuses, without modification: `framework/coverage.py`'s `render_owasp_map()`, `build_coverage_table()`, `build_evasion_verdicts()`, and `render_gaps_report()`; `framework/abom.py`'s `build_bom()` and `diff_shadow_servers()`; `framework/registry.py`'s `load_registry()` and `run_stateful_stage()`; `framework/structural.py`'s `run_batch()`; `framework/alerts.py`'s `normalize_and_join()`. All rule-matching goes through the real Wazuh engine (`wazuh-logtest`), never a Python reimplementation. Section 3 is the one section that runs this same engine against **your** telemetry directly (everything else in Sections 4-5 measures our own fixtures).

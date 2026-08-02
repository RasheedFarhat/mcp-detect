<!-- GENERATED FILE -- produced by analysis/evasion_report.py. Do not hand-edit; re-run `python3 analysis/evasion_report.py` to update. -->
# Phase 5 Report — Adversarial Evasion Testing

## Provenance

- Generator: `mcp-detect-analysis-evasion-report/1.0`
- `wazuh/local_rules.xml` sha256 (verified byte-identical to the live manager's loaded rule file): `fdae757605f6044fd610ffd08833944bba115151dd62cccdebe7d1ab43ed6f5a`
- Wazuh version: `v4.9.0`
- Inputs: full Phase 4 regression set (4727 benign records) plus `data/evasion_corpus_v1.jsonl` (154 records, 17 task_ids across 12 evasion classes)
- Regression: **0/4727** benign records alerted (no regression)
- No wall-clock timestamp embedded, same reasoning as `docs/PHASE4-REPORT.md`.

## Executive summary

**This report's success condition is finding gaps, not avoiding them.** **10 of 12 true evasion attempts succeed against the rule set as it currently stands** (E1-E9, E11, E12 — E10 is a false-positive probe, not an evasion attempt, reported separately below): attack_evasion_e1_keyword_avoiding, attack_evasion_e2_no_html_comment, attack_evasion_e3b_homoglyph, attack_evasion_e4_distance_bound, attack_evasion_e5_toolname_spoof, attack_evasion_e6_untested_key, attack_evasion_e7_secret_shape, attack_evasion_e8_encoded_payload, attack_evasion_e9_read_path, attack_evasion_e11_behavior_only. One of these (E3a) was originally a successful evasion too, closed by a hardening fix applied during this same round -- see "What happened during this round" below for the full sequence, including a proposed fix for a different class (E5) that was tested and rejected, not silently dropped. **"E3a now caught" is not "the class is closed"** -- the fix was validated against exactly one Format-category character plus the existing corpus, and every other codepoint in that category is a prediction from the pattern's structure, not a measurement (full caveat below). These are real gaps in the current ruleset, stated plainly, not softened into another set of caveated 100% tables.

## What happened during this round, in order

1. **First measurement (pre-hardening)**: all 12 evasion classes run against the rule set as it stood at the start of Phase 5. Result: 11 of 12 true evasion attempts succeeded, including **both** E3 sub-cases (E3a zero-width insertion, E3b homoglyph substitution) against `100102`.
2. **E3 investigated**: confirmed via `wazuh-logtest` that Wazuh's PCRE2 build supports `(*UTF)(*UCP)` mode and `\p{Cf}` (Unicode category "Format" -- zero-width/invisible characters) *before* writing anything. Hardened `100102`'s keyword alternation to tolerate `\p{Cf}*` between every letter of every keyword -- a genuine generalization (defeats any insertion of any Format-category character, not the one specimen E3a used), confirmed via `wazuh-logtest` to **not** also match E3b's homoglyph substitution (`\p{Cf}` doesn't touch printable characters), and confirmed via full-corpus batch `wazuh-logtest` to introduce **zero** new benign false positives (4727/4727 still land on `100100` only) and **zero** regressions on any other rule's canonical recall count.

   **This fix's own honesty boundary, stated as plainly as the original attacks' -- do not read "E3a now caught" as "the class is closed":** the `\p{Cf}` generalization was validated against exactly ONE Format-category character (U+200B, the zero-width space E3a happened to use) plus the full existing corpus. It was never tested against any of the dozens of other codepoints in the same Unicode category (zero-width joiner U+200D, zero-width non-joiner U+200C, word joiner U+2060, BOM U+FEFF, and more). The pattern's own construction (`\p{Cf}*` -- the whole category, not one enumerated codepoint) gives good reason to *predict* those would also be caught, but that is a prediction from the regex's structure, not a measurement -- no session in this corpus exercises them. This is the exact same "self-authored variant" limit `docs/PHASE3A-DESIGN.md` and `docs/PHASE4-REPORT.md` already named for the original attacks, now applied to this round's own fix rather than to an attack.
3. **E3 installed live** (`docker compose stop`/`up`; see "Restart budget, clarified" below for what that tracking actually means). E3a now reflects "caught" in the tables below; E3b remains an accepted, documented gap (see the Tool Poisoning section) -- enumerating homoglyph-equivalence classes would be the same open-ended whack-a-mole as E1's keyword list, not a genuine fix.
4. **E5 investigated, per your explicit instruction to prove the gate before proposing anything**: the candidate fix (negate on `tool_arguments.path`'s *absence* instead of `tool_name`) was tested via `wazuh-logtest -v` against E5's own true positive (the spoofed call, which has no `path` key at all) *before* anything else. **Unambiguous result, stated precisely so "failed" isn't read as "inconclusive"**: the test itself ran cleanly to completion, no error -- the verbose trace shows `Trying rule: <candidate>` (the engine reached and evaluated the candidate rule) followed by a final matched rule of `100100` (the no-alert parent). That is a definitive negative result: with this fix installed, E5's actual malicious call would **not** alert. The fix does not work; the test that proved it worked correctly and completely. This confirms the exact negate-on-absent-field landmine `docs/PHASE3A-DESIGN.md` already found once for `100103`'s own first draft. No known construction in Wazuh's classic rule DSL expresses "fire unless a sensitive path argument is present" without hitting this same wall. **E5 stays document-only.** This is the finding your sign-off asked to be flagged rather than quietly worked around -- flagged here, not routed past.

**The recursion applies to this round's own hardening too, not just the original attacks**: E3's fix is validated against exactly the two E3 specimens this round authored (zero-width insertion, one homoglyph substitution) plus the full existing corpus -- it is not proven against every possible Format-category character or every possible invisible-character construction, only the ones exercised here (restated from the honesty note in step 2 above, because this is the kind of caveat that's easy to skim past once a table says "caught").

## Restart budget, clarified

"Restart budget N, M used" (this round: 2 proposed, 1 used) is a **self-imposed tracking convention inherited from Phase 3a, not an environment or technical cap.** It exists because repeated, rapid manager restarts caused real problems early in this project (a wedged manager requiring full container recreate, `docs/PHASE0.md` and `docs/WAZUH-NOTES.md` finding #5 -- container-lifecycle fragility under QEMU emulation, `linux/amd64` on an `arm64` host) -- the discipline is "iterate via `wazuh-logtest` exclusively, restart only for an already-validated candidate, and count/announce every restart," not "stop installing fixes after N restarts." **Confirmed explicitly: no validated fix was deferred this round to stay under any restart count.** Exactly one restart was needed (installing E3, the only fix that passed validation). E5 was never a candidate for live installation at all -- it was rejected by the negate-gate test in step 4 above, which has nothing to do with restart budget. Had E5 (or any other fix) passed validation, installing it would have been a normal, unremarkable use of a second restart, not something the "budget" would have blocked.

## Tool poisoning (`100102`)

| class | mechanism targeted | targeted rule fired? | verdict |
|---|---|---|---|
| `attack_evasion_e1_keyword_avoiding` | fixed keyword alternation | (none) | **EVADED** |
| `attack_evasion_e2_no_html_comment` | HTML-comment-only structural requirement | (none) | **EVADED** |
| `attack_evasion_e3a_zero_width` | literal keyword byte-match (invisible-character insertion) -- HARDENED this round, see "What happened during this round" below | 100102 | caught |
| `attack_evasion_e3b_homoglyph` | literal keyword byte-match (homoglyph substitution) -- deliberately NOT hardened, see below | (none) | **EVADED** |
| `attack_evasion_e4_distance_bound` | the .{0,120} proximity bound | (none) | **EVADED** |

**Attack-efficacy note for each evasion that succeeded** (per your item B — evading detection is a weaker finding if the payload also stops working):
- `attack_evasion_e1_keyword_avoiding`: preserves efficacy -- "OBEY THIS PROTOCOL" reads as a clear imperative instruction to an LLM, no degradation
- `attack_evasion_e2_no_html_comment`: preserves efficacy -- the bracketed instruction is at least as readable/actionable to an LLM as the original HTML-comment version; arguably more visible, not less
- `attack_evasion_e3b_homoglyph`: preserves efficacy -- a single homoglyph swap is visually indistinguishable and unlikely to disrupt LLM comprehension
- `attack_evasion_e4_distance_bound`: preserves efficacy -- padding is inert filler; the actual instruction text is unchanged and fully readable

## Credential exfiltration (`100101` / `100103`–`107`)

Each class's own "targeted rule fired?" column checks *only* the rule(s) that specific class is testing — several of these sessions (E5/E6/E8) also include an unmodified real `.env` read alongside the actual evasion attempt on the exfil hop, and that unmodified read always trips `100101` regardless of whether the class's own target evaded or not. Shown separately so an unrelated signal firing isn't misread as the targeted evasion having failed.

| class | mechanism targeted | targeted rule fired? | other signal fired? | verdict |
|---|---|---|---|---|
| `attack_evasion_e5_toolname_spoof` | negate-list tool-name-based exclusion (exfil hop only -- the read hop is an unmodified real read, not part of what this class is testing) | (none) | 100101 | **EVADED** |
| `attack_evasion_e6_untested_key` | 5-key-family enumeration boundary | (none) | 100101 | **EVADED** |
| `attack_evasion_e7_secret_shape` | fixed secret-shape regex | (none) | (none) | **EVADED** |
| `attack_evasion_e8_encoded_payload` | literal-string/prefix matching | (none) | 100101 | **EVADED** |
| `attack_evasion_e9_read_path` | anchored path-suffix regex | (none) | 100103 | **EVADED** |

**Attack-efficacy note for each evasion that succeeded:**
- `attack_evasion_e5_toolname_spoof`: preserves efficacy -- the tool's real behavior (forwarding data to a destination URL) is unaffected by what it's named; the name is only ever seen by the rule and the calling model
- `attack_evasion_e6_untested_key`: preserves efficacy -- the tool still receives and forwards the secret; only the argument's key name changed
- `attack_evasion_e7_secret_shape`: preserves efficacy through the ghp_-shaped synthetic value; the Slack token shape is deliberately redacted so repository push protection is not bypassed
- `attack_evasion_e8_encoded_payload`: preserves efficacy for a real attacker -- base64 is trivially reversible by the attacker's own receiving infrastructure; confirmed the sink received the full, decodable payload (see build log)
- `attack_evasion_e9_read_path`: preserves efficacy -- .env.bak carries byte-identical content to .env; nothing about the secret is degraded

**E9 evades its own targeted rule (`100101`) but is not a full bypass of the attack overall** — the *content* signal (`100103`) still fires on the exfil step, since the exfiltrated content is byte-identical to the real `.env`. Defense-in-depth catching what the path-based signal alone would have missed — worth stating precisely rather than either calling this a clean evasion or ignoring the partial result.

## Rug pull (`100201` / `baseline/watch.py`)

Two-stage measurement: does `baseline/watch.py` emit a drift record at all (the detector's own decision), and if so, does `100201` fire on it (Wazuh's side). Both checked via the real code, not asserted.

| class | baseline/watch.py emitted drift? | 100201 fired? |
|---|---|---|
| `e10_legit_upgrade` | yes | 100201 |
| `e11_behavior_only` | **no** | n/a -- nothing to fire on |
| `e12_pulled` | yes | 100201 |

**E10 (legitimate version bump) — stated at its real operational severity, not as a footnote**: confirmed to fire. **As built, this detector fires on every legitimate update to a monitored tool or server, indistinguishably from a real rug pull.** Without the allowlist/re-baseline workflow `docs/PHASE3B-DESIGN.md` explicitly declined to build, this makes the detector *operationally close to unusable* in any environment where the monitored MCP servers are ever legitimately upgraded — every routine version bump is a false alarm indistinguishable from an actual attack. This is a real limitation of the current design, not a tuning gap.

**E11 (behavior-only rug pull)**: confirmed zero drift, as predicted. This is a structural, **not fixable within this architecture** blind spot: there is no field in MCP's protocol surface this project captures that exposes runtime behavior for hashing. A rug pull that changes only what a tool *does*, never what it *advertises*, is invisible to this whole detection philosophy, full stop — document, not a gap to chase.

**E12 (session-conditional serving)**: confirmed caught, as predicted -- TOFU-then-alert survives multiple prior clean observations, as predicted in `docs/PHASE5-DESIGN.md`. Not a gap.

### Unintended cross-scenario drift, found in this corpus too (not hidden)

`baseline/watch.py` doesn't know or care what an evasion class is testing — it only sees `(tool_name, server_command)` pairs and their hashes. This corpus reuses `poisoned_tool_server.py` (same tool name, same server command) across E1/E2/E3a/E3b/E4, each with a genuinely different description, and reuses `exfil_sink_server.py`'s `exfiltrate` tool across E6/E7/E8/E9 with a schema that changes between E6 (`msg` key) and the rest (`data` key). Exactly the same class of finding `docs/PHASE4-REPORT.md` already documented for 3a's own variant harness — the rug-pull detector is behaving exactly as designed (real schema drift, correctly detected); it's this corpus's own construction that reuses one server identity across variants with different content, not a new mechanism.

| task_id | rule(s) fired on the drift record |
|---|---|
| `attack_evasion_e2_no_html_comment` | 100201 |
| `attack_evasion_e3a_zero_width` | 100201 |
| `attack_evasion_e3b_homoglyph` | 100201 |
| `attack_evasion_e4_distance_bound` | 100201 |
| `attack_evasion_e7_secret_shape` | 100201 |

**This does not change any evasion verdict above** — with one now-stale name needing a correction rather than a silent edit: E2/E3b/E4 still evade `100102` (the rule they actually target); E7 still evades `100103`–`107` (the rule it targets). **E3a is the one exception, and for an unrelated reason**: it now shows `100102` in the *targeted*-rule table above because of the E3 hardening applied this round, not because of anything in this cross-scenario table — its appearance here (the rug-pull rule firing on an unrelated tool_poisoning task_id) was already true before the hardening and remains an unrelated artifact of this corpus's construction, exactly like the other four rows. An unrelated rule firing on the same task_id via an unrelated mechanism is not a catch of the evasion being tested — stated explicitly so this table isn't misread as "actually, some of these got caught after all."

**This isn't just an observation that happens to hold — it's structurally guaranteed by how this data is computed, confirmed by reading the actual code path, not just checking today's output.** Every verdict above comes from `targeted_and_other_fired()`, which reads *only* `task_results` — a dict built exclusively from the raw `data/evasion_corpus_v1.jsonl` records' own rule matches. Those raw records never carry the `mcp_drift_marker` field `100200` requires, so they **cannot** match `100200`/`100201` at all, structurally, regardless of what `baseline/watch.py` does downstream. The 5 firings in the table above live entirely in a separate dict, `drift_task_results` — built from the derived drift records on a completely different code path — which `targeted_and_other_fired()` never reads. There is no path by which a `100201` firing could reach a TP/CE verdict; this was true before this table existed, not a filter applied after the fact.

## The recursion, restated for this specific round

Any future hardening validated only against this round's own evasion corpus inherits the exact self-authored-variant problem `docs/PHASE3A-DESIGN.md` and `docs/PHASE4-REPORT.md` already named for the original attacks. A clean result against `data/evasion_corpus_v1.jsonl` is evidence a fix beats the specific evasions *this round* thought to author — not evidence of adversarial robustness in general. A differently-minded adversary, or a future Phase 6 red-team round, could plausibly find a class this round didn't consider.

## Deferred infrastructure, named on the record

The only genuine generalization available for E6 (the 6th-argument-key gap) is moving that content-signal check outside Wazuh entirely — an external, `tool_arguments`-shape-agnostic scanner that checks *any* leaf value under `tool_arguments` for secret-shaped content, regardless of key name, architecturally similar to how `baseline/watch.py` already moved rug-pull detection outside Wazuh for the same class of reason (no primitive inside Wazuh's rule DSL expresses it). Not built this round, per your sign-off — named here as the real fix, so the deferral is a decision on record, not a gap that gets silently rediscovered next time.

**The same external scanner would also close E5**, discovered while proving the negate gate above: E5's tool-name-spoofing gap and E6's key-name gap are symptoms of the same underlying limitation (Wazuh's classic rule DSL can't express "any tool call, any argument key, regardless of tool name" as one condition). A Python scanner checking "does `tool_arguments` have a `path` key matching the sensitive suffix" is a native, trivial absence check with no negate-on-absent-field landmine at all — the exact wall that ruled out fixing E5 inside Wazuh's rule DSL. One piece of deferred infrastructure, not two, closes both gaps.

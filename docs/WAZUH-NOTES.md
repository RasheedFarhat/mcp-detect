# Wazuh rule-engine notes: root-causing the `decoded_as`-only mystery

Phase 0 (`docs/PHASE0.md`) flagged an unresolved observation: a rule with only
`<decoded_as>json</decoded_as>` and no `<field>` condition never appeared in
`wazuh-logtest -v`'s "Trying rule" trace — "avoided, not explained." This
document is that investigation, timeboxed and closed out before any Phase 1/3
rule authoring proceeds, per the constraint that follows.

## tl;dr

**It was never a `decoded_as`-only defect.** A bare `<decoded_as>json</decoded_as>`
rule is syntactically valid and fires correctly the moment it's actually
evaluated. What Phase 0 actually observed is Wazuh's ordinary **first-match-wins
evaluation among sibling rule candidates** — true both for top-level rules and
for children of an already-matched parent. Our production parent rule
(`100100`, in `local_rules.xml`, present since Phase 0) matched every realistic
test payload first and shadowed every rule added afterward in a different file,
regardless of that rule's `decoded_as`/`field` shape, its numeric ID, or its
file name. The earlier note's suspicion of `decoded_as` specifically was a red
herring — five controlled tests below isolate the real mechanism.

## The hard constraint this implies for Phase 3

**Every specific detection rule that should reliably fire against MCP-DETECT
JSON telemetry must be a child (`<if_sid>`) of a single shared canonical
parent rule** (the `100100` pattern already in `local_rules.xml`) — never an
independent top-level rule that re-tests `decoded_as: json` on its own. Two
unrelated top-level rules that could both match the same event will silently
shadow one another depending on an internal load order that is **not**
alphabetical-by-filename and **not** numeric-by-rule-ID (both were tested and
ruled out below) — so nothing about rule authoring can reliably control which
one wins if they're siblings at the top level.

A second, sharper constraint falls out of the same tests: **even among
children of one matched parent, evaluation stops at the first match** — a
second child that would also match the same event is never even attempted.
If the Sigma→Wazuh compiler (Phase 3) ever emits two rules whose match
conditions overlap on the same telemetry shape (plausible if multiple threat
scenarios compile to structurally similar conditions), only one will alert,
and which one is not something rule ID or declaration position lets you
predict from first principles. **The compiler's rule set must either be
mutually exclusive by construction, or every overlapping pair must be
regression-tested with `wazuh-logtest` before shipping** — "the rules loaded
without error" is not evidence they all actually fire.

## Test evidence

All tests run against the live `single-node-wazuh.manager-1` container from
Phase 0 (Wazuh 4.9.0), using `wazuh-logtest -v` (verbose) so every attempted
rule shows up in the trace, cross-checked against `Total rules enabled` in
`ossec.log` to confirm each test rule actually loaded (parser accepted it)
independent of whether it later appeared in the trying-list.

**Test 1 — bare `decoded_as`-only rule, shadowed.**
Loaded a single rule (`100195`, `decoded_as: json`, no field) in a new file
that sorts *after* `local_rules.xml` alphabetically. Rule count went up by
exactly 1 (loaded fine). Fed a real telemetry record (has `session_id` +
`server_command`, so the production parent `100100` also matches). Result:
`100195` never appears in the trying-list at all; `100100` matches and wins.
→ Consistent with either "file order" or "decoded_as-only is broken."

**Test 2 — isolate `decoded_as`-only from `decoded_as`+field, same event.**
Added a second rule (`100194`, `decoded_as: json` + one trivial
`<field name="method" type="pcre2">.*</field>`) alongside `100195` in the
same file. Same telemetry record. Result: **neither** rule appears in the
trying-list; `100100` still wins. → Rules out "decoded_as-only specifically is
invalid" — a rule with a field condition was shadowed identically. The
variable is something else about *this* rule vs. `100100`, not the presence
of a field.

**Test 3 — decisive: an event `100100` can't match.**
Same two rules (`100194`, `100195`), but this time fed a bare unrelated JSON
payload (`{"foo":"bar","method":"something"}`) that the JSON decoder still
tags `name: json` but that lacks `session_id`/`server_command`, so `100100`
correctly fails to match. Result: `100100` **is** tried (and correctly fails),
then `100195` (`decoded_as`-only) **is** tried and **matches**, and an alert
is generated. **This directly proves a bare `decoded_as`-only rule fires
correctly** — it was reachable and worked the instant nothing upstream claimed
the event first.

**Test 4 — is "upstream" alphabetical file order, or rule ID?**
Renamed the test file to sort *before* `local_rules.xml` (`aaa_wn_test.xml`),
re-tested with a real telemetry record. `100100` still won; the renamed
file's rules were never tried. → Rules out alphabetical filename order.
Separately, added a rule with a *lower* numeric ID than `100100` (`99999`,
`decoded_as`-only) in yet another file — still shadowed by `100100`, which
rules out ascending-rule-ID evaluation order too. (Both loaded successfully
per the rule count delta; neither ordering theory survived.) The most
consistent explanation left standing: Wazuh's internal rule-file registration
order tracks something like directory-entry/creation order at the filesystem
level, not a property visible from rule ID or filename — i.e., **don't rely
on load order at all; it isn't something rule authoring controls.**

**Test 5 — do all children of a matched parent get tried, or just the first
match?** Added `100196` as a second child of `100100` (`<if_sid>100100</if_sid>`,
different field) alongside the existing child `100101`. Fed the tools/list
*response* record (no `tool_arguments`, so `100101`'s field condition
genuinely can't match) — result: `100101` tried and correctly failed, `100196`
tried next and matched, confirming Wazuh moves on to the next sibling once
one fails, as expected. But then fed the real sensitive `tools/call` record
(which `100101` **does** match) — result: `100101` tried and matched, and
**`100196` was never even attempted**, despite also being a candidate.
Evaluation among children stops at the first match, exactly like top-level
siblings. This is the finding behind the second constraint above.

## Inherited constraints from Phase 1/2 (consolidated for Phase 3)

Three constraints Phase 3 rule authoring must honor, discovered during
lab/corpus/attack generation rather than during rule-writing itself — collected
here, in the document Phase 3 already has to read for the `if_sid`
constraint above, so none of them get rediscovered mid-authoring. Full
write-ups live where they were found; this is the pointer, not a
duplicate.

1. **Near-boundary false-positive floor** (`data/benign_corpus_v2.summary.md`,
   `docs/PHASE1b.md`). Any per-tool detection's false-positive rate is
   computed against that tool's benign call count in the corpus. Every tool a
   detection might key on has 25+ benign events by construction *except*
   `git_show` (zero — a confirmed, accepted gap, not an oversight; see
   `docs/PHASE2-DESIGN.md`, Attack 3's technique mapping). A rule keyed on
   `git_show` has no denominator here and needs a supplemental baseline
   before its FP rate can be trusted.

2. **Rug-pull requires stateful infrastructure that does not exist yet**
   (`docs/PHASE2-DESIGN.md`, "Headline finding" + Attack 3's "Detection
   mechanism — resolved"). `tool_description_hash`/`server_version_hash`
   drift (SAF-T1201) is real, clean, and empirically verified in both the
   benign baseline (zero drift, 23/23 tool+server pairs) and the Attack 3
   telemetry (confirmed drift). But it is **not catchable by a stateless
   single-record rule**, and Wazuh's native bounded correlation
   (`same_field`/`different_field` + `frequency`/`timeframe`) is hard-capped
   at 99999 seconds (~27.7 hours) — real rug pulls (postmark-mcp: 15
   published versions before the backdoor) unfold over days to months, past
   that ceiling. The correct mechanism is a **persistent baseline
   comparison**, architecturally identical to Wazuh's own File Integrity
   Monitoring but keyed on `(tool_name, server_command)` instead of a
   filesystem path — infrastructure Phase 3 has to build, not a rule Phase 3
   can just author against what exists today.

3. **Credential-exfil content-signal scope is `tool_arguments`-only — do not
   broaden it without a guard** (`docs/PHASE2-DESIGN.md`, Attack 2's
   distinguishability check). The exfil-hop detection idea (secret-shaped
   strings — `postgres://`, private-key markers, `sk-`-prefixed keys, etc.
   — appearing in a tool call) was exhaustively regex-scanned against all
   4727 benign v2 records and is **clean when scoped to `tool_arguments`
   only** (zero collisions). It is **not** clean if broadened to the full
   record: `fs_read_makefile` and `git_show_head_commit` both legitimately
   surface secret-shaped substrings, because the Makefile's own source code
   contains the literal `printf` commands `make smoke` uses to plant the
   fake `.env`/`id_rsa` bait. If Phase 3 generalizes this signal from
   "argument" to "anywhere in the record" (`result_summary`/`raw` included),
   it **must** either exclude those fields or allowlist reads of the
   Makefile — otherwise it false-positives on two real benign tasks. Same
   class of finding as constraints 1 and 2 above: verified against real
   data, not assumed, and worth inheriting rather than rediscovering.

4. **`&lt;` (XML entity) inside a `<field type="pcre2">` pattern does not
   reliably compile to a literal `<` — use PCRE2's own `\x3c` hex escape
   instead** (found building `wazuh/local_rules.xml`'s `100102`, tool
   poisoning, `docs/PHASE3A-DESIGN.md`). A rule matching
   `&lt;!--...directive-keyword...` against `raw.result.tools` appeared to
   segfault `wazuh-manager` on restart — which, followed without checking
   the actual bytes first, led down a real but wrong path (suspecting the
   array-flattened field itself was unsafe to match against, see #5 below).
   Root cause, found by `xxd`-dumping the exact decoded field value instead
   of iterating on the pattern further: the telemetry data genuinely
   contains an unescaped, literal `<!--` (confirmed byte-for-byte — `3c 21
   2d 2d`, no entity, no corruption). A bare keyword match with no `<`
   involved at all fired correctly against the same field; every variant
   using `&lt;!--` did not. Swapping to PCRE2's `\x3c` hex escape for the
   same character fixed it immediately, confirmed via `wazuh-logtest`.
   **Any rule anywhere in this ruleset that needs to match a literal `<` or
   `>` should use `\x3c`/`\x3e`, not `&lt;`/`&gt;`, regardless of which
   field it targets** — this is a parser-level finding, not specific to
   `100102` or to array fields. **Audited, not just asserted**: grepped
   every loaded stock rule file (167) plus both custom rule files, and the
   decoder directories for completeness, for `type="pcre2"` patterns
   containing `&lt;`/`&gt;` — zero hits anywhere outside this file's own
   explanatory comment text. No phantom-coverage rule exists elsewhere in
   this ruleset; the bug was isolated to the one rule that had just been
   written and is already fixed.

5. **A rule that appears to crash `wazuh-manager` on restart is not
   sufficient evidence that the *field* or *pattern shape* is unsafe** —
   confirm via `wazuh-logtest` (see the new process rule immediately below)
   before concluding a structural incompatibility, the way #4 above
   initially did. Once the real `&lt;` bug was fixed, `raw.result.tools`
   (the field originally suspected of being crash-prone) was re-tested via
   `wazuh-logtest` and matched cleanly with no crash and no error. The
   actual segfaults, and one fully wedged manager (stuck mid-boot, service
   tree never finished starting, requiring a full container remove+recreate
   — `docker compose rm -sf <service>` + `up -d`, not just `restart` — to
   clear) were most plausibly a mix of the non-matching rule (harmless on
   its own) and unrelated container-lifecycle fragility compounding across
   many rapid restarts under QEMU emulation (this stack's `wazuh.manager`
   image is `linux/amd64`, emulated on an `arm64` host — Docker surfaces
   this explicitly on every recreate; the same class of fragility
   `docs/PHASE0.md` already flagged for a different daemon in this same
   image family). Plain `docker compose down`/`up` or `rm`+`up` do **not**
   reseed the `wazuh_etc` named volume (the seed script only triggers if
   `/var/ossec/etc` looks empty, and a populated volume never does) — safe
   to use for recovery without the reseed risk `docker-compose.yml`'s own
   comments warn about, as long as `-v`/`--volumes` is never added.

**New standing process rule, adopted after this cost real build time and
several restart cycles to learn — binding for future rule-authoring
phases**: iterate on Wazuh rule content via `docker compose cp` (a plain
file write into the running container — no service impact) followed by
`wazuh-logtest` (confirmed to read rule files fresh from disk on every
invocation, with no manager restart needed to pick up a change) exclusively.
Reserve actual `wazuh-manager` restarts for installing a candidate that has
already fully passed `wazuh-logtest` validation — true positives fire,
benign traffic stays silent — not for testing hypotheses about why a rule
isn't matching. If `wazuh-logtest` itself ever errors or crashes on a
candidate, that is still a clean, low-cost data point (no service
disruption) rather than a reason to restart the manager to investigate.

6. **`tool_arguments.*` (any key) decodes as a clean, reliable scalar
   field — unlike `raw.result.tools` (constraint 4/5 above), there is no
   array-flattening complexity to worry about when adding a rule scoped to
   a *new* argument key name.** Confirmed via `wazuh-logtest` before writing
   `100104`–`100107` (the credential-exfil siblings added to close a
   measured 3/11 exfil-hop recall gap, `docs/PHASE3A-DESIGN.md`):
   `tool_arguments.payload`, `.content`, `.body`, `.message` each decode
   identically to `.data`, because `tool_arguments` is always a plain JSON
   object and Wazuh flattens objects per-key, not per-array-index. Worth
   stating explicitly since the two field-related findings above (4 and 5)
   could otherwise read as "matching decoded fields is generally risky" —
   it isn't; the risk was specific to array-typed values, not decoded
   fields in general.

7. **Constraint 3 (the `fs_read_makefile`/`git_show_head_commit` Makefile
   collision) is about `result_summary`/`raw` specifically — it does not
   automatically block broadening within `tool_arguments`, but check the
   actual key usage before assuming a new key is risk-free.** Scanned all
   `tool_arguments` key names across the full 4727-record benign v2 corpus
   before broadening `100103` to more argument-key siblings: `data`/
   `payload`/`body`/`message` are used by zero real benign tools in this
   corpus. `content` **is** real and actively used (47 occurrences, from
   `write_file`) — confirmed none of those 47 values are secret-shaped, but
   this key carries a different, nonzero-in-principle risk profile than the
   other three and should be re-checked if the benign corpus grows to
   include more `write_file`-shaped variety, not assumed permanently clean
   because one scan came back empty.

8. **A new top-level `decoded_as: json` rule can be silently shadowed by a
   STOCK rule, not just by another custom one — the collision surface is
   the whole shipped ruleset, not just `local_rules.xml`/`mcp_detect_rules.xml`.**
   Found building `100200` (rug pull's baseline-drift parent,
   `docs/PHASE3B-DESIGN.md`, Phase 3b): the drift record's first draft used a
   field named `event_type` as its discriminator. Wazuh's own stock Suricata
   parent rule — `86600` in `/var/ossec/ruleset/rules/0475-suricata_rules.xml`,
   shipped, never touched by this project — requires exactly
   `<decoded_as>json</decoded_as>` plus fields literally named `timestamp`
   and `event_type` both present, and every drift record already carried
   `timestamp` too. `86600` matched first and shadowed everything downstream,
   by the identical first-match-wins mechanism Tests 1–5 above already proved
   — the only new information is *where* the colliding rule can live: the
   full shipped ruleset (hundreds of files, many third-party log formats,
   all sharing the `decoded_as: json` decoder), not just this project's own
   two rule files. Fixed by renaming the field (`mcp_drift_marker`) and
   re-verifying via `wazuh-logtest`.

   **Standing rule, generalized beyond this one collision**: before adding
   *any* new top-level `decoded_as: json` rule, grep every field name it
   discriminates on against the **entire loaded ruleset**
   (`/var/ossec/ruleset/rules/*.xml`, not only `local_rules.xml`/
   `mcp_detect_rules.xml`) for existing `<field name="...">` usage, the same
   way the phantom-`&lt;`-match audit (constraint 4 above) already treated
   the whole loaded ruleset as in-scope rather than just this project's own
   files. A clean grep against custom rules only is not sufficient evidence.

   **Sharper standing rule about how to run the actual disjointness check**:
   a "does my new rule collide with rule X" test must confirm **both** (a)
   rule X is tried and does not match, **and** (b) the new rule itself is
   tried and does match — not just (a) alone. The failure mode here was
   worse than "collides with `100100`": neither `100100` nor `100200` was
   ever reached at all, because an unrelated stock rule intercepted the
   event first. A check that only asks "did it avoid rule X" would have
   passed this exact case (it genuinely never touched `100100`) while
   shipping a rule that silently never fires — the same phantom-coverage
   failure mode as the `&lt;` bug and the negate-on-absent-field gate, just
   from a third direction. Confirming the trace end-to-end
   (`wazuh-logtest -v`, full "Trying rule" list, final matched rule id) is
   what catches this; confirming only the absence of one specific match does
   not.

## What was NOT root-caused at the C-source level

I did not read Wazuh's `analysisd`/rule-compiler source to find the exact
data structure or comparison function that determines this ordering (out of
scope for the timebox). The empirical behavior — first-match-wins among
siblings, order not controlled by rule ID or filename — is proven by the
tests above and is sufficient to derive the safe pattern. If Phase 3's
compiler output ever needs to *guarantee* a specific firing order between
two genuinely overlapping rules (rather than avoiding overlap by
construction), that would be the point to go read the source or ask
Wazuh upstream directly — flagging it here rather than guessing further.

# Phase 5 Design — Adversarial Evasion Testing

Status: **proposal — awaiting review.** No rule, no `lab/baseline/watch.py`, no
`lab/analysis/report.py`, and no telemetry has been touched. Per the standing
pattern, this is the check-in gate before any attack, measurement, or code
change.

## The mandate, restated so it can't quietly drift

Every recall number on record so far — 3a's 12/12 and 11/11, 3b's 3/3, 4's
consolidated tables — is measured against variants **I** authored to match
what the rule **already** looks for. Every one of those phases said so
explicitly, not as a footnote:

- 3a: "these are self-authored variants constructed to match the pattern
  each rule already looks for... not that the rule generalizes to
  independently-authored or adversarial phrasing it wasn't designed
  around."
- 4: "recall is measured against self-authored variants — plumbing proven,
  adversarial robustness not."

**Phase 5 attacks that gap directly.** The task is to author attacks
*designed to fail*, not to pass. A report full of successful evasions is
the success condition here — finding real gaps is the deliverable, not
something to minimize or explain away. If this round comes back with
another wall of 100% tables, that's a signal the evasions weren't
adversarial enough, not a clean bill of health.

## Restating the already-named blind spots, sourced precisely

Distinguishing, on purpose, between what the docs **already said** and
what I'm newly inferring from re-reading the rule mechanics myself —
conflating the two would misrepresent how much of this was actually
anticipated versus found now.

**Already named in the docs:**

- **`100102` (tool poisoning)**: `docs/PHASE3A-DESIGN.md` — "requires *both*
  an HTML comment structure... *and* directive-language content... at the
  cost of missing an obfuscation variant that skips recognizable directive
  keywords entirely." `docs/PHASE2-DESIGN.md` (Attack 1's named
  limitation): "SAF-T1001 documents stealthier variants (invisible
  Unicode, homoglyphs, bidirectional-text tricks) that a plain string-match
  on directive-phrasing wouldn't catch... explicitly out of scope for this
  first slice."
- **`100103`–`107` (credential exfil, exfil hop)**: `docs/PHASE3A-DESIGN.md`
  — "matches the literal field name `tool_arguments.data`... A malicious
  tool passing the same secret content under a *different* argument key
  name... would not be caught." After widening to 5 keys, restated in
  `docs/PHASE4-REPORT.md`: "bounded to the 5 argument-key names actually
  tested... a 6th, unobserved key name would still slip past this rule
  family by construction (Wazuh's rule DSL has no wildcard-field-name
  match)."
- **`100201` (rug pull)**: `docs/PHASE3B-DESIGN.md` — "legitimate version
  bumps read as drift under this model, by design... a real deployment
  with legitimate server upgrades would need a re-baseline/allowlist
  workflow this design does not build." `docs/PHASE4-REPORT.md` sharpens
  this to a concrete untested claim: "no benign fixture in this corpus
  exercises the actual case this detector needs to distinguish: a
  legitimate version bump."

**Not previously named anywhere — found now, by re-reading the actual rule
text rather than the prose describing it, the same discipline every prior
phase applied to itself:**

- `100102`'s pattern is `(?i)\x3c!--.{0,120}(SYSTEM|IMPORTANT|...)` — the
  `.{0,120}` bound is a hard mechanical limit no prior doc discussed:
  padding more than 120 characters between the comment opener and the
  keyword evades regardless of keyword choice.
- `100103`–`107`'s negate-list (`^(read_file|read_text_file|get_file_info|
  edit_file|create_directory|list_directory|directory_tree)$`) was added
  for *rule-disjointness* reasons (keeping these siblings from double-firing
  with `100101`), not as a security boundary — but it functions as one now,
  and nothing stops an attacker from naming their exfil tool identically to
  one of those seven strings.
- `lab/baseline/watch.py` hashes only *advertised metadata*
  (`{name, description, inputSchema}` / `{server_name, server_version,
  server_command}`, per `lab/schema/schema.md`'s hash recipe) — a rug pull that
  changes **only runtime behavior**, never any hashed field, produces zero
  drift and is invisible to this detector by construction. This is a
  sharper, previously-unstated version of the general "any hash change is
  anomalous" framing: the converse (no hash change ⇏ no attack) was never
  actually tested.

## 1. Evasion classes per technique

Sizing note before the list: one well-chosen representative session per
class, not multiple wordings of the same class. The point of this phase is
"does this *mechanism* evade," not another recall-on-phrasing-variants
exercise — that work is already done (3a's 12+10 variant rounds). A
combinatorial sweep here would just recreate the self-authored-variant
problem one level up.

### Tool poisoning (`100102`)

| # | class | targets |
|---|---|---|
| E1 | Keyword-avoiding directive phrasing — same `<!--...-->` structure, wording that means the same thing without any of the 9 listed keyword/phrase alternatives (e.g. "OBEY THE FOLLOWING:", "MANDATORY:", or plain narrative instruction with no imperative marker at all) | the fixed keyword alternation |
| E2 | Non-HTML-comment obfuscation — the identical hidden-instruction *content*, delivered with no `<!--...-->` wrapper at all (plain appended text, a different fake "hidden" convention, or just relying on the client never rendering full descriptions to a human) | the HTML-comment-only structural requirement |
| E3 | Unicode homoglyph / invisible-character keyword mangling — e.g. Cyrillic "Ѕ" for "S" in "SYSTEM", zero-width joiners spliced into a keyword, or the whole payload prefixed with zero-width spaces | the literal keyword byte-match |
| E4 | Instruction split across fields/tools — divide the payload so no single 120-char window contains both `<!--` and a keyword together, or split it across two tools in one multi-tool `tools/list` response, each half innocuous alone | the `.{0,120}` proximity bound and the single-flattened-string match scope |

### Credential exfiltration (`100101` / `100103`–`107`)

| # | class | targets |
|---|---|---|
| E5 | Tool-name spoofing — name the exfil tool identically to one of the 7 negate-listed benign read-tool names, while its actual arguments carry the secret under `data`/`payload`/etc. (not `path`) | the negate-list's tool-name-based exclusion, turned into an evasion surface |
| E6 | 6th, untested argument key (e.g. `payload_data`, `msg`, `value`) | the named, already-accepted 5-key-family boundary |
| E7 | Secret formats outside the 6 named shapes — a GitHub PAT (`ghp_...`), a Slack token (`xox[bp]-...`), a JWT, a MongoDB URI, a generic bearer token, or a raw high-entropy string with no recognizable prefix | the fixed secret-shape regex |
| E8 | Chunked/encoded payload — base64-encode the secret before the exfil call, or split it across multiple smaller, individually-innocuous-looking tool calls | literal-string/prefix matching generally |
| E9 | Read-path evasion for `100101` itself — read the same sensitive content via a path that doesn't end in exactly `.env`/`id_rsa`/`.aws/credentials` (case-insensitive) — a renamed copy, a `.bak` suffix, a symlink | the anchored path-suffix regex |

### Rug pull (`100201` / `lab/baseline/watch.py`)

| # | class | targets | shape |
|---|---|---|---|
| E10 | Legitimate version bump — `label=benign`, a genuine pinned-package upgrade (new version string, an honestly-updated description) against the same `(tool_name, server_command)` key that already has an established baseline | the accepted, previously-unmeasured FP gap | **FP probe, not an evasion** — framed differently below |
| E11 | Behavior-only rug pull — version string frozen, description/`inputSchema` byte-identical to baseline, simulating a runtime-only behavior change with nothing to hash differently | the metadata-only hashing scope | true evasion |
| E12 *(addition, flagging as beyond your explicit list)* | Session-conditional serving — the server serves the clean description to the first N sessions (so TOFU establishes a clean baseline) and only serves the malicious description later/selectively | whether TOFU-then-alert genuinely survives a server that can distinguish monitored from victim traffic | true evasion, but I'd predict this one is *caught* (TOFU fires on any later differing value regardless of when) — worth confirming rather than assuming |

E10 is not an evasion in the recall sense — nothing is trying to get past
anything. It's the direct FP-side probe of a gap `docs/PHASE3B-DESIGN.md`
already named and declined to build a fix for. Keeping it in this phase
because it's the same kind of "we asserted this, let's actually check"
discipline as everything else here, just measuring the opposite failure
mode (over-firing on legitimate change) instead of under-firing on an
attack.

## 2. Generation + measurement

**Generation**: extend the existing attack servers the same
env-var-parametrized way 3a/3b already do (`poisoned_tool_server.py`,
`exfil_sink_server.py`, `rugpull_email_server.py` all already support this
pattern — no new mechanism, more modes). One new session per evasion class
above, run through the real proxy against real servers — schema-valid
telemetry, not hand-fabricated JSON, matching the discipline every prior
phase held to.

**Where the telemetry lands — deliberately not the live canonical
`telemetry.jsonl`**: this is a measurement exercise that may iterate
(author an evasion, measure, decide to harden, re-measure), and Phase 5's
evasion sessions are conceptually a different kind of artifact than the
"attacks the rules are expected to catch" telemetry already frozen there.
Proposing a new, separately frozen/committed file — `data/evasion_corpus_v1.jsonl`,
naming it in the same family as `data/benign_corpus_v2.jsonl` since both
are committed, versioned fixtures, not live/mutable state — generated once
via a new `lab/attacks/evasion_harness.py` (or new modes on the existing
`lab/attacks/harness.py`; open question below). Flagging the exact name/location
as open, same as `lab/baseline/`'s and `lab/analysis/`'s naming were both open
questions in their own phases.

**Measurement**: batch `wazuh-logtest` over frozen inputs, the real engine,
zero live-pipeline mutation — identical discipline to 3a/3b/4. Concretely:
`data/benign_corpus_v2.jsonl` + the canonical attack slice + `rugpull_alerts.jsonl`
+ the new evasion corpus, all in one batch pass, so a regression against
everything already measured is free every time this phase's own measurement
runs.

**Reuse `lab/analysis/report.py`'s primitives, don't reimplement them**: the
rule-sync gate (`verify_rule_sync`), the batch runner
(`run_wazuh_logtest_batch`), and the join/normalization
(`normalize_and_join`) are exactly what this phase needs too — proposing a
new `lab/analysis/evasion_report.py` that imports them from `lab/analysis/report.py`
rather than duplicating the logic. `report.py`'s functions are already pure
enough to import safely (module-level work only runs under
`if __name__ == "__main__"`), so this shouldn't require restructuring it —
but if anything there does need to change to support import, the rule
after that change is non-negotiable: **re-run `lab/analysis/report.py` and
diff `docs/PHASE4-REPORT.md` byte-for-byte before Phase 5 is considered
done.** Reusing Phase 4's code must not silently alter Phase 4's own,
already-committed output.

**Metric framed correctly for a red-team report**: Phase 4's tables measure
recall where high-is-good. Phase 5's headline metric is the reverse — **how
many evasion classes succeeded**, where success (from the red-team's chair)
means the rule did *not* fire. Reusing `compute_scenario_recall`'s grouping
mechanics (by `scenario_id`/`task_id`) but presenting the result inverted:
"evaded" vs. "still caught," not folded into Phase 4's own recall numbers
or presented as a recall regression on the original attacks (it isn't one —
these are new attacks, not the old ones failing).

## 3. Harden-vs-document policy — the trap, and the rule for not falling into it

**The rule**: hardening is legitimate only when the fix is a genuine
**generalization** — it would also catch a differently-worded, differently
-encoded instance of the *same evasion class*, not just the literal string
this round authored. If the "fix" is adding the one new keyword, key name,
or tool name this round happened to invent to an OR-list or negate-list,
that's not hardening — it's memorizing this round's own test, which is
exactly the self-authored-variant problem the mandate above names, just
one level removed (self-authored *fixes* instead of self-authored
*variants*).

**Worked through each class above, so the policy isn't left abstract:**

- **E1 (keyword-avoiding phrasing)**: any fix here is close to unfalsifiable
  — natural language directive-phrasing is an open-ended space; expanding
  the keyword list to also catch this round's specific phrase doesn't
  close the class, it just moves the goalpost one word further out.
  **Document, don't harden**, as a standing rule for this class
  specifically — a keyword list can never be complete against unbounded
  phrasing, and pretending one more addition changes that would be
  dishonest about what got fixed.
- **E3 (Unicode homoglyph/invisible-char)**: genuinely different — Unicode
  NFC normalization (or stripping zero-width characters) before matching
  is a **structural** fix that generalizes to the whole class of
  homoglyph/invisible-character tricks, not just the one specimen
  authored here. Notably, `lab/proxy/hashing.py` already does NFC normalization
  for a different purpose (hash stability) — the same technique would
  apply here. **Legitimate hardening candidate, if E3 succeeds.**
- **E5 (tool-name spoofing via the negate-list)**: also a real candidate.
  The negate-list's actual intent was "don't double-fire when `100101`
  already claims this exact record" — which specifically means "this
  record also carries a sensitive-suffix `path` argument," not "this
  tool's name happens to match one of seven strings." Narrowing the
  negate condition to check for the *absence of a matching `path`
  argument* rather than tool identity would fix the actual gap the
  negate-list was trying to approximate, not just this round's specific
  tool name. **Legitimate hardening candidate, if E5 succeeds** — but
  needs its own disjointness re-validation against `100101` via
  `wazuh-logtest` before shipping, same discipline as the original fix.
- **E6 (6th argument key)**: this is the same shape of fix 3a already did
  once (widening `100103` to the `100103`–`107` family) — and doing it
  *again* reactively for whichever key this round picks would be exactly
  the self-authored-variant problem restated. **Document, don't harden** —
  restate the already-accepted structural limit (no wildcard-field-name
  primitive in Wazuh's DSL) rather than add an 8th sibling rule for one
  more observed string. A genuine generalization here would mean moving
  this signal outside Wazuh entirely (an external, `tool_arguments`-shape-
  agnostic scanner, architecturally similar to how `lab/baseline/watch.py`
  moved rug-pull detection outside Wazuh) — that's a real infrastructure
  decision, not a reactive rule edit, and is flagged as an open question
  below rather than decided here.
- **E7/E8 (secret-shape/encoding evasions)**: broadening the regex to
  include more secret *shapes* (JWT, GitHub/Slack token prefixes, generic
  bearer tokens) is a legitimate generalization — it's expanding a stated
  class ("secret-shaped content"), not memorizing one string, the same
  way `100103`'s original design already enumerated multiple shapes
  (`postgres://`, `sk-`, `AKIA`, etc.) as one class from day one.
  Encoding evasions (base64) are different in kind: no regex broadening
  meaningfully "generalizes" against arbitrary encoding — that's
  **document**, not harden, an honest structural limit of content
  matching (the same way the FP scoping in `docs/WAZUH-NOTES.md`
  constraint 3 already accepted a scope boundary rather than chase it).
- **E9 (read-path evasion)**: same shape as E6 — anchoring on more literal
  filename variants (`.env.bak`, etc.) memorizes specimens; there's no
  clean generalization available within a suffix-regex, so this is
  **document**.
- **E10 (legitimate version bump)**: not eligible for hardening in this
  round *by policy*, independent of what's found — `docs/PHASE3B-DESIGN.md`
  already declined to build the allowlist/re-baseline workflow this would
  need, and reactively building it now, mid-red-team-phase, would be scope
  creep beyond "measure the gap, don't necessarily close it here."
  **Document only**, restating the existing decision with a real measured
  number behind it instead of an assumption.
- **E11 (behavior-only rug pull)**: **not fixable within this
  architecture at all**, stated plainly rather than softened — there is no
  field to hash for "runtime behavior" in MCP's protocol surface as
  currently captured. This is a fundamental limit of a metadata-baseline
  approach, not a gap in this specific rule's tuning. Document as a
  structural boundary of the whole technique, not a to-do.
- **E12 (session-conditional serving)**: whichever way this measures, it's
  **document, not harden** — either it's already caught (TOFU's own
  semantics already generalize here, nothing to fix) or it reveals a real
  TOFU-model limitation that isn't fixable by tuning `lab/baseline/watch.py`,
  only by changing the trust model itself (e.g., requiring baseline
  agreement across multiple independent vantage points) — a much bigger
  architectural question than this phase should decide unilaterally.

**The recursion, made explicit rather than left implied**: any rule change
validated only against Phase 5's own evasion corpus inherits the *exact*
self-authored-variant problem 3a/4 already named for the original attacks.
A hardened rule's clean recall against Phase 5's own evasions is not
evidence the rule is unbeatable — it's evidence the rule beats the
specific evasions *this round* thought to author. A differently-minded
adversary, or a future Phase 6 red-team round, could plausibly find a
class this round didn't consider. This is not a defect in this phase's
methodology; it's an inherent property of red-teaming your own detector
without independent adversarial input, and it should be stated in the
report's own conclusion, not just here.

## 4. Deliverable + location

**`docs/PHASE5-REPORT.md`**, same generated-file banner convention as
`docs/PHASE4-REPORT.md`, produced by `lab/analysis/evasion_report.py` (sibling
to `lab/analysis/report.py`, importing its primitives rather than duplicating
them). Content, per evasion class: which rule it targeted, whether it
evaded or was caught, and — for anything that evaded — the harden-or-document
decision with reasoning, and (if hardened) the full-corpus regression
result plus the recursion caveat restated for that specific rule change.

**Headline framing, stated up front in the report** (mirroring how Phase
4's executive summary stated its own framing rule before the tables): *"N
of M evasion classes succeeded — these are gaps, and finding them is this
phase's success condition, not a defect being reported on this project."*

## Open questions for your sign-off

1. **Evasion corpus location/filename** — `data/evasion_corpus_v1.jsonl`
   (proposed) vs. living under `lab/attacks/` instead, since it's attack-side
   data.
2. **New harness file vs. extending the existing one** —
   `lab/attacks/evasion_harness.py` (proposed, keeps 3a/3b's original-attack
   harness unmodified and stable) vs. adding more modes to
   `lab/attacks/harness.py` directly.
3. **E5 and E3 pre-approved as legitimate hardening candidates if they
   succeed** — I've reasoned through why both pass the generalization test
   above; want your sign-off on treating them as approved-in-advance
   *categories* of fix (still each individually validated via
   `wazuh-logtest` before shipping), or would you rather review each
   specific fix after the evasion result is in hand, case by case?
4. **The `100103`–`107` argument-key-agnostic scanner** (the only
   genuine generalization available for E6) — explicitly named as future
   infrastructure, not built this round. Confirm that's the right call, or
   is this actually the phase to build it?
5. **Restart budget** — proposing 2, same size as every prior rule-changing
   round, spent only if E3 and/or E5 actually succeed and get hardened;
   held in reserve otherwise.

Awaiting sign-off before generating any evasion attack, touching any rule
or `lab/baseline/watch.py`, or writing anything beyond this document.

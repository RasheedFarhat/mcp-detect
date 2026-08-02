# Agentic Detection Readiness Assessment
### Prepared for: NorthwindPay (fictional entity, sample deliverable)

**Assessment window**: 2026-06-01T13:00Z -- 2026-06-02T02:46Z (telemetry capture)
**Environment reviewed**: 12 MCP servers, 538 agent sessions, 4,046 telemetry records
**Prepared by**: mcp-detect Agentic Detection Readiness service
**Report type**: SAMPLE -- illustrative deliverable built on a synthetic, fictional
environment (NorthwindPay does not exist). No real organization, credential, or
attack payload appears anywhere in this document.

---

## How to read this report

This is a security assessment of the MCP (Model Context Protocol) servers and
AI agent tool-calling activity NorthwindPay's environment produced during the
capture window. It answers three questions a technical evaluator should
asks:

1. **What is actually running, and who can it touch?** (Section 2)
2. **What did we find, and what should you do about it, in priority order?**
   (Section 3)
3. **What can this assessment NOT see, so you don't over-trust a clean
   scorecard?** (Section 5)

Every finding below is a real match produced by running the actual detection
engine (Wazuh) against NorthwindPay's own submitted telemetry -- not a
capability demo run against our own test data. Where a claim is about our
tooling's general capability rather than something observed in your
environment, this report says so explicitly.

---

## 1. Executive summary

NorthwindPay's agent fleet spans 12 MCP servers -- filesystem access (shared
docs, an agent scratch area, and a mount over production settlement/ledger
data), git, web fetch, a knowledge-graph memory store, time lookups, and five
custom internal integrations (Slack, expense OCR, FX rates, a support-ticket
bot, and one unlisted CRM bridge) -- across 538 sessions in the sampled
capture window.

**Four findings require action**, ranked by severity below. The most
important one first: **an agent-facing filesystem connection has write
access directly into production ledger data, and a credential was read from
and then exfiltrated through that same blast radius** during the capture
window. This is the kind of finding a point-in-time compliance checklist
does not catch, because nothing about it looks unusual in a server
inventory alone -- it only shows up when you look at what the agent actually
did.

**Bottom line**: this assessment found real, actionable issues, tells you
exactly what to fix first, and is equally explicit about three classes of
attack technique it structurally cannot see in telemetry alone (Section 5)
-- so you can decide where to add compensating controls rather than assuming
a clean scan means a clean environment. Note that two of the four findings --
the over-privileged production-ledger mount (3.1) and the shadow server (3.2)
-- are **evidence read directly from your telemetry**, independent of whether
our detection rules are complete; they would stand even if every rule-based
detection in Section 4 evaded.

| Severity | Finding | Section |
|---|---|---|
| **CRITICAL** | Credential read + exfiltration via an over-privileged production-ledger mount | 3.1 |
| **HIGH** | Unlisted ("shadow") MCP server in production traffic | 3.2 |
| **HIGH** | Poisoned tool description (hidden instruction) in the expense-OCR integration | 3.3 |
| **MEDIUM** | Path traversal attempt via a file-access tool | 3.4 |

---

## 2. Your environment (AI Bill of Materials)

Built directly from NorthwindPay's submitted telemetry export -- every server
and tool observed, not a sample. Advertised-surface-complete: a tool a server
advertises but never gets called still appears, with a call count of zero,
so dormant/unused capability is visible too, not just active usage.

| Server | Trust boundary (evidence-based) | Sessions | Tools |
|---|---|---|---|
| `mcp-server-fetch` | Network egress -- can reach arbitrary URLs | 30 | 1 |
| `mcp-server-git --repository /app/workspace` | Git repository (read-write) | 30 | 3 |
| `mcp-server-time` | Pure compute, no data access | 20 | 1 |
| Filesystem: `/app/sandbox` | **Read-write, confirmed** (agent scratch space) | 70 | 9 |
| Filesystem: `/app/workspace` | **Read-only, confirmed** (a write attempt was observed and denied) | 152 | 9 |
| Filesystem: `/data/production-ledger` | **Read-write, confirmed** (a write call succeeded) | 41 | 9 |
| `@modelcontextprotocol/server-memory` | Local memory store, no filesystem/network | 20 | 3 |
| `expense-ocr` (custom) | Unclassified -- not one of our recognized baseline server types | 40 | 1 |
| `fx-rates` (custom) | Unclassified | 30 | 1 |
| `slack-connector` (custom) | Unclassified | 65 | 3 |
| `support-ticket-bot` (custom) | Unclassified | 32 | 2 |
| **`mcp-crm-lite` (unlisted / shadow)** | Unclassified -- **absent from your declared server inventory** | 8 | 1 |

"Read-write, confirmed" and "read-only, confirmed" are not guesses from a
naming convention -- they are built from an actual observed write-capable
call in your telemetry either succeeding or being denied. A server that
never attempted a write-capable call during the capture window is reported
as "unconfirmed," never silently assumed either way.

Custom, non-catalog servers (`expense-ocr`, `fx-rates`, `slack-connector`,
`support-ticket-bot`, `mcp-crm-lite`) render as "unclassified": our trust-
boundary classifier is grounded in a known baseline server catalog and
deliberately does not guess at servers it doesn't recognize -- an honest
"needs manual review" rather than a false sense of precision. This is
expected for any environment with internal/custom MCP servers and is not
itself a finding.

---

## 3. Findings, ranked by severity

### 3.1 CRITICAL -- Credential read + exfiltration via an over-privileged production-ledger mount

**What we found**: The filesystem connection backing your ledger-reporting
workflow is mounted directly against `/data/production-ledger` with write
access -- a `write_file` call from that persona succeeded during the capture
window, confirming real (not theoretical) write capability into production
settlement data. Separately, in the same capture window, a session against
that same mount read a file whose path matched a known sensitive-credential
pattern (`config/.env`); shortly after, a different session -- against your
support-ticket integration -- carried a database-connection-string-shaped
secret verbatim inside a ticket-note argument. Read and exfiltration,
observed back to back, on real (if fictional-for-this-sample) secret
material.

**Why it matters**: A reporting workflow that only needs to *read*
settlement summaries has standing write access to the same production data
it reports on, and in this capture window that same blast radius is where a
credential got read and then carried into an outbound-facing tool call. Even
setting aside whether this specific sequence was malicious or a misconfigured
test, the underlying exposure -- read-only reporting logic with de facto
write access to production financial data -- is a least-privilege violation
on its own.

**Evidence**: AI-BOM Section 2 (`/data/production-ledger`, confirmed
read-write); real detection-engine matches for a sensitive-suffix file read
(`config/.env`) and a secret-shaped value in a subsequent tool-call argument
(argument value withheld from this report by design -- see Section 6).

**Remediation**:
1. Re-mount the ledger-reporting persona's filesystem connection read-only;
   if a write path is genuinely required (e.g. writing annotated summaries),
   scope it to a separate, non-production output directory.
2. Rotate any credential material reachable from that mount immediately;
   treat this capture window's read as a real exposure regardless of intent.
3. Add an explicit deny-list or separate low-privilege identity for agent
   tool calls against `/data/production-ledger` distinct from the identity
   used for legitimate scratch/reporting output (contrast with the
   `/app/sandbox` mount in Section 2, which is *intentionally* read-write
   and does not carry this risk, because it holds no production data).

### 3.2 HIGH -- Unlisted ("shadow") MCP server in production traffic

**What we found**: `mcp-crm-lite`, a small customer-lookup bridge, appears in
your telemetry across 8 sessions but is **absent from the server inventory
you declared to us** for this assessment.

**Why it matters**: An MCP server nobody centrally approved or inventoried is
exactly the blind spot shadow-IT concerns describe, just at the agent-tooling
layer instead of the SaaS layer -- it may hold its own credentials, log
customer data outside your retention policy, or simply stop being maintained
by whoever stood it up.

**Remediation**: Identify the owner/origin of `mcp-crm-lite`, bring it
through the same intake/security review as every other integration in
Section 2, and decide explicitly whether to formally adopt, replace, or
decommission it. Add it to your declared inventory either way, so future
assessments diff against ground truth instead of re-discovering it.

### 3.3 HIGH -- Poisoned tool description in the expense-OCR integration

**What we found**: The `parse_receipt` tool advertised by your expense-OCR
integration carries a hidden instruction embedded in its description (an
HTML-comment block invisible in a typical chat UI, but present in the raw
text an LLM agent receives) directing an agent to also read a credential
file and include its contents in the tool's output, and to conceal that it
was doing so. This was present in every session that listed this server's
tools during the capture window (40 sessions observed).

**Why it matters**: This is "tool poisoning" -- one of the more consequential
MCP-specific attack patterns, because the agent doing the wrong thing is
following instructions it was explicitly told not to reveal, not
malfunctioning. A user or reviewer glancing at the tool's name and stated
purpose ("extract receipt fields") would see nothing wrong.

**Remediation**:
1. Pull the current advertised description/schema for `parse_receipt` from
   the live server and inspect it directly (not just this report) before
   deciding next steps.
2. Treat this integration as compromised until the responsible team confirms
   whether the description change was authorized -- if not, roll back to a
   known-good version and audit for any credential file reads the poisoned
   instruction may have already triggered.
3. Add tool-description integrity monitoring (hash-based) for every
   internal/custom MCP server, not only catalog ones -- Section 4 shows this
   project's rug-pull baseline-drift detector already exists for exactly
   this, and could be pointed at future captures of this same environment.

### 3.4 MEDIUM -- Path traversal attempt via a file-access tool

**What we found**: One session issued a file-read call with a path
containing `../../../etc/hosts` -- reaching outside the intended workspace
directory to a system file, via your shared-docs filesystem connection.

**Why it matters**: A file tool that accepts relative paths without
enforcing a root boundary can be walked outside its intended scope. Whether
this specific call was a deliberate probe or an agent following a
manipulated instruction, the underlying capability (unbounded relative-path
resolution) is the same either way.

**Remediation**: Confirm the filesystem server enforces a root-directory
boundary server-side (not merely client-side convention), and review
whether `/etc/hosts` or any other file reached this way exposed anything
sensitive.

---

## 4. Coverage evidence (this assessment's methodology)

This assessment is built on **four registered detection techniques**, each
backed by a real rule running through the Wazuh detection engine (never a
pattern match reimplemented in this report):

| Technique | What it catches | Status |
|---|---|---|
| Tool poisoning (hidden HTML-comment instructions in tool descriptions) | SAF-T1001 | Deployed |
| Path traversal via file-access tools | SAF-T1105 | Validated |
| Credential exfiltration (sensitive-file read + secret-shaped exfil) | SAF-T1502 | Deployed |
| Rug-pull / baseline drift (a tool's advertised description or a server's version silently changing) | SAF-T1201 | Deployed |

Every finding in Section 3 traces to one of these four techniques, or to the
AI-BOM's evidence-based trust-boundary classification (the over-privileged
mount and shadow-server findings). This is **not a general-purpose anomaly
detector** -- it is four specific, well-understood MCP/agentic attack
techniques, mapped against the OWASP MCP Top 10 taxonomy below. 5 of 10
categories currently have a mapped detection; the rest are named gaps, not
silently omitted:

| OWASP MCP category | Coverage |
|---|---|
| MCP01 -- Token/credential mismanagement | Mapped (SAF-T1502) |
| MCP02 -- Privilege escalation / scope creep | Not yet mapped |
| MCP03 -- Tool poisoning / rug pull / shadowing | Mapped (SAF-T1001, SAF-T1201) |
| MCP04 -- Supply chain | Mapped (SAF-T1001, SAF-T1201) |
| MCP05 -- Command injection | Not yet mapped |
| MCP06 -- Intent-flow subversion / prompt injection | Mapped (SAF-T1001, structural pattern only -- no semantic backend yet) |
| MCP07 -- Insufficient authentication | Not yet mapped |
| MCP08 -- Weak telemetry/logging | Mitigated as a logging control (the capture pipeline itself), not a detection rule |
| MCP09 -- Shadow MCP servers | Covered by BOM diffing (Section 2), not a scored detection rule |
| MCP10 -- Context over-sharing | Mapped (SAF-T1105, SAF-T1502) |

Reproduction and adversarial-evasion numbers behind each technique's
"Deployed"/"Validated" status are measured against this project's own
self-authored test corpus, not NorthwindPay's synthetic telemetry, and are reported
separately as a statement about the tooling, not about NorthwindPay's
environment -- see the full technical report (`northwindpay/
audit_report_run.md`) for those numbers in detail.

---

## 5. What this assessment cannot see

Credibility here comes from naming the blind spots precisely, not from a
clean-looking scorecard. Three attack patterns are **structurally
undetectable** by telemetry-based rule matching, regardless of how the rules
are tuned -- confirmed during this assessment's own validation, not merely
asserted:

1. **Behavior-only compromise with no advertised-metadata change.** A tool
   can start returning subtly wrong or manipulated results (e.g. a
   miscalculated rate or a silently filtered result set) while its
   advertised name, description, and schema never change at all. Nothing in
   the MCP protocol surface exposes runtime behavior for hashing or
   comparison -- there is no field to watch. **Compensating control**:
   periodic output spot-checks against an independent source, not telemetry
   monitoring.
2. **Base64 (or otherwise encoded) credential exfiltration.** The
   credential-exfiltration detection matches secret-shaped plaintext in a
   tool call's arguments; an encoded payload does not match that pattern by
   construction. **Compensating control**: egress-side content inspection
   (decoding common encodings before pattern-matching), or DLP tooling
   downstream of the MCP layer, not telemetry-only detection.
3. **Homoglyph-substituted hidden instructions.** The tool-poisoning
   detection matches specific Latin-alphabet keyword patterns; a hidden
   instruction spelled using visually identical characters from a different
   Unicode script evades it, the same way homoglyph domain spoofing evades
   naive URL matching. **Compensating control**: Unicode-normalization
   pre-processing on tool descriptions before any keyword-based review, or
   periodic manual/LLM-assisted review of raw tool description bytes.

None of these three were flagged as findings in Section 3 above, and none
were fabricated as caught -- this assessment's own validation process
(hand-built test cases of exactly these three types) confirmed the report
correctly stays silent on all three rather than producing a false sense of
detection.

**Additional structural limits**, stated plainly rather than buried:
- This assessment covers **four techniques**, not a general security review
  of your agent fleet's authorization model, network egress policy, or data
  governance.
- All matching runs through a real rule engine (Wazuh); reproduction/evasion
  numbers behind each technique are measured on this project's own test
  corpus, not on NorthwindPay's data, and are reported as a statement about
  the tooling, not a guarantee about your specific environment.
- A rug-pull-style baseline drift limited to a server's version string alone
  (no accompanying tool-description change) is reported at reduced severity,
  not as a headline finding, to avoid false-alarming on routine version
  bumps -- disclosed explicitly because this means a sufficiently narrow
  attack could hide at that same reduced-severity tier.

---

## 6. Appendix

- Full technical report (raw tool output, unedited): `northwindpay/
  audit_report_run.md`
- AI-BOM + shadow-server diff, machine-readable: `northwindpay/
  audit_report_run.json`
- This assessment's own validation against a sealed ground-truth manifest
  (recall/false-finding/honesty scoring): `northwindpay/
  ASSESSMENT-VALIDATION.md`
- No tool-call argument values, secrets, or bypass payloads appear anywhere
  in this document, by design (Section 3's evidence entries withhold
  matched secret values; Section 5 names attack classes without literal
  payload text).

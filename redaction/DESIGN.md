# Data minimization — design

## Correction notice (read this first)

An earlier version of this document and `redaction/redact.py` described a
**blocklist redaction** design ("replace the six recognized secret shapes,
leave everything else untouched") using language like *"no recoverable
secret bytes survive anywhere in the shipped file"* and *"without ever
sending us a real secret."* **Those claims were false and have been
retracted.** A blocklist that only recognizes six specific credential
shapes says nothing about a plaintext password, an email+SSN pair, a JWT,
an internal hostname, or any other secret/PII shape it wasn't written to
recognize — all of that survived, completely untouched, in the prior
design. Shipping that design to a real client under those claims would
have caused real client data loss.

This document now describes the corrected design: **data minimization by
allowlist**, not redaction by blocklist. The six-shape marker logic from
the prior design is kept — it still does real, useful work (it's why
`wazuh/local_rules.xml`'s credential-exfil rules still fire on the
minimized export) — but it is no longer the mechanism this project relies
on for the overall secrecy claim. The mechanism for that claim is now: **a
field either has a specific, named reason to survive, or it doesn't survive
in any recoverable form.** See `redaction/REDACTION-VALIDATION.md` for
proof this holds against the actual detection engine, and the "What this
does NOT claim" section below for the honest scope of what remains.

## The problem, precisely (unchanged from the original design)

`wazuh/local_rules.xml`'s credential-exfil rules pattern-match specific,
narrow SHAPES inside `tool_arguments` — six of them, no more. Meanwhile a
real client's telemetry can carry an open-ended variety of sensitive
content that has nothing to do with those six shapes: plaintext passwords,
employee PII, JWTs, internal hostnames, arbitrary application secrets. A
blocklist approach ("scan for known-bad shapes, redact those, ship
everything else") is structurally incapable of bounding that risk, because
the set of "everything else" is unbounded and unenumerable — the same
open-ended-list problem this project has already refused to chase for
tool-poisoning keyword evasion (E1) and path-traversal encodings, now
recognized in a new place (redaction/DESIGN.md's own prior version didn't
recognize it here, which was the defect).

## Decision: allowlist minimization, not blocklist redaction

Keep ONLY the fields the assessment (`framework/abom.py`,
`framework/audit_report.py`, `baseline/watch.py`, and `wazuh/
local_rules.xml`'s dynamic field references) actually consumes. Reduce
every other content-bearing field to a fixed, non-recoverable value
regardless of whether it happens to look sensitive — **you cannot leak
what you never transmit**, and this sidesteps needing to correctly
recognize every possible secret/PII shape in the first place.

### Allowlist derivation (traced directly from the four consumers, not guessed)

| Field | Kept because | Consumer |
|---|---|---|
| `session_id`, `timestamp`, `direction`, `method`, `message_id`, `server_command`, `label`, `scenario_id`, `task_id`, `generator` | pure metadata, never content | schema.json `required`, every consumer |
| `tool_name` | server/tool inventory, rule-matching (negate-lists), BOM | `abom.py`, `wazuh/local_rules.xml` |
| `tool_description_hash`, `server_version_hash` | AI-BOM inventory, rug-pull baseline drift | `abom.py`, `baseline/watch.py` |
| `tool_arguments.path` / `raw.params.arguments.path` | THE detection signal for 100101 (sensitive suffix) and 100108 (traversal) | `wazuh/local_rules.xml` `<field name="tool_arguments.path">` |
| any scalar (bool/int/float/null) anywhere | cannot carry free-text content; specifically `raw.result.isError` (write-evidence classification) and `tool_arguments.dryRun` (dry-run exclusion) | `abom.py`'s `_classify_filesystem()`/`_is_dry_run_edit()` |
| `raw.result.tools` | THE detection signal for 100102 (tool poisoning) + exact input to `tool_description_hash` | `wazuh/local_rules.xml`, `proxy/hashing.py`'s recipe |
| `raw.result.serverInfo` | exact input to `server_version_hash` | `proxy/hashing.py`'s recipe |
| `raw.result.protocolVersion`/`capabilities`, `raw.params.protocolVersion`/`capabilities`/`clientInfo`/`name` | fixed protocol-negotiation fields, never client content | (kept for schema fidelity; not read by any rule) |
| presence (not content) of `raw.error` | write-evidence classification checks `bool(raw.get("error"))` | `abom.py` |

**Everything else is minimized**, regardless of key name, regardless of
whether it "looks" sensitive: every other `tool_arguments` value,
`result_summary`, and every other key under `raw.result`/`raw.error`
(response `content` blocks, `structuredContent`, error message text, and
any application-specific argument key a custom server happens to define).
This is deliberately not scoped to "the five named exfil-hop argument keys
(data/payload/content/body/message)" — a custom server's own argument name
carries the identical risk, and the allowlist above has no detection reason
to trust any key name it isn't listed for.

### What survives as a marker vs. a placeholder

A non-allowlisted STRING value is reduced to one of two things, never the
original text:

- If it contains one of the six credential shapes 100103–107 key on
  (`DATABASE_URL=`, `API_KEY=`, a `BEGIN ... PRIVATE KEY` header, an `sk-`
  key, a `postgres(ql)?://` URL, an `AKIA...` id), it becomes a **fixed
  canonical marker** for that shape (e.g. `DATABASE_URL=REDACTED`) — a
  constant, never derived from the input, carrying zero bits of the
  original value. This is what keeps 100101/100103–107 firing identically
  on the minimized export.
- Otherwise, it becomes a **generic placeholder**
  (`GENERIC_CONTENT_PLACEHOLDER`) with no relationship to the original
  content at all.

Critically, **the entire value is replaced, not just the matched span**: a
plaintext password sitting in the same sentence as a matched
`DATABASE_URL=` assignment is discarded along with everything else in that
value, not incidentally preserved the way the prior substring-replace
design would have left it. This is the actual fix — the prior design's
partial, in-place substitution was exactly why non-six-shape content
survived untouched.

## What is preserved verbatim (the complete list, no more)

Exactly the "kept because" column above. Two of these carry a disclosed
residual risk, not eliminated by this design:

- **`tool_arguments.path`** can itself reveal a username or internal
  directory structure (e.g. `backups/alex.smith@example.com/settings.json`).
  This is unavoidable without breaking 100101/100108's detection signal,
  which IS the path string — see `redaction/redact.py --report`'s
  residual-disclosure output, which flags exactly this case.
- **`raw.result.tools`** (tool descriptions/schemas) is free text authored
  by whoever wrote the MCP server, not the client's own runtime secrets —
  but it is shipped verbatim, and a compromised/careless server could in
  principle put something sensitive in a tool description. Necessary for
  SAF-T1001 and hash stability; also covered by the residual-disclosure
  scan.

## Residual-disclosure report (`redaction/redact.py --report`)

Advisory, not a guarantee. Lists every field still carrying free-text
content after minimization (the table above) with occurrence counts, then
scans those specific surviving fields — NOT the whole record, since
everything else has already been minimized to a fixed constant — for five
common secondary secret/PII shapes this project's own detection rules do
not key on: email addresses, SSN-shaped numbers, JWT-shaped tokens, bearer
tokens, and generic `token=`/`secret=`/`password=` assignments. Anything
flagged is for **manual review before sending**, explicitly not an
automatic block — the client decides what to do with a flagged record. This
list of five patterns is itself not exhaustive and cannot be; it exists to
catch obviously-reviewable cases in the small number of fields that still
carry free text, not to re-introduce the same open-ended blocklist problem
this design otherwise avoids.

## What this design does NOT claim (read before relying on it)

- **This is not a general-purpose secret or PII scrubber.** It removes six
  specific credential shapes as detectable markers and minimizes every
  other content-bearing field to a non-content placeholder. It does not
  claim to recognize, and does not try to recognize, arbitrary secret/PII
  shapes in the fields it minimizes — it doesn't need to, because those
  fields are dropped regardless of content.
- **The client is the final authority on what leaves their environment.**
  This tool makes that decision tractable (a short residual-disclosure
  report instead of a raw multi-megabyte capture) — it does not make the
  decision for the client, and does not guarantee the decision is safe to
  skip.
- **`tool_arguments.path` and `raw.result.tools`/`serverInfo` are shipped
  verbatim, by design**, and can carry sensitive content of their own (a
  username in a path, an unusual tool description). Named above, flagged
  by the residual report where a heuristic catches it, never silently
  assumed safe.
- **Encoded (e.g. base64) secret content**, inside a field that IS
  minimized, is dropped along with everything else in that value (good) —
  but if it happened to be inside `tool_arguments.path` (not a realistic
  case for this project's own tool set, but not structurally impossible for
  an arbitrary custom server), it would survive verbatim like any other
  path content. Not separately handled; mirrors SAF-T1502's own disclosed
  known gap E8 in spirit (this project does not chase encoded-payload
  detection generally).

## Why this design, not the alternatives considered

- **Shape-preserving blocklist redaction (the prior design)** — rejected,
  retroactively: it correctly preserved detection but made zero attempt to
  bound what ELSE could survive, and its documentation overclaimed that it
  did. Superseded by this document.
- **Full deletion of every non-allowlisted field (not even a shape marker)**
  — rejected: this would also remove the six-shape signal 100103–107 need,
  breaking detection exactly the way the original blocklist design was
  built to avoid. The marker mechanism is kept specifically because it lets
  minimization and detection-preservation coexist.
- **Hashing non-allowlisted content instead of a placeholder** — rejected:
  a hash is not more useful than a fixed constant for a field nothing reads
  computationally, and inventing a "reversible-looking" artifact for
  content that is supposed to be gone risks false confidence that it's
  recoverable/auditable when it isn't meant to be (same reasoning the
  original six-shape design already used to reject hashing for the
  credential markers themselves).
- **An exhaustive PII/secret blocklist for the residual-disclosure scan**
  — rejected as the PRIMARY mechanism (used only as an advisory secondary
  pass): expanding the six shapes to fifty doesn't change that the set of
  possible secret shapes is unbounded; allowlisting the fields the
  assessment needs is the only approach that doesn't depend on
  successfully enumerating an open-ended list.

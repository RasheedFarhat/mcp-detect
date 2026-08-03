# MCP-DETECT telemetry log schema — v1

One JSON object per line (JSONL). Each line is one JSON-RPC 2.0 message observed
by the proxy, in either direction, enriched with capture metadata, stable
hashes, and labeling/provenance fields. This document plus `schema.json` is
meant to be adoptable on its own — you should not need to read the proxy's
source to reproduce this schema against your own MCP capture tooling.

The proxy does not interpret or mutate the JSON-RPC message itself — `raw` is
always the exact message object as it appeared on the wire. Everything else is
metadata the proxy derives for detection/lab/analysis/dataset-provenance
convenience.

## Fields

| Field | Type | Description |
|---|---|---|
| `session_id` | string (UUID) | Generated once per proxy process invocation. Constant for every line in a session. |
| `timestamp` | string (ISO 8601, UTC, `Z` suffix) | Wall-clock time the proxy observed the line, not when it was sent. |
| `direction` | string enum | `client_to_server` or `server_to_client`. |
| `method` | string \| null | JSON-RPC `method` field, if present (requests/notifications). `null` for plain responses. |
| `message_id` | string \| number \| null | JSON-RPC `id` field, if present. `null` for notifications. |
| `tool_name` | string \| null | Populated only when `method == "tools/call"`: the `params.name` of the tool being invoked. `null` otherwise. |
| `tool_arguments` | object \| null | Populated only when `method == "tools/call"`: `params.arguments` verbatim. `null` otherwise. |
| `result_summary` | string \| null | For `server_to_client` responses: a short, truncated (256 char) stringified preview of `result` or `error`. `null` for requests/notifications. Exists so a human/detection can eyeball outcome without parsing `raw`. |
| `server_command` | string | The wrapped server command line the proxy launched, e.g. `npx -y @modelcontextprotocol/server-filesystem /path/to/sandbox`. Constant for every line in a session. |
| `tool_description_hash` | string \| null | Stable hash of the tool's advertised definition (see recipe below). Populated only on `tools/call`-related records, mirroring `tool_name`/`tool_arguments`; `null` otherwise, and also `null` if a `tools/call` happens before any `tools/list` response was ever observed this session. |
| `server_version_hash` | string \| null | Stable hash identifying the exact server the proxy is talking to (see recipe below). Populated on every record from the moment `initialize`'s response reveals `serverInfo` onward (including that very response record itself) — `null` only for records strictly before it, i.e. at most the `initialize` request. |
| `label` | string enum | `benign` or `malicious`. Ground truth for the session, supplied by whatever harness invoked the proxy (corpus generator, attack harness) — never inferred by the proxy itself. |
| `scenario_id` | string | Coarse scenario identifier. The Phase 1 benign corpus always uses `"benign"`; later phases use named attack scenario identifiers (e.g. `"credential_exfil_via_read"`). |
| `task_id` | string | Identifies the specific task template the session ran, e.g. `"read_and_summarize_file"`. Distinct sessions running the *same* task template share a `task_id` but have different `session_id`s. |
| `generator` | string | Name/version stamp of the capture tool that produced this record, e.g. `"mcp-detect-proxy/1.1"`. Lets a consumer of the frozen corpus tell which capture-logic version produced a given record. |
| `raw` | object | The complete, unmodified JSON-RPC 2.0 message as parsed from the wire. Source of truth; every other field above is derived from this (except `label`/`scenario_id`/`task_id`/`generator`, which are session-level provenance, not derived from wire content). On a `proxy_anomaly` marker record (below), `raw` is the minimal placeholder `{"jsonrpc": "2.0"}` — there is no real wire message to carry, only the `jsonrpc` key `raw`'s own schema requires. |
| `proxy_anomaly` | object, **absent** on every real record | Present *only* on a proxy-synthesized marker record: `{"reason": "invalid_json" \| "non_object_json", "byte_length": <int>}`. Optional, not required — existing captures without this field remain valid unchanged. See "Unparseable/non-JSON-RPC lines" below. |

## Hash canonicalization recipe

Both `tool_description_hash` and `server_version_hash` are computed the same
way, over different input objects. This recipe is language-agnostic — any
implementation that follows it produces byte-identical hashes for the same
logical input:

1. Recursively normalize every string value in the input object to Unicode
   Normalization Form C (NFC). This makes two strings that are visually and
   semantically identical but differently encoded (e.g. a precomposed é vs.
   `e` + combining acute accent) hash the same.
2. Serialize the normalized object to JSON with:
   - Object keys sorted lexicographically by Unicode code point, at every
     nesting level.
   - No insignificant whitespace: `,` between items, `:` between key and
     value, nothing else.
   - All non-ASCII characters escaped (`\uXXXX`) — the serialized string must
     be pure ASCII, so hashing is not sensitive to output-encoding choices.
3. Compute SHA-256 over the UTF-8 bytes of that serialized string.
4. Encode the digest as lowercase hex, prefixed `sha256:` — e.g.
   `sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`.

This is implemented in `lab/proxy/hashing.py` (`stable_hash`), which is the
reference implementation and includes a self-test
(`python3 lab/proxy/hashing.py`) asserting stability under key reordering and
Unicode normalization-form differences.

**`tool_description_hash` input**: `{"name": <tool.name>, "description":
<tool.description>, "inputSchema": <tool.inputSchema>}`, taken verbatim from
the tool's entry in a `tools/list` response, before any client-side
modification. `description`/`inputSchema` are included as-is (`null` if
absent) — deliberately broader than hashing the description text alone,
since a rug-pull can also silently change a tool's input schema (e.g.
quietly adding a new sensitive parameter) without touching its description.

**`server_version_hash` input**: `{"server_name": <serverInfo.name>,
"server_version": <serverInfo.version>, "server_command": <the exact command
line the proxy launched, verbatim>}`, taken from `initialize`'s response.
Including `server_command` means a server swapped out under an identical
`serverInfo` but launched via a different resolved package/version string
would still be visible as a different `server_version_hash` in some cases
(not all — a resolved version isn't always part of the launch command), which
is a deliberate best-effort widening, not a guarantee of detecting every
substitution.

## v0 → v1 migration

- `tool_description_hash` and `server_version_hash` are no longer reserved
  placeholders — they are computed, real values as of v1 (see recipe above).
  A v0 consumer that treated them as always-`null` will see non-null values
  now; check for `null` explicitly rather than assuming absence.
- Four new required fields: `label`, `scenario_id`, `task_id`, `generator`.
  A v0 JSONL file will not validate against `schema.json` v1 — these fields
  did not exist in v0 and have no defined default.
- No fields were removed or renamed.

## v1 → v1.1: `proxy_anomaly` (non-breaking addition)

The MCP stdio transport is newline-delimited JSON, and the proxy's own
contract is byte-transparent forwarding: every line it receives is
written to the other side exactly as received, *before* any attempt to
parse or log it, regardless of whether that line turns out to be
well-formed. Prior to this addition, a line that failed that parse step
was forwarded transparently but left **zero trace in telemetry** — a
`stderr`-only warning for invalid JSON, and *no warning at all* (not
even to `stderr`) for valid JSON that wasn't a JSON-RPC object (a bare
array, number, string, etc.). During an adversarial capture, a
dropped/malformed message being silently invisible is a false-negative
hazard, not just a cosmetic gap — found and closed during a
2026-07-11 cleanup session, prior to a planned attack-run capture.

`proxy_anomaly` closes this: every line that isn't a well-formed
JSON-RPC object now produces exactly one additional telemetry record,
in-place in the stream (same chronological position the anomalous line
occurred at, relative to every other record), with `proxy_anomaly` set
to:

- `{"reason": "invalid_json", "byte_length": N}` — the line didn't
  parse as JSON at all.
- `{"reason": "non_object_json", "byte_length": N}` — the line parsed
  as valid JSON but wasn't a JSON-RPC object (e.g. `[1, 2, 3]`, `"hi"`,
  `42`, `null`) — previously the silent case, no trace anywhere.

**This is metadata only, by design, not a second verbatim sink**: the
line's actual bytes/content are never captured in `proxy_anomaly` or
anywhere else — only a reason code and the line's byte length. This
matters specifically because the whole point of this field is visibility
into an *unparseable* line, which during an adversarial capture could
itself carry attacker-controlled payload; logging it verbatim would
recreate exactly the sensitivity concern `tool_arguments` already carries
(see Notes below), for content this project can't even confirm is
well-formed. `raw` on a `proxy_anomaly` record is the minimal
`{"jsonrpc": "2.0"}` placeholder (see the `raw` field row above) for the
same reason.

**Additive, not a modification of the stream**: the proxy's byte-transparent
forwarding is unconditional and happens before any parse attempt — this
addition only changes what gets *logged*, never what gets *forwarded*.
A `proxy_anomaly` record sits alongside the normal records a session
produces; it never replaces one.

**Non-breaking**: `proxy_anomaly` is optional (not in `schema.json`'s
`required` list). Every capture frozen before this addition
(`data/benign_corpus_v2.jsonl`, `data/evasion_corpus_v1.jsonl`) validates
against the updated schema completely unchanged — none of their records
gain, lose, or need this field.

## Notes

- Field order in emitted JSON is not guaranteed; consumers should key by name.
- `tool_arguments` is logged verbatim and may contain sensitive data (e.g. a
  file path to a credential file). This is intentional — do not point this at
  a system handling real secrets without adding redaction.
- One line == one JSON-RPC message. Batched JSON-RPC arrays are not specially
  handled (the MCP stdio transport does not use them in practice).
- `label`/`scenario_id`/`task_id` are supplied per proxy invocation (CLI
  flags), not detected from traffic — the proxy has no way to know a
  session's ground truth on its own. Anyone re-generating or extending this
  corpus is responsible for invoking the proxy with correct values.

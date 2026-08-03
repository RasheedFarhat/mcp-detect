#!/usr/bin/env python3
"""Client-side DATA MINIMIZATION for schema-v1 telemetry (allowlist, not
blocklist).

Design rationale: lab/redaction/DESIGN.md (read that first -- it also documents
a prior, superseded blocklist design and exactly why it was an honesty
defect, not just an implementation gap). Summary: this module does not try
to recognize and strip every possible secret/PII shape (an open-ended,
unwinnable list -- plaintext passwords, JWTs, emails, SSNs, internal
hostnames, arbitrary API tokens have no fixed shape a regex blocklist can
enumerate completely). Instead it keeps ONLY the fields the assessment
(`framework/abom.py`, `framework/audit_report.py`, `wazuh/local_rules.xml`)
actually consumes, and reduces every other content-bearing field to either
(a) a fixed, non-recoverable marker noting ONE OF SIX specific, narrow
credential shapes was present (so the two rules that key on those shapes
still fire), or (b) a generic "content removed" placeholder with zero
information from the original value. Nothing that isn't on the allowlist
below survives in any recoverable form -- you cannot leak what you never
transmit.

**This is not a general-purpose secret or PII scrubber, and it does not
guarantee no sensitive data survives.** `tool_arguments.path` and
`raw.result.tools`/`serverInfo` are preserved VERBATIM by design (they are
themselves the detection signal or the hash input the assessment needs) --
a path can reveal a username, a tool description is server-operator-
authored free text. `lab/redaction/redact.py --report` (see `build_residual_
report()` below) lists exactly what still carries free-text content and
flags anything in it that looks like a secondary secret/PII shape
(email, SSN, JWT, bearer token, generic token assignment) for manual
review -- advisory only, a best-effort heuristic pass, never a guarantee.
**The client is the final authority on what leaves their environment**;
this tool's job is to make that review tractable, not to replace it.

This module is intentionally the only new code in this kit: capture itself
is `lab/proxy/proxy.py`, reused directly rather than reimplemented here.
This is a post-capture pass over an already-written JSONL file, run
entirely on the client's own machine, producing a SEPARATE minimized file.

Stdlib-only, no new runtime dependency, consistent with the rest of this
project (`docs/PHASE6-DESIGN.md`'s own disclosed PyYAML-avoidance reasoning
applies here too).

Usage:
  python3 lab/redaction/redact.py <input.jsonl> <output.jsonl>
  python3 lab/redaction/redact.py <input.jsonl> <output.jsonl> --report
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
if str(LAB_ROOT / "proxy") not in sys.path:
    sys.path.insert(0, str(LAB_ROOT / "proxy"))

from proxy import summarize  # noqa: E402 -- reused unmodified, never reimplemented
from hashing import sanitize_server_command as minimize_server_command  # noqa: E402

# ---------------------------------------------------------------------------
# The allowlist: exactly what framework/abom.py, framework/audit_report.py,
# lab/baseline/watch.py, and wazuh/local_rules.xml's dynamic <field name="...">
# references actually read, re-derived directly from those five files (not
# guessed). Everything else is minimized. See lab/redaction/DESIGN.md's
# "Allowlist derivation" section for the field-by-field trace.
# ---------------------------------------------------------------------------

# Top-level record fields: pure metadata/identifiers, never free-text
# content, always required by schema.json's own `required` list or read
# directly by the pipeline -- kept verbatim, untouched, always.
TOP_LEVEL_METADATA_FIELDS = {
    "session_id", "timestamp", "direction", "method", "message_id",
    "server_command", "tool_description_hash", "server_version_hash",
    "label", "scenario_id", "task_id", "generator", "tool_name",
}

# tool_arguments / raw.params.arguments: only "path" is needed verbatim
# (100101's sensitive-suffix match and 100108's traversal match both read
# tool_arguments.path directly, by field name, per wazuh/local_rules.xml).
# Every other key's value is minimized regardless of key name -- this is
# deliberately NOT scoped to just the five named exfil-hop keys
# (data/payload/content/body/message): a custom server's own argument name
# could carry the same risk, and the allowlist doesn't special-case key
# names it has no detection reason to trust.
PRESERVED_ARGUMENT_KEYS = {"path"}

# raw.result: `tools` (SAF-T1001/100102's own signal + tool_description_hash's
# exact input) and `serverInfo` (server_version_hash's exact input) MUST
# survive byte-for-byte -- redacting either silently invalidates hashes
# already captured or breaks tool-poisoning detection. `protocolVersion`/
# `capabilities` are fixed protocol-negotiation fields, never content.
# Everything else (response `content` blocks, `structuredContent`, etc.) is
# minimized -- no wazuh rule reads any of it (confirmed: grep
# `<field name=` in wazuh/local_rules.xml never references raw.result.content
# at all), so there is no detection reason to keep any of it, minimized or
# not, beyond the same six-shape-or-generic-placeholder treatment every
# other non-allowlisted value gets.
PROTECTED_RESULT_KEYS = {"tools", "serverInfo", "protocolVersion", "capabilities"}

# raw.params keys that are protocol negotiation (initialize request),
# never content -- kept verbatim.
PROTECTED_PARAMS_KEYS = {"name", "protocolVersion", "capabilities", "clientInfo"}

GENERIC_CONTENT_PLACEHOLDER = "[content removed by minimization -- not required for detection]"

# ---------------------------------------------------------------------------
# The six credential shapes wazuh/local_rules.xml rules 100103-100107 (and,
# for AKIA/postgres/sk-/PRIVATE KEY specifically, only those five siblings)
# key on. A string matching one of these gets reduced to ONLY the fixed
# marker below -- discarding everything else in the value, not just the
# matched span, so any OTHER content sitting alongside a matched secret
# (a plaintext password in the same sentence, say) is dropped too, not
# incidentally preserved the way a naive substring-replace would. If NONE
# match, the whole value is dropped to GENERIC_CONTENT_PLACEHOLDER instead
# -- either way, no original free text survives beyond a fixed constant.
#
# Deliberately mirrors wazuh/local_rules.xml verbatim (same six shapes, same
# re.IGNORECASE scope -- that rule's `(?i)` wraps its whole alternation). A
# parallel Python definition, not a shared import: Wazuh's rule is
# declarative PCRE2 in XML, nothing importable across languages/engines. If
# 100103-107 ever change, this list must be updated by hand to match.
# ---------------------------------------------------------------------------
def _private_key_marker(match: re.Match) -> str:
    # The rule requires the SPECIFIC kind word (OPENSSH/RSA/EC/DSA/PGP)
    # literally present, not a generic "PRIVATE KEY" -- must be captured
    # from the actual match, not hardcoded, or detection silently breaks
    # for this shape (caught by test_all_six_shapes_preserved_in_isolation).
    kind = match.group(1).upper()
    return f"BEGIN {kind} PRIVATE KEY-----\nREDACTED\n-----END {kind} PRIVATE KEY-----"


# (name, pattern, marker) -- marker is either a fixed string or a
# callable(re.Match) -> str for shapes whose rule-required marker depends
# on which alternative matched (PRIVATE_KEY_BLOCK's kind word).
SHAPE_RULES: list[tuple[str, re.Pattern, object]] = [
    ("DATABASE_URL_ASSIGNMENT", re.compile(r"DATABASE_URL\s*=\s*\S+", re.IGNORECASE), "DATABASE_URL=REDACTED"),
    ("API_KEY_ASSIGNMENT", re.compile(r"API_KEY\s*=\s*\S+", re.IGNORECASE), "API_KEY=REDACTED"),
    ("PRIVATE_KEY_BLOCK", re.compile(r"BEGIN (OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY", re.IGNORECASE),
     _private_key_marker),
    ("SK_STYLE_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{6,}", re.IGNORECASE), "sk-REDACTEDKEY"),
    ("POSTGRES_URL", re.compile(r"postgres(?:ql)?://", re.IGNORECASE), "postgresql://REDACTED"),
    ("AKIA_STYLE_ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE), "AKIA" + "X" * 16),
]

# ---------------------------------------------------------------------------
# Advisory-only secondary scan, used ONLY by build_residual_report() below --
# never by the minimization pass itself. These are heuristic, best-effort
# shapes for common secret/PII classes this project's detection rules do
# NOT key on (so minimize_value() never treats them specially) -- flagged
# for human review in the fields that DO still carry free text after
# minimization (tool_arguments.path, raw.result.tools/serverInfo,
# server_command, tool_name). This list is not, and cannot be, exhaustive.
# ---------------------------------------------------------------------------
PII_REVIEW_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("SSN_SHAPED", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("JWT_SHAPED", re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}")),
    ("GENERIC_TOKEN_ASSIGNMENT", re.compile(r"(?i)\b(?:token|secret|passwd|password)\s*[:=]\s*\S{4,}")),
]

# Fields (dotted paths from a record) that still carry free-text content
# after minimization -- what build_residual_report() scans and discloses.
SURVIVING_FREE_TEXT_FIELDS = [
    "server_command", "tool_name", "tool_arguments.path",
    "raw.result.tools", "raw.result.serverInfo",
]


def is_scalar_non_string(value) -> bool:
    """bool/int/float/None can never carry free-text secret/PII content --
    kept verbatim wherever encountered, without needing a per-key
    allowlist entry (covers e.g. tool_arguments.dryRun, raw.result.isError,
    which framework/abom.py reads directly for dry-run exclusion and
    write-evidence classification respectively)."""
    return value is None or isinstance(value, (bool, int, float))


def _resolve_marker(marker, match: re.Match) -> str:
    return marker(match) if callable(marker) else marker


def minimize_string(s: str) -> str:
    """A non-preserved string value is reduced to EITHER the marker(s) for
    whichever of the six credential shapes it contains (discarding all
    other original content in the same value, not just the matched span),
    OR, if none match, a generic placeholder that carries zero information
    from the original. Either way nothing beyond a small fixed constant
    survives."""
    markers = []
    for _, pattern, marker in SHAPE_RULES:
        m = pattern.search(s)
        if m:
            markers.append(_resolve_marker(marker, m))
    if markers:
        seen = dict.fromkeys(markers)  # de-dup, preserve first-seen order
        return " ".join(seen)
    return GENERIC_CONTENT_PLACEHOLDER


def minimize_value(value):
    """Recursively minimizes a value that is NOT on the allowlist. Scalars
    survive verbatim (they cannot carry free text); strings are reduced per
    minimize_string(); dicts/lists recurse."""
    if is_scalar_non_string(value):
        return value
    if isinstance(value, str):
        return minimize_string(value)
    if isinstance(value, dict):
        return {k: minimize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [minimize_value(v) for v in value]
    return value


def minimize_tool_arguments(args):
    if not isinstance(args, dict):
        return minimize_value(args)
    return {
        k: (v if k in PRESERVED_ARGUMENT_KEYS else minimize_value(v))
        for k, v in args.items()
    }


def minimize_raw_result(result):
    if not isinstance(result, dict):
        return minimize_value(result)
    return {
        k: (v if k in PROTECTED_RESULT_KEYS else minimize_value(v))
        for k, v in result.items()
    }


def minimize_raw_params(params):
    if not isinstance(params, dict):
        return minimize_value(params)
    out = {}
    for k, v in params.items():
        if k == "arguments":
            out[k] = minimize_tool_arguments(v)
        elif k in PROTECTED_PARAMS_KEYS:
            out[k] = v
        else:
            out[k] = minimize_value(v)
    return out


def minimize_error(error):
    """Preserves TRUTHINESS only (framework/abom.py's write-evidence
    classification checks `bool(raw.get("error"))`) -- content is always
    replaced by a fixed, non-empty marker so that truthiness check still
    evaluates identically, without carrying the original error message
    text (which could itself echo back sensitive tool-argument content)."""
    if error is None:
        return None
    return {"minimized": True}


def redact_record(record: dict) -> dict:
    """Pure function: raw telemetry record in, minimized record out. Never
    mutates the input. Named redact_record (not minimize_record) for
    continuity with existing callers/tests -- the behavior is data
    minimization per lab/redaction/DESIGN.md, not blocklist substitution."""
    record = dict(record)
    if isinstance(record.get("server_command"), str):
        record["server_command"] = minimize_server_command(record["server_command"])
    raw = dict(record.get("raw") or {})

    minimized_args = None
    if record.get("tool_arguments") is not None:
        minimized_args = minimize_tool_arguments(record["tool_arguments"])
        record["tool_arguments"] = minimized_args

    if isinstance(raw.get("params"), dict):
        if "arguments" in raw["params"] and minimized_args is not None:
            raw["params"] = dict(raw["params"])
            # Same computed value as tool_arguments above -- never
            # independently re-derived, so the two fields can never disagree.
            raw["params"]["arguments"] = minimized_args
            for k in list(raw["params"].keys()):
                if k not in ({"arguments"} | PROTECTED_PARAMS_KEYS):
                    raw["params"][k] = minimize_value(raw["params"][k])
        else:
            raw["params"] = minimize_raw_params(raw["params"])

    if "result" in raw:
        raw["result"] = minimize_raw_result(raw["result"])
    if "error" in raw:
        raw["error"] = minimize_error(raw["error"])

    record["raw"] = raw

    # Recomputed from the now-minimized raw, using lab/proxy/proxy.py's own
    # summarize() unmodified -- reflects the minimized content (so a human
    # reviewer sees e.g. the generic placeholder, not nothing) without ever
    # independently re-deriving or re-scanning original text. Mirrors
    # proxy.py's build_record() condition exactly.
    if raw.get("method") is None and ("result" in raw or "error" in raw):
        if "error" in raw:
            record["result_summary"] = "ERROR: " + summarize(raw["error"])
        else:
            record["result_summary"] = summarize(raw.get("result"))
    else:
        record["result_summary"] = None

    return record


def redact_lines(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        out.append(json.dumps(redact_record(record)))
    return out


# ---------------------------------------------------------------------------
# Residual-disclosure report -- advisory only, run before the client sends
# anything. Lists exactly which fields still carry free-text content in the
# minimized export (the allowlist survivors) and flags any of it matching a
# common secondary secret/PII shape this project's own detection rules do
# not key on. This is a best-effort heuristic pass over an inherently
# open-ended problem (see lab/redaction/DESIGN.md) -- it is NOT a guarantee that
# the minimized export contains no sensitive data, and says so.
# ---------------------------------------------------------------------------

def _get_path(record: dict, dotted: str):
    node = record
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def scan_record_for_review(record: dict) -> list[tuple[str, str, str]]:
    """Returns (field_path, pii_type, preview) for every PII_REVIEW_PATTERNS
    hit found in this minimized record's surviving free-text fields."""
    hits = []
    for field_path in SURVIVING_FREE_TEXT_FIELDS:
        value = _get_path(record, field_path)
        if value is None:
            continue
        text = value if isinstance(value, str) else json.dumps(value)
        for name, pattern in PII_REVIEW_PATTERNS:
            m = pattern.search(text)
            if m:
                preview = text[max(0, m.start() - 15):m.end() + 15]
                hits.append((field_path, name, preview))
    return hits


def build_residual_report(minimized_lines: list[str]) -> str:
    out = ["# Redaction residual-disclosure report\n"]
    out.append("**Advisory only -- not a guarantee.** This lists what still carries "
                "free-text content after minimization, and flags anything matching a "
                "common secondary secret/PII shape (email, SSN, JWT, bearer token, "
                "generic token assignment) this project's detection rules do not key "
                "on and this pass does not otherwise scan for. The client is the "
                "final authority on what leaves their environment -- review the "
                "flagged items below before sending.\n")

    records = [json.loads(l) for l in minimized_lines if l.strip()]
    field_counts: dict[str, int] = {f: 0 for f in SURVIVING_FREE_TEXT_FIELDS}
    for r in records:
        for f in SURVIVING_FREE_TEXT_FIELDS:
            v = _get_path(r, f)
            if v:
                field_counts[f] += 1

    out.append("## Fields carrying free-text content by design\n")
    out.append("| Field | Records with non-empty content | Why it survives |")
    out.append("|---|---|---|")
    why = {
        "server_command": "server/tool inventory (AI-BOM)",
        "tool_name": "server/tool inventory, rule matching",
        "tool_arguments.path": "the detection signal itself (100101/100108)",
        "raw.result.tools": "tool-poisoning signal (100102) + tool_description_hash input",
        "raw.result.serverInfo": "server_version_hash input",
    }
    for f, count in field_counts.items():
        out.append(f"| `{f}` | {count} | {why.get(f, '')} |")
    out.append("")

    all_hits = []
    for i, r in enumerate(records):
        for field_path, pii_type, preview in scan_record_for_review(r):
            all_hits.append((i, r.get("session_id", "?"), field_path, pii_type, preview))

    out.append(f"## Flagged for manual review before sending ({len(all_hits)} hit(s))\n")
    if not all_hits:
        out.append("_None found by this heuristic pass. This is not a guarantee "
                    "the export is free of sensitive data -- see the module "
                    "docstring._\n")
    else:
        out.append("| Record # | Session (short) | Field | Pattern | Preview |")
        out.append("|---|---|---|---|---|")
        for i, sid, field_path, pii_type, preview in all_hits:
            out.append(f"| {i} | `{str(sid)[:8]}...` | `{field_path}` | {pii_type} | `{preview}` |")
        out.append("")

    marker_names = [name for name, _, _ in SHAPE_RULES]
    marker_hits = {name: 0 for name in marker_names}
    for r in records:
        text = json.dumps(r)
        for name, pattern, _ in SHAPE_RULES:
            # Markers are constructed to still match their own originating
            # pattern (proven by test_all_six_shapes_preserved_in_isolation),
            # so re-matching the pattern against the MINIMIZED text counts
            # marker occurrences correctly regardless of whether that
            # shape's marker is a fixed string or match-dependent (the
            # private-key case, which embeds the captured kind word).
            marker_hits[name] += len(pattern.findall(text))
    out.append("## Six-shape markers present (informational -- already non-recoverable)\n")
    out.append("| Shape | Occurrences (as fixed markers, no original content) |")
    out.append("|---|---|")
    for name, count in marker_hits.items():
        out.append(f"| {name} | {count} |")
    out.append("")

    return "\n".join(out) + "\n"


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="raw schema-v1 telemetry JSONL (local, never transmitted)")
    parser.add_argument("output", help="minimized schema-v1 telemetry JSONL (review before sending)")
    parser.add_argument("--report", action="store_true",
                         help="also print a residual-disclosure report (see build_residual_report()) "
                              "to stderr -- advisory only, review before sending")
    args = parser.parse_args()

    lines = Path(args.input).read_text().splitlines()
    redacted = redact_lines(lines)
    Path(args.output).write_text("\n".join(redacted) + "\n")
    print(f"[redact] {len(redacted)} record(s) minimized: {args.input} -> {args.output}",
          file=sys.stderr)

    if args.report:
        print(build_residual_report(redacted), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())

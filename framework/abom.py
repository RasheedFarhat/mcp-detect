#!/usr/bin/env python3
"""AI Bill of Materials -- inventory of MCP servers, tools, versions, and
trust boundaries observed in a telemetry JSONL file (schema/schema.md v1).

This is deliberately NOT a Detection: it has no wazuh_rule/stateful backend,
goes through none of framework/compiler.py's five gates, and is not part of
the registry framework/registry.py loads. It is a registry-adjacent report
tool in the same family as coverage.py's --gaps-report / --owasp-map: reads
telemetry, aggregates, renders -- no live Wazuh stack needed, no rule
matching, nothing dynamic.

Every field aggregated here (server_command, server_version_hash, tool_name,
tool_description_hash) already exists in schema/schema.md v1 -- this module
adds no new capture surface, only a new aggregation over what the proxy
already emits. Output is hashes/names/counts, never raw tool_arguments/
result_summary -- sanitizer-friendly by construction (see
docs/STATE-OF-PROJECT.md's own disclosed schema.md warning that
tool_arguments may carry sensitive data verbatim; this tool never reads it).

The tool inventory is advertised-surface-complete, not called-only: every
tools/list response's raw.result.tools (the same field 100102/SAF-T1001's
own rule reads) is ingested alongside tools/call records, so a tool a
server advertises but that is never called still appears, with a
zero call_count and a tool_description_hash computed directly from the
advertised entry (proxy/hashing.py's tool_description_hash recipe -- the
same recipe a tools/call record's own field already used, just computed
here instead of read off a record that may not exist for an uncalled
tool). This was a real, disclosed gap in an earlier version of this module
(docs/STATE-OF-PROJECT.md) -- fixed, not a design choice being described
after the fact.

Trust-boundary classification is a small, explicit, pattern-matched table
(TRUST_BOUNDARY_RULES below), not inferred. An observed server_command that
matches none of the patterns is reported as `"unknown"` -- an honest,
explicit "needs manual classification" state, never silently defaulted to
either "trusted" or "untrusted". This is the same discipline
framework/compiler.py's gates use: an unclassified state is a named gap, not
a guess.

**Filesystem ro/rw is evidence-based, not guessed from server_command --
a real bug fix, not a design refinement.** A prior version of this
classifier special-cased the literal substring `"sandbox"` in the path
(this project's own scratch-directory naming convention) to mean
read-write, anything else matching `server-filesystem` to mean read-only.
Found wrong during a live capture against real public MCP servers
(2026-07-11): a genuinely read-write scratch directory not named
`sandbox` was confidently mis-classified as read-only. Worse, the
underlying assumption doesn't hold at all --
`@modelcontextprotocol/server-filesystem` advertises the identical
14-tool schema (including `write_file`/`edit_file`/`move_file`/
`create_directory`) regardless of whether the mount is actually
writable, confirmed empirically against this project's own frozen
`data/benign_corpus_v2.jsonl`: its `/app/workspace` (Docker `:ro` bind
mount) and `/app/sandbox` (rw) servers advertise byte-identical tool
lists. Advertised surface cannot distinguish ro/rw for this server
family at all. `_classify_filesystem()` instead requires observed
evidence -- did a write-capable call's response actually succeed or get
denied (`raw.result.isError`, correlated back to its request via
`(session_id, message_id)` since responses never carry `tool_name`
themselves) -- and renders an honest "unconfirmed" state (not a guessed
ro or rw) when no write-capable tool was ever called in the capture at
all.

Shadow-server detection (--known-good) diffs the observed server_command set
against a client-declared known-good BOM (a JSON file: {"servers": [...]}).
Anything observed that isn't in the known-good list is a shadow-MCP-server
candidate (OWASP MCP09) -- the cheapest possible instance of that category,
built entirely from telemetry this project already captures. This is a
detection-adjacent capability, not a registered Detection with measured
recall/FP -- named as exactly that in framework/coverage.py's OWASP gap-map
(MCP09's NONE-row note), not oversold as equivalent to a wazuh-logtest-backed
rule.

Usage:
  python3 framework/abom.py <telemetry.jsonl>                        JSON to stdout
  python3 framework/abom.py <telemetry.jsonl> --markdown             rendered table
  python3 framework/abom.py <telemetry.jsonl> --known-good bom.json  + shadow-server diff
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "proxy") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "proxy"))

from hashing import tool_description_hash as compute_tool_description_hash  # noqa: E402
from framework.rendering import markdown_text  # noqa: E402


@dataclass
class TrustBoundary:
    label: str
    filesystem_access: str | None  # "ro" | "rw" | None
    network_egress: bool
    evidence: dict | None = None  # populated only for evidence-based classifications (filesystem)

    def as_dict(self) -> dict:
        d = {
            "label": self.label,
            "filesystem_access": self.filesystem_access,
            "network_egress": self.network_egress,
        }
        if self.evidence is not None:
            d["evidence"] = self.evidence
        return d


UNKNOWN_BOUNDARY = TrustBoundary(label="unknown -- needs manual classification",
                                  filesystem_access=None, network_egress=False)

# Filesystem write-capable tool names for @modelcontextprotocol/server-filesystem
# -- used only to correlate a call's response (isError) back to real ro/rw
# evidence, never to guess ro/rw from whether these names were merely
# advertised (see the module docstring: advertised surface is identical
# for ro and rw mounts of this server).
FILESYSTEM_WRITE_TOOLS = {"write_file", "edit_file", "move_file", "create_directory"}


def _is_dry_run_edit(tool_name: str, tool_arguments: dict | None) -> bool:
    """edit_file's own inputSchema supports dryRun: true -- a preview/diff
    mode that returns isError=false with real diff content WITHOUT ever
    writing to disk. Confirmed against data/benign_corpus_v2.jsonl's own
    /app/workspace (Docker `:ro` mount) session: one such dry-run call
    returned success while the same session's 29 real (non-dry-run)
    edit_file attempts were all denied -- naively counting the dry-run's
    isError=false as write evidence would have mis-classified a genuinely
    read-only mount as read-write. A dry-run call proves nothing about
    real write permission either way, so it is excluded from evidence
    entirely (neither success nor denial), not counted as either."""
    return tool_name == "edit_file" and (tool_arguments or {}).get("dryRun") is True


def _classify_filesystem(write_evidence: dict) -> TrustBoundary:
    evidence = dict(write_evidence) if write_evidence else None
    if any(counts.get("success", 0) > 0 for counts in write_evidence.values()):
        return TrustBoundary(
            "filesystem (read-write mount, confirmed -- an observed write-capable call succeeded)",
            "rw", False, evidence=evidence)
    if any(counts.get("denied", 0) > 0 for counts in write_evidence.values()):
        return TrustBoundary(
            "filesystem (read-only mount, confirmed -- an observed write-capable call was denied)",
            "ro", False, evidence=evidence)
    return TrustBoundary(
        "filesystem (read/write access unconfirmed -- no write-capable tool call observed in "
        "this capture; this server always advertises write tools regardless of actual mount "
        "permissions, so advertised surface alone cannot tell ro from rw)",
        None, False, evidence=evidence)


# Ordered (pattern, TrustBoundary | None) pairs, first match wins. Patterns are
# grounded in this project's own pinned server set (README.md "Pinned
# versions" / data/benign_corpus_v2.summary.md "By server") -- not a generic
# guess at what MCP servers might exist. A client environment will have
# servers this table doesn't recognize; that is exactly what the "unknown"
# fallback is for, not a bug to silently patch around per-deployment.
# `None` is a sentinel meaning "resolve via _classify_filesystem() using
# observed evidence, not a static TrustBoundary" -- currently only the
# filesystem entry needs this; every other pattern's boundary is a fixed,
# structural property of the server itself (time/memory never touch the
# filesystem or network at all regardless of usage; fetch always has
# network egress by design), not something usage evidence could change.
TRUST_BOUNDARY_RULES: list[tuple[re.Pattern, TrustBoundary | None]] = [
    (re.compile(r"server-filesystem"), None),
    (re.compile(r"mcp-server-git"),
     TrustBoundary("git repository (read-write)", "rw", False)),
    (re.compile(r"server-memory"),
     TrustBoundary("local memory store (no filesystem/network)", None, False)),
    (re.compile(r"mcp-server-time"),
     TrustBoundary("pure compute (no data access)", None, False)),
    (re.compile(r"mcp-server-fetch"),
     TrustBoundary("network egress -- can reach arbitrary URLs", None, True)),
]


def classify_trust_boundary(server_command: str, write_evidence: dict | None = None) -> TrustBoundary:
    for pattern, boundary in TRUST_BOUNDARY_RULES:
        if pattern.search(server_command):
            return _classify_filesystem(write_evidence or {}) if boundary is None else boundary
    return UNKNOWN_BOUNDARY


@dataclass
class ServerEntry:
    server_command: str
    server_version_hashes: set = field(default_factory=set)
    session_ids: set = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None
    tool_calls: dict = field(default_factory=lambda: defaultdict(int))
    tool_description_hashes: dict = field(default_factory=lambda: defaultdict(set))
    write_evidence: dict = field(default_factory=lambda: defaultdict(lambda: {"success": 0, "denied": 0}))

    def as_dict(self) -> dict:
        boundary = classify_trust_boundary(self.server_command, self.write_evidence)
        return {
            "server_command": self.server_command,
            "server_version_hashes": sorted(self.server_version_hashes),
            "session_count": len(self.session_ids),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "trust_boundary": boundary.as_dict(),
            "tools": {
                name: {
                    "call_count": count,
                    "tool_description_hashes": sorted(self.tool_description_hashes[name]),
                }
                for name, count in sorted(self.tool_calls.items())
            },
        }


def build_bom(lines: list[str]) -> dict:
    servers: dict[str, ServerEntry] = {}
    # (session_id, message_id) -> (tool_name, server_command) for a
    # write-capable filesystem call awaiting its response -- responses never
    # carry tool_name themselves (schema/schema.md: populated only on the
    # tools/call request record), so this is the only way to correlate a
    # call's real outcome back to the tool that produced it.
    pending_write_calls: dict[tuple, tuple[str, str]] = {}
    for line in lines:
        r = json.loads(line)
        cmd = r.get("server_command")
        if not cmd:
            continue
        entry = servers.setdefault(cmd, ServerEntry(server_command=cmd))
        entry.session_ids.add(r["session_id"])
        ts = r.get("timestamp")
        if ts:
            if entry.first_seen is None or ts < entry.first_seen:
                entry.first_seen = ts
            if entry.last_seen is None or ts > entry.last_seen:
                entry.last_seen = ts
        if r.get("server_version_hash"):
            entry.server_version_hashes.add(r["server_version_hash"])

        # A tools/list response -- identified the same way 100102/SAF-T1001's
        # own rule reads it (raw.result.tools), not by `method` (null on every
        # response, per schema/schema.md). Every advertised tool is recorded
        # here with a zero-or-observed call count, computing its description
        # hash directly from the advertised entry (proxy/hashing.py's own
        # tool_description_hash recipe -- byte-identical to what a tools/call
        # record's own tool_description_hash field would carry) -- available
        # even when the tool is never called, unlike that field.
        advertised = ((r.get("raw") or {}).get("result") or {}).get("tools")
        if isinstance(advertised, list):
            for tool in advertised:
                if not isinstance(tool, dict) or not tool.get("name"):
                    continue
                name = tool["name"]
                entry.tool_calls.setdefault(name, 0)
                h = compute_tool_description_hash(name, tool.get("description"), tool.get("inputSchema"))
                entry.tool_description_hashes[name].add(h)

        if r.get("method") == "tools/call" and r.get("tool_name"):
            entry.tool_calls[r["tool_name"]] += 1
            if r.get("tool_description_hash"):
                entry.tool_description_hashes[r["tool_name"]].add(r["tool_description_hash"])
            if r["tool_name"] in FILESYSTEM_WRITE_TOOLS and not _is_dry_run_edit(r["tool_name"], r.get("tool_arguments")):
                pending_write_calls[(r["session_id"], r.get("message_id"))] = (r["tool_name"], cmd)

        # A response to a pending write-capable call -- resolve real ro/rw
        # evidence from raw.result.isError (tool-level failure) or a bare
        # raw.error (JSON-RPC-level failure). No-op for every other
        # response (tools/list responses, non-write-tool calls) since their
        # (session_id, message_id) was never registered as pending above.
        if r.get("direction") == "server_to_client" and r.get("method") is None:
            pending = pending_write_calls.pop((r["session_id"], r.get("message_id")), None)
            if pending:
                tool_name, call_cmd = pending
                raw = r.get("raw") or {}
                failed = bool(raw.get("error")) or bool((raw.get("result") or {}).get("isError"))
                servers[call_cmd].write_evidence[tool_name]["denied" if failed else "success"] += 1

    servers_out = {cmd: e.as_dict() for cmd, e in sorted(servers.items())}
    return {
        "servers": servers_out,
        "server_count": len(servers_out),
        "tool_count": sum(len(e["tools"]) for e in servers_out.values()),
        "session_count": len({sid for e in servers.values() for sid in e.session_ids}),
    }


def diff_shadow_servers(bom: dict, known_good_path: Path) -> list[str]:
    """Anything observed whose server_command isn't in the client-declared
    known-good list is a shadow-MCP-server candidate (OWASP MCP09). The
    known-good file format is deliberately minimal: {"servers": ["<exact
    server_command string>", ...]} -- exact-string match, not fuzzy, so a
    false "not shadow" never happens by accident; a version-string change on
    an already-known server (e.g. a legitimate npm bump) WILL show up here
    too, same honestly-named limitation rug-pull's baseline drift already
    carries (docs/STATE-OF-PROJECT.md's E10) -- not silently different
    behavior for a superficially similar problem."""
    known_good = set(json.loads(known_good_path.read_text()).get("servers", []))
    return sorted(cmd for cmd in bom["servers"] if cmd not in known_good)


def render_markdown(bom: dict, shadow_candidates: list[str] | None = None) -> str:
    out = ["# AI Bill of Materials\n"]
    out.append(f"**{bom['server_count']} servers, {bom['tool_count']} distinct tools, "
                f"{bom['session_count']} sessions observed.**\n")
    out.append("| server_command | trust boundary | sessions | tools | version hash(es) |")
    out.append("|---|---|---|---|---|")
    for cmd, e in bom["servers"].items():
        boundary = e["trust_boundary"]
        b_label = boundary["label"]
        if shadow_candidates and cmd in shadow_candidates:
            b_label = f"**SHADOW CANDIDATE** -- {b_label}"
        n_versions = len(e["server_version_hashes"])
        out.append(f"| {markdown_text(cmd)} | {b_label} | {e['session_count']} | "
                   f"{len(e['tools'])} | {n_versions} |")
    out.append("")
    for cmd, e in bom["servers"].items():
        out.append(f"## {markdown_text(cmd)}\n")
        out.append(f"Trust boundary: **{e['trust_boundary']['label']}** "
                   f"(filesystem: {e['trust_boundary']['filesystem_access']}, "
                   f"network egress: {e['trust_boundary']['network_egress']})\n")
        out.append("| tool | calls | description hash(es) |")
        out.append("|---|---|---|")
        for tname, t in e["tools"].items():
            out.append(f"| {markdown_text(tname)} | {t['call_count']} | "
                       f"{len(t['tool_description_hashes'])} distinct |")
        out.append("")
    if shadow_candidates:
        out.append("## Shadow-server candidates (MCP09)\n")
        if shadow_candidates:
            for cmd in shadow_candidates:
                out.append(f"- {markdown_text(cmd)}")
        else:
            out.append("_None -- every observed server_command matched the known-good BOM._")
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("telemetry", help="path to a telemetry JSONL file (schema v1)")
    parser.add_argument("--known-good", help="path to a known-good BOM JSON file "
                                              "({\"servers\": [<server_command>, ...]}) "
                                              "-- enables shadow-server (MCP09) diffing")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="emit JSON (default)")
    fmt.add_argument("--markdown", action="store_true", help="emit a rendered markdown report")
    args = parser.parse_args()

    lines = Path(args.telemetry).read_text().splitlines()
    lines = [l for l in lines if l.strip()]
    bom = build_bom(lines)

    shadow_candidates = None
    if args.known_good:
        shadow_candidates = diff_shadow_servers(bom, Path(args.known_good))

    if args.markdown:
        print(render_markdown(bom, shadow_candidates))
        return 0

    out = dict(bom)
    if shadow_candidates is not None:
        out["shadow_candidates"] = shadow_candidates
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

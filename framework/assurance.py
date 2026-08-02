#!/usr/bin/env python3
"""Control-oriented analysis for MCP telemetry.

The Wazuh rules in this project remain useful, inspectable indicators, but
classic field-by-field rules cannot normalize nested values, walk arbitrary
argument keys, or correlate a sensitive read with a later outbound action.
This module supplies that missing analysis layer with only the Python standard
library.  It never claims that an indicator proves compromise and it never
copies secret-bearing values into its output.

The analyzer intentionally separates three questions:

* indicator: did the captured activity contain a risky shape?
* control: which preventive boundary should stop that activity?
* verification: what must an analyst test before calling the control effective?

This is report-side analysis, not a runtime sandbox.  Runtime enforcement still
belongs in the reviewed MCP host/server and its operating-system boundary.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import posixpath
import re
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import unquote

MAX_DECODE_PASSES = 3
MAX_TREE_DEPTH = 16
MAX_TREE_NODES = 4096
MAX_DECODE_BYTES = 16 * 1024

# A deliberately small, reviewable skeleton for common Greek/Cyrillic
# confusables used in security keywords. NFKC alone does not fold these
# characters. This widens an indicator; it is not presented as a complete
# implementation of the Unicode confusables data set.
CONFUSABLE_ASCII = str.maketrans({
    "Α": "A", "А": "A", "Β": "B", "В": "B", "Ε": "E", "Е": "E",
    "Η": "H", "Н": "H", "Ι": "I", "І": "I", "Ј": "J", "Κ": "K",
    "К": "K", "Μ": "M", "М": "M", "Ν": "N", "О": "O", "Ο": "O",
    "Ρ": "P", "Р": "P", "Ѕ": "S", "Τ": "T", "Т": "T", "Χ": "X",
    "Х": "X", "Υ": "Y", "Ү": "Y", "а": "a", "е": "e", "о": "o",
    "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
})

DIRECTIVE_PATTERNS = (
    re.compile(r"\b(system|developer|hidden)\s+(instruction|message|prompt)\b", re.I),
    re.compile(r"\b(do not|never)\s+(mention|reveal|disclose|tell)\b", re.I),
    re.compile(r"\b(keep|stay)\s+(quiet|silent)\b", re.I),
    re.compile(r"\bsilently\b", re.I),
    re.compile(r"\b(before|after)\s+(you\s+)?(return|respond|answer)\b", re.I),
    re.compile(r"\b(call|invoke|run|execute)\s+[a-z0-9_.-]+", re.I),
    re.compile(r"\b(read|open|send|upload|append)\b.{0,80}\b(secret|credential|token|\.env|id_rsa)\b", re.I | re.S),
)

SECRET_PATTERNS = (
    re.compile(r"postgres(?:ql)?://[^\s]+", re.I),
    re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----", re.I),
    re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:API_KEY|DATABASE_URL|CLIENT_SECRET|ACCESS_TOKEN)\s*[:=]\s*\S+", re.I),
)

SENSITIVE_PATH_PATTERNS = (
    re.compile(r"(?:^|/)\.env(?:\.[^/]*)?$", re.I),
    re.compile(r"(?:^|/)(?:id_rsa|id_ed25519)$", re.I),
    re.compile(r"(?:^|/)\.aws/credentials$", re.I),
    re.compile(r"(?:^|/)etc/(?:passwd|shadow|gshadow|sudoers|krb5\.keytab)$", re.I),
    re.compile(r"(?:^|/)etc/ssh/", re.I),
    re.compile(r"(?:^|/)root/", re.I),
    re.compile(r"(?:^|/)\.ssh/(?:authorized_keys|known_hosts|config)$", re.I),
    re.compile(r"^/proc/(?:self|[0-9]+)/environ$", re.I),
    re.compile(r"^/(?:var/run|run)/secrets/", re.I),
)

READ_TOOL_HINTS = ("read", "get_file", "download", "fetch_file", "open_file")
OUTBOUND_TOOL_HINTS = (
    "send", "post", "upload", "publish", "message", "email", "webhook",
    "request", "ticket", "note", "comment", "write", "create",
)


@dataclass(frozen=True)
class Indicator:
    indicator_id: str
    control_id: str
    severity: str
    summary: str
    session_id: str | None
    timestamp: str
    evidence: dict[str, Any]
    verification_status: str = "automated_indicator"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class BoundaryDecision:
    allowed: bool
    reason: str
    canonical_relative_path: str | None


def normalize_security_text(value: str) -> str:
    """Canonicalize a value for security analysis without mutating telemetry."""
    normalized = html.unescape(unicodedata.normalize("NFKC", value))
    normalized = "".join(
        char for char in normalized
        if unicodedata.category(char) != "Cf"
    )
    return normalized.translate(CONFUSABLE_ASCII)


def decode_transport_layers(value: str, max_passes: int = MAX_DECODE_PASSES) -> tuple[str, int]:
    """Apply bounded URL decoding, returning the canonical text and pass count."""
    current = normalize_security_text(value)
    passes = 0
    for _ in range(max_passes):
        # Invalid overlong UTF-8 encodings should be rejected by a runtime
        # parser. For analysis, map the common overlong dot/slash forms to
        # their security meaning so the attempted bypass remains visible.
        transport = re.sub(r"(?i)%c0%ae", ".", current)
        transport = re.sub(r"(?i)%c0%af", "/", transport)
        decoded = unquote(transport)
        decoded = normalize_security_text(decoded)
        if decoded == current:
            break
        current = decoded
        passes += 1
    return current, passes


def iter_string_leaves(value: Any) -> Iterator[tuple[tuple[str, ...], str]]:
    """Walk arbitrary JSON-like values with explicit depth and node bounds."""
    stack: list[tuple[tuple[str, ...], Any, int]] = [((), value, 0)]
    visited = 0
    while stack:
        path, current, depth = stack.pop()
        visited += 1
        if visited > MAX_TREE_NODES:
            raise ValueError("argument tree exceeds safe analysis node limit")
        if depth > MAX_TREE_DEPTH:
            raise ValueError("argument tree exceeds safe analysis depth limit")
        if isinstance(current, str):
            yield path, current
        elif isinstance(current, dict):
            for key, item in reversed(list(current.items())):
                stack.append((path + (str(key),), item, depth + 1))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((path + (str(index),), current[index], depth + 1))


def _base64_decoded(value: str) -> Iterator[str]:
    compact = "".join(value.split())
    if not 16 <= len(compact) <= MAX_DECODE_BYTES:
        return
    if not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        return
    padded = compact + "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
            if not raw or len(raw) > MAX_DECODE_BYTES:
                continue
            text = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        yield normalize_security_text(text)


def secret_shape(value: str) -> tuple[bool, str]:
    canonical, _ = decode_transport_layers(value)
    if any(pattern.search(canonical) for pattern in SECRET_PATTERNS):
        return True, "plain_or_url_encoded"
    for decoded in _base64_decoded(canonical):
        if any(pattern.search(decoded) for pattern in SECRET_PATTERNS):
            return True, "base64"
    return False, "none"


def path_risks(value: str) -> dict[str, Any]:
    canonical, decode_passes = decode_transport_layers(value)
    canonical = canonical.replace("\\", "/").replace("\x00", "")
    segments = [segment for segment in canonical.split("/") if segment not in ("", ".")]
    traversal = any(segment == ".." for segment in segments)
    absolute = canonical.startswith("/") or bool(re.match(r"^[A-Za-z]:/", canonical)) or canonical.startswith("//")
    sensitive = any(pattern.search(canonical) for pattern in SENSITIVE_PATH_PATTERNS)
    return {
        "decode_passes": decode_passes,
        "traversal": traversal,
        "absolute": absolute,
        "sensitive": sensitive,
        "normalized_path": posixpath.normpath(canonical),
    }


def resolve_within(root: Path, candidate: str) -> BoundaryDecision:
    """Resolve an existing or prospective path against an allowlisted root.

    Path.resolve() follows existing symlinks. Runtime code must still combine
    this decision with an OS sandbox and race-safe file opening; this helper is
    appropriate for review fixtures and negative tests, not as a complete
    replacement for openat2-style enforcement.
    """
    if "\x00" in candidate:
        return BoundaryDecision(False, "null_byte", None)
    canonical, _ = decode_transport_layers(candidate)
    canonical = canonical.replace("\\", "/")
    root_resolved = root.resolve(strict=True)
    requested = Path(canonical)
    if requested.is_absolute():
        resolved = requested.resolve(strict=False)
    else:
        resolved = (root_resolved / requested).resolve(strict=False)
    try:
        relative = resolved.relative_to(root_resolved)
    except ValueError:
        return BoundaryDecision(False, "outside_allowlisted_root", None)
    return BoundaryDecision(True, "inside_allowlisted_root", relative.as_posix())


def _tool_descriptions(record: dict[str, Any]) -> Iterable[tuple[str, str]]:
    raw = record.get("raw") or {}
    tools = ((raw.get("result") or {}).get("tools") or []) if isinstance(raw, dict) else []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        description = tool.get("description")
        if isinstance(description, str):
            yield str(tool.get("name") or "<unnamed>"), description


def _looks_like_path(path: tuple[str, ...], value: str) -> bool:
    key = path[-1].lower() if path else ""
    if any(hint in key for hint in ("path", "file", "directory", "folder", "target")):
        return True
    return value.startswith(("/", "../", "..\\", "%2e", "%25"))


def _tool_matches(tool_name: str, hints: tuple[str, ...]) -> bool:
    lowered = normalize_security_text(tool_name).lower()
    return any(hint in lowered for hint in hints)


class TelemetryAssuranceAnalyzer:
    def __init__(self) -> None:
        self._sensitive_reads: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def _correlation_keys(record: dict[str, Any]) -> list[str]:
        keys: list[str] = []
        session_id = record.get("session_id")
        task_id = record.get("task_id")
        if session_id:
            keys.append(f"session:{session_id}")
        if task_id and task_id != "benign":
            keys.append(f"task:{task_id}")
        return keys

    def _tool_poisoning(self, record: dict[str, Any]) -> list[Indicator]:
        findings: list[Indicator] = []
        for tool_name, description in _tool_descriptions(record):
            canonical = normalize_security_text(description)
            signals = [pattern.pattern for pattern in DIRECTIVE_PATTERNS if pattern.search(canonical)]
            hidden_markup = "<!--" in canonical or "display:none" in canonical.lower()
            invisible = any(unicodedata.category(char) == "Cf" for char in description)
            if hidden_markup or invisible or len(signals) >= 2:
                findings.append(Indicator(
                    indicator_id="SAF-T1001-NORMALIZED",
                    control_id="approved_tool_manifest",
                    severity="high",
                    summary="Tool description contains normalized directive or concealment signals",
                    session_id=record.get("session_id"),
                    timestamp=record.get("timestamp", ""),
                    evidence={
                        "server_command": record.get("server_command"),
                        "tool_name": tool_name,
                        "hidden_markup": hidden_markup,
                        "invisible_format_characters": invisible,
                        "directive_signal_count": len(signals),
                    },
                ))
        return findings

    def _tool_call(self, record: dict[str, Any]) -> list[Indicator]:
        if record.get("method") != "tools/call":
            return []
        arguments = record.get("tool_arguments") or {}
        leaves = list(iter_string_leaves(arguments))
        correlation_keys = self._correlation_keys(record)
        tool_name = str(record.get("tool_name") or "")
        timestamp = str(record.get("timestamp") or "")
        findings: list[Indicator] = []

        sensitive_sources: list[dict[str, Any]] = []
        for path, value in leaves:
            if not _looks_like_path(path, value):
                continue
            risk = path_risks(value)
            high_risk_path = ((risk["traversal"] and
                               (risk["sensitive"] or risk["decode_passes"] > 0)) or
                              (risk["absolute"] and risk["sensitive"]))
            if high_risk_path:
                findings.append(Indicator(
                    indicator_id="SAF-T1105-CANONICAL" if risk["traversal"] else "SAF-T1104-CANONICAL",
                    control_id="filesystem_boundary",
                    severity="high",
                    summary="Canonicalized tool argument targets a filesystem boundary",
                    session_id=record.get("session_id"),
                    timestamp=timestamp,
                    evidence={
                        "server_command": record.get("server_command"),
                        "tool_name": tool_name,
                        "argument_path": ".".join(path),
                        "decode_passes": risk["decode_passes"],
                        "traversal": risk["traversal"],
                        "absolute": risk["absolute"],
                        "sensitive": risk["sensitive"],
                    },
                ))
            if risk["sensitive"] and _tool_matches(tool_name, READ_TOOL_HINTS):
                sensitive_sources.append({
                    "tool_name": tool_name,
                    "argument_path": ".".join(path),
                    "timestamp": timestamp,
                })

        if correlation_keys and sensitive_sources:
            for correlation_key in correlation_keys:
                self._sensitive_reads.setdefault(correlation_key, []).extend(sensitive_sources)

        source_key = next((key for key in correlation_keys if key in self._sensitive_reads), None)
        if source_key is not None:
            for path, value in leaves:
                matched, encoding = secret_shape(value)
                if not matched:
                    continue
                source = self._sensitive_reads[source_key][-1]
                findings.append(Indicator(
                    indicator_id="SAF-T1502-CORRELATED",
                    control_id="secret_flow_and_egress",
                    severity="critical",
                    summary="Sensitive read is followed by an outbound secret-shaped argument",
                    session_id=record.get("session_id"),
                    timestamp=timestamp,
                    evidence={
                        "server_command": record.get("server_command"),
                        "source_tool": source["tool_name"],
                        "source_argument_path": source["argument_path"],
                        "correlation_scope": source_key.split(":", 1)[0],
                        "sink_tool": tool_name,
                        "sink_argument_path": ".".join(path),
                        "encoding": encoding,
                        "outbound_tool_name_signal": _tool_matches(tool_name, OUTBOUND_TOOL_HINTS),
                        "secret_value_withheld": True,
                    },
                ))
        return findings

    def process_record(self, record: dict[str, Any]) -> list[Indicator]:
        return self._tool_poisoning(record) + self._tool_call(record)

    def process_lines(self, lines: Iterable[str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in lines:
            if not line.strip():
                continue
            record = json.loads(line)
            findings.extend(indicator.as_dict() for indicator in self.process_record(record))
        return findings


def analyze_lines(lines: Iterable[str]) -> list[dict[str, Any]]:
    return TelemetryAssuranceAnalyzer().process_lines(lines)

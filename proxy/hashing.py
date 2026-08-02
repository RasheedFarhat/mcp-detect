"""Stable hashing for schema v1's tool_description_hash / server_version_hash.

Canonicalization recipe (see schema/schema.md for the language-agnostic spec):
  1. Recursively normalize every string to Unicode NFC.
  2. Serialize to JSON with sorted keys, compact separators, ASCII-only output.
  3. SHA-256 over the UTF-8 bytes of that string.
  4. Hex digest, prefixed "sha256:".

This must stay in lockstep with schema/schema.md's prose description -- if you
change one, change both, or the recipe stops being reproducible by others.
"""
import hashlib
import json
import re
import unicodedata
from typing import Any


_COMMAND_SECRET_PATTERNS = [
    re.compile(
        r"(?i)(--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|"
        r"token|secret|password|passwd|credential)(?:\s*=\s*|\s+))([^\s]+)"
    ),
    re.compile(
        r"(?i)(\b[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)"
        r"[A-Z0-9_]*\s*=\s*)([^\s]+)"
    ),
]
_COMMAND_SECRET_FLAG = re.compile(
    r"(?i)^--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|"
    r"token|secret|password|passwd|credential)$"
)
_COMMAND_SECRET_FLAG_EQUALS = re.compile(
    r"(?i)^(--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|"
    r"token|secret|password|passwd|credential)\s*=\s*)(.*)$"
)
_COMMAND_SECRET_ENV = re.compile(
    r"(?i)^(\s*[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)"
    r"[A-Z0-9_]*\s*=\s*)(.*)$"
)


def sanitize_server_command(command: str) -> str:
    """Remove common command-line credential values before capture/hashing."""
    sanitized = command
    for pattern in _COMMAND_SECRET_PATTERNS:
        sanitized = pattern.sub(lambda match: match.group(1) + "[REDACTED]", sanitized)
    return sanitized


def sanitize_server_command_parts(parts: list[str]) -> list[str]:
    """Sanitize argv without losing boundaries for values containing spaces."""
    sanitized: list[str] = []
    redact_next = False
    for part in parts:
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        if _COMMAND_SECRET_FLAG.match(part):
            sanitized.append(part)
            redact_next = True
            continue
        flag_match = _COMMAND_SECRET_FLAG_EQUALS.match(part)
        env_match = _COMMAND_SECRET_ENV.match(part)
        match = flag_match or env_match
        if match:
            sanitized.append(match.group(1) + "[REDACTED]")
            continue
        # A single shell-command argv element can still embed assignments.
        sanitized.append(sanitize_server_command(part))
    return sanitized


def _normalize_strings(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {k: _normalize_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_strings(v) for v in value]
    return value


def stable_hash(value: Any) -> str:
    canonical = json.dumps(
        _normalize_strings(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def tool_description_hash(name: str, description, input_schema) -> str:
    return stable_hash({"name": name, "description": description, "inputSchema": input_schema})


def server_version_hash(server_name, server_version, server_command: str) -> str:
    return stable_hash({
        "server_name": server_name,
        "server_version": server_version,
        "server_command": server_command,
    })


if __name__ == "__main__":
    # Self-test: stability under key reordering and Unicode normalization form.
    a = {"b": 2, "a": 1, "name": "café"}  # café, precomposed
    b = {"a": 1, "name": "café", "b": 2}  # café, decomposed (e + combining accent)
    assert stable_hash(a) == stable_hash(b), "hash must be stable across key order and NFC normalization"

    c = {"a": 1, "b": 3}
    assert stable_hash(a) != stable_hash(c), "hash must change when content changes"

    h1 = tool_description_hash("read_text_file", "Read a file", {"type": "object"})
    h2 = tool_description_hash("read_text_file", "Read a file", {"type": "object"})
    assert h1 == h2, "tool_description_hash must be deterministic"
    assert h1.startswith("sha256:") and len(h1) == len("sha256:") + 64

    print("hashing.py self-test: OK")

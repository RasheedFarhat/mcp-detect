"""Small, dependency-free helpers for rendering untrusted telemetry as Markdown."""

from __future__ import annotations

import html
import re


_MARKDOWN_PUNCTUATION = {
    "\\": "&#92;", "|": "&#124;", "`": "&#96;", "[": "&#91;",
    "]": "&#93;", "(": "&#40;", ")": "&#41;", "*": "&#42;",
    "_": "&#95;", "#": "&#35;", "!": "&#33;",
}
_MARKDOWN_PUNCTUATION_RE = re.compile(r"[\\|`\[\]\(\)\*_#!]")


def markdown_text(value: object) -> str:
    """Return one inert Markdown inline value.

    Telemetry-controlled values can contain table separators, Markdown links,
    raw HTML, newlines, or terminal control characters. Reports are also
    printed to terminals before they are rendered, so normalizing only HTML is
    insufficient. The returned string stays readable in Markdown/HTML while
    being unable to introduce structure of its own.
    """
    text = "" if value is None else str(value)
    normalized: list[str] = []
    for char in text:
        codepoint = ord(char)
        if char in "\r\n\t":
            normalized.append(" ")
        elif codepoint < 32 or 0x7F <= codepoint <= 0x9F:
            normalized.append("�")
        else:
            normalized.append(char)

    escaped = html.escape("".join(normalized), quote=False)
    # Use entities rather than backslash escapes so nested table/code contexts
    # cannot reinterpret the punctuation after another Markdown conversion.
    return _MARKDOWN_PUNCTUATION_RE.sub(
        lambda match: _MARKDOWN_PUNCTUATION[match.group(0)], escaped
    )

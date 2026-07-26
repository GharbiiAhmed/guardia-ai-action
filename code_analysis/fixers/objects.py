"""Inserting an entry into an object or dict literal.

Shared by the Python and JavaScript codemods, which differ in what they look
for — a returned dict versus the object handed to `Response.json` — but make
exactly the same edit once they have found it. Keeping the edit in one place
means the two cannot drift into formatting each other's patches differently.
"""
from __future__ import annotations

import re
from typing import Optional


def insert_entry(
    source: str,
    start_line: int,
    end_line: int,
    segment: str,
    entry: str,
) -> Optional[str]:
    """Replacement text for lines [start_line, end_line] with `entry` added.

    Returns None when the shape is not one we can edit safely — an empty
    literal, a mismatched segment, an out-of-range span. Declining is the
    normal outcome; a wrong patch under a compliance banner is the most
    expensive mistake this tool can make.
    """
    if not segment.startswith("{") or not segment.rstrip().endswith("}"):
        return None

    lines = source.splitlines()
    if start_line < 1 or end_line > len(lines) or end_line < start_line:
        return None

    if start_line == end_line:
        inner = segment[1:].lstrip()
        if inner.startswith("}"):
            # `{}` — nothing to separate the new entry from.
            replacement = "{" + entry + "}"
        else:
            replacement = "{" + entry + ", " + inner
        if not replacement.rstrip().endswith("}"):
            return None
        original = lines[start_line - 1]
        if segment not in original:
            return None
        return original.replace(segment, replacement)

    # Multi-line: match the indentation of the first existing entry so the patch
    # does not fight the file's own formatting.
    following = lines[start_line]
    indent = re.match(r"\s*", following).group(0)
    return "\n".join(
        [lines[start_line - 1], f"{indent}{entry},"] + lines[start_line:end_line]
    )

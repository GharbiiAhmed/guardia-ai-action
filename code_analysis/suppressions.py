"""Inline suppressions: ``# guardia: ignore GA-ART50-001 — reason``.

Suppressions live in the source rather than in our database on purpose. They
travel with branches and forks, they are reviewed like any other diff, and they
give us both an author (via git blame) and a justification — which is what
turns a developer's "not now" into a documented risk acceptance.

A suppression applies to the line it sits on, or to the line immediately below
it when it is on a line of its own.
"""
from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass

# `guardia: ignore RULE` with an optional reason after a dash, em dash or colon.
_PATTERN = re.compile(
    r"guardia:\s*ignore\s+(?P<rule>[A-Za-z0-9_\-]+)\s*(?:[-—:]+\s*(?P<reason>.+?))?\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    line: int          # line the suppression governs
    reason: str        # '' when the developer gave none
    declared_on: int   # line the comment itself is on


def parse(source: str) -> list[Suppression]:
    """Extract every suppression comment from Python source.

    Malformed source still yields whatever was tokenized before the error —
    a syntax error further down the file should not silently drop a valid
    suppression above it.
    """
    found: list[Suppression] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type != tokenize.COMMENT:
                continue
            match = _PATTERN.search(tok.string)
            if not match:
                continue

            comment_line = tok.start[0]
            # A comment that starts the line governs the line below it;
            # a trailing comment governs its own line.
            own_line = tok.line.lstrip().startswith("#")
            governs = comment_line + 1 if own_line else comment_line

            found.append(Suppression(
                rule_id=match.group("rule").upper(),
                line=governs,
                reason=(match.group("reason") or "").strip(),
                declared_on=comment_line,
            ))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return found


_COMMENT_START = re.compile(r"^\s*(//|/\*|\*|#)")


def parse_lines(source: str) -> list[Suppression]:
    """Line-based scan, for languages `tokenize` cannot read.

    Used for JavaScript and TypeScript, where the marker sits behind `//` or
    inside a block comment.
    """
    found: list[Suppression] = []
    for number, line in enumerate(source.splitlines(), start=1):
        match = _PATTERN.search(line.rstrip().rstrip("*/").rstrip())
        if not match:
            continue
        # A comment on its own line governs the line below it; a trailing
        # comment governs its own line.
        own_line = bool(_COMMENT_START.match(line))
        found.append(Suppression(
            rule_id=match.group("rule").upper(),
            line=number + 1 if own_line else number,
            reason=(match.group("reason") or "").strip().rstrip("*/").strip(),
            declared_on=number,
        ))
    return found


def index(source: str, language: str = "python") -> dict[tuple[str, int], Suppression]:
    """Suppressions keyed by (rule_id, line) for O(1) lookup during analysis."""
    found = parse(source) if language == "python" else parse_lines(source)
    return {(s.rule_id, s.line): s for s in found}

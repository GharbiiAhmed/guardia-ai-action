"""Record that an inference happened, next to the call that made it.

This fixer is deliberately modest, for a reason worth stating. The Article 12
rule fires when a function contains no logging call, and *any* logging call
silences it. A codemod that inserts a bare `logger.info("done")` would therefore
switch our own rule off while leaving the obligation exactly where it was —
gaming our own check and telling the customer they are covered when they are
not.

So two constraints:

* The line it inserts records *what was called*, not merely that something
  happened, and the description says plainly that this is a starting point
  rather than compliance. Article 12 expects events to be traceable over the
  system's lifetime; one log line is the first of those events, not all of them.
* It only fires where a logger already exists. Adding an import and configuring
  a logging framework is a bigger change than a compliance scanner should make
  to someone's code unasked.
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import SuggestedFix

_DESCRIPTION = (
    "Record the inference where it happens. This is the starting point for "
    "Article 12, not the whole of it: the obligation expects events to be "
    "traceable over the system's lifetime, so extend this to the inputs, "
    "outputs and retention your own policy requires."
)


def _logger_expression(source: str, language: str) -> Optional[str]:
    """How this file already writes a log, or None if it does not.

    Deliberately conservative: introducing a logging framework is not a change
    a scanner should make on someone's behalf.
    """
    if re.search(r"\blogger\b", source):
        return "logger"
    if re.search(r"\blog\.(debug|info|warning|error)\b", source):
        return "log"
    if language == "python" and re.search(r"^\s*import logging\b", source, re.MULTILINE):
        return "logging"
    if language != "python" and re.search(r"\bconsole\.(log|info)\b", source):
        # Console output is weak record-keeping, but a file already using it has
        # made that choice; matching it is less intrusive than imposing another.
        return "console"
    return None


def build_logging_fix(
    source: str,
    language: str,
    callee: str,
    start_line: int,
    end_line: int,
) -> Optional[SuggestedFix]:
    """Insert a log line after the statement that invokes the model."""
    logger = _logger_expression(source, language)
    if logger is None:
        return None

    lines = source.splitlines()
    if start_line < 1 or end_line > len(lines) or end_line < start_line:
        return None

    span = lines[start_line - 1:end_line]
    indent = re.match(r"\s*", span[0]).group(0)

    if language == "python":
        entry = (
            f'{indent}{logger}.info("ai_inference", '
            f'extra={{"provider_call": "{callee}"}})'
        )
    else:
        entry = (
            f'{indent}{logger}.info("ai_inference", '
            f'{{ provider_call: "{callee}" }});'
        )

    return SuggestedFix(
        description=_DESCRIPTION,
        start_line=start_line,
        end_line=end_line,
        replacement="\n".join([*span, entry]),
        # The insertion is exact; whether one line satisfies the duty is not
        # something a scanner can judge.
        confidence="medium",
    )

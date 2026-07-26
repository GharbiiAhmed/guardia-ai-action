"""Stable identity for a code finding.

Line numbers move on every edit. If a finding's identity is its line number,
then reformatting a file resurrects every finding someone already resolved or
accepted the risk on — and a compliance tool that re-raises settled issues gets
removed from CI within a fortnight.

So identity is built only from things that survive formatting:

    rule id | file path | enclosing symbol | what is called | which occurrence

Renaming the enclosing function or moving the file does change the fingerprint.
That is deliberate: both are genuine relocations, and re-surfacing the finding
once is the safer error.
"""
from __future__ import annotations

import hashlib

# Unit separator — cannot occur in any component, so the joined payload is
# unambiguous (a path containing '|' cannot impersonate a field boundary).
_SEP = "␟"


def normalize_path(path: str) -> str:
    """Repo-relative, forward-slashed, no leading './'."""
    cleaned = path.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def compute(
    rule_id: str,
    path: str,
    qualname: str,
    callee: str,
    occurrence: int = 0,
) -> str:
    """Build the fingerprint for one finding.

    `qualname` is the enclosing symbol ('ChatHandler.respond', or '<module>').
    `callee` is the dotted call target ('client.chat.completions.create').
    `occurrence` distinguishes repeated identical calls in the same symbol.
    """
    payload = _SEP.join([
        rule_id,
        normalize_path(path),
        qualname,
        callee,
        str(occurrence),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

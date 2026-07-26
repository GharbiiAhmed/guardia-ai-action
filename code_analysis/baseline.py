"""Pre-existing findings, frozen at adoption.

Turning this scanner on for the first time against a five-year-old codebase
produces a wall of findings nobody on the team caused and nobody has time to
fix. That is how a tool gets uninstalled in week two. A baseline records what
was already there, so the check starts green and only new work has to be clean.

Baselined findings are **marked, not deleted**. They stay visible in the report
and in the dashboard record — an obligation does not stop existing because it
predates the tool. They simply never fail a build.

The file keys on fingerprints, so it survives reformatting, and it stores the
human-readable location alongside for anyone reading the diff.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

from .models import CodeFinding, CodeScanResult

VERSION = 1


def build(result: CodeScanResult, commit_sha: str = "") -> dict:
    """A baseline document for everything this scan found."""
    return {
        "version": VERSION,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "commit_sha": commit_sha,
        # Sorted so re-generating the file produces a readable diff rather than
        # a reshuffle.
        "findings": sorted(
            (
                {
                    "fingerprint": finding.fingerprint,
                    "rule_id": finding.rule_id,
                    # Location is informational only — matching is by
                    # fingerprint, which does not move when the file does.
                    "file": finding.file,
                    "line": finding.line,
                    "symbol": finding.symbol,
                }
                for finding in result.findings
            ),
            key=lambda entry: (entry["file"], entry["line"], entry["rule_id"]),
        ),
    }


def load(path: str) -> Optional[set[str]]:
    """Fingerprints in the baseline, or None if there is no usable file.

    A missing or corrupt baseline is not an error: the scan still runs, it just
    has nothing to forgive. Failing here would block a pipeline over a file the
    team may not even know exists.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None

    entries = document.get("findings", []) if isinstance(document, dict) else []
    return {
        entry["fingerprint"]
        for entry in entries
        if isinstance(entry, dict) and entry.get("fingerprint")
    }


def apply(result: CodeScanResult, known: Optional[set[str]]) -> CodeScanResult:
    """Mark findings that were already present when the baseline was taken."""
    if not known:
        return result
    for finding in result.findings:
        if finding.fingerprint in known:
            finding.baselined = True
    return result


def dumps(result: CodeScanResult, commit_sha: str = "") -> str:
    return json.dumps(build(result, commit_sha), indent=2) + "\n"

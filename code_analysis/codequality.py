"""GitLab Code Quality report.

GitLab has no equivalent of GitHub's suggestion blocks, so the parity play is
its Code Quality artifact: findings render in the merge request widget and as
inline markers on the diff, which is the same "annotate the exact line"
experience by a different route.

The format is CodeClimate's, and GitLab keys deduplication off `fingerprint` —
the same job our own fingerprint already does, so it drops straight in and
findings survive a reformat here too.
"""
from __future__ import annotations

import json

from .models import CodeScanResult

# CodeClimate severities. Ours map cleanly except that 'critical' becomes
# 'blocker', which is what GitLab surfaces most prominently.
_SEVERITY = {
    "critical": "blocker",
    "high": "critical",
    "medium": "major",
    "low": "minor",
    "info": "info",
}


def to_code_quality(result: CodeScanResult) -> list:
    """Findings as a GitLab Code Quality report."""
    report = []
    for finding in result.findings:
        # A suppressed finding is an accepted risk, and a baselined one
        # predates adoption. Either way, putting a marker on that line is noise
        # on a diff the team did not write; both stay in the dashboard record.
        if finding.suppressed or finding.baselined:
            continue

        legal = finding.legal
        citation = legal.citation

        report.append({
            "description": f"{finding.claim} — {citation}",
            "check_name": finding.rule_id,
            "fingerprint": finding.fingerprint,
            "severity": "info" if finding.advisory else _SEVERITY.get(finding.severity, "major"),
            "location": {
                "path": finding.file,
                "lines": {"begin": finding.line, "end": max(finding.end_line, finding.line)},
            },
        })
    return report


def dumps(result: CodeScanResult) -> str:
    return json.dumps(to_code_quality(result), indent=2)

"""SARIF 2.1.0 output.

Emitting SARIF is the cheapest leverage in the whole feature: GitHub renders it
as inline pull-request annotations natively, so the "comment on the exact line"
experience costs nothing to build, and GitLab ingests the same file as a report
artifact.

Two fields carry more weight than the rest:

`partialFingerprints` is SARIF's own mechanism for tracking a result across
commits — GitHub uses it to decide whether an alert is the same one it saw last
week. Our fingerprint drops straight into it, which is why resolved findings
stay resolved through a reformat.

`suppressions` makes an inline `guardia: ignore` render as a dismissed alert
with its justification attached, rather than silently vanishing.
"""
from __future__ import annotations

import json

from .models import CodeFinding, CodeScanResult

from .rules.base import Rule, registry

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
TOOL_NAME = "Guardia AI"
TOOL_URI = "https://guardia-ai.com"

# GitHub renders error as a failing annotation, warning as a neutral one.
_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_descriptor(rule: Rule) -> dict:
    legal = rule.legal
    citation = legal.citation

    # The help text is where a reader meets the obligation itself. Quote it in
    # full rather than summarising: the point of the rule is that the reader can
    # check our reasoning, and a paraphrase defeats that.
    markdown = (
        f"### {rule.title}\n\n"
        f"**{citation}** — {legal.regulation_version}\n\n"
        f"> {legal.text}\n\n"
    )
    if legal.recital:
        markdown += f"See also {legal.recital}.\n\n"
    if legal.standard_ref:
        markdown += f"Related control: {legal.standard_ref}.\n\n"
    if rule.advisory:
        markdown += (
            "**Advisory.** This rule reads an obligation rather than matching its "
            "plain words, so it never fails a check.\n\n"
        )
    markdown += (
        f"Legal review: {legal.reviewed_by or '**not yet reviewed by counsel**'}.\n\n"
        f"This finding reports what the code does and quotes the obligation. "
        f"Whether the obligation applies to your system depends on its purpose "
        f"and deployment context, which a code scan cannot determine.\n"
    )

    return {
        "id": rule.rule_id,
        "name": type(rule).__name__,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": legal.text},
        "helpUri": legal.source_url,
        "help": {"text": legal.text, "markdown": markdown},
        "defaultConfiguration": {
            "level": "note" if rule.advisory else _LEVELS.get(rule.severity, "warning"),
        },
        "properties": {
            "tags": ["compliance", "eu-ai-act", legal.article.lower().replace(" ", "-")],
            "article": citation,
            "standard": legal.standard_ref,
            "textVerified": legal.text_verified,
            "reviewedBy": legal.reviewed_by,
        },
    }


def _result(finding: CodeFinding, rule_index: int) -> dict:
    region = {
        "startLine": finding.line,
        "endLine": max(finding.end_line, finding.line),
        # SARIF columns are 1-based; ast.col_offset is 0-based.
        "startColumn": finding.column + 1,
    }
    if finding.snippet:
        region["snippet"] = {"text": finding.snippet}

    entry = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        # An advisory rule is a prompt to a human, so it renders as a note
        # whatever its severity.
        "level": "note" if finding.advisory else _LEVELS.get(finding.severity, "warning"),
        "message": {"text": finding.claim},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file},
                "region": region,
            }
        }],
        # Versioned key: if the fingerprint algorithm ever changes, GitHub can
        # still match old alerts on the old key instead of duplicating them all.
        "partialFingerprints": {"guardiaFingerprint/v1": finding.fingerprint},
        "properties": {
            "symbol": finding.symbol,
            "confidence": finding.confidence,
            "advisory": finding.advisory,
            "article": finding.legal.article,
        },
    }

    if finding.fix:
        # SARIF fixes carry the patch alongside the result, so a reviewer sees
        # the change without leaving the annotation.
        entry["fixes"] = [{
            "description": {"text": finding.fix.description},
            "artifactChanges": [{
                "artifactLocation": {"uri": finding.file},
                "replacements": [{
                    "deletedRegion": {
                        "startLine": finding.fix.start_line,
                        "endLine": finding.fix.end_line,
                    },
                    "insertedContent": {"text": finding.fix.replacement},
                }],
            }],
        }]

    if finding.suppressed:
        entry["suppressions"] = [{
            "kind": "inSource",
            "justification": finding.suppression_reason or "No justification given",
        }]
    elif finding.baselined:
        # 'external' rather than 'inSource': nobody wrote a comment accepting
        # this, it simply predates adoption of the scanner.
        entry["suppressions"] = [{
            "kind": "external",
            "justification": "Present when the baseline was taken",
        }]

    return entry


def to_sarif(result: CodeScanResult, rules: list[Rule] | None = None) -> dict:
    """Build the SARIF log for a completed scan."""
    rules = rules if rules is not None else registry()
    index_of = {rule.rule_id: i for i, rule in enumerate(rules)}

    # Findings that need no attention are left out of the annotation surface.
    #
    # SARIF has a `suppressions` field for exactly this, and we emitted it —
    # but a live run showed GitHub still listing those alerts as `open`, so the
    # pull request comment said "held in the baseline" while code scanning
    # showed them as outstanding. Two surfaces disagreeing about the same
    # commit is worse than one surface saying less, and both remain in the
    # evidence record, the dashboard and the counts below.
    reportable = [
        f for f in result.findings
        if not f.suppressed and not f.baselined
    ]
    results = [
        _result(f, index_of.get(f.rule_id, 0))
        for f in reportable
    ]

    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "informationUri": TOOL_URI,
                "rules": [_rule_descriptor(r) for r in rules],
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "filesScanned": result.files_scanned,
                    "filesSkipped": result.files_skipped,
                    "durationMs": result.duration_ms,
                    # Reported here so the run still accounts for everything it
                    # found, even though these are not raised as alerts.
                    "suppressedCount": sum(1 for f in result.findings if f.suppressed),
                    "baselinedCount": sum(1 for f in result.findings if f.baselined),
                },
            }],
        }],
    }


def dumps(result: CodeScanResult, rules: list[Rule] | None = None) -> str:
    return json.dumps(to_sarif(result, rules), indent=2)

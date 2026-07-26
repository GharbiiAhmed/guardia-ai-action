"""A review document for counsel, generated from the rules themselves.

Written as code rather than a hand-maintained file for one reason: a review
document that drifts from the rules is worse than none, because a lawyer signs
off on behaviour the tool no longer has. Regenerate it and the answer is always
what ships.

What a reviewer is being asked is deliberately narrow. Not "is this system
compliant" — that is their client's question, not ours. Only: *does this rule
cite the right provision, quote it correctly, and describe what it observes
without overstating what that proves?*
"""
from __future__ import annotations

from datetime import datetime

from .evidence import RULESET_VERSION
from .rules.base import Rule, registry

_PREAMBLE = """# Guardia AI — rule cards for legal review

**Ruleset version {version}** · generated {date}

Guardia AI scans source code and reports observations about it alongside the
text of the obligation each observation relates to. It does not determine
whether a system is compliant, whether an obligation applies, or whether a
breach has occurred.

## What we are asking you to review

For each rule below, three questions:

1. **Is the citation right?** Does the rule point at the provision that actually
   governs the behaviour it observes?
2. **Is the quotation accurate and complete?** Each quote is transcribed from
   the Official Journal text of Regulation (EU) 2024/1689. Where a provision
   contains an exception, we have tried to keep it — dropping one would misstate
   the duty to anyone reading only the finding.
3. **Is the claim honest?** Findings state what the code does and quote the
   obligation separately, so the reader draws the inference. We would like to
   know where that separation slips, or where a phrasing reads as a legal
   conclusion.

We are **not** asking you to validate the detection logic, or to advise on any
particular customer's compliance.

## How findings are worded

Every finding has two halves that are never merged:

- **The observation** — a fact about the code, at a file and line.
- **The obligation** — the provision, quoted verbatim.

A test in the codebase fails if the words "violate", "breach", "non-compliant"
or "illegal" appear in an observation.

## Rules that never fail a build

Rules marked **advisory** rest on reading an obligation rather than matching its
plain words. They are reported to the developer but never block a build, because
a rule that cannot be precise should not be able to stop someone shipping.

## Review status

Every rule currently records `reviewed_by: null`, and the tool says so in its
output — in the pull request comment, in the SARIF help text, and in the audit
record it produces. That is deliberate: a reader should know how much review a
rule has had. Signing a card below changes that field.

---
"""

_CARD = """
## {rule_id} — {title}

|  |  |
|---|---|
| **Provision** | {citation} |
| **Recital** | {recital} |
| **Related standard** | {standard} |
| **Severity** | {severity} |
| **Blocks a build** | {gating} |
| **Review status** | {review} |

### The provision, as quoted to the reader

> {text}

Source: {source}

### What the rule observes

{observes}

### What it deliberately does not claim

{limitations}

### Reviewer sign-off

| Field | |
|---|---|
| Citation correct? | ☐ yes ☐ no — |
| Quotation accurate and complete? | ☐ yes ☐ no — |
| Wording free of legal conclusions? | ☐ yes ☐ no — |
| Reviewed by | |
| Firm | |
| Date | |
| Notes | |

---
"""

# What each rule observes, in a sentence a non-programmer can check.
_OBSERVATIONS = {
    "GA-ART50-001": (
        "An endpoint or application screen that a person interacts with, which "
        "reaches a language model, in a repository where no text anywhere informs "
        "the user that responses are AI-generated."
    ),
    "GA-ART12-001": (
        "A call that invokes a language model, inside a function containing no "
        "logging, audit or tracing call of any kind."
    ),
    "GA-ART14-001": (
        "A model's output being acted upon — a record written, a notification "
        "sent, an application rejected — in the same function that produced it, "
        "with nothing resembling a review, approval or escalation step."
    ),
    "GA-ART10-001": (
        "Code that trains a machine-learning model, in a repository where no bias "
        "or fairness test was found in any scanned file."
    ),
    "GA-ART5-001": (
        "A library whose purpose is inferring emotion, imported in a file whose "
        "path or contents reference hiring, employment or education."
    ),
}


def _bullets(items) -> str:
    if not items:
        return "_None recorded._"
    return "\n".join(f"- {item}" for item in items)


def to_markdown(rules: list[Rule] | None = None) -> str:
    rules = rules if rules is not None else registry()

    parts = [_PREAMBLE.format(
        version=RULESET_VERSION,
        date=datetime.utcnow().strftime("%d %B %Y"),
    )]

    for rule in rules:
        legal = rule.legal
        parts.append(_CARD.format(
            rule_id=rule.rule_id,
            title=rule.title,
            citation=f"{legal.citation} — {legal.regulation_version}",
            recital=legal.recital or "—",
            standard=legal.standard_ref or "—",
            severity=rule.severity,
            gating="No — advisory" if rule.advisory else "Yes",
            review=legal.reviewed_by or "**Not yet reviewed by counsel**",
            text=legal.text,
            source=legal.source_url,
            observes=_OBSERVATIONS.get(rule.rule_id, "—"),
            limitations=_bullets(rule.limitations),
        ))

    parts.append(
        "\n_Generated from the rule definitions in "
        "`Backend/services/code_analysis/rules/`. Regenerate with "
        "`python -m services.code_analysis --rule-cards PATH` so this document "
        "cannot drift from what the tool does._\n"
    )
    return "".join(parts)

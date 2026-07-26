"""GA-ART14-001 — a model's output acted on with no human review on the path.

This is the first **advisory** rule, and the distinction matters. Articles 50
and 12 match the plain words of an obligation: "inform the person", "record
events". Article 14 asks whether a system "can be effectively overseen by
natural persons", which is a property of a whole sociotechnical arrangement —
the interface, the operator's training, the time they have to intervene. A code
scanner sees one function.

So this rule never fails a build. What it can honestly observe is narrow and
worth surfacing: a model was invoked, its output was acted on in the same
function, and nothing in that function looks like a review step. That is a
prompt to a human, not a verdict.

Precision comes from insisting all four signals appear together, and from a
conservative list of what counts as acting on the output. Persisting a record or
sending a notification is an action; formatting a string is not.
"""
from __future__ import annotations

from .. import fingerprint, providers
from .art12_logging import _is_logging_call
from ..models import CodeFinding, LegalReference
from .base import Rule, RuleContext

# Acting on a decision. Deliberately concrete verbs — anything vaguer produces
# a rule that fires on every function that does something.
# 'approve', 'accept' and 'authorise' are deliberately absent: each reads
# equally well as the review step or as the automated action, and a rule that
# cannot tell them apart should stay quiet rather than guess. They appear in
# the review list below instead — the direction that risks a missed finding
# rather than a false accusation.
_ACTION_MARKERS = (
    "reject", "deny", "decline",
    "block", "ban", "suspend", "terminate", "disable", "revoke", "flag",
    "charge", "refund", "payout", "transfer", "disburse",
    "hire", "shortlist", "rank", "score", "grade", "assign",
    "publish", "send", "notify", "dispatch", "escalate", "delete", "remove",
)

# Persisting the outcome counts as acting on it: the decision has left the
# function and something downstream will read it.
# 'update' and 'write' are gone: they matched `kwargs.update` and other
# collection mutations far more often than a decision being stored.
_PERSIST_MARKERS = ("save", "commit", "insert", "upsert", "persist")

# Anything on this list means a person is in the loop somewhere in this
# function. Generous on purpose: the cost of missing a review step is a false
# accusation, and this rule is advisory precisely because that judgement is
# hard.
_REVIEW_MARKERS = (
    "review", "approv", "accept", "authoris", "authoriz",
    "human", "manual", "confirm", "moderat", "escalat",
    "verify", "validate", "oversight", "supervis", "audit", "queue", "pending",
    "draft", "propose", "suggest", "await", "consent", "acknowledg", "override",
)


def _matches(callee: str, markers: tuple[str, ...]) -> bool:
    """Match the called name only, never the object it hangs off.

    Matching the whole dotted path meant `updated_messages.append(...)` counted
    as an action because a *variable* contained "update".
    """
    tail = callee.rsplit(".", 1)[-1].lower()
    return any(marker in tail for marker in markers)


def _is_constructor(callee: str) -> bool:
    """`BetaTextBlock(...)` is a type, not a decision — it matched "block"."""
    tail = callee.rsplit(".", 1)[-1]
    return bool(tail) and tail[0].isupper()


class Article14Oversight(Rule):
    rule_id = "GA-ART14-001"
    severity = "medium"
    advisory = True
    title = "Model output acted on with no review step in the same function"

    limitations = (
        "Whether a system can be 'effectively overseen' depends on the interface, the "
        "operator's training and the time available to intervene. None of that is in "
        "the code. This rule observes only that an output was acted on in the same "
        "function with nothing resembling review.",
        "Oversight implemented in another service, a separate queue or an operational "
        "process is invisible.",
        "Never measured against real decision systems — no repository scanned so far "
        "exercises it.",
    )

    @property
    def legal(self) -> LegalReference:
        return LegalReference(
            article="Article 14",
            paragraph="1",
            text=(
                "High-risk AI systems shall be designed and developed in such a way, "
                "including with appropriate human-machine interface tools, that they can be "
                "effectively overseen by natural persons during the period in which they are "
                "in use."
            ),
            source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689",
            text_verified=True,
            recital="Recitals 66 and 73",
            standard_ref="ISO/IEC 42001:2023 A.9.2",
            reviewed_by=None,
        )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        if not ctx.uses_provider:
            return []

        findings: list[CodeFinding] = []
        for func in ctx.file.functions:
            generation = next(
                (c for c in func.calls if ctx.is_generation(c.callee)),
                None,
            )
            if generation is None:
                continue

            # A review step anywhere in the function — or a decorator that
            # routes the result somewhere for approval — settles it.
            if any(_matches(call.callee, _REVIEW_MARKERS) for call in func.calls):
                continue
            if any(_matches(name, _REVIEW_MARKERS) for name in func.decorators):
                continue
            if _matches(func.name, _REVIEW_MARKERS):
                continue

            action = next(
                (
                    call for call in func.calls
                    if call is not generation
                    # A decision cannot be acted on before it is made. This
                    # alone removed several findings where the "action" ran
                    # twenty lines above the model call.
                    and call.line > generation.line
                    # Recording the output is not acting on it —
                    # `commit_conversation_trace` matched "commit".
                    and not _is_logging_call(call.callee)
                    and not _is_constructor(call.callee)
                    and (_matches(call.callee, _ACTION_MARKERS)
                         or _matches(call.callee, _PERSIST_MARKERS))
                ),
                None,
            )
            if action is None:
                continue

            findings.append(CodeFinding(
                rule_id=self.rule_id,
                fingerprint=fingerprint.compute(
                    rule_id=self.rule_id,
                    path=ctx.path,
                    qualname=func.name,
                    callee=generation.callee,
                    occurrence=ctx.occurrence_of(func, generation),
                ),
                file=ctx.path,
                line=generation.line,
                end_line=generation.end_line,
                column=generation.col,
                symbol=func.qualname,
                snippet=generation.snippet,
                claim=(
                    f"`{generation.callee}` invokes a model inside `{func.qualname}`, "
                    f"whose output is acted on by `{action.callee}` at line {action.line} "
                    f"with no review, approval or escalation step in that function."
                ),
                legal=self.legal,
                severity=self.severity,
                # Whether oversight exists is a question about the whole system,
                # not this function. The observation is local; the conclusion is
                # not ours to draw.
                confidence="low",
                advisory=True,
                fix=None,
            ))
        return findings

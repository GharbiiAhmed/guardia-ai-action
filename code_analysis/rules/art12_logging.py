"""GA-ART12-001 — a model is invoked with no record of it.

Article 12 binds high-risk systems, and a scanner cannot know whether a system
is high-risk — that depends on purpose and deployment context, which are not in
the syntax tree. So this rule does not assert the obligation applies. It reports
what the code does and quotes the duty, whose own first words ("High-risk AI
systems shall…") carry the condition to the reader.

Detection of *existing* logging is deliberately generous. Missing a real logging
call costs a false accusation; over-matching only costs a missed finding, and
the second error is much cheaper than the first.
"""
from __future__ import annotations

from .. import fingerprint, providers
from ..models import CodeFinding, LegalReference
from .base import Rule, RuleContext

# Method names that plausibly record something.
_LOG_METHODS = {
    "debug", "info", "warning", "warn", "error", "exception", "critical",
    "log", "event", "audit", "record", "emit", "write", "capture",
    "capture_message", "capture_event", "add_event", "track",
}

_LOG_MARKERS = ("log", "metric", "journal", "record")

# Naming any of these is itself the evidence — these libraries exist to record
# things, and their call shapes look nothing like `logger.info`.
_STRONG_MARKERS = (
    "audit", "trace", "telemetry", "sentry", "datadog", "opentelemetry", "otel",
)

# Decorating a function with any of these means the recording happens outside
# the function body, where a scan of its call sites will never see it.
_LOG_DECORATOR_MARKERS = ("log", "audit", "trace", "monitor", "observe", "track")


def _is_logging_call(callee: str) -> bool:
    """Generous by design — see the module docstring on which error is cheaper."""
    if not callee:
        return False
    lowered = callee.lower()

    # Dedicated observability tooling doesn't use logger verbs:
    # `tracer.start_as_current_span(...)`, `sentry_sdk.set_context(...)`.
    # Naming the tool at all is enough.
    if any(marker in lowered for marker in _STRONG_MARKERS):
        return True

    if not any(marker in lowered for marker in _LOG_MARKERS):
        return False
    tail = lowered.rsplit(".", 1)[-1]
    # `audit_log(...)` is a bare function; `logger.info(...)` is a method.
    return tail in _LOG_METHODS or "log" in tail


class Article12Logging(Rule):
    rule_id = "GA-ART12-001"
    severity = "medium"
    title = "Model invoked with no record-keeping in scope"

    limitations = (
        "Article 12 binds high-risk systems only. This rule cannot tell whether a "
        "system is high-risk, so it reports the code and quotes the duty without "
        "asserting the duty applies.",
        "Logging done by a framework or middleware outside the function is not always "
        "visible, though decorators are checked.",
        "Detection of existing logging is deliberately generous: a function that "
        "merely mentions tracing is treated as recording.",
    )

    @property
    def legal(self) -> LegalReference:
        return LegalReference(
            article="Article 12",
            paragraph="1",
            text=(
                "High-risk AI systems shall technically allow for the automatic recording of "
                "events (logs) over the lifetime of the system."
            ),
            source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689",
            text_verified=True,
            recital="Recital 71",
            standard_ref="ISO/IEC 42001:2023 A.6.2.8",
            reviewed_by=None,
        )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        if not ctx.uses_provider:
            return []

        module_logs = any(_is_logging_call(call.callee) for call in ctx.calls)

        findings: list[CodeFinding] = []
        for func in ctx.file.functions:
            if any(_is_logging_call(call.callee) for call in func.calls):
                continue
            if any(
                marker in decorator.lower()
                for decorator in func.decorators
                for marker in _LOG_DECORATOR_MARKERS
            ):
                continue

            for call in func.calls:
                if not ctx.is_generation(call.callee):
                    continue

                where = (
                    "this file logs elsewhere, but not around this call"
                    if module_logs else
                    "no logging call appears anywhere in this file"
                )
                findings.append(CodeFinding(
                    rule_id=self.rule_id,
                    fingerprint=fingerprint.compute(
                        rule_id=self.rule_id,
                        path=ctx.path,
                        qualname=func.name,
                        callee=call.callee,
                        occurrence=ctx.occurrence_of(func, call),
                    ),
                    file=ctx.path,
                    line=call.line,
                    end_line=call.end_line,
                    column=call.col,
                    symbol=func.qualname,
                    snippet=call.snippet,
                    claim=(
                        f"`{call.callee}` invokes a model inside `{func.qualname}`, and no "
                        f"logging, audit or tracing call was found in that function "
                        f"({where})."
                    ),
                    legal=self.legal,
                    severity=self.severity,
                    # Absence within one function is a local, checkable claim.
                    # Absence across the whole file is stronger evidence.
                    confidence="medium" if module_logs else "high",
                    fix=None,
                ))
        return findings

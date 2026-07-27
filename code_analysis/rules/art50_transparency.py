"""GA-ART50-001 — a user-facing surface reaching a model with no AI disclosure.

Article 50 leads the pack for two reasons: its obligation is among the plainest
in the Act, and it is the only one with a live deadline — the high-risk duties
moved to December 2027 while the transparency duties stay at August 2026.

The rule anchors on the **route handler**, not the model call, because the duty
is about a person interacting with a system. How far the provider call sits from
the handler is an implementation detail of the application, and the first corpus
run proved it: requiring the call inside the handler found zero findings across
three real applications, because every one of them puts the provider behind a
service layer.

Disclosure is checked across the whole repository, not just the calling module.
The notice almost always lives in a template or a frontend component, and
reporting a missing disclosure on an app that displays one is the worst
available error.
"""
from __future__ import annotations

import re

from .. import callgraph, disclosure, fingerprint, providers
from ..fixers import (
    build_disclosure_fix,
    build_js_disclosure_fix,
    build_ui_notice_fix,
)
from ..models import CodeFinding, LegalReference
from .base import Rule, RuleContext

# How many notice locations to name before the list stops being readable.
_MAX_NAMED = 3

# Responses that cannot carry a field. A streamed answer has no object to patch,
# and a proxied one belongs to the provider. Injecting into either would corrupt
# the protocol the client is parsing, so no fix is offered — but the finding
# should say where the notice does belong rather than going quiet about it.
_STREAMING_MARKERS = (
    # Python
    "streamingresponse", "streaminghttpresponse", "eventsourceresponse",
    "stream=true", "stream_response",
    # JavaScript: `stream: true` and a Response built from a ReadableStream
    "stream: true", "stream:true", "readablestream", "new response(stream",
    "tostreamresponse", "toaireadablestream",
    # Both
    "text/event-stream",
)


def _delivery_note(func_text: str) -> str:
    lowered = func_text.lower()
    if not any(marker in lowered for marker in _STREAMING_MARKERS):
        return ""
    return (
        " This endpoint streams its response, so there is no payload to carry a "
        "notice and no patch is offered: the disclosure belongs in the interface "
        "that renders the stream."
    )

# Path segments that say nothing about which feature a file belongs to. Two
# files both living under `app/` are not related; two files both mentioning
# `chat` almost certainly are.
_GENERIC_SEGMENTS = {
    "app", "src", "lib", "libs", "components", "component", "pages", "page",
    "api", "routes", "router", "routers", "handlers", "templates", "template",
    "static", "public", "assets", "views", "view", "index", "main", "server",
    "backend", "frontend", "services", "service", "utils", "util", "common",
    "shared", "core", "internal", "v1", "v2", "web", "www", "ui", "screens",
}


def _tokens(path: str) -> set[str]:
    """Meaningful path words: segments and file stem, minus the generic ones."""
    cleaned = path.lower().replace("\\", "/")
    parts = re.split(r"[/_.\-]+", cleaned)
    return {p for p in parts if p and p not in _GENERIC_SEGMENTS and not p.isdigit()
            and p not in {"py", "ts", "tsx", "js", "jsx", "html", "vue", "svelte"}}


def _covers(route_file: str, notice_file: str) -> bool:
    """Does this notice plausibly belong to the same feature as this endpoint?

    A template named for the same thing as the handler is its notice. A notice
    on an unrelated page is not — which is how an Annex IV page came to exempt
    a chat endpoint.
    """
    return bool(_tokens(route_file) & _tokens(notice_file))


def _disclosure_note(elsewhere: list) -> str:
    """The disclosure half of the claim, written to what was actually seen."""
    if not elsewhere:
        return (
            "No disclosure that the response is AI-generated was found anywhere "
            "in this repository."
        )
    shown = ", ".join(elsewhere[:_MAX_NAMED])
    more = f" and {len(elsewhere) - _MAX_NAMED} other file(s)" if len(elsewhere) > _MAX_NAMED else ""
    return (
        f"No disclosure was found in this file. One appears in {shown}{more} — "
        f"confirm it is shown to the people using this endpoint."
    )


class Article50Disclosure(Rule):
    rule_id = "GA-ART50-001"
    severity = "high"
    title = "User-facing endpoint reaches a model with no AI disclosure"

    def __init__(self, max_hops: int = callgraph.MAX_DEPTH) -> None:
        # Lower this to tighten the claim: 0 means "the call is in the handler
        # itself", which is precise but only true of tutorials.
        self.max_hops = max_hops

    limitations = (
        "The Article 50(1) carve-out for what is 'obvious from the point of view of a "
        "natural person' is not modelled, and arguably cannot be.",
        "A disclosure anywhere in the repository exempts every endpoint in it, so an "
        "app whose copy mentions AI-generated content can hide a genuinely "
        "undisclosed chatbot.",
        "Reachability resolves function names without following imports, so a "
        "multi-hop path can be wrong. Those findings carry lower confidence and name "
        "the file and line they claim to reach.",
        "Only Python, JavaScript and TypeScript are read.",
    )

    @property
    def legal(self) -> LegalReference:
        return LegalReference(
            article="Article 50",
            paragraph="1",
            # Transcribed from the Official Journal text of Regulation (EU)
            # 2024/1689. Both sentences are kept: the carve-out matters, because
            # a law-enforcement reporting tool is outside this duty and a reader
            # needs to see that without leaving the finding.
            text=(
                "Providers shall ensure that AI systems intended to interact directly with "
                "natural persons are designed and developed in such a way that the natural "
                "persons concerned are informed that they are interacting with an AI system, "
                "unless this is obvious from the point of view of a natural person who is "
                "reasonably well-informed, observant and circumspect, taking into account the "
                "circumstances and the context of use. This obligation shall not apply to AI "
                "systems authorised by law to detect, prevent, investigate or prosecute criminal "
                "offences, subject to appropriate safeguards for the rights and freedoms of "
                "third parties, unless those systems are available for the public to report a "
                "criminal offence."
            ),
            source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R1689",
            text_verified=True,
            recital="Recital 132",
            standard_ref="ISO/IEC 42001:2023 A.9.3",
            reviewed_by=None,
        )

    def analyze(self, ctx: RuleContext) -> list[CodeFinding]:
        # A notice in this file settles it: whatever this endpoint returns, the
        # module that builds it discloses.
        if disclosure.in_strings(ctx.file.user_strings):
            return []

        # A notice *somewhere else* is weaker evidence than it looks. Guardia's
        # own frontend discloses on its Annex IV page, which silenced the chat
        # route entirely — a different feature, exempting an endpoint it has
        # nothing to do with. Rather than swallow the finding or ignore the
        # notice, the finding is reported at lower confidence and says where the
        # notice was found, so the reader can confirm it covers this endpoint.
        notices = list(ctx.repo.disclosure_files) if ctx.repo is not None else []
        if any(_covers(ctx.path, notice) for notice in notices):
            return []
        elsewhere = notices

        findings: list[CodeFinding] = []

        # A Streamlit or Gradio script has no handler to anchor on: the module
        # itself is the surface a person uses.
        if ctx.file.ui_surface:
            module_call = next(
                (c for c in ctx.file.module_calls if ctx.is_generation(c.callee)),
                None,
            )
            if module_call is not None:
                findings.append(self._module_finding(ctx, module_call, elsewhere))

        for func in ctx.file.functions:
            if not func.is_route:
                continue

            reach = self._reach(ctx, func)
            if reach is None:
                continue
            invocation, hops = reach
            if hops > self.max_hops:
                continue

            findings.append(self._finding(ctx, func, invocation, hops, elsewhere))
        return findings

    def _module_finding(self, ctx: RuleContext, call, elsewhere: list) -> CodeFinding:
        return CodeFinding(
            rule_id=self.rule_id,
            fingerprint=fingerprint.compute(
                rule_id=self.rule_id, path=ctx.path,
                qualname="<module>", callee=call.callee, occurrence=0,
            ),
            file=ctx.path,
            line=call.line,
            end_line=call.end_line,
            column=call.col,
            symbol="<module>",
            snippet=call.snippet,
            claim=(
                f"This module is a user-facing application script and calls "
                f"`{call.callee}`. " + _disclosure_note(elsewhere)
            ),
            legal=self.legal,
            severity=self.severity,
            confidence="medium" if elsewhere else "high",
            fix=build_ui_notice_fix(
                ctx.source, ctx.file.imports, call.line, call.end_line,
            ),
        )

    def _reach(self, ctx: RuleContext, func):
        """Where this handler reaches a model, and how far away.

        Only generative calls count. Article 50(1) is about content produced for
        a person to read, and this rule's fix inserts "this response was
        generated by an AI system" — which is nonsense attached to a credit
        score. Classical predictions matter to Articles 12 and 14 instead.
        """
        if ctx.repo is not None:
            reached = ctx.repo.reaches_model(ctx.path, func.name)
            if reached is not None and reached[0].kind == "model":
                return None
            return reached

        # Single-file analysis has no reachability information, so the only
        # defensible claim is about a call inside the handler itself.
        if not ctx.uses_provider:
            return None
        for call in func.calls:
            if ctx.is_generation(call.callee):
                return callgraph.Invocation(ctx.path, call.line, call.callee, "sdk"), 0
        return None

    def _finding(self, ctx: RuleContext, func, invocation, hops: int,
                 elsewhere: list) -> CodeFinding:
        if hops == 0:
            path_note = "in the handler itself"
            confidence = "high"
        else:
            hop_word = "call" if hops == 1 else "calls"
            path_note = f"{hops} {hop_word} away, at {invocation.file}:{invocation.line}"
            # Each hop is one more assumption. Name resolution is by bare
            # function name, so a long chain is likelier to have taken a wrong
            # turn.
            confidence = "medium" if hops == 1 else "low"

        how = {
            "sdk": "an SDK call",
            "http": "an HTTP request to a provider endpoint",
            "model": "a trained model",
        }.get(invocation.kind, "a model call")

        # A notice elsewhere in the repository makes the claim weaker, not void.
        if elsewhere and confidence != "low":
            confidence = "low" if confidence == "medium" else "medium"

        return CodeFinding(
            rule_id=self.rule_id,
            fingerprint=fingerprint.compute(
                rule_id=self.rule_id,
                path=ctx.path,
                qualname=func.name,
                callee=invocation.callee,
                occurrence=0,
            ),
            file=ctx.path,
            line=func.line,
            end_line=func.end_line,
            column=func.col,
            symbol=func.qualname,
            snippet=func.snippet,
            claim=(
                f"The endpoint `{func.name}` reaches a model via `{invocation.callee}` "
                f"({how}, {path_note}). " + _disclosure_note(elsewhere)
                + _delivery_note(func.text)
            ),
            legal=self.legal,
            severity=self.severity,
            confidence=confidence,
            fix=self._fix(ctx, func),
        )

    @staticmethod
    def _fix(ctx: RuleContext, func):
        """Each language patches the shape its responses actually take."""
        if ctx.file.language != "python":
            return build_js_disclosure_fix(
                ctx.source, ctx.path, func.line, func.end_line,
            )

        import ast

        try:
            tree = ast.parse(ctx.source)
        except (SyntaxError, ValueError):
            return None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and node.name == func.name and node.lineno == func.line:
                return build_disclosure_fix(ctx.source, node, ctx.path)
        return None

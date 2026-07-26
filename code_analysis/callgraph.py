"""Repo-level reachability: does this route handler end up invoking a model?

Built because the first corpus run found nothing on three real applications.
Production code puts the provider call behind a service layer — khoj calls
`chat.completions.create` in `processor/conversation/openai/utils.py` while its
routes live in `routers/api_chat.py`, several layers apart. A rule that only
looks inside the route function sees tutorials, not systems.

Resolution is by bare function name, not by resolving imports. That
over-approximates: two same-named functions in different modules are treated as
one. The alternative is a full import resolver, which is a large amount of
machinery for a gain that mostly matters in repos with heavy name collisions.
Findings that depend on a multi-hop path say so and carry lower confidence, so
the over-approximation is visible to the reader rather than hidden.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from . import providers

# How far a route handler may be from the model call before we stop claiming a
# connection. Three hops covers route → service → client wrapper, which is the
# shape almost every application uses; beyond that the claim gets too thin.
MAX_DEPTH = 3

@dataclass
class Invocation:
    """Where a model is actually invoked."""
    file: str
    line: int
    callee: str
    kind: str          # 'sdk' | 'http'


@dataclass
class FunctionInfo:
    file: str
    qualname: str
    name: str                       # bare name, used for cross-file matching
    lineno: int
    is_route: bool
    calls: set[str] = field(default_factory=set)
    invocation: Optional[Invocation] = None   # direct invocation, if any


@dataclass
class RepoModel:
    functions: list[FunctionInfo] = field(default_factory=list)
    # bare name -> (invocation, hops). hops 0 means the function invokes
    # directly; 2 means two calls away.
    reaching: dict[str, tuple[Invocation, int]] = field(default_factory=dict)
    disclosure: bool = False
    # Whether anything in the repository tests for bias. Article 10's claim is
    # an absence over the whole repo, so it cannot be answered file by file.
    fairness_tested: bool = False

    def reaches_model(self, name: str) -> Optional[tuple[Invocation, int]]:
        return self.reaching.get(name)


def index_file(model) -> list[FunctionInfo]:
    """Every function in one file, with what it calls and whether it invokes.

    Takes a language-neutral FileModel, so Python and JavaScript both land here
    through the same door.
    """
    all_callees = tuple(call.callee for call in model.all_calls())
    sdk_capable = providers.uses_provider(model.imports, all_callees)

    infos: list[FunctionInfo] = []
    for func in model.functions:
        info = FunctionInfo(
            file=model.path,
            qualname=func.qualname,
            name=func.name,
            lineno=func.line,
            is_route=func.is_route,
        )

        # Evidence that an HTTP call targets a provider is looked for in the
        # enclosing function plus the module's own constants — the base URL is
        # usually a module-level setting while the call sits inside a handler.
        scope_text = func.text + "\n" + model.module_constants

        for call in func.calls:
            # Only plain `name(...)` calls make an edge, and only when the
            # module defines or imports that name. A method call on an object
            # we cannot resolve tells us nothing about which function runs.
            if call.callee and "." not in call.callee and call.callee in model.resolvable:
                info.calls.add(call.callee)

            if info.invocation is not None:
                continue
            if sdk_capable and providers.is_generation_call(call.callee):
                info.invocation = Invocation(model.path, call.line, call.callee, "sdk")
            elif providers.looks_like_http_model_call(call.callee, scope_text):
                info.invocation = Invocation(model.path, call.line, call.callee, "http")

        infos.append(info)
    return infos


def build(
    indexed: list[FunctionInfo],
    disclosure: bool = False,
    fairness_tested: bool = False,
) -> RepoModel:
    """Propagate 'invokes a model' backwards along call edges."""
    model = RepoModel(
        functions=indexed,
        disclosure=disclosure,
        fairness_tested=fairness_tested,
    )

    # Which bare names invoke directly.
    frontier: deque[tuple[str, Invocation, int]] = deque()
    for info in indexed:
        if info.invocation is not None:
            existing = model.reaching.get(info.name)
            if existing is None or existing[1] > 0:
                model.reaching[info.name] = (info.invocation, 0)
                frontier.append((info.name, info.invocation, 0))

    # Callers of a reaching function reach it too, one hop further out.
    callers: dict[str, list[FunctionInfo]] = {}
    for info in indexed:
        for callee_name in info.calls:
            callers.setdefault(callee_name, []).append(info)

    while frontier:
        name, invocation, hops = frontier.popleft()
        if hops >= MAX_DEPTH:
            continue
        for caller in callers.get(name, []):
            if caller.name == name:          # direct recursion
                continue
            known = model.reaching.get(caller.name)
            if known is not None and known[1] <= hops + 1:
                continue
            model.reaching[caller.name] = (invocation, hops + 1)
            frontier.append((caller.name, invocation, hops + 1))

    return model

"""Walks a workspace, runs the rule pack, returns findings.

The analyzer is the only component that touches disk, and it never calls out to
a network service. Detection has to run entirely inside a customer's CI with
their source never leaving it — an LLM call from the scanner would be a
data-exfiltration objection that ends enterprise conversations before they start.

A workspace scan is two passes. The first builds a language-neutral model of
every file, indexes its functions and looks for an AI disclosure anywhere in the
repository; the second runs the rules with that knowledge available. Rules that
need to know whether a route handler eventually reaches a model — which is most
of them — cannot answer that from one file.
"""
from __future__ import annotations

import ast
import os
import time
from typing import Optional

from . import callgraph, disclosure, filemodel, js, scope, suppressions
from .callgraph import RepoModel
from .filemodel import FileModel
from .models import CodeFinding, CodeScanResult
from .rules import art10_data_governance as art10
from .rules.base import Rule, RuleContext, registry

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", ".next",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    "vendor", ".terraform", "migrations",
}

MAX_FILE_BYTES = 1_000_000


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return None


def build_model(path: str, source: str) -> Optional[FileModel]:
    """A language-neutral model of one file, or None if it cannot be parsed.

    A customer's syntax error is not our finding to report, and one bad file
    must never abort a scan.
    """
    if path.endswith(".py"):
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return None
        return filemodel.from_python(path, source, tree)

    if js.is_js_file(path):
        return js.from_javascript(path, source)

    return None


def is_analyzable(path: str) -> bool:
    return path.endswith(".py") or (js.is_js_file(path) and js.AVAILABLE)


def analyze_source(
    path: str,
    source: str,
    rules: list[Rule] | None = None,
    repo: RepoModel | None = None,
) -> list[CodeFinding]:
    """Run the rule pack against one file's source."""
    model = build_model(path, source)
    if model is None:
        return []
    return analyze_model(model, rules=rules, repo=repo)


def analyze_model(
    model: FileModel,
    rules: list[Rule] | None = None,
    repo: RepoModel | None = None,
) -> list[CodeFinding]:
    rules = rules if rules is not None else registry()
    ctx = RuleContext(file=model, repo=repo)

    suppressed = suppressions.index(model.source, model.language)
    findings: list[CodeFinding] = []

    for rule in rules:
        try:
            produced = rule.analyze(ctx)
        except Exception:
            # A broken rule must not take the scan down with it. Findings from
            # the other rules are still worth returning.
            continue

        for finding in produced:
            # A finding anchored on a route handler spans the whole function,
            # and a developer will write the ignore comment next to the model
            # call rather than next to the `def`. Any suppression inside the
            # finding's span counts.
            for line in range(finding.line, max(finding.end_line, finding.line) + 1):
                hit = suppressed.get((finding.rule_id.upper(), line))
                if hit:
                    finding.suppressed = True
                    finding.suppression_reason = hit.reason
                    break
            findings.append(finding)

    return findings


def analyze_workspace(
    root: str,
    rules: list[Rule] | None = None,
    include_non_shipped: bool = False,
) -> CodeScanResult:
    """Scan the source files under `root` that represent a deployed system.

    Tests, examples and docs are excluded unless `include_non_shipped` is set —
    see `scope`, which exists because they were 84 of 84 findings on one repo.
    """
    started = time.perf_counter()
    rules = rules if rules is not None else registry()

    models: list[FileModel] = []
    indexed: list[callgraph.FunctionInfo] = []
    disclosure_files: list[str] = []
    found_fairness = False
    scanned = skipped = out_of_scope = 0

    # ---- pass 1: model every file, and look for a disclosure anywhere ----
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")

            if not is_analyzable(rel):
                # A disclosure usually lives in a template, so those are worth
                # reading once — but only until one is found, since a single
                # notice settles the question. Files outside the shipped system
                # cannot carry a runtime notice.
                if disclosure.is_template(rel) and scope.in_scope(rel):
                    text = _read(full)
                    if text and disclosure.has_disclosure(text):
                        disclosure_files.append(rel)
                continue

            if not include_non_shipped and not scope.in_scope(rel):
                out_of_scope += 1
                # A fairness test usually lives in tests/, which is exactly
                # where this rule must still look.
                if not found_fairness:
                    text = _read(full)
                    if text and art10.repo_tests_fairness(text):
                        found_fairness = True
                continue

            source = _read(full)
            if source is None:
                skipped += 1
                continue

            scanned += 1
            model = build_model(rel, source)
            if model is None:
                continue

            models.append(model)
            # String literals only: a comment saying "this is an AI" informs
            # the reader of the code, not the user of the product.
            if disclosure.in_strings(model.user_strings):
                disclosure_files.append(rel)
            # Article 10 asks whether fairness is tested anywhere at all, so
            # every file counts — including the ones out of scope for findings.
            if not found_fairness and art10.repo_tests_fairness(source):
                found_fairness = True
            indexed.extend(callgraph.index_file(model))

    # A handler registered in one file is often defined in another —
    # `app.post("/chat", chatHandler)` in server.js, `chatHandler` in
    # handlers.js. Route-ness has to be resolved once every file is modelled.
    registered = {name for model in models for name in model.route_registrations}
    if registered:
        indexed = []
        for model in models:
            for func in model.functions:
                if func.name in registered:
                    func.is_route = True
            indexed.extend(callgraph.index_file(model))

    repo = callgraph.build(
        indexed,
        disclosure=bool(disclosure_files),
        fairness_tested=found_fairness,
        disclosure_files=disclosure_files,
    )

    # ---- pass 2: run the rules with reachability available ----
    findings: list[CodeFinding] = []
    for model in models:
        findings.extend(analyze_model(model, rules=rules, repo=repo))

    findings.sort(key=lambda f: (f.file, f.line))
    return CodeScanResult(
        findings=findings,
        files_scanned=scanned,
        files_skipped=skipped,
        files_out_of_scope=out_of_scope,
        rules_run=[r.rule_id for r in rules],
        suppressed_count=sum(1 for f in findings if f.suppressed),
        duration_ms=int((time.perf_counter() - started) * 1000),
    )

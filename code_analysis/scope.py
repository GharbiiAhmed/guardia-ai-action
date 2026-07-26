"""Which files represent a deployed AI system.

Scanning openai-python produced 84 findings: 78 in `tests/`, 6 in `examples/`.
Every one was technically accurate and commercially worthless — a test fixture
calling a model without logging it is not a compliance gap, and telling a
customer otherwise is how a tool gets uninstalled.

The obligations in the Act attach to a system placed on the market or put into
service. Test suites, example scripts and documentation snippets are none of
those, so they are out of scope by default and in scope only on request.
"""
from __future__ import annotations

import re

# Directory names that mean "not the shipped system", matched on any path segment.
_OUT_OF_SCOPE_DIRS = {
    "test", "tests", "testing", "e2e", "fixtures", "conftest",
    "example", "examples", "sample", "samples", "demo", "demos",
    "doc", "docs", "documentation", "tutorial", "tutorials", "cookbook",
    "benchmark", "benchmarks", "notebook", "notebooks", "scripts",
}

_OUT_OF_SCOPE_FILES = re.compile(
    r"(^|/)(test_[^/]+|[^/]+_test|conftest|setup|noxfile|tasks)\.py$",
    re.IGNORECASE,
)


def in_scope(path: str) -> bool:
    """False for tests, examples, docs and other non-shipped code."""
    normalized = path.replace("\\", "/").lower()
    segments = normalized.split("/")[:-1]
    if any(segment in _OUT_OF_SCOPE_DIRS for segment in segments):
        return False
    return not _OUT_OF_SCOPE_FILES.search(normalized)


def reason(path: str) -> str:
    """Why a path was skipped — surfaced so the exclusion is auditable."""
    normalized = path.replace("\\", "/").lower()
    for segment in normalized.split("/")[:-1]:
        if segment in _OUT_OF_SCOPE_DIRS:
            return f"under '{segment}/'"
    if _OUT_OF_SCOPE_FILES.search(normalized):
        return "test or build support file"
    return ""

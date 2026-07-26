"""Small AST helpers shared by every rule.

Kept deliberately boring: rules should express a compliance question, not
re-implement tree walking. Anything here that starts encoding a specific
article belongs in that article's rule module instead.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional, Union

FuncNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]


@dataclass
class CallSite:
    node: ast.Call
    qualname: str                 # enclosing symbol, '<module>' at top level
    func: Optional[FuncNode]      # enclosing function, None at module level
    callee: str                   # dotted call target, '' if not a plain name


def dotted_name(node: ast.AST) -> str:
    """'client.chat.completions.create' for an attribute/name chain, else ''."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    elif isinstance(current, ast.Call):
        # e.g. get_client().chat.create — keep the attribute tail, drop the call
        inner = dotted_name(current.func)
        if inner:
            parts.append(inner)
    else:
        return ""
    return ".".join(reversed(parts))


def module_imports(tree: ast.Module) -> set[str]:
    """Top-level package names imported anywhere in the module.

    'from google.generativeai import x' contributes both 'google' and
    'google.generativeai' so rules can match at either granularity.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
    return names


def iter_calls(tree: ast.Module) -> list[CallSite]:
    """Every call in the module, tagged with the symbol that encloses it."""
    sites: list[CallSite] = []

    def visit(node: ast.AST, stack: list[str], func: Optional[FuncNode]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, stack + [child.name], child)
            elif isinstance(child, ast.ClassDef):
                visit(child, stack + [child.name], func)
            else:
                if isinstance(child, ast.Call):
                    sites.append(CallSite(
                        node=child,
                        qualname=".".join(stack) or "<module>",
                        func=func,
                        callee=dotted_name(child.func),
                    ))
                visit(child, stack, func)

    visit(tree, [], None)
    return sites


def string_constants(node: ast.AST) -> list[str]:
    """Every string literal under `node`, including f-string literal parts."""
    out: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            out.append(child.value)
    return out


def decorator_names(func: FuncNode) -> list[str]:
    """Dotted names of a function's decorators, calls unwrapped.

    '@router.post("/chat")' yields 'router.post'.
    """
    names: list[str] = []
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = dotted_name(target)
        if name:
            names.append(name)
    return names


def assigned_names(func: FuncNode, call: ast.Call) -> set[str]:
    """Variables bound directly to the result of `call` within `func`."""
    bound: set[str] = set()
    for node in ast.walk(func):
        value = getattr(node, "value", None)
        if value is not call:
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound.add(target.id)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(node.target, ast.Name):
                bound.add(node.target.id)
        elif isinstance(node, ast.Await):
            # `x = await client.create(...)` — the Await wraps the call, so
            # walk one level out to find the binding.
            for outer in ast.walk(func):
                outer_value = getattr(outer, "value", None)
                if outer_value is node and isinstance(outer, ast.Assign):
                    for target in outer.targets:
                        if isinstance(target, ast.Name):
                            bound.add(target.id)
    return bound


def reaches_return(func: FuncNode, call: ast.Call) -> bool:
    """Does the value of `call` plausibly reach a return statement?

    Conservative and intentionally shallow: direct return, return of a variable
    the call was assigned to, or that variable appearing anywhere inside a
    returned expression. Deliberately does not attempt full dataflow — a rule
    that fires on a guess is worse than one that stays quiet.
    """
    names = assigned_names(func, call)
    for node in ast.walk(func):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        for inner in ast.walk(node.value):
            if inner is call:
                return True
            if isinstance(inner, ast.Name) and inner.id in names:
                return True
    return False


def source_segment(source: str, node: ast.AST, max_lines: int = 3) -> str:
    """Readable snippet for a node, trimmed so PR comments stay short."""
    try:
        segment = ast.get_source_segment(source, node) or ""
    except Exception:
        segment = ""
    if not segment:
        return ""
    lines = segment.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["    ..."]
    return "\n".join(lines).strip()

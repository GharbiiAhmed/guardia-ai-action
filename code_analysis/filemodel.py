"""A language-neutral view of one source file.

Rules ask the same four questions of any file — what does it import, what does
it call, which of its functions are user-facing, and does it contain a
disclosure — so they should not have to know whether the answers came from
Python's `ast` or from tree-sitter. Everything language-specific lives in a
builder (`from_python`, and `js.from_javascript`); everything above this line is
shared.

Adding a third language means writing one builder, not touching any rule.
"""
from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CallRef:
    """One call site."""
    callee: str                 # dotted target, e.g. 'client.chat.completions.create'
    line: int
    end_line: int
    col: int = 0
    snippet: str = ""
    # True when this call only runs if something went wrong. A log inside an
    # exception handler records failures, not the events the system performed.
    in_error_handler: bool = False


@dataclass
class FunctionModel:
    name: str                   # bare name — how the call graph resolves across files
    qualname: str               # display name, e.g. 'ChatHandler.respond'
    line: int
    end_line: int
    col: int = 0
    is_route: bool = False      # directly reachable by a user over HTTP
    calls: list[CallRef] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    text: str = ""              # source of the function body, for URL evidence
    snippet: str = ""           # one-line signature, for display


@dataclass
class FileModel:
    path: str
    language: str               # 'python' | 'javascript' | 'typescript'
    source: str
    imports: set[str] = field(default_factory=set)
    functions: list[FunctionModel] = field(default_factory=list)
    module_calls: list[CallRef] = field(default_factory=list)
    module_constants: str = ""  # top-level assignments, where base URLs live
    # Strings a user could actually see. Excludes comments and docstrings: a
    # comment saying "this is an AI" informs the reader of the code, not the
    # user of the product.
    user_strings: list[str] = field(default_factory=list)
    # Names this module defines or imports. An edge is only drawn to one of
    # these — see callgraph for why that matters.
    resolvable: set[str] = field(default_factory=set)
    # Handlers registered by name here but usually defined elsewhere, e.g.
    # `app.post("/chat", chatHandler)`. Resolved across files by the analyzer.
    route_registrations: set[str] = field(default_factory=set)
    # Streamlit, Gradio and friends have no route handler — the script itself
    # is what a person interacts with. GPTInterviewer, a behavioural screening
    # tool, has no HTTP layer at all.
    ui_surface: bool = False
    # The source with the contents of module-level constant tables blanked out.
    #
    # A rule that searches raw text cannot tell code that *does* a thing from
    # code that *names* it. Guardia's own Article 5 rule file lists "cctv",
    # "scrape" and "face_encodings" as the markers it looks for, and so reported
    # itself for facial scraping, biometric categorisation and live biometric
    # identification. Any vocabulary list — a policy engine, a moderation
    # config, a security scanner — has the same shape.
    #
    # Only the string *contents* are blanked; the names, the structure and every
    # other line are untouched, so a marker used anywhere else still matches.
    # Equal to `source` for languages where this is not computed.
    code_text: str = ""

    def all_calls(self) -> list[CallRef]:
        calls = list(self.module_calls)
        for func in self.functions:
            calls.extend(func.calls)
        return calls

    def function_at(self, name: str) -> Optional[FunctionModel]:
        for func in self.functions:
            if func.name == name:
                return func
        return None


# ---------- Python builder ----------

def from_python(path: str, source: str, tree) -> FileModel:
    import ast

    from . import astutil, disclosure

    model = FileModel(
        path=path,
        language="python",
        source=source,
        imports=astutil.module_imports(tree),
        module_constants=_python_module_constants(source, tree),
    )

    # Names this module could actually be calling.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            model.resolvable.add(node.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                model.resolvable.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    model.resolvable.add(alias.asname)

    lines = source.splitlines()

    # Calls that live inside an `except` block.
    handled: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    handled.add(id(inner))

    by_id: dict[int, FunctionModel] = {}
    for site in astutil.iter_calls(tree):
        ref = CallRef(
            callee=site.callee,
            line=site.node.lineno,
            end_line=getattr(site.node, "end_lineno", site.node.lineno) or site.node.lineno,
            col=site.node.col_offset,
            in_error_handler=id(site.node) in handled,
        )
        if site.func is None:
            model.module_calls.append(ref)
            continue

        func = by_id.get(id(site.func))
        if func is None:
            func = FunctionModel(
                name=site.func.name,
                qualname=site.qualname,
                line=site.func.lineno,
                end_line=getattr(site.func, "end_lineno", site.func.lineno) or site.func.lineno,
                col=site.func.col_offset,
                is_route=_python_is_route(site.func, astutil),
                decorators=astutil.decorator_names(site.func),
                text="\n".join(lines[site.func.lineno - 1:site.func.end_lineno or site.func.lineno]),
                snippet=lines[site.func.lineno - 1].strip() if lines else "",
            )
            by_id[id(site.func)] = func
            model.functions.append(func)
        func.calls.append(ref)

    # Functions with no calls at all still matter: a route handler that only
    # returns a constant is a route handler.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if id(node) in by_id:
            continue
        model.functions.append(FunctionModel(
            name=node.name,
            qualname=node.name,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            col=node.col_offset,
            is_route=_python_is_route(node, astutil),
            decorators=astutil.decorator_names(node),
            text="\n".join(lines[node.lineno - 1:node.end_lineno or node.lineno]),
            snippet=lines[node.lineno - 1].strip() if lines else "",
        ))

    model.ui_surface = bool(_UI_FRAMEWORKS & model.imports)
    if model.ui_surface:
        # Every function in such a script runs in response to a person using it.
        for func in model.functions:
            func.is_route = True

    model.user_strings = disclosure.python_string_literals(tree)
    model.code_text = _blank_constant_tables(source, tree)
    return model


def _blank_constant_tables(source: str, tree: ast.Module) -> str:
    """Blank the parts of a file that describe rather than do.

    Three kinds of text can name a behaviour without performing it, and a
    keyword rule cannot tell them from the real thing:

    * **comments** — a note about cctv footage is not a camera;
    * **docstrings** — including a quoted article of the Regulation, which is
      how the word "CCTV" ends up in a file whose job is to look for it;
    * **strings assigned to a name** — a marker table, a moderation vocabulary,
      a list of column names. Declaring a word is not using it.

    A string passed to a call is left alone: `analyze(image, actions=["race"])`
    is the behaviour itself. Everything outside these spans is untouched, so a
    marker appearing anywhere else still matches.
    """
    spans: list[tuple[int, int, int, int]] = []

    def record(node) -> None:
        if getattr(node, "end_lineno", None) is not None:
            spans.append((node.lineno, node.col_offset,
                          node.end_lineno, node.end_col_offset))

    # Strings assigned to a name, at any nesting level.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = getattr(node, "value", None)
            if value is None:
                continue
            for inner in ast.walk(value):
                if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                    record(inner)
        # Docstrings: the first statement of a module, class or function.
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                record(body[0].value)

    # Comments are not in the tree at all.
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                spans.append((token.start[0], token.start[1],
                              token.end[0], token.end[1]))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass

    if not spans:
        return source

    lines = source.splitlines(keepends=True)
    for start_line, start_col, end_line, end_col in spans:
        for lineno in range(start_line, end_line + 1):
            index = lineno - 1
            if index >= len(lines):
                continue
            line = lines[index]
            begin = start_col if lineno == start_line else 0
            finish = end_col if lineno == end_line else len(line.rstrip("\n"))
            lines[index] = line[:begin] + " " * max(0, finish - begin) + line[finish:]
    return "".join(lines)


# Frameworks where the whole module is the user interface.
_UI_FRAMEWORKS = {
    "streamlit", "gradio", "chainlit", "panel", "dash", "nicegui", "reflex",
    "mesop", "solara", "taipy",
}

_PY_ROUTE_DECORATORS = {
    "get", "post", "put", "patch", "delete", "route", "websocket", "api_route",
}


def _python_is_route(func, astutil) -> bool:
    for name in astutil.decorator_names(func):
        tail = name.rsplit(".", 1)[-1].lower()
        if tail in _PY_ROUTE_DECORATORS and "." in name:
            return True
    return False


def _python_module_constants(source: str, tree) -> str:
    import ast

    lines = source.splitlines()
    parts = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            start = getattr(node, "lineno", None)
            end = getattr(node, "end_lineno", None)
            if start and end:
                parts.append("\n".join(lines[start - 1:end]))
    return "\n".join(parts)

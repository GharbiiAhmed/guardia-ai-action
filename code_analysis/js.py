"""JavaScript and TypeScript, via tree-sitter.

Python's `ast` has no counterpart here, so this builds the same FileModel from a
tree-sitter parse. The awkward part is not parsing — it is that "a user-facing
endpoint" looks completely different in each framework:

* **Express / Fastify / Koa** — `app.post('/chat', handler)`. The handler is an
  argument, so the route-ness of a function is decided at the *call site*, not
  at the definition. Handlers passed by name are resolved back to their
  definition.
* **Next.js App Router** — `export async function POST(req)` in a `route.ts`.
  The HTTP verb is the function's name and nothing marks it as a route.
* **NestJS** — `@Post()` on a class method, closest to the Python decorator
  shape.

If tree-sitter is unavailable the module reports so and the analyzer skips
JS/TS rather than failing: a missing optional parser must not break a scan.
"""
from __future__ import annotations

from typing import Optional

from .filemodel import CallRef, FileModel, FunctionModel

try:
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Parser

    _JS = Language(tree_sitter_javascript.language())
    _TS = Language(tree_sitter_typescript.language_typescript())
    _TSX = Language(tree_sitter_typescript.language_tsx())
    AVAILABLE = True
except Exception:  # pragma: no cover - depends on the environment
    AVAILABLE = False

SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")

_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "all", "use", "options", "head"}

# Next.js App Router exports the verb as the function name.
_NEXT_ROUTE_NAMES = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

_FUNCTION_NODES = {
    "function_declaration", "function_expression", "arrow_function",
    "method_definition", "generator_function_declaration",
}


def language_for(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith((".ts", ".mts", ".cts")):
        return "typescript"
    if lowered.endswith(".tsx"):
        return "tsx"
    return "javascript"


def is_js_file(path: str) -> bool:
    return path.lower().endswith(SUFFIXES)


def _parser_for(path: str):
    kind = language_for(path)
    if kind == "typescript":
        return Parser(_TS)
    if kind == "tsx":
        return Parser(_TSX)
    return Parser(_JS)


def _text(node, data: bytes) -> str:
    return data[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _dotted(node, data: bytes) -> str:
    """'client.chat.completions.create' for a member expression chain."""
    if node is None:
        return ""
    if node.type == "identifier":
        return _text(node, data)
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        head = _dotted(obj, data)
        tail = _text(prop, data) if prop is not None else ""
        return f"{head}.{tail}" if head and tail else (head or tail)
    if node.type == "call_expression":
        # getClient().chat.create — keep the attribute tail, drop the call
        return _dotted(node.child_by_field_name("function"), data)
    if node.type in {"await_expression", "parenthesized_expression", "non_null_expression"}:
        for child in node.named_children:
            found = _dotted(child, data)
            if found:
                return found
    return ""


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _function_name(node, data: bytes) -> Optional[str]:
    """Name of a function node, including the `const x = () => {}` shape."""
    named = node.child_by_field_name("name")
    if named is not None:
        return _text(named, data)

    # Arrow functions and function expressions take the name of whatever they
    # are bound to.
    parent = node.parent
    if parent is None:
        return None
    if parent.type == "variable_declarator":
        target = parent.child_by_field_name("name")
        if target is not None:
            return _text(target, data)
    if parent.type == "pair":                      # { handler: () => {} }
        key = parent.child_by_field_name("key")
        if key is not None:
            return _text(key, data).strip("'\"")
    if parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None:
            return _dotted(left, data).rsplit(".", 1)[-1]
    return None


def _decorators(node, data: bytes) -> list:
    """Decorator names on a class method — NestJS's `@Post()`, `@Audited()`."""
    parent = node.parent
    if parent is None:
        return []
    return [
        _text(sibling, data).lstrip("@").split("(")[0].strip()
        for sibling in parent.children
        if sibling.type == "decorator"
    ]


def _has_route_decorator(node, data: bytes) -> bool:
    """NestJS: @Post() on a method."""
    parent = node.parent
    if parent is None:
        return False
    for sibling in parent.children:
        if sibling.type != "decorator":
            continue
        if _text(sibling, data).lstrip("@").split("(")[0].strip().lower() in _HTTP_VERBS:
            return True
    return False


def from_javascript(path: str, source: str) -> Optional[FileModel]:
    """Build a FileModel, or None if the parser is unavailable."""
    if not AVAILABLE:
        return None

    data = source.encode("utf-8")
    try:
        tree = _parser_for(path).parse(data)
    except Exception:
        return None

    kind = language_for(path)
    model = FileModel(
        path=path,
        language="typescript" if kind in {"typescript", "tsx"} else "javascript",
        source=source,
    )

    lines = source.splitlines()
    nodes = list(_walk(tree.root_node))

    # ---- imports ----
    for node in nodes:
        if node.type == "import_statement":
            src = node.child_by_field_name("source")
            if src is not None:
                model.imports.add(_text(src, data).strip("'\"`"))
            # The *names* an import binds matter as much as the module path:
            # without them `import { generateReply } from "./llm"` leaves the
            # caller unable to draw an edge to the function it just imported.
            for child in node.named_children:
                if child.type == "string":
                    continue
                for inner in _walk(child):
                    if inner.type == "identifier":
                        model.resolvable.add(_text(inner, data))
        elif node.type == "call_expression":
            callee = _dotted(node.child_by_field_name("function"), data)
            if callee in {"require", "import"}:
                args = node.child_by_field_name("arguments")
                if args is not None and args.named_children:
                    model.imports.add(_text(args.named_children[0], data).strip("'\"`"))
                # `const { chatHandler } = require("./handlers")` binds names too.
                declarator = node.parent
                while declarator is not None and declarator.type not in {
                    "variable_declarator", "program",
                }:
                    declarator = declarator.parent
                if declarator is not None and declarator.type == "variable_declarator":
                    target = declarator.child_by_field_name("name")
                    if target is not None:
                        for inner in _walk(target):
                            if inner.type in {"identifier", "shorthand_property_identifier_pattern"}:
                                model.resolvable.add(_text(inner, data))

    # Bare package names too, so 'openai/resources' still matches 'openai'.
    model.imports |= {name.split("/")[0] for name in list(model.imports)}

    # ---- functions ----
    # Keyed by `node.id`, not `id(node)`: the tree-sitter binding hands back a
    # fresh Node object on every access, so `node.parent` never matches an
    # identity built from the Python object. Everything was attributed to
    # module scope until this was keyed properly.
    by_node: dict[int, FunctionModel] = {}
    for node in nodes:
        if node.type not in _FUNCTION_NODES:
            continue
        name = _function_name(node, data)
        if not name:
            continue
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        func = FunctionModel(
            name=name,
            qualname=name,
            line=start,
            end_line=end,
            col=node.start_point[1],
            # A Next.js route file exports the verb as the function name; NestJS
            # marks the method with a decorator. Express is handled below, at
            # the call site that registers the handler.
            is_route=(name in _NEXT_ROUTE_NAMES) or _has_route_decorator(node, data),
            decorators=_decorators(node, data),
            text=_text(node, data),
            snippet=lines[start - 1].strip() if start - 1 < len(lines) else "",
        )
        by_node[node.id] = func
        model.functions.append(func)
        model.resolvable.add(name)

    # ---- calls, attributed to their enclosing function ----
    for node in nodes:
        if node.type != "call_expression":
            continue
        callee = _dotted(node.child_by_field_name("function"), data)
        if not callee:
            continue
        ref = CallRef(
            callee=callee,
            line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            col=node.start_point[1],
        )

        enclosing = node.parent
        owner = None
        while enclosing is not None:
            if enclosing.id in by_node:
                owner = by_node[enclosing.id]
                break
            enclosing = enclosing.parent

        if owner is None:
            model.module_calls.append(ref)
        else:
            owner.calls.append(ref)

        # ---- Express-style registration: app.post('/chat', handler) ----
        tail = callee.rsplit(".", 1)[-1].lower()
        if "." in callee and tail in _HTTP_VERBS:
            _mark_express_handlers(node, data, by_node, model)

    # ---- module constants and user-visible strings ----
    const_parts, strings = [], []
    for node in nodes:
        # jsx_text is the visible text between tags — the most likely place
        # for a notice to actually live in a React component.
        if node.type in {"string", "template_string", "jsx_text"}:
            strings.append(_text(node, data).strip("'\"`"))
        # Property names count too: `{ reply, ai_disclosure: "..." }` discloses
        # by its field name. In Python a dict key is a string literal and is
        # already covered; in JS it is a bare identifier.
        elif node.type in {"property_identifier", "shorthand_property_identifier"}:
            strings.append(_text(node, data))
        elif node.type in {"lexical_declaration", "variable_declaration"} and node.parent is not None \
                and node.parent.type == "program":
            const_parts.append(_text(node, data))
    model.module_constants = "\n".join(const_parts)
    model.user_strings = strings

    return model


def _mark_express_handlers(call_node, data: bytes, by_node: dict, model: FileModel) -> None:
    """Whatever `app.post('/x', ...)` was handed is a route handler.

    Covers both an inline arrow function and a handler passed by name — the
    second is the common shape once a codebase grows past one file.
    """
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return
    for arg in args.named_children:
        if arg.type in _FUNCTION_NODES and arg.id in by_node:
            by_node[arg.id].is_route = True
        elif arg.type in _FUNCTION_NODES:
            # An anonymous inline handler: register it so the call graph and
            # the rules can still see it.
            start = arg.start_point[0] + 1
            model.functions.append(FunctionModel(
                name=f"<handler@{start}>",
                qualname=f"<handler@{start}>",
                line=start,
                end_line=arg.end_point[0] + 1,
                col=arg.start_point[1],
                is_route=True,
                calls=[
                    CallRef(
                        callee=_dotted(inner.child_by_field_name("function"), data),
                        line=inner.start_point[0] + 1,
                        end_line=inner.end_point[0] + 1,
                    )
                    for inner in _walk(arg)
                    if inner.type == "call_expression"
                    and _dotted(inner.child_by_field_name("function"), data)
                ],
                text=_text(arg, data),
            ))
            by_node[arg.id] = model.functions[-1]
        elif arg.type == "identifier":
            name = _text(arg, data)
            func = model.function_at(name)
            if func is not None:
                func.is_route = True
            else:
                # Defined in another module — the analyzer resolves this once
                # every file has been modelled.
                model.route_registrations.add(name)


# ---- support for the Article 50 codemod ----

# How a JSON body reaches the client. `Response.json` and `NextResponse.json`
# cover the Next.js App Router; `res.json` covers Express and the Pages Router.
_JSON_RESPONSE_CALLS = (
    "response.json", "nextresponse.json", "res.json", "reply.send", "res.send",
)


def json_response_objects(path: str, source: str, start_line: int, end_line: int) -> list:
    """Object literals handed to a JSON response helper within a line range.

    The Python codemod patches a returned dict. The equivalent here is the
    object passed to `Response.json({...})`, which is why the two fixers cannot
    share an implementation even though they make the same change.
    """
    if not AVAILABLE:
        return []
    data = source.encode("utf-8")
    try:
        tree = _parser_for(path).parse(data)
    except Exception:
        return []

    found = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        line = node.start_point[0] + 1
        if not (start_line <= line <= end_line):
            continue
        callee = _dotted(node.child_by_field_name("function"), data).lower()
        if callee not in _JSON_RESPONSE_CALLS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None or not args.named_children:
            continue
        first = args.named_children[0]
        if first.type != "object":
            continue
        keys = []
        for pair in first.named_children:
            key = pair.child_by_field_name("key") if pair.type == "pair" else None
            if key is not None:
                keys.append(_text(key, data).strip("'\"`"))
        found.append({
            "line": first.start_point[0] + 1,
            "end_line": first.end_point[0] + 1,
            "text": _text(first, data),
            "keys": keys,
        })
    return found

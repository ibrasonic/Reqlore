"""Phase 7 — JavaScript static AST taint analysis.

Parses JS responses with :mod:`esprima` and walks the AST looking for
flows from a known taint source (``location.hash``, ``document.referrer``,
``window.name``, ``localStorage.getItem(...)``, etc.) to a known sink
(``eval``, ``innerHTML``, ``document.write``, etc.) without an
intervening sanitiser (``DOMPurify.sanitize``, ``encodeURIComponent``).

The analyser is intentionally **lightweight**:

* one tree walk; intra-procedural; tracks variable taint within the
  declaring scope (script-level + function-body). Tainted state
  inherits into nested functions; assignment to a variable removes
  taint unless the new value is itself tainted
* sanitiser calls strip taint on their *return value* only — the
  argument variable keeps its previous taint state
* a hard wall-clock budget (default 5 s) bounds analysis; source files
  larger than ``max_size`` bytes (default 2 MB) are skipped outright

The output is a list of :class:`Finding` objects with ``host="" url=""``
so the caller (passive scanner) can fill those in from the response
context. Confidence is biased toward ``firm`` for direct flows and
``tentative`` when the flow passes through a partial sanitiser
(``encodeURIComponent`` reaching an HTML sink, for instance, prevents
JS-string injection but not all HTML injection).

Public surface::

    from reqlore.scanner.js_static import analyze_js

    findings = analyze_js(js_source, budget_s=5.0)

If ``esprima`` is not installed, :func:`analyze_js` returns an empty
list and records nothing — the rest of the scanner continues to work.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .findings import Finding

try:
    import esprima  # type: ignore[import-untyped]
    _HAVE_ESPRIMA = True
except ImportError:  # pragma: no cover — covered in optional-deps test
    esprima = None  # type: ignore[assignment]
    _HAVE_ESPRIMA = False


# ---------------------------------------------------------------------------
# Source / sink / sanitiser catalogues.
# ---------------------------------------------------------------------------

# Member-expression patterns (object . property) that produce attacker-
# controllable strings. Each entry: tuple of (object_name, property_name);
# property "*" matches any property (used for localStorage / sessionStorage).
_SOURCE_MEMBERS: tuple[tuple[str, str], ...] = (
    ("location", "hash"),
    ("location", "search"),
    ("location", "href"),
    ("location", "pathname"),
    ("document", "URL"),
    ("document", "documentURI"),
    ("document", "referrer"),
    ("document", "baseURI"),
    ("window", "name"),
    ("history", "state"),
    # Whole-object reads — coarser; covers `var x = location;` then `x.hash`.
    # We don't model that follow-up access; treat the whole `location`/`document.location` as a source.
    ("location", ""),  # bare `location` reference (rare but real)
)

# Source-like *calls*: callee.property == name where object is a storage shape.
_SOURCE_CALLS: tuple[tuple[str, str], ...] = (
    ("localStorage", "getItem"),
    ("sessionStorage", "getItem"),
    ("JSON", "parse"),  # parses untrusted JSON; treat result as tainted-if-arg-tainted
)

# Member-expression sinks (writes via assignment). Property name → severity.
_SINK_PROPERTIES: dict[str, tuple[str, str]] = {
    # property name → (sink-category, CWE)
    "innerHTML": ("html", "CWE-79"),
    "outerHTML": ("html", "CWE-79"),
    "srcdoc": ("html", "CWE-79"),
    "src": ("url", "CWE-601"),
    "href": ("url", "CWE-601"),
    "action": ("url", "CWE-601"),
    "formAction": ("url", "CWE-601"),
    "background": ("url", "CWE-601"),
}

# Call-expression sinks: simple identifier callees → (category, CWE).
_SINK_CALLS_BARE: dict[str, tuple[str, str]] = {
    "eval": ("eval", "CWE-95"),
    "Function": ("eval", "CWE-95"),
}

# Call-expression sinks where the callee is a member: (object_name or "*", method) → category/CWE.
_SINK_CALLS_MEMBER: dict[tuple[str, str], tuple[str, str]] = {
    ("document", "write"): ("html", "CWE-79"),
    ("document", "writeln"): ("html", "CWE-79"),
    ("*", "insertAdjacentHTML"): ("html", "CWE-79"),
    ("*", "setAttribute"): ("url", "CWE-601"),  # only flagged when attr is dangerous
    ("location", "assign"): ("url", "CWE-601"),
    ("location", "replace"): ("url", "CWE-601"),
}

# setTimeout/setInterval are eval-equivalent ONLY when the first arg is a string.
_TIMER_FUNCTIONS = frozenset({"setTimeout", "setInterval"})

# Calls whose return value is sanitised — strip taint on the return.
_SANITISER_BARE = frozenset({
    "encodeURIComponent", "encodeURI", "escape",
})
_SANITISER_MEMBER: tuple[tuple[str, str], ...] = (
    ("DOMPurify", "sanitize"),
    ("Sanitizer", "sanitize"),
    ("CSS", "escape"),
)

# Attributes whose value can lead to script execution if attacker-controlled.
_DANGEROUS_ATTR_NAMES = frozenset({
    "src", "href", "srcdoc", "action", "formaction", "background",
    "data", "poster", "xlink:href", "ping",
})

# Category → finding metadata.
_CATEGORY_META: dict[str, dict[str, str]] = {
    "eval": {
        "title": "DOM-based code injection (eval-class sink)",
        "owasp": "A03:2021-Injection",
        "severity": "high",
    },
    "html": {
        "title": "DOM-based cross-site scripting",
        "owasp": "A03:2021-Injection",
        "severity": "high",
    },
    "url": {
        "title": "DOM-based open redirect / link manipulation",
        "owasp": "A01:2021-Broken Access Control",
        "severity": "medium",
    },
}


# ---------------------------------------------------------------------------
# Internal taint state.
# ---------------------------------------------------------------------------

@dataclass
class _Taint:
    """A taint label attached to a value, identifier, or expression."""
    source: str            # human label, e.g. "location.hash"
    line: int              # line at which the source was read
    sanitised_html: bool = False   # value passed through encodeURI*; still risky in HTML
    sanitised_full: bool = False   # value passed through DOMPurify; safe everywhere


@dataclass
class _Scope:
    """A lexical scope. We track named-variable taint within a scope.

    Outer scopes are linked via :attr:`parent`; lookup walks upward.
    Writes to an unbound name go into the script-root scope (closest to
    real JS semantics for hoisted ``var`` without ``let``/``const``).
    """
    parent: "_Scope | None" = None
    vars: dict[str, _Taint | None] = field(default_factory=dict)

    def get(self, name: str) -> _Taint | None:
        if name in self.vars:
            return self.vars[name]
        if self.parent is not None:
            return self.parent.get(name)
        return None

    def set(self, name: str, taint: _Taint | None) -> None:
        # Block-level taint lives in the nearest scope that already declared
        # the name; otherwise we treat it as a fresh declaration here.
        scope: _Scope | None = self
        while scope is not None:
            if name in scope.vars:
                scope.vars[name] = taint
                return
            scope = scope.parent
        # Unbound → declare in script root.
        scope = self
        while scope.parent is not None:
            scope = scope.parent
        scope.vars[name] = taint

    def declare(self, name: str, taint: _Taint | None) -> None:
        """Declaration always lives in the current scope (let/const/var/param)."""
        self.vars[name] = taint


class _BudgetExceeded(RuntimeError):
    """Raised internally when the wall-clock budget is exhausted."""


# ---------------------------------------------------------------------------
# Helpers — recognising AST node shapes.
# ---------------------------------------------------------------------------

def _node_type(node: Any) -> str:
    return getattr(node, "type", "") or ""


def _member_pair(node: Any) -> tuple[str, str] | None:
    """For a MemberExpression / StaticMemberExpression node, return
    ``(object_name, property_name)``.

    Handles nested chains by walking back to the last two segments:

    * ``location.hash`` → ``("location", "hash")``
    * ``window.name`` → ``("window", "name")`` (bare window kept)
    * ``window.location.hash`` → ``("location", "hash")`` (window stripped)
    * ``document.body.setAttribute`` → ``("body", "setAttribute")``
      (deep chain → only the rightmost two segments survive; sink lookups
      fall back to ``("*", "setAttribute")`` wildcard)

    Returns None only when neither part of the rightmost pair is an
    Identifier (e.g. dynamic ``obj[expr]`` access).
    """
    if not node:
        return None
    t = _node_type(node)
    if t not in ("MemberExpression", "StaticMemberExpression"):
        return None
    obj = getattr(node, "object", None)
    prop = getattr(node, "property", None)
    if obj is None or prop is None:
        return None
    # The property must be a plain Identifier for our purposes — computed
    # accesses like obj[expr] are out of scope.
    if getattr(node, "computed", False):
        return None
    prop_name = getattr(prop, "name", "") or ""
    if not prop_name:
        return None
    obj_t = _node_type(obj)
    if obj_t == "Identifier":
        return (getattr(obj, "name", "") or "", prop_name)
    if obj_t in ("MemberExpression", "StaticMemberExpression"):
        inner = _member_pair(obj)
        if inner is None:
            return ("*", prop_name)
        # window.X.Y → strip the leading window: use (X, Y).
        if inner[0] == "window":
            return (inner[1], prop_name)
        # Otherwise keep the rightmost-two segments — sink/source tables
        # only need the immediate parent.
        return (inner[1], prop_name)
    return None


def _line_of(node: Any) -> int:
    loc = getattr(node, "loc", None)
    if loc is None:
        return 0
    start = getattr(loc, "start", None)
    if start is None:
        return 0
    return int(getattr(start, "line", 0) or 0)


def _is_string_literal(node: Any) -> bool:
    return (_node_type(node) == "Literal"
            and isinstance(getattr(node, "value", None), str))


# ---------------------------------------------------------------------------
# Analyser.
# ---------------------------------------------------------------------------

@dataclass
class _Ctx:
    deadline: float
    findings: list[Finding] = field(default_factory=list)
    seen: set[tuple[str, str, int]] = field(default_factory=set)

    def check_budget(self) -> None:
        if time.monotonic() > self.deadline:
            raise _BudgetExceeded()


def analyze_js(
    source: str,
    *,
    budget_s: float = 5.0,
    max_size: int = 2_000_000,
    host: str = "",
    url: str = "",
) -> list[Finding]:
    """Return DOM-XSS / DOM-injection findings for the given JS source.

    Parameters
    ----------
    source : str
        Raw JavaScript text. Module or script form — both parse paths are tried.
    budget_s : float
        Wall-clock budget for the analysis. If exhausted, the partial
        findings collected so far are returned (never raised).
    max_size : int
        Skip the analysis entirely (return empty) if ``len(source) > max_size``.
        Keeps pathological 50 MB minified bundles from blowing memory.
    host, url : str
        Optional metadata propagated onto every emitted :class:`Finding`.

    Returns
    -------
    list[Finding]
        Possibly empty. Each entry has ``confidence`` set to ``firm``,
        ``tentative``, or ``certain`` per the source/sanitiser path.
    """
    if not _HAVE_ESPRIMA:
        return []
    if not source or len(source) > max_size:
        return []
    parse_opts = {"loc": True, "range": False, "tolerant": True}
    try:
        # parseModule supports ES-modules; parseScript supports classic script.
        # Try script first (more permissive about top-level returns).
        try:
            tree = esprima.parseScript(source, parse_opts)
        except esprima.Error:  # type: ignore[union-attr]
            tree = esprima.parseModule(source, parse_opts)
    except Exception:
        return []
    ctx = _Ctx(deadline=time.monotonic() + max(budget_s, 0.05))
    root_scope = _Scope()
    try:
        for stmt in (getattr(tree, "body", []) or []):
            _visit(stmt, root_scope, ctx)
    except _BudgetExceeded:
        # Partial results are still valid; flag the truncation as info.
        ctx.findings.append(Finding(
            severity="info",
            title="JS static analyser hit wall-clock budget",
            description=(
                f"AST taint analysis aborted after {budget_s:.1f}s. "
                "Findings so far are preserved; the rest of this file "
                "was not scanned."
            ),
            cwe="",
            host=host, url=url,
            evidence=f"budget_s={budget_s}",
            confidence="tentative",
        ))
    # Stamp host/url on every finding.
    if host or url:
        for f in ctx.findings:
            if host and not f.host:
                f.host = host
            if url and not f.url:
                f.url = url
    return ctx.findings


# ---------------------------------------------------------------------------
# Visitor — returns a Taint label when the visited expression is tainted.
# ---------------------------------------------------------------------------

def _expr_taint(node: Any, scope: _Scope, ctx: _Ctx) -> _Taint | None:
    """Return a Taint label if the expression is tainted, else None.

    Recurses through arithmetic, conditionals, template literals,
    member accesses, calls. Sanitiser calls strip taint on the return.
    """
    ctx.check_budget()
    if node is None:
        return None
    t = _node_type(node)

    if t == "Identifier":
        name = getattr(node, "name", "") or ""
        return scope.get(name)

    if t == "Literal" or t == "TemplateElement":
        return None

    if t in ("MemberExpression", "StaticMemberExpression"):
        # 1. Pattern match a known source: (obj, prop).
        pair = _member_pair(node)
        if pair is not None:
            for src_obj, src_prop in _SOURCE_MEMBERS:
                if pair[0] == src_obj and (src_prop == "" or pair[1] == src_prop):
                    label = f"{src_obj}.{src_prop}" if src_prop else src_obj
                    return _Taint(source=label, line=_line_of(node))
        # 2. Otherwise: taint of underlying object propagates.
        return _expr_taint(getattr(node, "object", None), scope, ctx)

    if t == "CallExpression":
        callee = getattr(node, "callee", None)
        # 2a. Bare-name sanitiser: encodeURIComponent(x) — strip JS-string risk
        # but keep an html-risk flag.
        if callee and _node_type(callee) == "Identifier":
            cname = getattr(callee, "name", "") or ""
            args = getattr(node, "arguments", []) or []
            if cname in _SANITISER_BARE:
                if args:
                    inner = _expr_taint(args[0], scope, ctx)
                    if inner is not None:
                        return _Taint(
                            source=inner.source,
                            line=inner.line,
                            sanitised_html=False,  # still HTML-risky
                            sanitised_full=False,
                        )._with_html_sanitiser_marked()
                return None
        # 2b. Member-style sanitiser: DOMPurify.sanitize(x) — full strip.
        if callee and _node_type(callee) in ("MemberExpression", "StaticMemberExpression"):
            pair = _member_pair(callee)
            if pair is not None and pair in _SANITISER_MEMBER:
                return None  # sanitised
            # JSON.parse / localStorage.getItem propagate.
            if pair is not None:
                if pair in _SOURCE_CALLS:
                    # localStorage.getItem() → tainted regardless of arg.
                    if pair[0] in ("localStorage", "sessionStorage"):
                        return _Taint(source=f"{pair[0]}.{pair[1]}", line=_line_of(node))
                    # JSON.parse(x) → propagate taint of x.
                    args = getattr(node, "arguments", []) or []
                    if args:
                        inner = _expr_taint(args[0], scope, ctx)
                        if inner is not None:
                            return _Taint(
                                source=f"JSON.parse({inner.source})",
                                line=_line_of(node),
                            )
                    return None
        # Default: taint of any argument propagates conservatively when the
        # call has no recognised effect (chained string methods etc.).
        args = getattr(node, "arguments", []) or []
        for a in args:
            inner = _expr_taint(a, scope, ctx)
            if inner is not None:
                return inner
        return None

    if t == "BinaryExpression" or t == "LogicalExpression":
        left = _expr_taint(getattr(node, "left", None), scope, ctx)
        if left is not None:
            return left
        return _expr_taint(getattr(node, "right", None), scope, ctx)

    if t == "ConditionalExpression":
        # cond ? a : b — taint comes from either branch.
        a = _expr_taint(getattr(node, "consequent", None), scope, ctx)
        if a is not None:
            return _Taint(source=a.source, line=a.line, sanitised_html=True)
        return _expr_taint(getattr(node, "alternate", None), scope, ctx)

    if t == "TemplateLiteral":
        for expr in (getattr(node, "expressions", []) or []):
            inner = _expr_taint(expr, scope, ctx)
            if inner is not None:
                return inner
        return None

    if t in ("UnaryExpression", "UpdateExpression"):
        return _expr_taint(getattr(node, "argument", None), scope, ctx)

    if t == "AssignmentExpression":
        return _expr_taint(getattr(node, "right", None), scope, ctx)

    if t == "ArrayExpression":
        for elt in (getattr(node, "elements", []) or []):
            inner = _expr_taint(elt, scope, ctx)
            if inner is not None:
                return inner
        return None

    if t == "ObjectExpression":
        for prop in (getattr(node, "properties", []) or []):
            inner = _expr_taint(getattr(prop, "value", None), scope, ctx)
            if inner is not None:
                return inner
        return None

    return None


def _Taint_with_html_sanitiser_marked(self: _Taint) -> _Taint:
    """Mark a taint as having passed through a partial sanitiser
    (``encodeURIComponent`` etc.) — JS-string risk neutralised but HTML
    risk remains."""
    return _Taint(
        source=self.source,
        line=self.line,
        sanitised_html=True,
        sanitised_full=False,
    )


_Taint._with_html_sanitiser_marked = _Taint_with_html_sanitiser_marked  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Statement visitor.
# ---------------------------------------------------------------------------

def _visit(node: Any, scope: _Scope, ctx: _Ctx) -> None:
    """Walk a statement/expression sub-tree, recording sink hits and
    propagating taint through declarations + assignments."""
    if node is None:
        return
    ctx.check_budget()
    t = _node_type(node)

    if t in ("Program", "Script", "Module", "BlockStatement"):
        for child in (getattr(node, "body", []) or []):
            _visit(child, scope, ctx)
        return

    if t == "VariableDeclaration":
        for decl in (getattr(node, "declarations", []) or []):
            id_node = getattr(decl, "id", None)
            init = getattr(decl, "init", None)
            taint = _expr_taint(init, scope, ctx) if init is not None else None
            if id_node is not None and _node_type(id_node) == "Identifier":
                scope.declare(getattr(id_node, "name", "") or "", taint)
            if init is not None:
                _visit_for_sinks(init, scope, ctx)
        return

    if t == "ExpressionStatement":
        _visit_for_sinks(getattr(node, "expression", None), scope, ctx)
        return

    if t == "FunctionDeclaration":
        # Body has its own scope; params start un-tainted.
        inner = _Scope(parent=scope)
        for p in (getattr(node, "params", []) or []):
            if _node_type(p) == "Identifier":
                inner.declare(getattr(p, "name", "") or "", None)
        body = getattr(node, "body", None)
        _visit(body, inner, ctx)
        return

    if t == "FunctionExpression" or t == "ArrowFunctionExpression":
        inner = _Scope(parent=scope)
        for p in (getattr(node, "params", []) or []):
            if _node_type(p) == "Identifier":
                inner.declare(getattr(p, "name", "") or "", None)
        body = getattr(node, "body", None)
        if body is not None and _node_type(body) == "BlockStatement":
            _visit(body, inner, ctx)
        else:
            # Concise arrow body — expression form.
            _visit_for_sinks(body, inner, ctx)
        return

    if t == "IfStatement":
        _visit_for_sinks(getattr(node, "test", None), scope, ctx)
        _visit(getattr(node, "consequent", None), scope, ctx)
        if getattr(node, "alternate", None) is not None:
            _visit(getattr(node, "alternate", None), scope, ctx)
        return

    if t in ("ForStatement", "WhileStatement", "DoWhileStatement",
              "ForInStatement", "ForOfStatement"):
        # Walk init/update/test for sinks, body for both.
        for attr in ("init", "test", "update", "left", "right"):
            v = getattr(node, attr, None)
            if v is not None and hasattr(v, "type"):
                _visit_for_sinks(v, scope, ctx)
        _visit(getattr(node, "body", None), scope, ctx)
        return

    if t == "ReturnStatement":
        _visit_for_sinks(getattr(node, "argument", None), scope, ctx)
        return

    if t == "TryStatement":
        _visit(getattr(node, "block", None), scope, ctx)
        if getattr(node, "handler", None) is not None:
            _visit(getattr(node.handler, "body", None), scope, ctx)
        if getattr(node, "finalizer", None) is not None:
            _visit(getattr(node, "finalizer", None), scope, ctx)
        return

    if t == "SwitchStatement":
        _visit_for_sinks(getattr(node, "discriminant", None), scope, ctx)
        for case in (getattr(node, "cases", []) or []):
            for s in (getattr(case, "consequent", []) or []):
                _visit(s, scope, ctx)
        return

    if t == "ThrowStatement":
        _visit_for_sinks(getattr(node, "argument", None), scope, ctx)
        return

    # Fall-through: descend any children we can identify.
    for attr in ("body", "expression", "argument", "elements", "properties",
                  "declarations"):
        v = getattr(node, attr, None)
        if isinstance(v, list):
            for c in v:
                if hasattr(c, "type"):
                    _visit(c, scope, ctx)
        elif v is not None and hasattr(v, "type"):
            _visit(v, scope, ctx)


def _visit_for_sinks(node: Any, scope: _Scope, ctx: _Ctx) -> None:
    """Walk an expression looking for sink writes/calls; track assignment
    taint into the scope as we go."""
    if node is None:
        return
    ctx.check_budget()
    t = _node_type(node)

    # Sink: assignment to a dangerous property.
    if t == "AssignmentExpression":
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        # 1. Sink: left is a MemberExpression with dangerous property.
        if left is not None and _node_type(left) in ("MemberExpression", "StaticMemberExpression"):
            prop = getattr(left, "property", None)
            prop_name = getattr(prop, "name", "") or "" if prop is not None else ""
            if prop_name in _SINK_PROPERTIES:
                cat, cwe = _SINK_PROPERTIES[prop_name]
                taint = _expr_taint(right, scope, ctx)
                if taint is not None:
                    _emit(ctx, cat, cwe, taint, prop_name, _line_of(node))
            # Special-case: `location.href = x` — `location` is the object.
            # Catches direct `location = ...` via the Identifier branch below.
        # 2. Sink: bare `location = x`.
        if left is not None and _node_type(left) == "Identifier":
            name = getattr(left, "name", "") or ""
            if name == "location":
                taint = _expr_taint(right, scope, ctx)
                if taint is not None:
                    _emit(ctx, "url", "CWE-601", taint, "location", _line_of(node))
        # 3. Propagate: track variable taint when LHS is an Identifier.
        if left is not None and _node_type(left) == "Identifier":
            scope.set(getattr(left, "name", "") or "",
                       _expr_taint(right, scope, ctx))
        # Recurse so nested sinks don't get missed.
        _visit_for_sinks(right, scope, ctx)
        return

    # Sink: call to a known dangerous function.
    if t == "CallExpression":
        callee = getattr(node, "callee", None)
        args = getattr(node, "arguments", []) or []
        if callee is not None:
            ct = _node_type(callee)
            if ct == "Identifier":
                cname = getattr(callee, "name", "") or ""
                if cname in _SINK_CALLS_BARE and args:
                    cat, cwe = _SINK_CALLS_BARE[cname]
                    taint = _expr_taint(args[0], scope, ctx)
                    if taint is not None:
                        _emit(ctx, cat, cwe, taint, cname, _line_of(node))
                elif cname in _TIMER_FUNCTIONS and args:
                    arg0 = args[0]
                    arg0_type = _node_type(arg0)
                    # setTimeout(fn, ...) is fine; setTimeout("code", ...) is
                    # eval-class. We can't always tell statically, so flag
                    # whenever the first arg is *not* an obvious function
                    # form (FunctionExpression/ArrowFunctionExpression).
                    if arg0_type not in ("FunctionExpression",
                                          "ArrowFunctionExpression"):
                        taint = _expr_taint(arg0, scope, ctx)
                        if taint is not None:
                            _emit(ctx, "eval", "CWE-95", taint, cname,
                                    _line_of(node))
            elif ct in ("MemberExpression", "StaticMemberExpression"):
                pair = _member_pair(callee)
                if pair is not None:
                    # Object-keyed first.
                    sink = (_SINK_CALLS_MEMBER.get(pair)
                             or _SINK_CALLS_MEMBER.get(("*", pair[1])))
                    if sink:
                        cat, cwe = sink
                        # setAttribute(name, value): only the value matters,
                        # and only when name is dangerous.
                        if pair[1] == "setAttribute" and len(args) >= 2:
                            attr_name_node = args[0]
                            attr_name = (
                                getattr(attr_name_node, "value", "") or ""
                            ).lower() if _is_string_literal(attr_name_node) else ""
                            if attr_name in _DANGEROUS_ATTR_NAMES:
                                taint = _expr_taint(args[1], scope, ctx)
                                if taint is not None:
                                    _emit(ctx, cat, cwe, taint,
                                            f"setAttribute({attr_name})",
                                            _line_of(node))
                        elif pair[1] == "insertAdjacentHTML" and len(args) >= 2:
                            taint = _expr_taint(args[1], scope, ctx)
                            if taint is not None:
                                _emit(ctx, cat, cwe, taint,
                                        pair[1], _line_of(node))
                        elif args:
                            taint = _expr_taint(args[0], scope, ctx)
                            if taint is not None:
                                _emit(ctx, cat, cwe, taint,
                                        f"{pair[0]}.{pair[1]}", _line_of(node))
        # Recurse into args so we catch any nested sinks.
        for a in args:
            _visit_for_sinks(a, scope, ctx)
        # Recurse into callee object (e.g. `obj.method().chain.x = ...`).
        if callee is not None and hasattr(callee, "type"):
            _visit_for_sinks(callee, scope, ctx)
        return

    # Descent into all sub-children.
    for attr in ("expression", "argument", "left", "right", "object",
                  "property", "elements", "properties", "arguments",
                  "callee", "body", "test", "consequent", "alternate",
                  "expressions"):
        v = getattr(node, attr, None)
        if isinstance(v, list):
            for c in v:
                if hasattr(c, "type"):
                    _visit_for_sinks(c, scope, ctx)
        elif v is not None and hasattr(v, "type"):
            _visit_for_sinks(v, scope, ctx)


# ---------------------------------------------------------------------------
# Finding emission.
# ---------------------------------------------------------------------------

def _emit(ctx: _Ctx, category: str, cwe: str, taint: _Taint,
          sink_name: str, line: int) -> None:
    """Emit a Finding for a source→sink flow, with dedupe.

    Confidence policy:
      - sanitised_full=True → not reachable (we return early in _expr_taint).
      - sanitised_html=True AND category=="html" → tentative.
      - sanitised_html=True AND category=="url" → no finding (URL encoding
        prevents URL-side injection effectively).
      - else → firm.
    """
    if taint.sanitised_full:
        return
    if taint.sanitised_html and category == "url":
        return
    confidence = "tentative" if taint.sanitised_html else "firm"

    key = (taint.source, sink_name, line)
    if key in ctx.seen:
        return
    ctx.seen.add(key)

    meta = _CATEGORY_META.get(category, _CATEGORY_META["html"])
    flow = f"{taint.source} (line {taint.line}) -> {sink_name} (line {line})"
    description = (
        f"Untrusted value from {taint.source} flows to the {sink_name} "
        f"sink without an effective sanitiser. {meta['title']} risk."
    )
    if confidence == "tentative":
        description += (
            " A partial encoder (e.g. encodeURIComponent) was applied; "
            "this neutralises JS-string injection but not HTML injection."
        )
    remediation = {
        "eval": (
            "Never pass untrusted input to eval / Function / setTimeout "
            "/ setInterval with a string argument. Refactor to call the "
            "intended function directly."
        ),
        "html": (
            "Assign untrusted text to .textContent / .innerText instead "
            "of .innerHTML, or pass through a strict sanitiser such as "
            "DOMPurify.sanitize."
        ),
        "url": (
            "Validate the URL against a server-side allow-list of "
            "trusted origins before assigning to a navigation sink."
        ),
    }[category]

    ctx.findings.append(Finding(
        severity=meta["severity"],
        title=meta["title"],
        description=description,
        remediation=remediation,
        cwe=cwe,
        owasp=meta["owasp"],
        evidence=flow,
        payload="",
        confidence=confidence,
    ))


__all__ = ["analyze_js"]

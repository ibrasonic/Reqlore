"""AST-whitelist boolean expression evaluator for the job runner.

The runner's ``assert`` step needs to evaluate a tiny domain expression
like ``vars['x'] == '42'`` against an environment provided by the
runner. Using ``eval()`` with ``__builtins__={}`` is **not** safe — an
attacker who controls the job file can still escape via attribute
walks like ``().__class__.__bases__[0].__subclasses__()``.

This module parses the expression once with :mod:`ast`, walks the
tree, and refuses any node not on the whitelist below. Only after the
tree is proved benign do we compile and evaluate it. The whitelist
covers exactly the constructs the documented runner expressions need:
constants, variable lookups, subscripting, comparisons, boolean
algebra, ``in``/``not in``, and basic numeric/string arithmetic.

Function calls, attribute access, lambdas, comprehensions, and
``__import__`` are all rejected. Any rejection raises
:class:`UnsafeExpressionError` with the offending node type so the
runner can report a clear failure to the user.
"""
from __future__ import annotations

import ast
from typing import Any, Mapping


class UnsafeExpressionError(ValueError):
    """Raised when an expression contains a non-whitelisted AST node."""


# Every AST node type this evaluator tolerates. Anything outside this
# tuple is rejected up front. Keep the list short and audited.
_ALLOWED: tuple[type, ...] = (
    ast.Expression,
    ast.Constant,
    ast.Name, ast.Load,
    ast.Subscript,
    ast.Tuple, ast.List, ast.Dict, ast.Set,
    ast.Compare,
    ast.BoolOp, ast.And, ast.Or,
    ast.UnaryOp, ast.Not, ast.UAdd, ast.USub,
    ast.BinOp, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
    ast.Mod,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn, ast.Is, ast.IsNot,
)
# ast.Index existed in Python <3.9; keep it tolerated when present so
# we do not break older interpreters.
if hasattr(ast, "Index"):  # pragma: no cover - runtime guard
    _ALLOWED = _ALLOWED + (ast.Index,)  # type: ignore[attr-defined]


def _validate(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED):
            raise UnsafeExpressionError(
                f"disallowed expression element: {type(node).__name__}"
            )


def safe_eval_bool(expr: str, env: Mapping[str, Any]) -> bool:
    """Evaluate ``expr`` in ``env`` after AST whitelisting; return ``bool(result)``.

    ``env`` exposes the runner's locals (``vars``, ``status``,
    ``body_text``). Builtins are stripped entirely — the AST guard
    already forbids ``Call``, so even if a builtin slipped in it could
    not be invoked.
    """
    tree = ast.parse(expr, mode="eval")
    _validate(tree)
    code = compile(tree, "<assert>", "eval")
    # ``__builtins__={}`` neutralises any name resolution Python would
    # otherwise fall back to. ``env`` is consumed read-only by ``eval``.
    return bool(eval(code, {"__builtins__": {}}, dict(env)))  # noqa: S307

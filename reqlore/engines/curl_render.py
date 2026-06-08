"""curl renderer — produces curl command strings without ever invoking curl."""
from __future__ import annotations

from ..a11y import render_curl as _render
from . import Request


def render(req: Request) -> str:
    return _render(req.method, req.url, req.headers, req.body or None)

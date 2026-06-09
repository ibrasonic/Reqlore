"""In-process LRU cache for Post/Redirect/Get result stashing.

Each tool blueprint that mutates state on POST stores its result here under
a short opaque token, then 302-redirects to ``?t=<token>``. The GET handler
reads the token and renders the stashed data — so the browser back-button
returns the user to the previous page cleanly, with no "Resubmit form?"
warning and no accidental re-execution of the action.
"""
from __future__ import annotations

from collections import OrderedDict
from threading import Lock
from typing import Any
from uuid import uuid4


class PRGCache:
    """Bounded, thread-safe, in-process token→value store (LRU eviction)."""

    def __init__(self, max_entries: int = 32) -> None:
        self._max = max_entries
        self._data: OrderedDict[str, Any] = OrderedDict()
        self._lock = Lock()

    def put(self, value: Any) -> str:
        token = uuid4().hex[:12]
        with self._lock:
            self._data[token] = value
            self._data.move_to_end(token)
            while len(self._data) > self._max:
                self._data.popitem(last=False)
        return token

    def get(self, token: str | None) -> Any:
        if not token:
            return None
        with self._lock:
            value = self._data.get(token)
            if value is not None:
                self._data.move_to_end(token)
            return value

"""Bounded-time regex helpers built on the third-party ``regex`` library.

Reqlore runs many user-supplied or target-supplied regular expressions
(intercept rules, match-replace rules, macro captures). The stdlib
``re`` module has no timeout, so a malicious or accidentally
catastrophic pattern can pin a worker thread (ReDoS).

The ``regex`` module supports a ``timeout=`` argument that aborts a
search/sub once the deadline is exceeded. We wrap the few call sites
Reqlore needs and turn the timeout into a benign result (no match /
unchanged input) instead of an exception so callers do not have to
rewrite control flow.

If a pattern is malformed we likewise return the safe default — input
validation belongs at the rule-save boundary, not at every dispatch.
"""
from __future__ import annotations

from typing import Any

import regex as _regex

# Default per-call deadline. 100 ms is more than enough for any sane
# pattern against a single HTTP message body and short enough that a
# pathological pattern cannot stall the proxy for noticeable time.
DEFAULT_TIMEOUT = 0.1


def safe_search(pattern: str, text: str, *, flags: int = 0,
                timeout: float = DEFAULT_TIMEOUT) -> Any:
    """``regex.search`` with a hard timeout. Returns ``None`` on timeout/error."""
    try:
        return _regex.search(pattern, text, flags=flags, timeout=timeout)
    except (_regex.error, TimeoutError, ValueError):
        return None


def safe_sub(pattern: str, repl: str, text: str, *, flags: int = 0,
             count: int = 0, timeout: float = DEFAULT_TIMEOUT) -> str:
    """``regex.sub`` with a hard timeout. Returns input unchanged on failure."""
    try:
        return _regex.sub(pattern, repl, text, count=count, flags=flags,
                          timeout=timeout)
    except (_regex.error, TimeoutError, ValueError):
        return text


def safe_compile(pattern: str, *, flags: int = 0) -> Any:
    """Compile a user-supplied pattern. Returns ``None`` if the pattern is invalid.

    Callers use this for save-time validation; the runtime call sites
    above re-parse on each call so we do not trade a cache slot for a
    silent failure mode.
    """
    try:
        return _regex.compile(pattern, flags=flags)
    except _regex.error:
        return None


def is_valid_pattern(pattern: str) -> bool:
    """True if the user-supplied pattern compiles without error."""
    return safe_compile(pattern) is not None

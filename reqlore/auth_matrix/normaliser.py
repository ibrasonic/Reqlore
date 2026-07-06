"""Response normaliser for Auth Matrix similarity scoring.

The verdict heuristics work by comparing the baseline (the response
the original request got, captured in history) against the candidate
(the response produced when we re-send the request under a different
session). A naive ``a == b`` check would fail on every CSRF token,
every ``Set-Cookie`` expiry, every ISO timestamp embedded in HTML.

The :class:`Normaliser` applies a small bag of regex substitutions
that replace volatile material with sentinels *before* similarity is
computed. The same normaliser is applied to both sides so a swapped
token does not move the score; an actual data-divergence (admin vs.
forbidden) still does.

The default rule list is intentionally conservative — false positives
in this layer mean *missed* auth bugs. Operators can extend it via
:class:`reqlore.auth_matrix.runner.RunOptions.normaliser_extra`.
"""
from __future__ import annotations

import difflib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from re import Pattern

_DEFAULT_BODY_RULES: tuple[tuple[str, str], ...] = (
    # HTML CSRF tokens — input fields.
    (
        r"""(<input[^>]*\bname\s*=\s*["']?(?:csrf|_token|xsrf|authenticity_token|csrfmiddlewaretoken)[a-z0-9_\-]*["']?[^>]*\bvalue\s*=\s*["'])[^"']+(["'])""",
        r"\1<TOKEN>\2",
    ),
    # HTML CSRF tokens — meta tags.
    (
        r"""(<meta[^>]*\bname\s*=\s*["']?(?:csrf|xsrf)[a-z0-9_\-]*["']?[^>]*\bcontent\s*=\s*["'])[^"']+(["'])""",
        r"\1<TOKEN>\2",
    ),
    # ISO 8601 timestamps.
    (
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        "<TIMESTAMP>",
    ),
    # UUID v4.
    (
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        "<UUID>",
    ),
    # Long hex strings (>=24 chars) — session ids / signed payloads.
    (
        r"\b[0-9a-f]{24,}\b",
        "<HEX>",
    ),
)

_DEFAULT_HEADER_BLOCKLIST = frozenset({
    # These rotate per request and pollute diffs.
    "date",
    "set-cookie",
    "etag",
    "last-modified",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-amzn-trace-id",
    "x-amzn-requestid",
    "x-runtime",
    "x-response-time",
    "server-timing",
    "cf-ray",
    "cf-cache-status",
    "via",
})


@dataclass(frozen=True)
class Normaliser:
    """A frozen, picklable container for the rules + blocklist."""

    body_rules: tuple[tuple[Pattern[str], str], ...] = ()
    header_blocklist: frozenset[str] = field(default_factory=frozenset)

    def normalise_body(self, body: bytes | str) -> str:
        return normalise_body(body, self)

    def normalise_headers(
        self, headers: Iterable[tuple[str, str]],
    ) -> list[tuple[str, str]]:
        return normalise_headers(headers, self)


def _compile_rules(
    rules: Iterable[tuple[str, str]],
) -> tuple[tuple[Pattern[str], str], ...]:
    out: list[tuple[Pattern[str], str]] = []
    for pattern, replacement in rules:
        try:
            out.append(
                (re.compile(pattern, re.IGNORECASE | re.DOTALL), replacement)
            )
        except re.error:
            # Bad operator regex shouldn't crash a run. Skip it.
            continue
    return tuple(out)


def default_normaliser(
    *, extra_body_rules: Iterable[tuple[str, str]] | None = None,
    extra_header_blocklist: Iterable[str] | None = None,
) -> Normaliser:
    """Build the default normaliser, optionally extended.

    ``extra_body_rules`` are appended after the built-ins so they run
    *after* the generic strips — useful for app-specific tokens.

    ``extra_header_blocklist`` is unioned with the default block list.
    """
    rules = _compile_rules(
        list(_DEFAULT_BODY_RULES) + list(extra_body_rules or [])
    )
    block = _DEFAULT_HEADER_BLOCKLIST | {
        h.strip().lower() for h in (extra_header_blocklist or []) if h.strip()
    }
    return Normaliser(body_rules=rules, header_blocklist=frozenset(block))


def normalise_body(body: bytes | str, normaliser: Normaliser) -> str:
    """Apply every body rule in order, returning the normalised text."""
    if isinstance(body, (bytes, bytearray)):
        try:
            text = bytes(body).decode("utf-8", errors="replace")
        except Exception:
            text = ""
    else:
        text = str(body or "")
    for pattern, replacement in normaliser.body_rules:
        try:
            text = pattern.sub(replacement, text)
        except re.error:
            continue
    return text


def normalise_headers(
    headers: Iterable[tuple[str, str]], normaliser: Normaliser,
) -> list[tuple[str, str]]:
    """Strip blocklisted headers and lower-case the names for stable
    diffing. Values are preserved verbatim."""
    out: list[tuple[str, str]] = []
    for name, value in headers:
        low = (name or "").strip().lower()
        if not low or low in normaliser.header_blocklist:
            continue
        out.append((low, value))
    out.sort(key=lambda kv: kv[0])
    return out


def body_similarity_pct(
    baseline: str, candidate: str, *, max_chars: int = 200_000,
) -> int:
    """Return 0–100 similarity using :func:`difflib.SequenceMatcher`.

    Truncates each side to ``max_chars`` so a multi-MB binary body
    can't pin the worker — operators can override this from the
    blueprint if they really need to compare giant payloads.
    """
    a = baseline[:max_chars] if baseline else ""
    b = candidate[:max_chars] if candidate else ""
    if not a and not b:
        return 100
    if not a or not b:
        return 0
    if a == b:
        return 100
    ratio = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
    pct = int(round(ratio * 100))
    if pct < 0:
        return 0
    if pct > 100:
        return 100
    return pct

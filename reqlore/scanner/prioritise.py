"""Phase 12 — audit prioritisation (attack-surface scoring).

Burp Suite's audit queue does not iterate history rows in arrival
order. Instead it scores each row on two axes and audits the
highest-scoring rows first:

* **Attack-surface exposure (80% weight by default).** How many
  insertion points does this row contribute that the queue hasn't
  already audited? A login form on ``/auth/login`` introduces a
  username + password pair the first time it's seen; a second hit
  on the same form adds zero new surface and drops in priority.

* **Interest level (20%).** Three equally-weighted factors:
  - **Action type.** State-changing methods (POST/PUT/PATCH/DELETE)
    score 1.0; safe methods (GET/HEAD/OPTIONS) score 0.0.
  - **Content type.** Structured response bodies (HTML / JSON / XML)
    score 1.0; opaque types (binary, octet-stream, images) score 0.0.
  - **Authentication requirement.** A request that carries an
    ``Authorization`` header, a session-named cookie, or that
    answered with HTTP 401 is more interesting than an anonymous
    GET of a static asset.

The scoring is pure: no I/O, no network, no global state. Tests
construct fake :class:`HistoryRow`-shaped objects and feed them to
:func:`prioritise_queue`; the active scanner consumes the same API
from :meth:`ActiveScanner.run_on_project` when
:attr:`ActiveOptions.prioritise` is enabled.

Determinism: ties are broken by row ``id`` ascending (lower id first)
so re-runs produce identical orderings even when scores collide.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .insertion_points import iter_insertion_points

__all__ = [
    "STATE_CHANGING_METHODS",
    "STRUCTURED_CONTENT_HINTS",
    "SESSION_COOKIE_NAMES",
    "ScoringWeights",
    "InterestFactors",
    "RowScore",
    "is_state_changing",
    "looks_like_session_cookie",
    "request_carries_auth",
    "interest_level",
    "insertion_point_keys",
    "score_row",
    "prioritise_queue",
]


# ---------------------------------------------------------------------------
# Module-level canonical constants. Inlined ad-hoc lists in
# StoredXSSCheck / RaceConditionCheck should ideally call into these,
# but Phase 12 leaves the existing inlines alone to keep the diff
# bounded — a future tidy-up can fold them in.
# ---------------------------------------------------------------------------

STATE_CHANGING_METHODS: frozenset[str] = frozenset({
    "POST", "PUT", "PATCH", "DELETE",
})

# Content-type substrings that indicate "the body has machinery a
# scanner can fuzz". Matched as case-insensitive substrings against
# the raw ``Content-Type`` header value, so ``text/html; charset=utf-8``
# and ``application/json; profile=...`` both match.
STRUCTURED_CONTENT_HINTS: tuple[str, ...] = (
    "text/html",
    "application/json",
    "application/xml",
    "text/xml",
    "application/xhtml",
    "+json",
    "+xml",
)

# Cookie names that look like session / auth tokens. The list is the
# same one the sequencer auto-feed uses, lowercased for case-
# insensitive matching.
SESSION_COOKIE_NAMES: frozenset[str] = frozenset({
    "session", "sessionid", "session_id", "sid",
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspxauth",
    "auth", "authentication", "auth_token", "authtoken",
    "token", "access_token", "id_token",
    "remember_token", "remember_me", "_session", "_session_id",
})


# ---------------------------------------------------------------------------
# Configuration dataclasses.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScoringWeights:
    """Linear blend coefficients for the final priority score.

    ``surface`` and ``interest`` need not sum to 1 — internally the
    composite score is ``surface * surface_norm + interest * interest_norm``
    where each ``*_norm`` is independently in ``[0, 1]``. Defaults
    are Burp's 80/20 split.
    """

    surface: float = 0.8
    interest: float = 0.2

    def __post_init__(self) -> None:
        if self.surface < 0 or self.interest < 0:
            raise ValueError(
                f"ScoringWeights must be non-negative; got "
                f"surface={self.surface}, interest={self.interest}"
            )
        if self.surface == 0 and self.interest == 0:
            raise ValueError(
                "ScoringWeights cannot both be zero — at least one "
                "axis must contribute to the composite score"
            )


@dataclass(frozen=True)
class InterestFactors:
    """Operator-overridable thresholds for the three interest signals.

    The defaults match Burp; tests construct alternate factor sets
    to exercise edge cases (e.g. "what if the project flags
    OPTIONS as state-changing too?").
    """

    state_changing_methods: frozenset[str] = field(
        default_factory=lambda: STATE_CHANGING_METHODS,
    )
    structured_content_hints: tuple[str, ...] = field(
        default_factory=lambda: STRUCTURED_CONTENT_HINTS,
    )
    session_cookie_names: frozenset[str] = field(
        default_factory=lambda: SESSION_COOKIE_NAMES,
    )


# ---------------------------------------------------------------------------
# Per-row score.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RowScore:
    """A single row's scoring breakdown.

    The ``score`` field is *only* populated after
    :func:`prioritise_queue` normalises across the queue — calling
    :func:`score_row` in isolation leaves ``score`` at ``0.0`` and
    populates the raw axes (``surface_novelty``, ``interest``) so
    callers can implement their own ranking. Splitting the two
    lets the live worker re-rank incrementally without re-scoring.
    """

    history_id: int
    surface_novelty: int
    surface_total: int
    method_score: float
    content_type_score: float
    auth_score: float
    interest: float
    score: float = 0.0

    @property
    def novelty_ratio(self) -> float:
        """Fraction of this row's insertion points that were novel
        at scoring time. Returns 0.0 for rows with no insertion
        points (a static asset)."""
        if self.surface_total <= 0:
            return 0.0
        return self.surface_novelty / float(self.surface_total)


# ---------------------------------------------------------------------------
# Method / content-type / auth helpers.
# ---------------------------------------------------------------------------

def is_state_changing(
    method: str | None,
    factors: InterestFactors | None = None,
) -> bool:
    """Return ``True`` when ``method`` mutates server state.

    Defensive: an empty / None method falls back to ``False`` rather
    than raising, because parsing failures upstream can produce
    them. ``CONNECT`` / ``TRACE`` are deliberately not considered
    state-changing — they're transport-level verbs Burp also
    excludes."""
    if not method:
        return False
    f = factors or InterestFactors()
    return method.strip().upper() in f.state_changing_methods


def looks_like_session_cookie(
    name: str | None,
    factors: InterestFactors | None = None,
) -> bool:
    if not name:
        return False
    f = factors or InterestFactors()
    return name.strip().lower() in f.session_cookie_names


def _content_type_of_response(
    headers: list[tuple[str, str]],
) -> str:
    for k, v in headers or []:
        if k.lower() == "content-type":
            return (v or "").lower()
    return ""


def _content_type_score(
    ct: str,
    factors: InterestFactors | None = None,
) -> float:
    """1.0 when the response body looks parser-friendly, else 0.0.

    The "0 or 1" shape matches Burp's binary interest factor — the
    scanner doesn't try to differentiate "very interesting JSON"
    from "mildly interesting HTML"."""
    if not ct:
        return 0.0
    f = factors or InterestFactors()
    lowered = ct.lower()
    for hint in f.structured_content_hints:
        if hint in lowered:
            return 1.0
    return 0.0


def request_carries_auth(
    req_headers: list[tuple[str, str]],
    resp_status: int,
    factors: InterestFactors | None = None,
) -> bool:
    """Heuristic ``True`` when this request looks like it required
    authentication. Three signals (any one is sufficient):

    * an ``Authorization`` request header (Basic / Bearer / NTLM…),
    * a ``Cookie`` request header whose key matches
      :data:`SESSION_COOKIE_NAMES`,
    * a 401 response status (the server explicitly said "auth
      required"; we count this even on requests that didn't carry
      auth because the *endpoint* is auth-gated).

    Note we don't classify 403 as auth-required — Burp doesn't
    either; 403 is often used for "you're authenticated but lack
    permission" which is a different signal.
    """
    f = factors or InterestFactors()
    if resp_status == 401:
        return True
    for k, v in req_headers or []:
        kl = k.lower()
        if kl == "authorization" and (v or "").strip():
            return True
        if kl == "cookie":
            # Parse "a=1; b=2" naively; bad cookies are skipped.
            for chunk in (v or "").split(";"):
                if "=" not in chunk:
                    continue
                name, _ = chunk.split("=", 1)
                if looks_like_session_cookie(name.strip(), factors=f):
                    return True
    return False


def interest_level(
    row: Any,
    factors: InterestFactors | None = None,
) -> tuple[float, float, float, float]:
    """Compute the three interest signals for ``row`` and their
    mean. Returns ``(method_score, content_type_score, auth_score,
    mean)``, each in ``[0, 1]``.

    The row may be a real :class:`HistoryRow` or any object with
    the same attribute shape (``method``, ``status``, ``req_blob``,
    ``resp_blob``). Missing attributes degrade to zero — never
    raise — because the only caller (:func:`score_row`) wraps us
    inside the same defensive frame the active scanner uses for
    its per-row body.
    """
    from ..scanner.passive import _split_http
    f = factors or InterestFactors()
    method = getattr(row, "method", "") or ""
    method_score = 1.0 if is_state_changing(method, factors=f) else 0.0
    req_blob = getattr(row, "req_blob", b"") or b""
    resp_blob = getattr(row, "resp_blob", b"") or b""
    try:
        _, req_headers, _ = _split_http(req_blob)
    except (ValueError, AttributeError):
        req_headers = []
    try:
        _, resp_headers, _ = _split_http(resp_blob)
    except (ValueError, AttributeError):
        resp_headers = []
    ct = _content_type_of_response(resp_headers)
    ct_score = _content_type_score(ct, factors=f)
    status = int(getattr(row, "status", 0) or 0)
    auth_score = 1.0 if request_carries_auth(
        req_headers, status, factors=f,
    ) else 0.0
    mean = (method_score + ct_score + auth_score) / 3.0
    return method_score, ct_score, auth_score, mean


# ---------------------------------------------------------------------------
# Insertion-point keys.
# ---------------------------------------------------------------------------

def insertion_point_keys(row: Any) -> set[tuple[str, str, str]]:
    """Return the set of insertion-point identity keys for ``row``.

    Each key is ``(host, ip_type, name)`` — the same shape the
    :class:`InsertionPointCache` uses internally minus the
    ``rule_id`` axis, because for surface scoring we want "how many
    unique insertion points does this row introduce" regardless of
    which rule would probe them.

    Parser failures degrade to the empty set so a malformed row
    contributes zero surface (and ends up de-prioritised), never
    raises.
    """
    from ..scanner.passive import _split_http
    req_blob = getattr(row, "req_blob", b"") or b""
    try:
        _, req_headers, req_body = _split_http(req_blob)
    except (ValueError, AttributeError):
        return set()
    host = getattr(row, "host", "") or ""
    method = getattr(row, "method", "") or ""
    url = getattr(row, "url", "") or ""
    keys: set[tuple[str, str, str]] = set()
    try:
        points = iter_insertion_points(
            url=url, method=method, headers=req_headers, body=req_body,
        )
    except (ValueError, TypeError, AttributeError):
        return set()
    for p in points:
        keys.add((host, p.ip_type, p.name))
    return keys


# ---------------------------------------------------------------------------
# Scoring.
# ---------------------------------------------------------------------------

def score_row(
    row: Any,
    *,
    already_audited: set[tuple[str, str, str]] | None = None,
    factors: InterestFactors | None = None,
) -> RowScore:
    """Score a single ``row`` against the supplied audited-key set.

    The returned :class:`RowScore` has ``score=0.0`` — the composite
    only makes sense after the queue's surface counts are
    normalised. Callers that want a single-row ranking can use
    ``rs.surface_novelty`` and ``rs.interest`` directly.
    """
    audited = already_audited if already_audited is not None else set()
    keys = insertion_point_keys(row)
    surface_total = len(keys)
    surface_novelty = len(keys - audited)
    m, c, a, mean = interest_level(row, factors=factors)
    return RowScore(
        history_id=int(getattr(row, "id", 0) or 0),
        surface_novelty=surface_novelty,
        surface_total=surface_total,
        method_score=m,
        content_type_score=c,
        auth_score=a,
        interest=mean,
        score=0.0,
    )


def prioritise_queue(
    rows: Iterable[Any],
    *,
    weights: ScoringWeights | None = None,
    factors: InterestFactors | None = None,
    already_audited: set[tuple[str, str, str]] | None = None,
    recompute_after_row: bool = False,
) -> list[tuple[Any, RowScore]]:
    """Score every row and return ``[(row, RowScore), …]`` sorted
    highest-priority first.

    Surface novelty is normalised by the **maximum novelty in the
    queue** so the composite score lives in ``[0, weights.surface +
    weights.interest]``. Interest is already ``[0, 1]``. Ties are
    broken by row id ascending — that's deterministic *and* nudges
    older rows ahead of identical newer ones, which matches Burp's
    arrival-order intuition for "everything else equal, do the
    older one first".

    Two modes:

    * **Default (``recompute_after_row=False``).** A single scoring
      pass, then sort. O(n) scoring + O(n log n) sort. The active
      scanner uses this mode because it operates on a snapshot.

    * **Incremental (``recompute_after_row=True``).** After each
      row is "picked" the audited-key set grows and every remaining
      row is re-scored. O(n²) but Burp-accurate: a row whose surface
      is entirely consumed by an earlier pick can drop ten ranks.
      Live workers will use this mode in a future phase.
    """
    rows_list = list(rows)
    if not rows_list:
        return []
    weights = weights or ScoringWeights()
    factors = factors or InterestFactors()
    audited = set(already_audited) if already_audited else set()

    if not recompute_after_row:
        scored = [score_row(r, already_audited=audited, factors=factors)
                  for r in rows_list]
        return _normalise_and_sort(rows_list, scored, weights)

    # Incremental mode: pick one row at a time, re-score every
    # remaining row after each pick. Stable on the first pick (no
    # audit history) and converges to a queue Burp would produce.
    remaining: list[tuple[Any, int]] = list(enumerate(rows_list))
    order: list[tuple[Any, RowScore]] = []
    while remaining:
        scored_pairs = []
        for idx, (orig_idx, r) in enumerate(remaining):
            del orig_idx
            scored_pairs.append((idx, r, score_row(
                r, already_audited=audited, factors=factors,
            )))
        # Reuse the normalisation pass on the *current* remaining
        # set so each pick is locally optimal.
        normalised = _normalise_and_sort(
            [r for _, r, _ in scored_pairs],
            [s for _, _, s in scored_pairs],
            weights,
        )
        pick_row, pick_score = normalised[0]
        order.append((pick_row, pick_score))
        # Locate the picked row in `remaining` (by identity) and
        # drop it; update audited set with its keys.
        for i, (_, r) in enumerate(remaining):
            if r is pick_row:
                remaining.pop(i)
                break
        audited |= insertion_point_keys(pick_row)
    return order


def _normalise_and_sort(
    rows_list: list[Any],
    scored: list[RowScore],
    weights: ScoringWeights,
) -> list[tuple[Any, RowScore]]:
    max_novelty = max((s.surface_novelty for s in scored), default=0)
    norm = max(1, max_novelty)  # avoid div-by-zero
    composite = []
    for r, s in zip(rows_list, scored, strict=False):
        surface_norm = s.surface_novelty / norm
        composite_score = (
            weights.surface * surface_norm
            + weights.interest * s.interest
        )
        composite.append((r, RowScore(
            history_id=s.history_id,
            surface_novelty=s.surface_novelty,
            surface_total=s.surface_total,
            method_score=s.method_score,
            content_type_score=s.content_type_score,
            auth_score=s.auth_score,
            interest=s.interest,
            score=composite_score,
        )))
    # Highest score first, then lowest id (stable tie-break).
    composite.sort(key=lambda rs: (-rs[1].score, rs[1].history_id))
    return composite

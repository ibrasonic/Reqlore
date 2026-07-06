"""Verdict heuristics — turn a (baseline, candidate) response pair
into a label the operator can scan at a glance.

Labels
------

``bypass-suspect``
    The candidate session returned a 2xx with a body that closely
    mirrors the baseline's privileged response — strong evidence the
    session in this column has access it shouldn't.

``denied-correctly``
    The candidate returned a 401/403 (or 302 to a login page) and
    the baseline returned a 2xx. The access-control boundary is
    enforced.

``denied-status-only``
    The candidate's *status* changed (e.g. 200 → 403) but its body
    still resembles the baseline by more than the similarity floor.
    Worth a human eye — some apps "deny" with a banner and still
    leak the protected content.

``different-payload``
    Both sides returned a similar status code but their bodies
    diverge. Usually fine (each session gets its own view) but
    surfaces account-data leakage on shared endpoints.

``identical``
    Same status, near-identical normalised body. Includes the
    common "baseline was also denied" case.

``no-baseline``
    The shadow / active run had no baseline to compare against.
    Emitted by the shadow worker when the proxied response had no
    paired session capture.

``error``
    The candidate replay failed (network error, timeout, malformed
    response). Status/body are unreliable for this cell.

``dismissed``
    Operator marked the cell as false-positive. Not produced by the
    runner — only by the blueprint write path.
"""
from __future__ import annotations

from dataclasses import dataclass

VERDICT_LABELS: tuple[str, ...] = (
    "bypass-suspect",
    "denied-correctly",
    "denied-status-only",
    "different-payload",
    "identical",
    "no-baseline",
    "error",
    "dismissed",
)


_PRIVILEGED_STATUSES: frozenset[int] = frozenset({
    200, 201, 202, 204, 206, 207, 208,
})
_DENIED_STATUSES: frozenset[int] = frozenset({401, 403, 407, 451})
_REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

_LOGIN_HINTS: tuple[str, ...] = (
    "/login", "/signin", "/sign-in", "/auth", "/oauth",
    "/sso", "/account/login",
)


@dataclass(frozen=True)
class Verdict:
    """Outcome of the heuristic. ``confidence`` and ``severity`` are
    advisory — the blueprint uses them to colour cells and choose
    a default issues-table severity when materialising a finding."""

    label: str
    note: str = ""
    confidence: str = "firm"   # "tentative" | "firm" | "certain"


def _looks_like_login_redirect(
    location: str, content_type: str, body_snip: str,
) -> bool:
    loc = (location or "").lower()
    if any(h in loc for h in _LOGIN_HINTS):
        return True
    if "text/html" in (content_type or "").lower():
        low = (body_snip or "").lower()
        if "sign in" in low or "log in" in low or "login" in low:
            return True
    return False


def decide_verdict(
    *,
    baseline_status: int | None,
    candidate_status: int,
    similarity_pct: int,
    similarity_floor: int = 80,
    privileged_floor: int = 90,
    candidate_location: str = "",
    candidate_content_type: str = "",
    candidate_body_snip: str = "",
    candidate_error: str = "",
) -> Verdict:
    """Decide the verdict label.

    Parameters
    ----------
    baseline_status:
        HTTP status from the original captured request. ``None``
        means we have no baseline.
    candidate_status:
        Status of the replayed request. ``0`` indicates a transport
        error — callers should also pass ``candidate_error``.
    similarity_pct:
        0-100 normalised body similarity (see
        :func:`reqlore.auth_matrix.normaliser.body_similarity_pct`).
    similarity_floor:
        Bodies at or above this percent are "similar" for the
        purposes of denied-status-only / identical detection.
    privileged_floor:
        Stricter floor used for the bypass-suspect heuristic. The
        higher we set this, the fewer false positives and the more
        missed bugs.
    candidate_location / candidate_content_type / candidate_body_snip:
        Hints from the candidate response — used to detect login
        redirects and HTML denial banners.
    candidate_error:
        Non-empty transport error string forces an ``error`` verdict.
    """
    if candidate_error:
        return Verdict(label="error", note=candidate_error[:200],
                       confidence="tentative")
    if baseline_status is None:
        return Verdict(label="no-baseline",
                       note="no paired baseline response",
                       confidence="tentative")

    baseline_priv = baseline_status in _PRIVILEGED_STATUSES
    candidate_priv = candidate_status in _PRIVILEGED_STATUSES
    candidate_denied = (
        candidate_status in _DENIED_STATUSES
        or (
            candidate_status in _REDIRECT_STATUSES
            and _looks_like_login_redirect(
                candidate_location, candidate_content_type,
                candidate_body_snip,
            )
        )
    )

    # Bypass: baseline was privileged AND candidate also privileged
    # AND bodies are very similar -> the column session reached
    # private content it shouldn't have.
    if (
        baseline_priv and candidate_priv
        and similarity_pct >= privileged_floor
    ):
        return Verdict(
            label="bypass-suspect",
            note=(
                f"baseline {baseline_status} & candidate {candidate_status} "
                f"with similarity {similarity_pct}%"
            ),
            confidence="firm",
        )

    # Denied-correctly: baseline private, candidate denied, bodies
    # diverge enough to look like a proper denial page.
    if baseline_priv and candidate_denied and similarity_pct < similarity_floor:
        return Verdict(
            label="denied-correctly",
            note=f"candidate {candidate_status}, similarity {similarity_pct}%",
            confidence="firm",
        )

    # Denied-status-only: status says deny, body still looks private.
    if baseline_priv and candidate_denied and similarity_pct >= similarity_floor:
        return Verdict(
            label="denied-status-only",
            note=(
                f"candidate status {candidate_status} but body similarity is "
                f"{similarity_pct}%"
            ),
            confidence="firm",
        )

    # Same broad status family, very similar body — boring.
    if (
        baseline_status == candidate_status
        and similarity_pct >= 95
    ):
        return Verdict(label="identical",
                       note=f"both {baseline_status}, similarity {similarity_pct}%",
                       confidence="firm")

    # Otherwise: same-ish status, different body, or status-class mismatch
    # that didn't fit the rules above. Surface for inspection.
    return Verdict(
        label="different-payload",
        note=(
            f"baseline {baseline_status} vs candidate {candidate_status}, "
            f"similarity {similarity_pct}%"
        ),
        confidence="tentative",
    )


def finding_severity_for_verdict(label: str) -> str:
    """Map a verdict label to the severity used when materialising an
    issues-table row. ``info`` for benign, ``high`` for confirmed
    bypass."""
    if label == "bypass-suspect":
        return "high"
    if label == "denied-status-only":
        return "medium"
    if label == "different-payload":
        return "info"
    return "info"

"""Auth Matrix — session-based access-control testing.

Two modes:

* **Active** — operator picks history rows × saved sessions, the
  :class:`AuthMatrixRunner` replays each row under each session and
  records a verdict cell per pair.

* **Shadow** — every proxied response is replayed under every
  *active* session in the background by :class:`AuthShadowWorker`
  and a one-cell run is recorded when the verdict diverges from
  the original.

The module is organised as:

* :mod:`reqlore.auth_matrix.crypto`     — per-project key + payload
  encryption helpers.
* :mod:`reqlore.auth_matrix.sessions`   — :class:`Session` dataclass +
  builder helpers (cookie / bearer / header / multi / anon).
* :mod:`reqlore.auth_matrix.normaliser` — strip CSRF, timestamps,
  Set-Cookie expiry, UUIDs before similarity scoring.
* :mod:`reqlore.auth_matrix.verdict`    — heuristics that turn a
  (baseline, candidate) response pair into a verdict label.
* :mod:`reqlore.auth_matrix.replay`     — substitute a session into a
  raw history request and call the engine.
* :mod:`reqlore.auth_matrix.runner`     — background thread for active
  runs (analog to :class:`reqlore.plugin_runner.PluginRunner`).
* :mod:`reqlore.auth_matrix.shadow`     — passive worker (analog to
  :class:`reqlore.scanner.live.LiveScanWorker`).
"""
from __future__ import annotations

from .crypto import (
    ProjectKey,
    decrypt_payload,
    derive_or_load_key,
    encrypt_payload,
)
from .normaliser import (
    Normaliser,
    body_similarity_pct,
    default_normaliser,
    normalise_body,
    normalise_headers,
)
from .replay import (
    ReplayOutcome,
    replay_history_with_session,
)
from .runner import AuthMatrixRunner, RunOptions
from .sessions import (
    SESSION_KINDS,
    Session,
    SessionKind,
    apply_session_to_request,
    build_substitution,
    capture_session_from_history,
    session_already_present,
)
from .shadow import AuthShadowWorker
from .verdict import (
    VERDICT_LABELS,
    Verdict,
    decide_verdict,
    finding_severity_for_verdict,
)

__all__ = [
    "ProjectKey",
    "encrypt_payload",
    "decrypt_payload",
    "derive_or_load_key",
    "Session",
    "SessionKind",
    "SESSION_KINDS",
    "build_substitution",
    "apply_session_to_request",
    "capture_session_from_history",
    "session_already_present",
    "Normaliser",
    "default_normaliser",
    "normalise_body",
    "normalise_headers",
    "body_similarity_pct",
    "Verdict",
    "VERDICT_LABELS",
    "decide_verdict",
    "finding_severity_for_verdict",
    "ReplayOutcome",
    "replay_history_with_session",
    "AuthMatrixRunner",
    "RunOptions",
    "AuthShadowWorker",
]

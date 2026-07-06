"""Passive shadow worker — replays every proxied response under every
active session in the background.

The worker mirrors :class:`reqlore.scanner.live.LiveScanWorker`:

* Bounded in-memory :class:`queue.Queue` (hot lane).
* Durable overflow into the existing ``live_scan_backlog`` table is
  *not* re-used here — Auth Matrix has its own appetite for traffic
  and an overflow there would compete with the passive scanner. We
  drop on overflow instead, and the operator can run an *active*
  matrix run later to backfill specific rows.
* Daemon thread with :class:`threading.Event` stop signal.
* Per-host throttle: at most one shadow batch in flight per host so
  a runaway worker doesn't spam a single target.

The worker writes one shadow run per process lifetime and appends
cells under it. The blueprint surfaces this run with ``mode="shadow"``
on the runs list.
"""
from __future__ import annotations

import contextlib
import logging
import queue
import threading
import time
from collections import Counter
from collections.abc import Callable
from typing import Any

from .crypto import derive_or_load_key
from .normaliser import default_normaliser
from .replay import replay_history_with_session
from .runner import (
    RunOptions,
    _build_session_from_row,
    _default_sender,
    _extract_body_from_serialised,
)
from .sessions import session_already_present
from .verdict import finding_severity_for_verdict

log = logging.getLogger(__name__)

_DEFAULT_QUEUE_MAX = 256
_SCOPE_REFRESH_S = 5.0


class AuthShadowWorker:
    """Background passive Auth Matrix.

    Lifecycle:

    1. :meth:`start` — spawns the daemon thread and creates a shadow
       run row (lazy, on first enqueue, so an idle project never has
       an empty shadow run cluttering the runs list).
    2. :meth:`enqueue` — proxy hands a history id whenever a response
       lands. The worker queues it; on overflow, the row is dropped
       and a counter ticks.
    3. :meth:`stop` — set the stop flag and join.

    The worker is read by the blueprint via :meth:`snapshot`.
    """

    def __init__(
        self, project: Any, *,
        maxsize: int = _DEFAULT_QUEUE_MAX,
        respect_scope: bool = True,
        sender_factory: Callable[[RunOptions], Callable] | None = None,
        options: RunOptions | None = None,
    ) -> None:
        self._project = project
        self._respect_scope = bool(respect_scope)
        self._options = options or RunOptions()
        self._sender_factory = sender_factory or _default_sender
        self._q: queue.Queue[int] = queue.Queue(maxsize=max(1, int(maxsize)))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._run_id: int | None = None
        self._scope_rules: list[dict] = []
        self._last_scope_refresh = 0.0
        # Metrics
        self.enqueued = 0
        self.processed = 0
        self.dropped = 0
        self.findings_added = 0
        self.skipped_out_of_scope = 0
        self.errors = 0
        self.verdict_counts: Counter[str] = Counter()
        self.last_error = ""
        self.last_error_ts = 0.0

    # ---- lifecycle -------------------------------------------------

    def is_alive(self) -> bool:
        t = self._thread
        return t is not None and t.is_alive()

    def start(self) -> None:
        with self._lock:
            if self.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="reqlore-authmatrix-shadow",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            with contextlib.suppress(Exception):
                t.join(timeout=max(0.0, float(timeout)))
        self._thread = None

    def shutdown(self) -> None:
        self.stop(timeout=_DEFAULT_QUEUE_MAX / 256.0 + 1.0)

    # ---- queue -----------------------------------------------------

    def enqueue(self, hid: int) -> None:
        try:
            self._q.put_nowait(int(hid))
            self.enqueued += 1
        except queue.Full:
            self.dropped += 1

    def snapshot(self) -> dict:
        return {
            "alive": self.is_alive(),
            "queue_depth": self._q.qsize(),
            "enqueued": self.enqueued,
            "processed": self.processed,
            "dropped": self.dropped,
            "findings_added": self.findings_added,
            "skipped_out_of_scope": self.skipped_out_of_scope,
            "errors": self.errors,
            "verdict_counts": dict(self.verdict_counts),
            "run_id": self._run_id,
            "last_error": self.last_error,
            "last_error_ts": int(self.last_error_ts) if self.last_error_ts else 0,
        }

    # ---- internals -------------------------------------------------

    def _ensure_run_id(self) -> int:
        if self._run_id is not None:
            return self._run_id
        with self._lock:
            if self._run_id is not None:
                return self._run_id
            rid = int(self._project.auth_matrix_create_run(
                mode="shadow",
                label="passive shadow",
                history_ids=[],
                compare_session_ids=[],
                options=self._options.as_dict(),
            ))
            try:
                self._project.auth_matrix_update_run(
                    rid, status="running",
                )
            except Exception:
                log.exception("auth_matrix shadow: cannot flip to running")
            self._run_id = rid
            return rid

    def _refresh_scope_rules(self) -> None:
        try:
            self._scope_rules = list(self._project.list_scope())
        except Exception:
            self._scope_rules = []
        self._last_scope_refresh = time.monotonic()

    def _in_scope(self, host: str) -> bool:
        if not self._respect_scope:
            return True
        if not host:
            return True
        try:
            from ..scanner.scope_utils import host_in_scope
            return host_in_scope(host, self._scope_rules)
        except Exception:
            return True

    def _loop(self) -> None:
        self._refresh_scope_rules()
        normaliser = default_normaliser(
            extra_body_rules=self._options.extra_body_rules,
            extra_header_blocklist=self._options.extra_header_blocklist,
        )
        sender = self._sender_factory(self._options)
        try:
            key = derive_or_load_key(self._project)
        except Exception:
            log.exception("auth_matrix shadow: cannot derive project key")
            return
        while not self._stop.is_set():
            try:
                hid = self._q.get(timeout=0.25)
            except queue.Empty:
                if time.monotonic() - self._last_scope_refresh > _SCOPE_REFRESH_S:
                    self._refresh_scope_rules()
                continue
            try:
                self._handle(hid, normaliser, sender, key)
            except Exception as exc:
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"[:200]
                self.last_error_ts = time.monotonic()
                log.exception("auth_matrix shadow: error on hid=%s", hid)

    def _handle(self, hid: int, normaliser, sender, key) -> None:
        try:
            hrow = self._project.get_history(int(hid))
        except Exception:
            hrow = None
        if hrow is None:
            return
        host = str(getattr(hrow, "host", "") or "")
        if not self._in_scope(host):
            self.skipped_out_of_scope += 1
            return
        try:
            sessions = self._project.auth_matrix_list_sessions(active_only=True)
        except Exception:
            sessions = []
        if not sessions:
            return
        raw_req = bytes(getattr(hrow, "req_blob", b"") or b"")
        resp_blob = bytes(getattr(hrow, "resp_blob", b"") or b"")
        baseline_status = int(getattr(hrow, "status", 0) or 0)
        baseline_body = _extract_body_from_serialised(resp_blob)
        run_id = self._ensure_run_id()
        url = str(getattr(hrow, "url", "") or "")
        for s_row in sessions:
            if self._stop.is_set():
                return
            session = _build_session_from_row(s_row, key)
            # Self-baseline guard: if the captured request was already
            # authenticated under this session, replaying it under the
            # same session is a tautology — never a bypass. Skip and
            # record an "identical" cell so the operator still sees
            # the column was considered.
            if (
                (session.source_hid is not None
                 and int(session.source_hid) == int(hid))
                or session_already_present(session, raw_req)
            ):
                try:
                    self._project.auth_matrix_add_cell(
                        run_id=run_id,
                        history_id=int(hid),
                        session_id=int(session.id or 0),
                        status=baseline_status,
                        body_len=len(baseline_body or b""),
                        duration_ms=0,
                        baseline_status=baseline_status,
                        baseline_len=len(baseline_body or b""),
                        similarity_pct=100,
                        verdict="identical",
                        error="",
                        request_blob=raw_req,
                        response_blob=resp_blob,
                        baseline_response_blob=resp_blob,
                        finding_id=None,
                    )
                except Exception:
                    log.exception(
                        "auth_matrix shadow: cannot persist self-baseline cell")
                self.verdict_counts["identical"] += 1
                continue
            try:
                outcome = replay_history_with_session(
                    raw_history_request=raw_req,
                    session=session,
                    sender=sender,
                    history_id=int(hid),
                    baseline_status=baseline_status,
                    baseline_body=baseline_body,
                    normaliser=normaliser,
                    similarity_floor=self._options.similarity_floor,
                    privileged_floor=self._options.privileged_floor,
                )
            except Exception as exc:
                self.errors += 1
                self.last_error = f"{type(exc).__name__}: {exc}"[:200]
                self.last_error_ts = time.monotonic()
                continue
            finding_id: int | None = None
            if (
                self._options.record_findings
                and outcome.verdict.label in self._options.finding_verdicts
            ):
                try:
                    finding_id = int(self._project.add_finding(
                        title=(
                            f"Auth Matrix (shadow) {outcome.verdict.label}: "
                            f"#{hid} under '{session.name}'"
                        ),
                        severity=finding_severity_for_verdict(
                            outcome.verdict.label),
                        host=host,
                        url=url,
                        description=outcome.verdict.note,
                        evidence=(
                            f"Baseline status={baseline_status}, "
                            f"candidate status={outcome.status}, "
                            f"similarity={outcome.similarity_pct}%."
                        ),
                        cwe="CWE-639",
                        owasp="A01:2021-Broken Access Control",
                        source="auth_matrix",
                        rule_id=f"auth_matrix:shadow:{outcome.verdict.label}",
                        request_id=int(hid),
                        confidence=outcome.verdict.confidence,
                        dedupe_key=(
                            f"auth_matrix:shadow:{outcome.verdict.label}:"
                            f"{hid}:{session.id}"
                        ),
                    ))
                    self.findings_added += 1
                except Exception:
                    log.exception("auth_matrix shadow: cannot add finding")
            try:
                self._project.auth_matrix_add_cell(
                    run_id=run_id,
                    history_id=int(hid),
                    session_id=int(session.id or 0),
                    status=outcome.status,
                    body_len=outcome.body_len,
                    duration_ms=outcome.duration_ms,
                    baseline_status=baseline_status,
                    baseline_len=len(baseline_body or b""),
                    similarity_pct=outcome.similarity_pct,
                    verdict=outcome.verdict.label,
                    error=outcome.error,
                    request_blob=outcome.request_blob,
                    response_blob=outcome.response_blob,
                    baseline_response_blob=resp_blob,
                    finding_id=finding_id,
                )
            except Exception:
                log.exception("auth_matrix shadow: cannot persist cell")
            self.verdict_counts[outcome.verdict.label] += 1
        self.processed += 1

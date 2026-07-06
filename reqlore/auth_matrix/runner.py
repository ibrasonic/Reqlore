"""Active-mode Auth Matrix runner — operator-launched replay batches.

Architecture mirrors :class:`reqlore.plugin_runner.PluginRunner`:

* One daemon thread per run, owned by the runner instance.
* :class:`threading.Event` cooperative-cancel signal stored per run.
* :class:`threading.Timer` watchdog with a per-run timeout (defaults
  to 10 minutes; configurable through :class:`RunOptions`).
* Every cell write is isolated — a single bad row never crashes the
  run, the worker just logs and moves on.
* Status transitions: ``pending`` -> ``running`` -> ``ok`` |
  ``error`` | ``cancelled`` | ``timeout``.

The runner is shared across the web app via
``current_app.extensions["reqlore_auth_matrix_runner"]``.
"""
from __future__ import annotations

import contextlib
import logging
import threading
import time
import traceback
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from .crypto import ProjectKey, decrypt_payload, derive_or_load_key
from .normaliser import Normaliser, default_normaliser
from .replay import replay_history_with_session
from .sessions import Session
from .verdict import finding_severity_for_verdict

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 600.0       # 10 min hard cap per run
_SHUTDOWN_JOIN_S = 1.0
_INTER_REQUEST_SLEEP_S = 0.0     # operator-configurable via RunOptions


@dataclass
class RunOptions:
    """Per-run knobs the operator can tweak in the blueprint."""

    similarity_floor: int = 80
    privileged_floor: int = 90
    timeout_s: float = _DEFAULT_TIMEOUT_S
    inter_request_sleep_s: float = _INTER_REQUEST_SLEEP_S
    record_findings: bool = True
    finding_verdicts: tuple[str, ...] = (
        "bypass-suspect", "denied-status-only",
    )
    extra_body_rules: tuple[tuple[str, str], ...] = ()
    extra_header_blocklist: tuple[str, ...] = ()
    engine: str = "httpx"
    verify_tls: bool = False    # operator may switch on for live targets
    follow_redirects: bool = False
    proxy: str | None = None

    def as_dict(self) -> dict:
        return {
            "similarity_floor": self.similarity_floor,
            "privileged_floor": self.privileged_floor,
            "timeout_s": self.timeout_s,
            "inter_request_sleep_s": self.inter_request_sleep_s,
            "record_findings": self.record_findings,
            "finding_verdicts": list(self.finding_verdicts),
            "extra_body_rules": [list(r) for r in self.extra_body_rules],
            "extra_header_blocklist": list(self.extra_header_blocklist),
            "engine": self.engine,
            "verify_tls": self.verify_tls,
            "follow_redirects": self.follow_redirects,
            "proxy": self.proxy,
        }

    @classmethod
    def from_dict(cls, payload: dict | None) -> RunOptions:
        d = payload or {}
        return cls(
            similarity_floor=int(d.get("similarity_floor", 80)),
            privileged_floor=int(d.get("privileged_floor", 90)),
            timeout_s=float(d.get("timeout_s", _DEFAULT_TIMEOUT_S)),
            inter_request_sleep_s=float(
                d.get("inter_request_sleep_s", _INTER_REQUEST_SLEEP_S)),
            record_findings=bool(d.get("record_findings", True)),
            finding_verdicts=tuple(
                d.get("finding_verdicts",
                      ["bypass-suspect", "denied-status-only"])),
            extra_body_rules=tuple(
                (str(r[0]), str(r[1]))
                for r in (d.get("extra_body_rules") or [])
                if isinstance(r, (list, tuple)) and len(r) == 2
            ),
            extra_header_blocklist=tuple(
                d.get("extra_header_blocklist") or []),
            engine=str(d.get("engine", "httpx")),
            verify_tls=bool(d.get("verify_tls", False)),
            follow_redirects=bool(d.get("follow_redirects", False)),
            proxy=d.get("proxy"),
        )


@dataclass
class _RunState:
    run_id: int
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None


def _build_session_from_row(row: dict, key: ProjectKey) -> Session:
    payload = ""
    try:
        payload = decrypt_payload(key, row.get("payload_blob") or b"").decode(
            "utf-8", errors="replace"
        )
    except Exception:
        # Mis-keyed or corrupt — surface to verdict as an empty session.
        payload = ""
    kind_str = str(row["kind"])
    if kind_str not in ("cookie", "bearer", "header", "multi", "anon"):
        kind_str = "anon"
    return Session(
        id=int(row["id"]),
        name=str(row["name"]),
        kind=cast("Literal['cookie', 'bearer', 'header', 'multi', 'anon']", kind_str),
        payload=payload,
        source=str(row.get("source") or ""),
        source_hid=row.get("source_hid"),
        created_at=int(row.get("created_at") or 0),
        last_used_at=int(row.get("last_used_at") or 0),
        active=bool(row.get("active", True)),
    )


def _default_sender(options: RunOptions):
    from ..engines import httpx_engine

    def _send(req):
        return httpx_engine.send(
            req,
            follow_redirects=options.follow_redirects,
            verify=options.verify_tls,
            proxy=options.proxy,
            timeout=30.0,
        )
    return _send


class AuthMatrixRunner:
    """Holds the active runs for one project.

    Public surface:

    * :meth:`start`  — launch a new run (returns run_id).
    * :meth:`stop`   — cooperative-cancel signal a run.
    * :meth:`is_running` — boolean by run id.
    * :meth:`shutdown` — used on web-app teardown.
    """

    def __init__(
        self, project: Any, *,
        sender_factory: Callable[[RunOptions], Callable] | None = None,
    ) -> None:
        self.project = project
        self._lock = threading.RLock()
        self._active: dict[int, _RunState] = {}
        self._shutdown = False
        self._sender_factory = sender_factory or _default_sender

    def is_running(self, run_id: int) -> bool:
        with self._lock:
            state = self._active.get(int(run_id))
        return state is not None and state.thread is not None and state.thread.is_alive()

    def start(
        self, *,
        mode: str = "active",
        label: str = "",
        history_ids: list[int],
        compare_session_ids: list[int],
        baseline_session_id: int | None = None,
        options: RunOptions | None = None,
    ) -> int:
        if not history_ids:
            raise ValueError("history_ids must be non-empty")
        if not compare_session_ids:
            raise ValueError("compare_session_ids must be non-empty")
        opts = options or RunOptions()
        with self._lock:
            if self._shutdown:
                raise RuntimeError("AuthMatrixRunner is shutting down")
            run_id = int(self.project.auth_matrix_create_run(
                mode=mode, label=label,
                baseline_session_id=baseline_session_id,
                compare_session_ids=list(compare_session_ids),
                history_ids=list(history_ids),
                options=opts.as_dict(),
            ))
            state = _RunState(run_id=run_id)
            self._active[run_id] = state
            t = threading.Thread(
                target=self._execute,
                args=(run_id, state, opts),
                name=f"reqlore-authmatrix-{run_id}",
                daemon=True,
            )
            state.thread = t
        t.start()
        return run_id

    def stop(self, run_id: int) -> bool:
        with self._lock:
            state = self._active.get(int(run_id))
            if state is None:
                return False
            state.stop.set()
            return True

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True
            states = list(self._active.values())
            for s in states:
                s.stop.set()
        for s in states:
            t = s.thread
            if t is None:
                continue
            with contextlib.suppress(Exception):
                t.join(timeout=_SHUTDOWN_JOIN_S)

    # ---- internals -------------------------------------------------

    def _execute(
        self, run_id: int, state: _RunState, options: RunOptions,
    ) -> None:
        try:
            self.project.auth_matrix_update_run(
                run_id, status="running")
        except Exception:
            log.exception("auth_matrix: cannot flip run %s to running", run_id)
        timed_out = {"hit": False}

        def _on_timeout() -> None:
            timed_out["hit"] = True
            state.stop.set()
            try:
                self.project.auth_matrix_append_run_log(
                    run_id,
                    f"[timeout] run exceeded {options.timeout_s:.0f}s",
                )
            except Exception:
                log.exception("auth_matrix: cannot write timeout log %s", run_id)

        timer = threading.Timer(
            max(1.0, float(options.timeout_s)), _on_timeout)
        timer.daemon = True
        timer.start()

        status = "ok"
        error_msg = ""
        try:
            self._run_loop(run_id, state, options)
            if timed_out["hit"]:
                status = "timeout"
            elif state.stop.is_set():
                status = "cancelled"
        except Exception as exc:
            status = "timeout" if timed_out["hit"] else "error"
            error_msg = f"{type(exc).__name__}: {exc}"[:1024]
            try:
                tb = traceback.format_exc(limit=8)
                self.project.auth_matrix_append_run_log(
                    run_id, f"[error] {error_msg}")
                self.project.auth_matrix_append_run_log(run_id, tb)
            except Exception:
                log.exception("auth_matrix: failed error log %s", run_id)
        finally:
            timer.cancel()
            try:
                counts = self.project.auth_matrix_cell_counts(run_id)
            except Exception:
                counts = {}
            try:
                self.project.auth_matrix_update_run(
                    run_id,
                    status=status,
                    finished_at=int(time.time()),
                    error=error_msg,
                    verdict_counts=counts,
                )
            except Exception:
                log.exception("auth_matrix: cannot finalise run %s", run_id)
            with self._lock:
                if self._active.get(run_id) is state:
                    self._active.pop(run_id, None)

    def _run_loop(
        self, run_id: int, state: _RunState, options: RunOptions,
    ) -> None:
        run = self.project.auth_matrix_get_run(run_id)
        if run is None:
            return
        history_ids = list(run.get("history_ids") or [])
        compare_ids = list(run.get("compare_session_ids") or [])
        baseline_id = run.get("baseline_session_id")

        key = derive_or_load_key(self.project)

        # Hydrate sessions once.
        session_rows = {
            int(s["id"]): s
            for s in self.project.auth_matrix_list_sessions()
        }
        compare_sessions: list[Session] = []
        for sid in compare_ids:
            row = session_rows.get(int(sid))
            if row is None:
                self._log(run_id, f"[skip] session {sid} not found")
                continue
            compare_sessions.append(_build_session_from_row(row, key))

        baseline_session: Session | None = None
        if baseline_id is not None:
            row = session_rows.get(int(baseline_id))
            if row is not None:
                baseline_session = _build_session_from_row(row, key)

        normaliser = default_normaliser(
            extra_body_rules=options.extra_body_rules,
            extra_header_blocklist=options.extra_header_blocklist,
        )
        sender = self._sender_factory(options)

        total = max(1, len(history_ids) * max(1, len(compare_sessions)))
        try:
            self.project.auth_matrix_update_run(
                run_id, progress_total=total, progress_done=0,
                progress_msg="starting",
            )
        except Exception:
            log.exception("auth_matrix: cannot stamp progress total")

        verdict_counter: Counter[str] = Counter()
        done = 0

        for hid in history_ids:
            if state.stop.is_set():
                break
            try:
                hrow = self.project.get_history(int(hid))
            except Exception:
                hrow = None
            if hrow is None:
                self._log(run_id, f"[skip] history #{hid} missing")
                done += len(compare_sessions)
                self._stamp_progress(run_id, done, total, f"row #{hid} missing")
                continue
            raw_req = bytes(getattr(hrow, "req_blob", b"") or b"")
            baseline_status: int | None = None
            baseline_body: bytes = b""
            baseline_resp_blob: bytes = b""
            if baseline_session is not None:
                base_outcome = self._safe_replay(
                    raw_req, baseline_session, sender, normaliser,
                    history_id=hid, baseline_status=None,
                    baseline_body=b"", options=options,
                )
                baseline_status = base_outcome.status
                baseline_body = b""  # captured into response_blob below
                baseline_resp_blob = base_outcome.response_blob
                try:
                    # Use the raw response bytes for baseline_body so the
                    # comparison cells score against a real response.
                    baseline_body = _extract_body_from_serialised(
                        baseline_resp_blob)
                except Exception:
                    baseline_body = b""
            else:
                # Fall back to the captured response in history as baseline.
                resp_blob = bytes(getattr(hrow, "resp_blob", b"") or b"")
                baseline_status = int(getattr(hrow, "status", 0) or 0)
                baseline_body = _extract_body_from_serialised(resp_blob)
                baseline_resp_blob = resp_blob

            for sess in compare_sessions:
                if state.stop.is_set():
                    break
                outcome = self._safe_replay(
                    raw_req, sess, sender, normaliser,
                    history_id=hid,
                    baseline_status=baseline_status,
                    baseline_body=baseline_body,
                    options=options,
                )
                # When the operator put the baseline session into the
                # compare list as well, force ``identical`` — it would
                # otherwise trip the bypass heuristic against itself.
                if (
                    baseline_session is not None
                    and int(sess.id) == int(baseline_session.id)
                ):
                    from .verdict import Verdict
                    outcome.verdict = Verdict(
                        label="identical",
                        note="baseline session self-comparison",
                        confidence="certain",
                    )
                self._persist_cell(
                    run_id=run_id, history_id=int(hid),
                    session=sess, outcome=outcome,
                    baseline_status=baseline_status,
                    baseline_len=len(baseline_body or b""),
                    baseline_resp_blob=baseline_resp_blob,
                    options=options,
                    host=str(getattr(hrow, "host", "") or ""),
                    url=str(getattr(hrow, "url", "") or ""),
                )
                verdict_counter[outcome.verdict.label] += 1
                done += 1
                self._stamp_progress(
                    run_id, done, total,
                    f"#{hid} × {sess.name}: {outcome.verdict.label}",
                )
                if options.inter_request_sleep_s > 0:
                    time.sleep(options.inter_request_sleep_s)

            with contextlib.suppress(Exception):
                self.project.auth_matrix_update_session(
                    int(sess.id), bump_last_used=True,
                ) if compare_sessions else None

        try:
            self.project.auth_matrix_update_run(
                run_id, verdict_counts=dict(verdict_counter),
                progress_msg="done",
            )
        except Exception:
            log.exception("auth_matrix: cannot stamp verdict_counts")

    # ---- helpers ---------------------------------------------------

    def _safe_replay(
        self, raw_req: bytes, session: Session, sender,
        normaliser: Normaliser, *,
        history_id: int,
        baseline_status: int | None,
        baseline_body: bytes,
        options: RunOptions,
    ):
        try:
            return replay_history_with_session(
                raw_history_request=raw_req,
                session=session,
                sender=sender,
                history_id=history_id,
                baseline_status=baseline_status,
                baseline_body=baseline_body,
                normaliser=normaliser,
                similarity_floor=options.similarity_floor,
                privileged_floor=options.privileged_floor,
            )
        except Exception as exc:
            from .replay import ReplayOutcome
            from .verdict import Verdict
            return ReplayOutcome(
                session_id=int(session.id or 0),
                history_id=int(history_id),
                status=0,
                body_len=0,
                duration_ms=0,
                similarity_pct=0,
                verdict=Verdict(
                    label="error",
                    note=f"{type(exc).__name__}: {exc}"[:200],
                    confidence="tentative",
                ),
                error=f"{type(exc).__name__}: {exc}"[:200],
            )

    def _persist_cell(
        self, *, run_id: int, history_id: int, session: Session,
        outcome, baseline_status: int | None, baseline_len: int,
        baseline_resp_blob: bytes, options: RunOptions,
        host: str, url: str,
    ) -> None:
        finding_id: int | None = None
        if (
            options.record_findings
            and outcome.verdict.label in options.finding_verdicts
        ):
            try:
                finding_id = int(self.project.add_finding(
                    title=(
                        f"Auth Matrix {outcome.verdict.label}: "
                        f"#{history_id} under '{session.name}'"
                    ),
                    severity=finding_severity_for_verdict(outcome.verdict.label),
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
                    rule_id=f"auth_matrix:{outcome.verdict.label}",
                    request_id=history_id,
                    confidence=outcome.verdict.confidence,
                    dedupe_key=(
                        f"auth_matrix:{outcome.verdict.label}:"
                        f"{history_id}:{session.id}"
                    ),
                ))
            except Exception:
                log.exception("auth_matrix: cannot record finding")

        try:
            self.project.auth_matrix_add_cell(
                run_id=run_id,
                history_id=history_id,
                session_id=int(session.id or 0),
                status=outcome.status,
                body_len=outcome.body_len,
                duration_ms=outcome.duration_ms,
                baseline_status=baseline_status,
                baseline_len=baseline_len,
                similarity_pct=outcome.similarity_pct,
                verdict=outcome.verdict.label,
                error=outcome.error,
                request_blob=outcome.request_blob,
                response_blob=outcome.response_blob,
                baseline_response_blob=baseline_resp_blob,
                finding_id=finding_id,
            )
        except Exception:
            log.exception("auth_matrix: cannot persist cell")

    def _stamp_progress(
        self, run_id: int, done: int, total: int, msg: str,
    ) -> None:
        try:
            self.project.auth_matrix_update_run(
                run_id, progress_done=done, progress_total=total,
                progress_msg=str(msg)[:200],
            )
        except Exception:
            log.exception("auth_matrix: cannot stamp progress")

    def _log(self, run_id: int, msg: str) -> None:
        try:
            ts = time.strftime("%H:%M:%S")
            self.project.auth_matrix_append_run_log(
                run_id, f"{ts} {msg}")
        except Exception:
            log.exception("auth_matrix: cannot append log")


def _extract_body_from_serialised(blob: bytes) -> bytes:
    """Pull the body half out of a serialised HTTP response (the
    format produced by :func:`reqlore.auth_matrix.replay._serialise_response`
    and the proxy's :func:`_serialise_response`)."""
    if not blob:
        return b""
    sep = blob.find(b"\r\n\r\n")
    if sep < 0:
        return blob
    return blob[sep + 4:]

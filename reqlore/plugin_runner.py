"""Phase 16 — Plugin App runner.

A :class:`PluginRunner` owns the live execution of standalone
plugin apps (see :class:`reqlore.plugins_sdk.PluginApp`). Each run is
a fresh daemon thread executing the plugin author's ``@runner``
function inside a guarded :class:`reqlore.plugins_sdk.PluginContext`.
Every operator-visible artefact (settings, log lines, result rows,
progress, status, error) is persisted into the ``plugin_runs`` table
so the web UI can poll a JSON snapshot without reaching into runner
internals.

Design notes
------------

* **One running execution per plugin slug.** A per-slug
  :class:`threading.Lock` prevents accidentally starting the same
  plugin twice from two browser tabs. The user can launch *different*
  plugins in parallel — only same-slug double-start is blocked.

* **Cooperative cancel.** Each run owns a
  :class:`threading.Event` named ``_stop``. ``stop_run(slug)`` sets
  it; the plugin author is expected to check
  :meth:`PluginContext.stop_requested` (or use
  :meth:`PluginContext.sleep` / :meth:`PluginContext.check_stop`) in
  their loops.

* **Hard timeout.** A watchdog thread sets the stop event after
  ``app.timeout_s`` seconds. The runner thread will eventually
  notice and exit. If a plugin is wedged in blocking C code (e.g. a
  network call without a timeout), we still flip the row to
  ``status='timeout'`` so the UI can report it; the thread itself
  remains a daemon and dies when the host process exits.

* **Total exception isolation.** Every callback, every storage
  write, every plugin invocation runs inside ``try/except``. A
  malformed plugin must never bring down the runner. Failures are
  recorded into the run row's ``error`` column and surfaced in the
  UI.

* **Shutdown.** :meth:`shutdown` signals every active run and joins
  the runner threads briefly. Any thread that does not honour the
  stop signal in time is abandoned (daemon).
"""
from __future__ import annotations

import logging
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from .plugins_sdk import (
    CancelledError,
    PluginApp,
    PluginContext,
    ScopeView,
    SeedRequest,
    parse_seed_request,
)


log = logging.getLogger("reqlore.plugin_runner")


# How many seconds to wait per stop event during shutdown before
# abandoning a thread. Daemon threads die with the process so this
# is just a courtesy.
_SHUTDOWN_JOIN_S = 1.0


@dataclass
class _RunState:
    slug: str
    run_id: int
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    started_at: float = field(default_factory=time.monotonic)
    seed_history_id: int | None = None


class PluginRunner:
    """Manages plugin app executions for one project."""

    def __init__(self, project: Any, *, oast: Any = None):
        self.project = project
        self._oast = oast
        self._lock = threading.RLock()
        # per-slug guard: prevents starting a second run while the
        # first is alive. Holds a thin _RunState pointer.
        self._active: dict[str, _RunState] = {}
        self._shutdown = False

    # -------------------------------------------------------------- start

    def start(
        self, app: PluginApp, settings: dict[str, Any], *,
        on_start: Callable[[_RunState], None] | None = None,
        seed_history_id: int | None = None,
    ) -> int:
        """Validate ``settings`` against ``app``'s fields, write a
        ``pending`` row to ``plugin_runs``, and spawn the daemon
        thread that will execute the runner.

        ``seed_history_id``, when set, is the history row the operator
        Sent-to-plugin from. The runner persists it on the run row
        and exposes the parsed request as ``ctx.seed_request`` so the
        plugin can act on it.

        Returns the new run id.

        Raises :class:`RuntimeError` if a run with the same slug is
        already active. Raises :class:`ValueError` if the plugin has
        no runner or ``settings`` fails validation.
        """
        if not isinstance(app, PluginApp):
            raise TypeError("PluginRunner.start expects a PluginApp")
        if not app.is_runnable():
            raise ValueError(
                f"plugin app {app.slug!r} has no @runner function")
        with self._lock:
            if self._shutdown:
                raise RuntimeError("PluginRunner is shutting down")
            if self.is_running(app.slug):
                raise RuntimeError(
                    f"plugin {app.slug!r} is already running")
            validated = app.validate_settings(settings or {})
            run_id = int(self.project.create_plugin_run(
                slug=app.slug, settings=validated,
                seed_history_id=seed_history_id,
            ))
            state = _RunState(
                slug=app.slug, run_id=run_id,
                seed_history_id=(int(seed_history_id)
                                 if seed_history_id is not None else None),
            )
            self._active[app.slug] = state
            t = threading.Thread(
                target=self._execute,
                args=(app, state, validated),
                name=f"reqlore-plugin-{app.slug}-{run_id}",
                daemon=True,
            )
            state.thread = t
        if on_start is not None:
            try:
                on_start(state)
            except Exception:
                log.exception("PluginRunner: on_start hook failed")
        t.start()
        return run_id

    # -------------------------------------------------------------- stop

    def stop(self, slug: str) -> bool:
        """Signal cooperative cancel. Returns ``True`` if a run was
        signalled, ``False`` if nothing was active for ``slug``."""
        with self._lock:
            state = self._active.get(str(slug))
            if state is None:
                return False
            state.stop.set()
            return True

    def stop_run(self, run_id: int) -> bool:
        """Cancel by run id. Useful when the operator hits Stop on a
        historical view; only the currently-active run for that slug
        is signalled."""
        with self._lock:
            for state in self._active.values():
                if state.run_id == int(run_id):
                    state.stop.set()
                    return True
        return False

    # ---------------------------------------------------------- introspection

    def is_running(self, slug: str) -> bool:
        with self._lock:
            state = self._active.get(str(slug))
            if state is None:
                return False
            t = state.thread
            return bool(t and t.is_alive())

    def active_slugs(self) -> list[str]:
        with self._lock:
            return [s for s, st in self._active.items()
                    if st.thread and st.thread.is_alive()]

    # --------------------------------------------------------------- shutdown

    def shutdown(self) -> None:
        """Signal every active run and wait briefly for each thread
        to wind down. Always succeeds."""
        with self._lock:
            self._shutdown = True
            states = list(self._active.values())
            for state in states:
                state.stop.set()
        for state in states:
            t = state.thread
            if t is None:
                continue
            try:
                t.join(timeout=_SHUTDOWN_JOIN_S)
            except Exception:
                pass

    # --------------------------------------------------------------- internals

    def _execute(
        self, app: PluginApp, state: _RunState, settings: dict[str, Any],
    ) -> None:
        """Thread entry point. Builds the context, runs the user
        function under a watchdog, and updates the run row."""
        # Mark running before the watchdog timer starts so observers
        # see the transition.
        try:
            self.project.update_plugin_run(state.run_id, status="running")
        except Exception:
            log.exception(
                "PluginRunner: failed to mark run %s as running",
                state.run_id)

        scope = ScopeView.from_project(self.project)
        seed = self._resolve_seed(state.seed_history_id)
        ctx = self._build_context(app, state, settings, scope, seed)

        # Watchdog: flip stop after timeout_s. We use a Timer so we
        # don't spin a thread polling time.monotonic.
        timed_out = {"hit": False}

        def _on_timeout() -> None:
            timed_out["hit"] = True
            state.stop.set()
            try:
                self.project.append_plugin_run_log(
                    state.run_id,
                    f"[timeout] plugin exceeded {app.timeout_s}s limit")
            except Exception:
                log.exception(
                    "PluginRunner: failed to write timeout log for run %s",
                    state.run_id)

        timer = threading.Timer(max(1.0, float(app.timeout_s)), _on_timeout)
        timer.daemon = True
        timer.start()

        status = "ok"
        error_msg = ""
        try:
            app.runner_fn(ctx)  # type: ignore[misc]
            # If the watchdog fired before the function returned, prefer
            # the timeout label over plain "ok" so the operator sees why
            # the run ended.
            if timed_out["hit"]:
                status = "timeout"
            elif state.stop.is_set():
                status = "cancelled"
            else:
                status = "ok"
        except CancelledError:
            status = "cancelled"
        except Exception as exc:
            # Any unhandled exception inside the plugin is treated as
            # an error. We capture both a one-line summary and a short
            # traceback in the log so the operator can debug without
            # having to re-run.
            status = "timeout" if timed_out["hit"] else "error"
            error_msg = f"{type(exc).__name__}: {exc}"[:1024]
            try:
                tb = traceback.format_exc(limit=8)
                self.project.append_plugin_run_log(
                    state.run_id, f"[error] {error_msg}\n{tb}")
            except Exception:
                log.exception(
                    "PluginRunner: failed to write error log for run %s",
                    state.run_id)
        finally:
            timer.cancel()
            try:
                self.project.update_plugin_run(
                    state.run_id,
                    status=status,
                    finished_at=int(time.time()),
                    error=error_msg,
                )
            except Exception:
                log.exception(
                    "PluginRunner: failed to finalise run %s", state.run_id)
            # Drop the slug from active map last; an external caller
            # checking is_running() during finalisation should still
            # see True until the row is written.
            with self._lock:
                if self._active.get(app.slug) is state:
                    self._active.pop(app.slug, None)

    def _resolve_seed(self, history_id: int | None) -> SeedRequest | None:
        """Look up the seed history row and return a parsed
        :class:`SeedRequest`. Returns ``None`` if no seed was provided
        or the row no longer exists.

        Errors during lookup are swallowed: a missing history row must
        never crash the plugin run — the plugin author can branch on
        ``ctx.seed_request is None`` if it matters to them.
        """
        if history_id is None:
            return None
        try:
            row = self.project.get_history(int(history_id))
        except Exception:
            log.exception(
                "PluginRunner: seed history lookup failed for hid=%s",
                history_id)
            return None
        if row is None:
            return None
        try:
            return parse_seed_request(int(history_id), row.req_blob)
        except Exception:
            log.exception(
                "PluginRunner: seed request parse failed for hid=%s",
                history_id)
            return None

    def _build_context(
        self, app: PluginApp, state: _RunState,
        settings: dict[str, Any], scope: ScopeView,
        seed: SeedRequest | None = None,
    ) -> PluginContext:
        """Wire the context callbacks. Every callback swallows its
        own exceptions; the runner has stronger logging."""
        project = self.project
        run_id = state.run_id

        def _on_log(level: str, msg: str) -> None:
            try:
                ts = time.strftime("%H:%M:%S")
                project.append_plugin_run_log(
                    run_id, f"{ts} [{level}] {msg}")
            except Exception:
                log.exception(
                    "PluginRunner: log callback failed for run %s", run_id)

        def _on_progress(done: int, total: int, message: str) -> None:
            try:
                project.update_plugin_run(
                    run_id,
                    progress_done=int(done),
                    progress_total=int(total),
                    progress_msg=str(message),
                )
            except Exception:
                log.exception(
                    "PluginRunner: progress callback failed for run %s",
                    run_id)

        def _on_result(row: dict) -> None:
            try:
                project.append_plugin_run_result(run_id, row)
            except Exception:
                log.exception(
                    "PluginRunner: result callback failed for run %s", run_id)

        return PluginContext(
            project=project,
            slug=app.slug,
            run_id=run_id,
            settings=settings,
            scope=scope,
            stop_event=state.stop,
            on_log=_on_log,
            on_progress=_on_progress,
            on_result=_on_result,
            oast=self._oast,
            seed_request=seed,
        )

"""Scheduled passive scans — opt-in background job runner.

If APScheduler is installed (``pip install reqlore[schedule]``) we use it.
Otherwise a tiny thread-based fallback (sleep + run) keeps the surface area
identical: jobs persist in ``project_state`` (so they survive process restarts)
and ``Scheduler.start()`` re-arms them automatically.

Public API::

    sched = Scheduler(project)
    sched.add_job(name="hourly-scan", interval_s=3600, scan_limit=1000)
    sched.start()
    ...
    sched.stop()
    sched.list_jobs()      # -> list[ScheduledJob]
    sched.run_now(name)    # synchronous one-shot
    sched.remove_job(name)
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

try:
    from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore
    _APS_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when extra is installed
    BackgroundScheduler = None  # type: ignore
    _APS_AVAILABLE = False

from .scanner import BUILTIN_RULES, Scanner

_STATE_KEY = "sched:jobs"
# Phase 18 — cross-process lock: refuse to start a second scheduler
# against the same .rlr file. The lock is a JSON stamp persisted in
# project_state with a heartbeat; readers treat a stamp older than
# ``_LOCK_TTL_S`` as stale (likely a crashed process).
_LOCK_KEY = "sched:lock"
_LOCK_TTL_S = 30
_LOCK_REFRESH_S = 10


@dataclass
class ScheduledJob:
    name: str
    interval_s: int
    scan_limit: int = 1000
    enabled: bool = True
    last_run_ts: int = 0
    last_findings: int = 0
    last_finished_ts: int = 0
    # Empty string == last execution succeeded (or no execution yet).
    last_error: str = ""


@dataclass
class SchedulerStatus:
    running: bool
    backend: str               # "apscheduler" | "thread" | "stopped"
    jobs: list[ScheduledJob] = field(default_factory=list)


def _serialise(jobs: list[ScheduledJob]) -> str:
    return json.dumps([asdict(j) for j in jobs])


def _deserialise(raw: str | None) -> list[ScheduledJob]:
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except Exception:
        return []
    out: list[ScheduledJob] = []
    # Tolerate rows persisted before Phase 14 added `last_error` /
    # `last_finished_ts`: drop unknown keys (would crash the dataclass
    # constructor) and let the new keys fall back to their defaults.
    allowed = {f for f in ScheduledJob.__dataclass_fields__}
    for j in payload:
        if not isinstance(j, dict):
            continue
        kwargs = {k: v for k, v in j.items() if k in allowed}
        try:
            out.append(ScheduledJob(**kwargs))
        except TypeError:
            continue
    return out


class SchedulerLockError(RuntimeError):
    """Raised when another Reqlore process already holds the scheduler
    lock for this project. The ``pid`` and ``host`` attributes describe
    the holder so callers can surface a precise message."""

    def __init__(self, pid: int | None, host: str) -> None:
        self.pid = pid
        self.host = host or ""
        who = (f"pid {pid} on {self.host}" if pid is not None and self.host
               else f"pid {pid}" if pid is not None
               else f"host {self.host}" if self.host
               else "another process")
        super().__init__(
            f"Scheduler is already running for this project ({who}). "
            f"Stop the other Reqlore process or wait for its lock to "
            f"expire."
        )


class Scheduler:
    """Persistent passive-scan scheduler scoped to a single project."""

    def __init__(self, project: Any):
        self.project = project
        self._lock = threading.RLock()
        self._jobs: list[ScheduledJob] = _deserialise(
            project.get_state(_STATE_KEY, "[]")
        )
        self._aps = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Cross-process lock bookkeeping. ``_lock_held`` flips True
        # once ``_acquire_lock`` succeeds; the heartbeat refresh in
        # ``_thread_loop`` only runs while it's True so a Scheduler
        # that never called ``start()`` cannot accidentally stamp the
        # lock.
        self._lock_held = False
        self._lock_last_refresh = 0.0
        # Populated when ``_acquire_lock`` refuses; the route / CLI
        # uses these to build a precise error message.
        self._blocking_pid: int | None = None
        self._blocking_host: str = ""

    # ---- persistence ----
    def _save(self) -> None:
        self.project.set_state(_STATE_KEY, _serialise(self._jobs))

    # ---- job CRUD ----
    def list_jobs(self) -> list[ScheduledJob]:
        with self._lock:
            return list(self._jobs)

    def add_job(self, *, name: str, interval_s: int, scan_limit: int = 1000,
                enabled: bool = True) -> ScheduledJob:
        if interval_s < 30:
            raise ValueError("interval_s must be at least 30")
        with self._lock:
            self._jobs = [j for j in self._jobs if j.name != name]
            job = ScheduledJob(name=name, interval_s=interval_s,
                                scan_limit=scan_limit, enabled=enabled)
            self._jobs.append(job)
            self._save()
            if self.is_running():
                self._arm(job)
        return job

    def remove_job(self, name: str) -> bool:
        with self._lock:
            before = len(self._jobs)
            self._jobs = [j for j in self._jobs if j.name != name]
            removed = len(self._jobs) != before
            if removed:
                self._save()
                if self._aps is not None:
                    try:
                        self._aps.remove_job(name)
                    except Exception:
                        pass
        return removed

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            for j in self._jobs:
                if j.name == name:
                    j.enabled = enabled
                    self._save()
                    return True
        return False

    # ---- execution ----
    def run_now(self, name: str) -> int:
        """Run the named job immediately. Returns findings added."""
        with self._lock:
            job = next((j for j in self._jobs if j.name == name), None)
        if not job:
            raise KeyError(name)
        return self._run_job(job)

    def _run_job(self, job: ScheduledJob) -> int:
        scanner = Scanner(rules=BUILTIN_RULES)
        with self._lock:
            job.last_run_ts = int(time.time())
            self._save()
        try:
            result = scanner.scan_project(self.project, limit=job.scan_limit)
        except Exception as exc:
            with self._lock:
                job.last_error = f"{type(exc).__name__}: {exc}"[:240]
                job.last_finished_ts = int(time.time())
                self._save()
            raise
        with self._lock:
            job.last_findings = result.findings_added
            job.last_finished_ts = int(time.time())
            job.last_error = ""
            self._save()
        return result.findings_added

    # ---- lifecycle ----
    def is_running(self) -> bool:
        return (self._aps is not None
                or (self._thread is not None and self._thread.is_alive()))

    # ---- cross-process lock ----
    def _read_lock(self) -> dict | None:
        raw = self.project.get_state(_LOCK_KEY, "")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    def _stamp_lock(self) -> None:
        """Persist a fresh lock stamp for this process."""
        stamp = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "ts": int(time.time()),
        }
        try:
            self.project.set_state(_LOCK_KEY, json.dumps(stamp))
            self._lock_held = True
            self._lock_last_refresh = time.monotonic()
        except Exception:
            # Storage write failed (DB locked / closed). The caller
            # surfaces the error from start(); the lock simply isn't
            # held in this run.
            pass

    def _acquire_lock(self) -> bool:
        """Try to claim the scheduler lock for this project.

        Returns True on success. On failure populates
        ``_blocking_pid`` / ``_blocking_host`` so ``start()`` can
        build a precise error. A stamp older than ``_LOCK_TTL_S`` is
        treated as stale (the owning process crashed) and overridden.
        Same-process / same-host stamps are silently refreshed.
        """
        existing = self._read_lock()
        if existing is not None:
            pid = existing.get("pid")
            host = existing.get("host", "")
            ts = existing.get("ts", 0)
            try:
                age = max(0, int(time.time()) - int(ts))
            except (TypeError, ValueError):
                age = _LOCK_TTL_S + 1
            same = (pid == os.getpid()
                    and host == socket.gethostname())
            if not same and age < _LOCK_TTL_S:
                self._blocking_pid = pid if isinstance(pid, int) else None
                self._blocking_host = str(host or "")
                return False
        # Either no stamp, stale stamp, or our own stamp: take it.
        self._blocking_pid = None
        self._blocking_host = ""
        self._stamp_lock()
        return True

    def _release_lock(self) -> None:
        if not self._lock_held:
            return
        # Only clear the row if we still own it: a concurrent process
        # may have stolen the slot after our TTL expired.
        existing = self._read_lock()
        if existing is not None:
            if existing.get("pid") == os.getpid() \
                    and existing.get("host") == socket.gethostname():
                try:
                    self.project.set_state(_LOCK_KEY, "")
                except Exception:
                    pass
        self._lock_held = False

    def _maybe_refresh_lock(self) -> None:
        if not self._lock_held:
            return
        if time.monotonic() - self._lock_last_refresh < _LOCK_REFRESH_S:
            return
        self._stamp_lock()

    def start(self) -> str:
        with self._lock:
            if self.is_running():
                return "apscheduler" if self._aps else "thread"
            if not self._acquire_lock():
                raise SchedulerLockError(
                    self._blocking_pid, self._blocking_host)
            if _APS_AVAILABLE:
                self._aps = BackgroundScheduler(daemon=True)
                self._aps.start()
                for job in self._jobs:
                    if job.enabled:
                        self._arm(job)
                return "apscheduler"
            self._stop.clear()
            self._thread = threading.Thread(target=self._thread_loop,
                                             name="reqlore-scheduler",
                                             daemon=True)
            self._thread.start()
            return "thread"

    def stop(self) -> None:
        with self._lock:
            if self._aps is not None:
                try:
                    self._aps.shutdown(wait=False)
                finally:
                    self._aps = None
            if self._thread is not None:
                self._stop.set()
                self._thread = None
            self._release_lock()

    def status(self) -> SchedulerStatus:
        backend = "stopped"
        if self._aps is not None:
            backend = "apscheduler"
        elif self._thread is not None and self._thread.is_alive():
            backend = "thread"
        return SchedulerStatus(running=self.is_running(), backend=backend,
                                jobs=self.list_jobs())

    # ---- backends ----
    def _arm(self, job: ScheduledJob) -> None:
        if self._aps is None:
            return
        try:
            self._aps.add_job(self._run_job, "interval",
                              seconds=job.interval_s,
                              id=job.name, replace_existing=True,
                              args=(job,))
        except Exception:
            pass

    def _thread_loop(self) -> None:
        next_run: dict[str, float] = {}
        while not self._stop.is_set():
            now = time.monotonic()
            with self._lock:
                jobs = [j for j in self._jobs if j.enabled]
            for j in jobs:
                t = next_run.get(j.name)
                if t is None:
                    next_run[j.name] = now + j.interval_s
                    continue
                if now >= t:
                    try:
                        self._run_job(j)
                    except Exception:
                        # `_run_job` already persisted `last_error`;
                        # swallow here so the thread loop keeps running
                        # other jobs.
                        pass
                    next_run[j.name] = now + j.interval_s
            self._maybe_refresh_lock()
            self._stop.wait(timeout=1.0)

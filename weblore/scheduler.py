"""Scheduled passive scans — opt-in background job runner.

If APScheduler is installed (``pip install weblore[schedule]``) we use it.
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


@dataclass
class ScheduledJob:
    name: str
    interval_s: int
    scan_limit: int = 1000
    enabled: bool = True
    last_run_ts: int = 0
    last_findings: int = 0


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
        return [ScheduledJob(**j) for j in json.loads(raw)]
    except Exception:
        return []


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
        result = scanner.scan_project(self.project, limit=job.scan_limit)
        with self._lock:
            job.last_run_ts = int(time.time())
            job.last_findings = result.findings_added
            self._save()
        return result.findings_added

    # ---- lifecycle ----
    def is_running(self) -> bool:
        return (self._aps is not None
                or (self._thread is not None and self._thread.is_alive()))

    def start(self) -> str:
        with self._lock:
            if self.is_running():
                return "apscheduler" if self._aps else "thread"
            if _APS_AVAILABLE:
                self._aps = BackgroundScheduler(daemon=True)
                self._aps.start()
                for job in self._jobs:
                    if job.enabled:
                        self._arm(job)
                return "apscheduler"
            self._stop.clear()
            self._thread = threading.Thread(target=self._thread_loop,
                                             name="weblore-scheduler",
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
                        pass
                    next_run[j.name] = now + j.interval_s
            self._stop.wait(timeout=1.0)

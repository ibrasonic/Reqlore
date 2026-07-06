"""Phase 14 — scheduler auto-start + per-job enable toggle + last_error.

Covers:

* ``ScheduledJob`` gains ``last_finished_ts`` and ``last_error`` (defaults).
* ``_run_job`` clears ``last_error`` on success and stamps both timestamps.
* ``_run_job`` populates ``last_error`` when the scanner throws.
* Persistence round-trip tolerates older project rows without the new keys.
* The web blueprint exposes:
    - ``POST /schedule/auto-start`` toggling ``sched:auto_start``.
    - ``POST /schedule/<name>/toggle`` flipping ``ScheduledJob.enabled``.
* ``create_app`` boot hook starts a scheduler only when ``sched:auto_start``
  is ``"1"`` at app creation time.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from reqlore import scheduler as sched_mod
from reqlore.config import Settings
from reqlore.scheduler import (
    ScheduledJob,
    Scheduler,
    _deserialise,
    _serialise,
)
from reqlore.storage import Project
from reqlore.web import create_app

# ---------------------------------------------------------------------------
# dataclass + serialisation
# ---------------------------------------------------------------------------


def test_scheduled_job_has_new_phase14_fields() -> None:
    j = ScheduledJob(name="x", interval_s=60)
    assert j.last_finished_ts == 0
    assert j.last_error == ""


def test_deserialise_tolerates_legacy_rows() -> None:
    # Simulate a row persisted before Phase 14 — no `last_error` or
    # `last_finished_ts` keys.  Must NOT raise; missing keys default.
    raw = '[{"name":"old","interval_s":60,"scan_limit":10,"enabled":true,' \
          '"last_run_ts":123,"last_findings":2}]'
    back = _deserialise(raw)
    assert len(back) == 1
    assert back[0].name == "old"
    assert back[0].last_error == ""
    assert back[0].last_finished_ts == 0


def test_deserialise_drops_unknown_keys() -> None:
    # Forward-compatibility: keys we don't know about must be ignored,
    # not crash the dataclass constructor.
    raw = '[{"name":"future","interval_s":60,"scan_limit":1,' \
          '"surprise_field":"hello"}]'
    back = _deserialise(raw)
    assert len(back) == 1 and back[0].name == "future"


def test_serialise_round_trip_includes_new_fields() -> None:
    jobs = [ScheduledJob(name="a", interval_s=60, scan_limit=5,
                          last_finished_ts=999, last_error="boom")]
    raw = _serialise(jobs)
    back = _deserialise(raw)
    assert back[0].last_finished_ts == 999
    assert back[0].last_error == "boom"


# ---------------------------------------------------------------------------
# _run_job behaviour
# ---------------------------------------------------------------------------


def test_run_job_success_clears_error_and_stamps_finished(
    tmp_path: Path,
) -> None:
    project = Project(tmp_path / "p14_ok.rlr")
    try:
        s = Scheduler(project)
        s.add_job(name="ok", interval_s=60, scan_limit=1)
        s.run_now("ok")
        job = next(j for j in s.list_jobs() if j.name == "ok")
        assert job.last_error == ""
        assert job.last_run_ts > 0
        assert job.last_finished_ts >= job.last_run_ts
    finally:
        project.close()


def test_run_job_records_error_when_scanner_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project(tmp_path / "p14_err.rlr")
    try:
        s = Scheduler(project)
        s.add_job(name="boom", interval_s=60, scan_limit=1)

        class _Boom:
            def __init__(self, *a, **kw): pass
            def scan_project(self, *_a, **_kw):
                raise RuntimeError("simulated scanner failure")

        monkeypatch.setattr(sched_mod, "Scanner", _Boom)

        with pytest.raises(RuntimeError):
            s.run_now("boom")

        job = next(j for j in s.list_jobs() if j.name == "boom")
        assert "simulated scanner failure" in job.last_error
        assert job.last_finished_ts > 0

        # Re-loading from disk must preserve the error message.
        s2 = Scheduler(project)
        job2 = next(j for j in s2.list_jobs() if j.name == "boom")
        assert job2.last_error == job.last_error
    finally:
        project.close()


def test_run_job_subsequent_success_clears_prior_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = Project(tmp_path / "p14_clear.rlr")
    try:
        s = Scheduler(project)
        s.add_job(name="flap", interval_s=60, scan_limit=1)

        class _Boom:
            def __init__(self, *a, **kw): pass
            def scan_project(self, *_a, **_kw):
                raise RuntimeError("first failure")

        monkeypatch.setattr(sched_mod, "Scanner", _Boom)
        with pytest.raises(RuntimeError):
            s.run_now("flap")
        assert next(j for j in s.list_jobs() if j.name == "flap").last_error

        monkeypatch.undo()

        s.run_now("flap")
        job = next(j for j in s.list_jobs() if j.name == "flap")
        assert job.last_error == ""
    finally:
        project.close()


# ---------------------------------------------------------------------------
# web routes — auto-start toggle
# ---------------------------------------------------------------------------


@pytest.fixture
def app_and_client(tmp_path: Path):
    app = create_app(tmp_path / "p14_web.rlr", Settings(), proxy=None)
    app.testing = True
    return app, app.test_client()


def _csrf(client) -> str:
    client.get("/schedule/")
    with client.session_transaction() as sess:
        tok = sess.get("csrf", "")
    assert tok, "schedule index must seed a CSRF token"
    return tok


def test_auto_start_state_defaults_off(app_and_client) -> None:
    app, _ = app_and_client
    proj = app.extensions["reqlore_project"]
    assert proj.get_state("sched:auto_start", "0") == "0"


def test_auto_start_toggle_round_trip(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    tok = _csrf(c)

    r = c.post("/schedule/auto-start",
                data={"_csrf": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert proj.get_state("sched:auto_start", "0") == "1"

    r = c.post("/schedule/auto-start",
                data={"_csrf": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert proj.get_state("sched:auto_start", "0") == "0"


def test_index_renders_auto_start_label(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    proj.set_state("sched:auto_start", "1")
    r = c.get("/schedule/")
    assert r.status_code == 200
    assert b"Auto-start on app boot" in r.data
    assert b"Disable auto-start" in r.data


# ---------------------------------------------------------------------------
# web routes — per-job enable toggle
# ---------------------------------------------------------------------------


def test_job_toggle_flips_enabled(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    s = Scheduler(proj)
    s.add_job(name="t1", interval_s=60, scan_limit=1)
    app.extensions["reqlore_scheduler"] = s
    tok = _csrf(c)

    r = c.post("/schedule/t1/toggle",
                data={"_csrf": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert next(j for j in s.list_jobs() if j.name == "t1").enabled is False

    r = c.post("/schedule/t1/toggle",
                data={"_csrf": tok}, follow_redirects=True)
    assert next(j for j in s.list_jobs() if j.name == "t1").enabled is True


def test_job_toggle_unknown_name_does_not_crash(app_and_client) -> None:
    app, c = app_and_client
    tok = _csrf(c)
    r = c.post("/schedule/nosuch/toggle",
                data={"_csrf": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert b"not found" in r.data


def test_index_shows_last_error_when_present(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    s = Scheduler(proj)
    s.add_job(name="dirty", interval_s=60, scan_limit=1)
    # Force a persisted error directly.
    with s._lock:
        s._jobs[0].last_error = "RuntimeError: persisted"
        s._jobs[0].last_finished_ts = int(time.time())
        s._save()
    app.extensions["reqlore_scheduler"] = s

    r = c.get("/schedule/")
    assert r.status_code == 200
    assert b"persisted" in r.data


# ---------------------------------------------------------------------------
# boot hook
# ---------------------------------------------------------------------------


def test_boot_hook_does_not_start_when_flag_off(tmp_path: Path) -> None:
    app = create_app(tmp_path / "boot_off.rlr", Settings(), proxy=None)
    sched = app.extensions.get("reqlore_scheduler")
    # The scheduler is always constructed (so the UI can toggle it) but
    # must NOT be running when the flag is off.
    assert sched is not None
    assert sched.is_running() is False
    sched.stop()


def test_boot_hook_starts_when_flag_on(tmp_path: Path) -> None:
    # Prime the persisted flag, then boot a fresh app over the same DB.
    db_path = tmp_path / "boot_on.rlr"
    p = Project(db_path)
    try:
        p.set_state("sched:auto_start", "1")
    finally:
        p.close()

    app = create_app(db_path, Settings(), proxy=None)
    try:
        sched = app.extensions.get("reqlore_scheduler")
        assert sched is not None
        assert sched.is_running() is True
    finally:
        # Best-effort cleanup so the file lock releases.
        sched = app.extensions.get("reqlore_scheduler")
        if sched is not None:
            sched.stop()

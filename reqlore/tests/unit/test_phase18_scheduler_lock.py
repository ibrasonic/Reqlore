"""Phase 18 - distributed scheduler lock.

Refuses to start a second scheduler against the same project. The lock
is a JSON stamp persisted in ``project_state['sched:lock']`` with a
heartbeat; stale stamps are overridden, same-process stamps are silently
refreshed, fresh stamps from a different process cause start() to
raise SchedulerLockError.
"""
from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.scheduler import (
    _LOCK_KEY,
    _LOCK_TTL_S,
    Scheduler,
    SchedulerLockError,
)
from reqlore.storage import Project
from reqlore.web import create_app

# ---------------------------------------------------------------------------
# acquire / release
# ---------------------------------------------------------------------------


def test_start_stamps_lock_into_project_state(tmp_path: Path) -> None:
    project = Project(tmp_path / "lock_stamp.rlr")
    try:
        s = Scheduler(project)
        try:
            s.start()
            raw = project.get_state(_LOCK_KEY, "")
            assert raw, "start() must persist a lock stamp"
            stamp = json.loads(raw)
            assert stamp["pid"] == os.getpid()
            assert stamp["host"] == socket.gethostname()
            assert int(stamp["ts"]) > 0
        finally:
            s.stop()
    finally:
        project.close()


def test_stop_clears_lock(tmp_path: Path) -> None:
    project = Project(tmp_path / "lock_clear.rlr")
    try:
        s = Scheduler(project)
        s.start()
        s.stop()
        assert project.get_state(_LOCK_KEY, "") == ""
    finally:
        project.close()


# ---------------------------------------------------------------------------
# rejection of foreign holder
# ---------------------------------------------------------------------------


def _seed_fresh_foreign_lock(project: Project, *, pid: int = 999_999,
                             host: str = "another-host") -> dict:
    stamp = {"pid": pid, "host": host, "ts": int(time.time())}
    project.set_state(_LOCK_KEY, json.dumps(stamp))
    return stamp


def test_start_refuses_when_foreign_lock_is_fresh(tmp_path: Path) -> None:
    project = Project(tmp_path / "lock_refuse.rlr")
    try:
        _seed_fresh_foreign_lock(project)
        s = Scheduler(project)
        with pytest.raises(SchedulerLockError) as excinfo:
            s.start()
        assert excinfo.value.pid == 999_999
        assert excinfo.value.host == "another-host"
        assert "999999" in str(excinfo.value)
        assert s.is_running() is False
    finally:
        project.close()


def test_start_overrides_stale_foreign_lock(tmp_path: Path) -> None:
    project = Project(tmp_path / "lock_stale.rlr")
    try:
        # Plant a lock far older than the TTL.
        stamp = {
            "pid": 999_999,
            "host": "long-dead-host",
            "ts": int(time.time()) - (_LOCK_TTL_S + 60),
        }
        project.set_state(_LOCK_KEY, json.dumps(stamp))
        s = Scheduler(project)
        try:
            s.start()  # must succeed: the stamp is stale
            raw = project.get_state(_LOCK_KEY, "")
            assert json.loads(raw)["pid"] == os.getpid()
        finally:
            s.stop()
    finally:
        project.close()


def test_start_overrides_corrupt_lock(tmp_path: Path) -> None:
    project = Project(tmp_path / "lock_corrupt.rlr")
    try:
        project.set_state(_LOCK_KEY, "{not-json")
        s = Scheduler(project)
        try:
            s.start()  # must not crash on bad JSON
            raw = project.get_state(_LOCK_KEY, "")
            assert json.loads(raw)["pid"] == os.getpid()
        finally:
            s.stop()
    finally:
        project.close()


def test_start_refreshes_own_stamp(tmp_path: Path) -> None:
    """Same-process re-acquire (e.g. after a stop/start cycle) must not
    refuse; it should refresh the timestamp."""
    project = Project(tmp_path / "lock_self.rlr")
    try:
        s = Scheduler(project)
        s.start()
        before = json.loads(project.get_state(_LOCK_KEY, ""))
        s.stop()

        # Plant a same-process stamp older than the refresh window but
        # younger than the TTL.
        forged = {
            "pid": os.getpid(),
            "host": socket.gethostname(),
            "ts": int(time.time()) - 5,
        }
        project.set_state(_LOCK_KEY, json.dumps(forged))

        s2 = Scheduler(project)
        try:
            s2.start()  # must succeed
            after = json.loads(project.get_state(_LOCK_KEY, ""))
            assert after["pid"] == os.getpid()
            assert after["ts"] >= forged["ts"]
            # And the in-memory bookkeeping must reflect ownership.
            assert s2._lock_held is True
        finally:
            s2.stop()
        # Quiet the linter about ``before`` being unused.
        assert before["pid"] == os.getpid()
    finally:
        project.close()


def test_stop_does_not_clear_foreign_lock(tmp_path: Path) -> None:
    """If a foreign process took the slot after our TTL expired, our
    stop() must not nuke their stamp."""
    project = Project(tmp_path / "lock_no_steal.rlr")
    try:
        s = Scheduler(project)
        s.start()
        # Foreign process steals the slot.
        foreign = {"pid": 999_999, "host": "other",
                   "ts": int(time.time())}
        project.set_state(_LOCK_KEY, json.dumps(foreign))
        s.stop()
        # The foreign stamp must still be there.
        raw = project.get_state(_LOCK_KEY, "")
        assert raw
        assert json.loads(raw)["pid"] == 999_999
    finally:
        project.close()


# ---------------------------------------------------------------------------
# web boot + route integration
# ---------------------------------------------------------------------------


def test_boot_hook_swallows_lock_error_when_foreign_holds_it(
    tmp_path: Path,
) -> None:
    """When auto-start is on but another process already holds the
    lock, app boot must NOT raise. The scheduler simply isn't running."""
    db_path = tmp_path / "boot_locked.rlr"
    p = Project(db_path)
    try:
        p.set_state("sched:auto_start", "1")
        _seed_fresh_foreign_lock(p)
    finally:
        p.close()

    app = create_app(db_path, Settings(), proxy=None)
    try:
        sched = app.extensions.get("reqlore_scheduler")
        assert sched is not None
        assert sched.is_running() is False
    finally:
        sched = app.extensions.get("reqlore_scheduler")
        if sched is not None:
            sched.stop()


def test_schedule_start_route_flashes_lock_error(tmp_path: Path) -> None:
    db_path = tmp_path / "route_locked.rlr"
    p = Project(db_path)
    try:
        _seed_fresh_foreign_lock(p, pid=4242, host="route-host")
    finally:
        p.close()

    app = create_app(db_path, Settings(), proxy=None)
    app.testing = True
    client = app.test_client()
    # Seed CSRF.
    assert client.get("/schedule/").status_code == 200
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    assert token

    r = client.post("/schedule/start",
                     data={"_csrf": token}, follow_redirects=True)
    assert r.status_code == 200
    assert b"4242" in r.data
    assert b"route-host" in r.data
    # Scheduler must not have started.
    sched = app.extensions.get("reqlore_scheduler")
    assert sched is not None
    assert sched.is_running() is False

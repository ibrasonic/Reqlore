"""B.5 — passive scanner tooling polish: resumable runs + deadline guard.

Covers:

* ``ScanResult`` carries the new ``aborted_due_to_deadline``,
  ``rows_skipped_resume``, ``last_scanned_id`` and ``deadline_seconds`` fields.
* ``Scanner.scan_project(resume=True)`` (the default) skips rows whose id is
  ``<=`` the persisted marker; passing ``resume=False`` re-scans everything.
* The resume marker is read from / written to ``project_state`` under
  ``scanner.passive.last_scanned_id`` and advances after each successful run.
* ``deadline_seconds`` aborts the loop between rows; partial results are
  still persisted and the resume marker is updated to the highest row id
  the partial run actually touched.
* The CLI ``reqlore scan`` parser accepts ``--full`` and ``--deadline``.
* The optional-deps shim (`reqlore._optdeps`) exposes the two new flags.
"""
from __future__ import annotations

from unittest.mock import patch

from reqlore._optdeps import DNS_AVAILABLE, PLAYWRIGHT_AVAILABLE
from reqlore.cli import build_parser
from reqlore.scanner import BUILTIN_RULES, Scanner
from reqlore.scanner.engine import (
    _RESUME_STATE_KEY,
    DEFAULT_DEADLINE_SECONDS,
    ScanResult,
)
from reqlore.storage import Project

# ----------------------------- helpers ---------------------------------------


def _missing_csp_response() -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body>hi</body></html>"
    )


def _seed_row(project: Project, *, n: int = 1) -> list[int]:
    """Insert `n` history rows that will all fire a passive rule."""
    ids: list[int] = []
    for i in range(n):
        ids.append(project.add_history(
            host=f"x{i}.test", method="GET", url=f"https://x{i}.test/",
            status=200, duration_ms=1, engine="httpx",
            raw_req=b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n",
            raw_resp=_missing_csp_response(),
        ))
    return ids


# ----------------------------- ScanResult defaults ---------------------------


def test_scan_result_has_b5_fields_with_defaults():
    r = ScanResult()
    assert r.aborted_due_to_deadline is False
    assert r.rows_skipped_resume == 0
    assert r.last_scanned_id is None
    assert r.deadline_seconds == 0.0


def test_default_deadline_is_300_seconds():
    assert DEFAULT_DEADLINE_SECONDS == 300.0


# ----------------------------- resumable scans -------------------------------


def test_first_scan_writes_resume_marker(tmp_path):
    project = Project(tmp_path / "b5_first.rlr")
    try:
        ids = _seed_row(project, n=3)
        result = Scanner(rules=BUILTIN_RULES).scan_project(project)
        assert result.rows_scanned == 3
        assert result.last_scanned_id == max(ids)
        assert project.get_state(_RESUME_STATE_KEY) == str(max(ids))
    finally:
        project.close()


def test_second_scan_skips_rows_already_scanned(tmp_path):
    project = Project(tmp_path / "b5_skip.rlr")
    try:
        _seed_row(project, n=2)
        Scanner(rules=BUILTIN_RULES).scan_project(project)
        # No new rows since: a re-run must process zero rows but report
        # how many it skipped.
        result = Scanner(rules=BUILTIN_RULES).scan_project(project)
        assert result.rows_scanned == 0
        assert result.rows_skipped_resume == 2
        assert result.findings_added == 0
    finally:
        project.close()


def test_full_rescan_ignores_resume_marker(tmp_path):
    project = Project(tmp_path / "b5_full.rlr")
    try:
        _seed_row(project, n=2)
        Scanner(rules=BUILTIN_RULES).scan_project(project)
        result = Scanner(rules=BUILTIN_RULES).scan_project(project, resume=False)
        assert result.rows_scanned == 2
        assert result.rows_skipped_resume == 0
    finally:
        project.close()


def test_resume_marker_advances_when_new_rows_arrive(tmp_path):
    project = Project(tmp_path / "b5_advance.rlr")
    try:
        first_ids = _seed_row(project, n=2)
        Scanner(rules=BUILTIN_RULES).scan_project(project)
        assert project.get_state(_RESUME_STATE_KEY) == str(max(first_ids))

        # New row arrives; only the new one should be scanned.
        new_ids = _seed_row(project, n=1)
        result = Scanner(rules=BUILTIN_RULES).scan_project(project)
        assert result.rows_scanned == 1
        assert result.rows_skipped_resume == 2
        assert project.get_state(_RESUME_STATE_KEY) == str(max(new_ids))
    finally:
        project.close()


def test_resume_marker_survives_corrupt_state(tmp_path):
    """A stray non-integer value in project_state must not crash; the scan
    falls back to scanning everything."""
    project = Project(tmp_path / "b5_corrupt.rlr")
    try:
        _seed_row(project, n=2)
        project.set_state(_RESUME_STATE_KEY, "not-a-number")
        result = Scanner(rules=BUILTIN_RULES).scan_project(project)
        assert result.rows_scanned == 2
        # Marker is overwritten with a valid integer.
        assert project.get_state(_RESUME_STATE_KEY).isdigit()
    finally:
        project.close()


# ----------------------------- deadline guard --------------------------------


def test_deadline_zero_means_disabled(tmp_path):
    project = Project(tmp_path / "b5_d0.rlr")
    try:
        _seed_row(project, n=1)
        # Passing None for deadline_seconds disables the deadline entirely.
        result = Scanner(rules=BUILTIN_RULES).scan_project(
            project, deadline_seconds=None,
        )
        assert result.aborted_due_to_deadline is False
        assert result.deadline_seconds == 0.0
    finally:
        project.close()


def test_deadline_aborts_between_rows_and_persists_partial(tmp_path):
    """Use a patched ``time.monotonic`` to make the second row trip the
    deadline check. We seed two rows, give a 1-second deadline, and make
    the clock jump past it after the first row is scanned."""
    project = Project(tmp_path / "b5_deadline.rlr")
    try:
        _seed_row(project, n=3)
        # Sequence of monotonic samples: t0, then between-row checks.
        # We use a counter so the first row is processed at t=0, the second
        # check sees t=10 (>>1.0 deadline), and the loop bails out.
        # The implementation calls time.monotonic at:
        #   1) loop start (t0 = sample 1)
        #   2) per-row deadline check (samples 2, 3, …)
        #   3) elapsed_ms calculation at end (last sample)
        samples = iter([0.0, 0.05, 10.0, 10.05, 10.1, 10.2, 10.3])

        def _fake_monotonic():
            try:
                return next(samples)
            except StopIteration:
                return 10.3

        with patch("reqlore.scanner.engine.time.monotonic", _fake_monotonic):
            result = Scanner(rules=BUILTIN_RULES).scan_project(
                project, deadline_seconds=1.0,
            )
        assert result.aborted_due_to_deadline is True
        assert result.rows_scanned == 1
        assert result.last_scanned_id is not None
        # Resume marker was persisted at the partial-run high-water mark.
        assert project.get_state(_RESUME_STATE_KEY) == str(result.last_scanned_id)
        assert result.deadline_seconds == 1.0
    finally:
        project.close()


def test_deadline_partial_then_resume_finishes_remaining(tmp_path):
    """Two-phase scan: phase 1 hits the deadline after 1 row, phase 2 runs
    without a deadline and processes the rest."""
    project = Project(tmp_path / "b5_two_phase.rlr")
    try:
        _seed_row(project, n=3)

        samples = iter([0.0, 0.05, 10.0, 10.05, 10.1])
        with patch("reqlore.scanner.engine.time.monotonic",
                    lambda: next(samples, 10.1)):
            r1 = Scanner(rules=BUILTIN_RULES).scan_project(
                project, deadline_seconds=1.0,
            )
        assert r1.aborted_due_to_deadline is True
        assert r1.rows_scanned == 1

        r2 = Scanner(rules=BUILTIN_RULES).scan_project(project)
        assert r2.aborted_due_to_deadline is False
        assert r2.rows_scanned == 2
        assert r2.rows_skipped_resume == 1
    finally:
        project.close()


# ----------------------------- CLI parser ------------------------------------


def test_cli_scan_accepts_full_and_deadline_flags():
    parser = build_parser()
    ns = parser.parse_args([
        "scan", "--project", "x.rlr", "--limit", "10",
        "--full", "--deadline", "60",
    ])
    assert ns.subcommand == "scan"
    assert ns.full is True
    assert ns.deadline == 60.0


def test_cli_scan_defaults_full_false_and_deadline_300():
    parser = build_parser()
    ns = parser.parse_args(["scan", "--project", "x.rlr"])
    assert ns.full is False
    assert ns.deadline == 300.0


# ----------------------------- optional deps ---------------------------------


def test_optdeps_exposes_playwright_and_dns_flags():
    """The flags must exist and be booleans, regardless of whether the
    extras are installed in the test environment."""
    assert isinstance(PLAYWRIGHT_AVAILABLE, bool)
    assert isinstance(DNS_AVAILABLE, bool)

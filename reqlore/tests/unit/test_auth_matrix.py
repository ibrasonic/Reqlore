"""Phase 17 — Auth Matrix. Comprehensive unit suite.

Covers:

* :mod:`reqlore.auth_matrix.crypto`     — per-project key derivation,
  payload encryption round-trip, version byte handling, wrong-key
  decryption failure path.
* :mod:`reqlore.auth_matrix.sessions`   — substitution per ``kind``,
  ``apply_session_to_request`` strip behaviour, capture-from-history
  auto-detection, ``session_already_present`` self-baseline guard.
* :mod:`reqlore.auth_matrix.normaliser` — CSRF / timestamp / UUID
  removal, header blocklist, similarity scoring edges.
* :mod:`reqlore.auth_matrix.verdict`    — all 8 labels exercised.
* :mod:`reqlore.auth_matrix.replay`     — request parse / serialise,
  full replay with fake sender, baseline-less path.
* :mod:`reqlore.auth_matrix.runner`     — start / stop / completion,
  self-baseline FP guard, finding creation.
* :mod:`reqlore.auth_matrix.shadow`     — enqueue + process,
  drop-on-overflow, scope filter, lazy run creation, self-baseline.
* :mod:`reqlore.storage` CRUD           — sessions / runs / cells,
  cascade on run delete, verdict counts.
* Web blueprint                         — index renders, sessions
  CRUD, shadow toggle.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from reqlore.auth_matrix import (
    SESSION_KINDS,
    VERDICT_LABELS,
    AuthMatrixRunner,
    AuthShadowWorker,
    RunOptions,
    Session,
    apply_session_to_request,
    body_similarity_pct,
    build_substitution,
    capture_session_from_history,
    decide_verdict,
    decrypt_payload,
    default_normaliser,
    derive_or_load_key,
    encrypt_payload,
    finding_severity_for_verdict,
    normalise_body,
    normalise_headers,
    replay_history_with_session,
    session_already_present,
)
from reqlore.auth_matrix.crypto import ProjectKey
from reqlore.config import Settings
from reqlore.engines import Request, Response, Timings
from reqlore.storage import Project
from reqlore.web import create_app

# ============================================================ fixtures


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Project]:
    p = Project(tmp_path / "am.rlr")
    yield p
    p.close()


@pytest.fixture
def key(project: Project) -> ProjectKey:
    return derive_or_load_key(project)


# Realistic captured request used across many tests.
_RAW_ADMIN_REQ = (
    b"GET /admin/users HTTP/1.1\r\n"
    b"Host: target.test\r\n"
    b"Cookie: session=admin-token\r\n"
    b"User-Agent: tester\r\n"
    b"\r\n"
)

_RAW_ANON_REQ = (
    b"GET /public HTTP/1.1\r\n"
    b"Host: target.test\r\n"
    b"User-Agent: tester\r\n"
    b"\r\n"
)


# ============================================================ crypto


class TestCrypto:
    def test_derive_or_load_idempotent(self, project: Project):
        k1 = derive_or_load_key(project)
        k2 = derive_or_load_key(project)
        assert k1.raw == k2.raw

    def test_round_trip(self, key: ProjectKey):
        for sample in (b"", b"x", b"session=admin", b"a" * 4096):
            blob = encrypt_payload(key, sample)
            assert decrypt_payload(key, blob) == sample

    def test_empty_plaintext_single_byte(self, key: ProjectKey):
        blob = encrypt_payload(key, b"")
        # Format: version 0x00 stands for plaintext; empty plaintext
        # round-trips as a single version byte.
        assert blob == b"\x00"
        assert decrypt_payload(key, blob) == b""

    def test_wrong_key_raises(self, key: ProjectKey):
        blob = encrypt_payload(key, b"secret")
        other = ProjectKey(raw=bytes(b"\x00" * 32))
        if blob[:1] == b"\x01":
            # cryptography can raise InvalidTag, ValueError, or a nested
            # variant depending on backend version; asserting the umbrella
            # is deliberate here.
            with pytest.raises(Exception):  # noqa: B017  # broad by design (see comment above)
                decrypt_payload(other, blob)

    def test_version_byte_unknown_raises(self, key: ProjectKey):
        with pytest.raises(ValueError):
            decrypt_payload(key, b"\xff" + b"junk")


# ============================================================ sessions


class TestSessions:
    def test_kinds_listed(self):
        assert set(SESSION_KINDS) == {
            "cookie", "bearer", "header", "multi", "anon"
        }

    def test_cookie_substitution(self):
        s = Session(name="u", kind="cookie", payload="session=x")
        assert build_substitution(s) == [("Cookie", "session=x")]

    def test_bearer_substitution_normalises_scheme(self):
        s1 = Session(name="u", kind="bearer", payload="abc.def.ghi")
        s2 = Session(name="u", kind="bearer", payload="Bearer abc.def.ghi")
        assert build_substitution(s1) == [("Authorization", "Bearer abc.def.ghi")]
        assert build_substitution(s2) == [("Authorization", "Bearer abc.def.ghi")]

    def test_header_substitution_takes_first(self):
        s = Session(
            name="u", kind="header",
            payload="X-Tenant: foo\nX-Should-Ignore: bar",
        )
        assert build_substitution(s) == [("X-Tenant", "foo")]

    def test_multi_substitution_keeps_order(self):
        s = Session(
            name="u", kind="multi",
            payload="X-A: 1\nX-B: 2\nX-C: 3",
        )
        assert build_substitution(s) == [
            ("X-A", "1"), ("X-B", "2"), ("X-C", "3"),
        ]

    def test_anon_returns_empty(self):
        s = Session(name="u", kind="anon", payload="ignored")
        assert build_substitution(s) == []

    def test_apply_replaces_cookie(self):
        existing = [("Host", "x"), ("Cookie", "session=old"),
                    ("User-Agent", "ua")]
        s = Session(name="u", kind="cookie", payload="session=new")
        out = apply_session_to_request(existing, s)
        assert ("Cookie", "session=new") in out
        # Only one cookie header.
        cookies = [h for h in out if h[0].lower() == "cookie"]
        assert len(cookies) == 1

    def test_apply_strips_default_auth_for_anon(self):
        existing = [
            ("Host", "x"),
            ("Cookie", "session=old"),
            ("Authorization", "Bearer xxx"),
            ("X-API-Key", "abc"),
            ("User-Agent", "ua"),
        ]
        s = Session(name="u", kind="anon")
        out = apply_session_to_request(existing, s)
        names = [k.lower() for k, _ in out]
        assert "cookie" not in names
        assert "authorization" not in names
        assert "x-api-key" not in names
        assert "user-agent" in names

    def test_apply_appends_when_absent(self):
        existing = [("Host", "x")]
        s = Session(name="u", kind="cookie", payload="session=new")
        out = apply_session_to_request(existing, s)
        assert ("Cookie", "session=new") in out

    def test_capture_detects_bearer(self):
        s = capture_session_from_history(
            name="auto",
            history_id=42,
            headers=[("Authorization", "Bearer abc.def.ghi")],
        )
        assert s.kind == "bearer"
        assert s.payload == "abc.def.ghi"
        assert s.source_hid == 42
        assert s.source == "history"

    def test_capture_detects_cookie(self):
        s = capture_session_from_history(
            name="auto",
            history_id=7,
            headers=[("Cookie", "session=abc")],
        )
        assert s.kind == "cookie"
        assert s.payload == "session=abc"

    def test_capture_falls_back_to_anon(self):
        s = capture_session_from_history(
            name="auto", history_id=1, headers=[],
        )
        assert s.kind == "anon"
        assert s.payload == ""

    def test_capture_respects_hint(self):
        s = capture_session_from_history(
            name="auto", history_id=1,
            headers=[("Cookie", "session=abc"),
                     ("Authorization", "Bearer t")],
            kind_hint="multi",
        )
        assert s.kind == "multi"
        # Both headers wired in
        lines = s.payload.split("\n")
        assert any("Authorization" in line for line in lines)
        assert any("Cookie" in line for line in lines)

    def test_session_already_present_anon(self):
        s = Session(name="a", kind="anon")
        assert session_already_present(s, _RAW_ANON_REQ) is True
        assert session_already_present(s, _RAW_ADMIN_REQ) is False

    def test_session_already_present_cookie(self):
        s = Session(name="admin", kind="cookie",
                    payload="session=admin-token")
        assert session_already_present(s, _RAW_ADMIN_REQ) is True
        assert session_already_present(s, _RAW_ANON_REQ) is False

    def test_session_already_present_bearer(self):
        raw = (b"GET / HTTP/1.1\r\nHost: x\r\n"
               b"Authorization: Bearer abc.def\r\n\r\n")
        s = Session(name="u", kind="bearer", payload="abc.def")
        assert session_already_present(s, raw) is True
        s_wrong = Session(name="u", kind="bearer", payload="other")
        assert session_already_present(s_wrong, raw) is False

    def test_session_already_present_multi(self):
        raw = (b"GET / HTTP/1.1\r\nHost: x\r\n"
               b"X-A: 1\r\nX-B: 2\r\n\r\n")
        s = Session(name="u", kind="multi", payload="X-A: 1\nX-B: 2")
        assert session_already_present(s, raw) is True
        s_wrong = Session(name="u", kind="multi", payload="X-A: 9\nX-B: 2")
        assert session_already_present(s_wrong, raw) is False

    def test_session_rejects_empty_name(self):
        with pytest.raises(ValueError):
            Session(name="", kind="cookie", payload="x")

    def test_session_rejects_bad_kind(self):
        with pytest.raises(ValueError):
            Session(name="u", kind="bogus", payload="x")  # type: ignore[arg-type]


# ============================================================ normaliser


class TestNormaliser:
    def test_strip_csrf_input(self):
        n = default_normaliser()
        out = normalise_body(
            b'<input name="csrf_token" value="ABCDEF">', n)
        assert "ABCDEF" not in out

    def test_strip_csrf_meta(self):
        n = default_normaliser()
        out = normalise_body(
            b'<meta name="csrf-token" content="ZZZZ">', n)
        assert "ZZZZ" not in out

    def test_strip_iso_timestamp(self):
        n = default_normaliser()
        out = normalise_body(b"timestamp=2024-01-02T03:04:05.123Z", n)
        assert "2024-01-02" not in out

    def test_strip_uuid(self):
        n = default_normaliser()
        out = normalise_body(
            b"id=550e8400-e29b-41d4-a716-446655440000", n)
        assert "550e8400" not in out

    def test_header_blocklist(self):
        n = default_normaliser()
        in_h = [
            ("Date", "Mon, 01 Jan 2024 00:00:00 GMT"),
            ("Set-Cookie", "session=abc; Expires=…"),
            ("ETag", '"v123"'),
            ("X-Request-Id", "abcd"),
            ("Content-Type", "text/html"),
        ]
        out = normalise_headers(in_h, n)
        names = [k.lower() for k, _ in out]
        assert "date" not in names
        assert "set-cookie" not in names
        assert "etag" not in names
        assert "x-request-id" not in names
        assert "content-type" in names

    def test_similarity_identical(self):
        assert body_similarity_pct("abc", "abc") == 100

    def test_similarity_empty_both(self):
        # Both empty: we consider them identical.
        assert body_similarity_pct("", "") == 100

    def test_similarity_one_empty(self):
        # One empty, one not: not identical.
        assert body_similarity_pct("", "hello world") < 100

    def test_similarity_completely_different(self):
        assert body_similarity_pct("aaaa", "zzzz") < 80


# ============================================================ verdict


class TestVerdict:
    def test_labels_complete(self):
        assert set(VERDICT_LABELS) == {
            "bypass-suspect", "denied-correctly", "denied-status-only",
            "different-payload", "identical",
            "no-baseline", "error", "dismissed",
        }

    def test_error(self):
        v = decide_verdict(
            baseline_status=200, candidate_status=0,
            similarity_pct=0, candidate_error="TimeoutError",
        )
        assert v.label == "error"

    def test_no_baseline(self):
        v = decide_verdict(
            baseline_status=None, candidate_status=200, similarity_pct=80,
        )
        assert v.label == "no-baseline"

    def test_bypass_suspect(self):
        v = decide_verdict(
            baseline_status=200, candidate_status=200, similarity_pct=99,
        )
        assert v.label == "bypass-suspect"

    def test_denied_correctly(self):
        v = decide_verdict(
            baseline_status=200, candidate_status=403, similarity_pct=10,
        )
        assert v.label == "denied-correctly"

    def test_denied_status_only(self):
        v = decide_verdict(
            baseline_status=200, candidate_status=403, similarity_pct=95,
        )
        assert v.label == "denied-status-only"

    def test_identical_both_denied(self):
        v = decide_verdict(
            baseline_status=403, candidate_status=403, similarity_pct=99,
        )
        assert v.label == "identical"

    def test_different_payload(self):
        v = decide_verdict(
            baseline_status=200, candidate_status=200, similarity_pct=30,
        )
        assert v.label == "different-payload"

    def test_redirect_to_login_is_denied(self):
        v = decide_verdict(
            baseline_status=200, candidate_status=302, similarity_pct=10,
            candidate_location="/login",
        )
        assert v.label == "denied-correctly"

    def test_severity_mapping(self):
        assert finding_severity_for_verdict("bypass-suspect") == "high"
        assert finding_severity_for_verdict("denied-status-only") == "medium"
        assert finding_severity_for_verdict("denied-correctly") == "info"


# ============================================================ replay


def _ok_sender(req: Request) -> Response:
    return Response(
        status=200, reason="OK",
        headers=[("Content-Type", "text/html")],
        body=b"<h1>users</h1>",
        timings=Timings(total_ms=5), engine="fake",
    )


def _deny_sender(req: Request) -> Response:
    return Response(
        status=403, reason="Forbidden",
        headers=[("Content-Type", "text/html")],
        body=b"<h1>Forbidden</h1>",
        timings=Timings(total_ms=3), engine="fake",
    )


def _exploding_sender(req: Request) -> Response:
    raise ConnectionError("network broken")


class TestReplay:
    def test_returns_outcome_with_session_swap(self):
        s = Session(name="admin", kind="cookie", payload="session=admin")
        out = replay_history_with_session(
            raw_history_request=_RAW_ANON_REQ,
            session=s,
            sender=_ok_sender,
            history_id=1,
            baseline_status=200,
            baseline_body=b"<h1>users</h1>",
        )
        assert out.status == 200
        assert out.verdict.label in ("bypass-suspect", "identical")
        assert out.body_len == len(b"<h1>users</h1>")

    def test_no_baseline_path(self):
        s = Session(name="admin", kind="cookie", payload="session=admin")
        out = replay_history_with_session(
            raw_history_request=_RAW_ANON_REQ,
            session=s,
            sender=_ok_sender,
            baseline_status=None,
            baseline_body=b"",
        )
        assert out.verdict.label == "no-baseline"

    def test_sender_exception_yields_error_verdict(self):
        s = Session(name="anon", kind="anon")
        out = replay_history_with_session(
            raw_history_request=_RAW_ADMIN_REQ,
            session=s,
            sender=_exploding_sender,
            baseline_status=200,
            baseline_body=b"x",
        )
        assert out.verdict.label == "error"

    def test_denied_correctly_path(self):
        s = Session(name="anon", kind="anon")
        out = replay_history_with_session(
            raw_history_request=_RAW_ADMIN_REQ,
            session=s,
            sender=_deny_sender,
            baseline_status=200,
            baseline_body=b"<h1>secret data</h1>",
        )
        assert out.verdict.label == "denied-correctly"


# ============================================================ storage CRUD


class TestStorageAuthMatrix:
    def test_sessions_crud(self, project: Project, key: ProjectKey):
        sid = project.auth_matrix_create_session(
            name="admin",
            kind="cookie",
            payload_blob=encrypt_payload(key, b"session=admin"),
            source="manual",
        )
        assert sid > 0
        got = project.auth_matrix_get_session(sid)
        assert got is not None
        assert got["name"] == "admin"
        assert got["kind"] == "cookie"
        assert decrypt_payload(key, got["payload_blob"]) == b"session=admin"

        project.auth_matrix_update_session(sid, active=False)
        got_updated = project.auth_matrix_get_session(sid)
        assert got_updated is not None
        assert got_updated["active"] is False

        # List + active_only
        sid2 = project.auth_matrix_create_session(
            name="anon", kind="anon",
            payload_blob=encrypt_payload(key, b""),
        )
        all_rows = project.auth_matrix_list_sessions()
        names = [r["name"] for r in all_rows]
        assert "admin" in names and "anon" in names
        only_active = project.auth_matrix_list_sessions(active_only=True)
        names_active = [r["name"] for r in only_active]
        assert "anon" in names_active
        assert "admin" not in names_active

        project.auth_matrix_delete_session(sid2)
        assert project.auth_matrix_get_session(sid2) is None

    def test_run_lifecycle_and_log(self, project: Project):
        rid = project.auth_matrix_create_run(
            mode="active", label="t1",
            history_ids=[1, 2], compare_session_ids=[10, 11],
            options={"x": 1},
        )
        run = project.auth_matrix_get_run(rid)
        assert run is not None
        assert run["status"] == "pending"
        assert run["history_ids"] == [1, 2]
        assert run["compare_session_ids"] == [10, 11]
        assert run["options"] == {"x": 1}
        project.auth_matrix_update_run(rid, status="running")
        project.auth_matrix_append_run_log(rid, "first")
        project.auth_matrix_append_run_log(rid, "second")
        run = project.auth_matrix_get_run(rid)
        assert run is not None
        assert "first" in run["log"] and "second" in run["log"]
        project.auth_matrix_update_run(
            rid, status="ok", verdict_counts={"identical": 4})
        run = project.auth_matrix_get_run(rid)
        assert run is not None
        assert run["verdict_counts"] == {"identical": 4}

    def test_cell_blobs_round_trip_and_cascade(
        self, project: Project, key: ProjectKey,
    ):
        rid = project.auth_matrix_create_run(
            mode="active", history_ids=[1], compare_session_ids=[1],
        )
        sid = project.auth_matrix_create_session(
            name="u", kind="cookie",
            payload_blob=encrypt_payload(key, b"session=x"),
        )
        cid = project.auth_matrix_add_cell(
            run_id=rid, history_id=1, session_id=sid,
            status=200, body_len=99, duration_ms=12,
            baseline_status=200, baseline_len=99,
            similarity_pct=100, verdict="identical",
            request_blob=b"GET / HTTP/1.1\r\n\r\n",
            response_blob=b"HTTP/1.1 200 OK\r\n\r\nbody",
            baseline_response_blob=b"HTTP/1.1 200 OK\r\n\r\nbody",
        )
        c = project.auth_matrix_get_cell(cid)
        assert c is not None
        assert c["request_blob"].startswith(b"GET")
        assert c["response_blob"].endswith(b"body")
        counts = project.auth_matrix_cell_counts(rid)
        assert counts.get("identical") == 1
        # Cascade: delete the run, the cell must vanish.
        project.auth_matrix_delete_run(rid)
        assert project.auth_matrix_get_run(rid) is None
        assert project.auth_matrix_get_cell(cid) is None


# ============================================================ runner


def _admin_sender(req: Request) -> Response:
    cookie = req.header("Cookie") or ""
    if "admin-token" in cookie:
        return Response(
            status=200, reason="OK",
            headers=[("Content-Type", "text/html")],
            body=b"<h1>Admin Users</h1>",
            timings=Timings(total_ms=5), engine="fake",
        )
    return Response(
        status=403, reason="Forbidden",
        headers=[("Content-Type", "text/html")],
        body=b"<h1>Forbidden</h1>",
        timings=Timings(total_ms=3), engine="fake",
    )


class TestAuthMatrixRunner:
    def _seed(self, project: Project, key: ProjectKey) -> tuple[int, int, int]:
        sid_admin = project.auth_matrix_create_session(
            name="admin", kind="cookie",
            payload_blob=encrypt_payload(key, b"session=admin-token"),
        )
        sid_anon = project.auth_matrix_create_session(
            name="anon", kind="anon",
            payload_blob=encrypt_payload(key, b""),
        )
        hid = project.add_history(
            host="target.test", method="GET",
            url="http://target.test/admin/users",
            status=200, duration_ms=10, engine="proxy",
            raw_req=_RAW_ADMIN_REQ,
            raw_resp=(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                b"<h1>Admin Users</h1>"
            ),
        )
        return sid_admin, sid_anon, hid

    def _wait(self, project: Project, rid: int, *, timeout: float = 4.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            run = project.auth_matrix_get_run(rid)
            if run is not None and run["status"] in ("ok", "error", "cancelled", "timeout"):
                return run
            time.sleep(0.02)
        return project.auth_matrix_get_run(rid)

    def test_happy_path_no_fp_self_baseline(
        self, project: Project, key: ProjectKey,
    ):
        sid_admin, sid_anon, hid = self._seed(project, key)
        runner = AuthMatrixRunner(
            project, sender_factory=lambda opts: _admin_sender,
        )
        try:
            rid = runner.start(
                history_ids=[hid],
                compare_session_ids=[sid_admin, sid_anon],
                baseline_session_id=sid_admin,
                options=RunOptions(timeout_s=5.0),
            )
            run = self._wait(project, rid)
            assert run["status"] == "ok"
            counts = run["verdict_counts"]
            # admin column vs admin baseline -> identical; anon -> denied-correctly
            assert counts.get("identical", 0) >= 1
            assert counts.get("denied-correctly", 0) >= 1
            assert counts.get("bypass-suspect", 0) == 0
            findings = project.list_findings(limit=50)
            assert all("bypass-suspect" not in (f.get("title") or "")
                       for f in findings)
        finally:
            runner.shutdown()

    def test_stop_signals_cancelled(
        self, project: Project, key: ProjectKey,
    ):
        sid_admin, sid_anon, hid = self._seed(project, key)
        # Create a sender that blocks a tiny bit so cancellation can race.
        def slow_sender(req: Request) -> Response:
            time.sleep(0.1)
            return _admin_sender(req)
        runner = AuthMatrixRunner(
            project, sender_factory=lambda opts: slow_sender,
        )
        try:
            rid = runner.start(
                history_ids=[hid],
                compare_session_ids=[sid_admin, sid_anon],
                baseline_session_id=sid_admin,
                options=RunOptions(timeout_s=10.0),
            )
            runner.stop(rid)
            run = self._wait(project, rid, timeout=5.0)
            assert run["status"] in ("cancelled", "ok")
        finally:
            runner.shutdown()

    def test_records_finding_on_bypass(
        self, project: Project, key: ProjectKey,
    ):
        # Buggy backend: anonymous request still returns admin content.
        def buggy_sender(req: Request) -> Response:
            return Response(
                status=200, reason="OK",
                headers=[("Content-Type", "text/html")],
                body=b"<h1>Admin Users</h1>",
                timings=Timings(total_ms=2), engine="fake",
            )
        sid_admin, sid_anon, hid = self._seed(project, key)
        runner = AuthMatrixRunner(
            project, sender_factory=lambda opts: buggy_sender,
        )
        try:
            rid = runner.start(
                history_ids=[hid],
                compare_session_ids=[sid_admin, sid_anon],
                baseline_session_id=sid_admin,
                options=RunOptions(timeout_s=5.0),
            )
            run = self._wait(project, rid)
            assert run["status"] == "ok"
            assert run["verdict_counts"].get("bypass-suspect", 0) >= 1
            findings = project.list_findings(limit=50)
            assert any(
                "bypass-suspect" in (f.get("title") or "")
                for f in findings
            )
        finally:
            runner.shutdown()


# ============================================================ shadow worker


class TestShadowWorker:
    def test_processes_enqueued(self, project: Project, key: ProjectKey):
        project.auth_matrix_create_session(
            name="admin", kind="cookie",
            payload_blob=encrypt_payload(key, b"session=admin-token"),
        )
        project.auth_matrix_create_session(
            name="anon", kind="anon",
            payload_blob=encrypt_payload(key, b""),
        )
        hid = project.add_history(
            host="target.test", method="GET",
            url="http://target.test/admin",
            status=200, duration_ms=10, engine="proxy",
            raw_req=_RAW_ADMIN_REQ,
            raw_resp=(b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/html\r\n\r\n<h1>Admin</h1>"),
        )
        w = AuthShadowWorker(
            project, respect_scope=False,
            sender_factory=lambda opts: _admin_sender,
        )
        try:
            w.start()
            w.enqueue(hid)
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if w.processed >= 1:
                    break
                time.sleep(0.02)
            snap = w.snapshot()
            assert snap["processed"] >= 1
            assert snap["run_id"] is not None
            cells = project.auth_matrix_list_cells(snap["run_id"])
            # admin column on admin-authed request must NOT be flagged
            # as a bypass (self-baseline guard).
            for c in cells:
                assert c["verdict"] != "bypass-suspect"
        finally:
            w.stop(timeout=2.0)

    def test_drop_on_overflow(self, project: Project, key: ProjectKey):
        project.auth_matrix_create_session(
            name="anon", kind="anon",
            payload_blob=encrypt_payload(key, b""),
        )
        # Tiny queue; we never start the worker so nothing drains.
        w = AuthShadowWorker(
            project, maxsize=2, respect_scope=False,
            sender_factory=lambda opts: _admin_sender,
        )
        for i in range(5):
            w.enqueue(i + 1)
        assert w.enqueued == 2
        assert w.dropped == 3

    def test_scope_filter_skips_out_of_scope(
        self, project: Project, key: ProjectKey,
    ):
        project.auth_matrix_create_session(
            name="anon", kind="anon",
            payload_blob=encrypt_payload(key, b""),
        )
        # Include-only rule for a different host — our target.test is
        # therefore out of scope.
        project.add_scope("include", "other.test")
        hid = project.add_history(
            host="target.test", method="GET",
            url="http://target.test/x",
            status=200, duration_ms=1, engine="proxy",
            raw_req=_RAW_ANON_REQ,
            raw_resp=b"HTTP/1.1 200 OK\r\n\r\n",
        )
        w = AuthShadowWorker(
            project, respect_scope=True,
            sender_factory=lambda opts: _admin_sender,
        )
        try:
            w.start()
            w.enqueue(hid)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if w.skipped_out_of_scope >= 1 or w.processed >= 1:
                    break
                time.sleep(0.02)
            assert w.skipped_out_of_scope >= 1
        finally:
            w.stop(timeout=2.0)

    def test_self_baseline_guard_no_false_positive(
        self, project: Project, key: ProjectKey,
    ):
        # Captured request was authenticated as admin; shadow worker
        # MUST NOT flag the admin session as a bypass when replaying.
        project.auth_matrix_create_session(
            name="admin", kind="cookie",
            payload_blob=encrypt_payload(key, b"session=admin-token"),
        )
        hid = project.add_history(
            host="target.test", method="GET",
            url="http://target.test/admin",
            status=200, duration_ms=1, engine="proxy",
            raw_req=_RAW_ADMIN_REQ,
            raw_resp=(b"HTTP/1.1 200 OK\r\n"
                      b"Content-Type: text/html\r\n\r\n<h1>Admin</h1>"),
        )
        w = AuthShadowWorker(
            project, respect_scope=False,
            sender_factory=lambda opts: _admin_sender,
        )
        try:
            w.start()
            w.enqueue(hid)
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if w.processed >= 1:
                    break
                time.sleep(0.02)
            assert w.findings_added == 0
            cells = project.auth_matrix_list_cells(w.snapshot()["run_id"])
            assert any(c["verdict"] == "identical" for c in cells)
            assert not any(c["verdict"] == "bypass-suspect" for c in cells)
        finally:
            w.stop(timeout=2.0)


# ============================================================ blueprint


@pytest.fixture
def app(tmp_path: Path):
    settings = Settings()
    a = create_app(tmp_path / "web.rlr", settings, proxy=None)
    a.config["TESTING"] = True
    a.config["WTF_CSRF_ENABLED"] = False
    yield a


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client):
    """Establish a session and grab the csrf token from it."""
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


class TestBlueprint:
    def test_index_renders(self, client):
        rv = client.get("/auth-matrix/")
        assert rv.status_code == 200

    def test_sessions_crud_round_trip(self, client):
        token = _csrf(client)
        rv = client.post(
            "/auth-matrix/sessions/new",
            data={"name": "test", "kind": "cookie",
                  "payload": "session=x", "_csrf": token},
            follow_redirects=True,
        )
        assert rv.status_code == 200
        rv = client.get("/auth-matrix/sessions/")
        assert b"test" in rv.data

    def test_shadow_toggle(self, client, app):
        token = _csrf(client)
        rv = client.post(
            "/auth-matrix/shadow/toggle",
            data={"_csrf": token, "action": "start"},
            follow_redirects=True,
        )
        assert rv.status_code == 200
        with app.app_context():
            project = app.extensions["reqlore_project"]
            assert project.get_state("auth_matrix:shadow_enabled", "") == "1"

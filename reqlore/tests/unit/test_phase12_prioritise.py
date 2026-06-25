"""Phase 12 — audit prioritisation (attack-surface scoring).

Burp-parity row ordering. Tests cover:

* :class:`ScoringWeights` / :class:`InterestFactors` dataclass
  validation.
* The three interest helpers: ``is_state_changing``,
  ``looks_like_session_cookie``, ``request_carries_auth``.
* ``interest_level`` returning the four-tuple.
* ``insertion_point_keys`` deduplicating per (host, ip_type, name).
* ``score_row`` honouring an "already audited" set.
* ``prioritise_queue`` in both default and incremental modes.
* End-to-end integration with ``ActiveScanner.run_on_project``.
* The ``/scanner/priority-preview`` Flask route.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from reqlore.scanner.active import (
    ActiveOptions,
    ActiveScanner,
)
from reqlore.scanner.prioritise import (
    SESSION_COOKIE_NAMES,
    STATE_CHANGING_METHODS,
    InterestFactors,
    RowScore,
    ScoringWeights,
    insertion_point_keys,
    interest_level,
    is_state_changing,
    looks_like_session_cookie,
    prioritise_queue,
    request_carries_auth,
    score_row,
)
from reqlore.storage import Project


# ---------------------------------------------------------------------------
# Helper: build fake history rows. We don't need a full HistoryRow
# dataclass — duck-typing on the attributes the scoring API reads is
# enough and keeps tests cheap.
# ---------------------------------------------------------------------------

@dataclass
class _Row:
    id: int
    host: str
    method: str
    url: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _row(
    *,
    rid: int = 1,
    host: str = "x.y",
    method: str = "GET",
    url: str = "https://x.y/",
    status: int = 200,
    extra_req_headers: tuple[tuple[str, str], ...] = (),
    resp_ct: str = "text/html",
    resp_status_line: str = "HTTP/1.1 200 OK",
    body: bytes = b"",
) -> _Row:
    """Construct a minimal history row with a parseable request blob."""
    req_lines = [f"{method} {url} HTTP/1.1".encode(), f"Host: {host}".encode()]
    for k, v in extra_req_headers:
        req_lines.append(f"{k}: {v}".encode())
    req_blob = b"\r\n".join(req_lines) + b"\r\n\r\n" + body
    resp_blob = (
        f"{resp_status_line}\r\n"
        f"Content-Type: {resp_ct}\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()
    return _Row(
        id=rid, host=host, method=method, url=url, status=status,
        req_blob=req_blob, resp_blob=resp_blob,
    )


# ---------------------------------------------------------------------------
# 1) Constants sanity.
# ---------------------------------------------------------------------------

class TestConstants:

    def test_state_changing_methods_canonical(self) -> None:
        assert STATE_CHANGING_METHODS == frozenset(
            {"POST", "PUT", "PATCH", "DELETE"}
        )

    def test_safe_methods_excluded(self) -> None:
        for m in ("GET", "HEAD", "OPTIONS", "TRACE", "CONNECT"):
            assert m not in STATE_CHANGING_METHODS

    def test_session_cookie_names_include_common(self) -> None:
        for name in ("session", "sid", "jsessionid", "phpsessid"):
            assert name in SESSION_COOKIE_NAMES


# ---------------------------------------------------------------------------
# 2) ScoringWeights validation.
# ---------------------------------------------------------------------------

class TestScoringWeights:

    def test_defaults_are_burp_80_20(self) -> None:
        w = ScoringWeights()
        assert w.surface == 0.8
        assert w.interest == 0.2

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValueError):
            ScoringWeights(surface=-0.1, interest=0.5)
        with pytest.raises(ValueError):
            ScoringWeights(surface=0.5, interest=-0.1)

    def test_rejects_both_zero(self) -> None:
        with pytest.raises(ValueError):
            ScoringWeights(surface=0.0, interest=0.0)

    def test_one_zero_is_allowed(self) -> None:
        # Operator who only cares about surface (interest weight = 0)
        # is a valid configuration.
        ScoringWeights(surface=1.0, interest=0.0)
        ScoringWeights(surface=0.0, interest=1.0)


# ---------------------------------------------------------------------------
# 3) Method classifier.
# ---------------------------------------------------------------------------

class TestIsStateChanging:

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_state_changing(self, method: str) -> None:
        assert is_state_changing(method) is True

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "TRACE"])
    def test_safe(self, method: str) -> None:
        assert is_state_changing(method) is False

    def test_case_insensitive(self) -> None:
        assert is_state_changing("post") is True
        assert is_state_changing("Patch") is True

    def test_whitespace_tolerated(self) -> None:
        assert is_state_changing("  POST  ") is True

    def test_empty_or_none(self) -> None:
        assert is_state_changing("") is False
        assert is_state_changing(None) is False

    def test_custom_factor_set(self) -> None:
        f = InterestFactors(state_changing_methods=frozenset({"GET"}))
        assert is_state_changing("GET", factors=f) is True
        assert is_state_changing("POST", factors=f) is False


# ---------------------------------------------------------------------------
# 4) Cookie classifier.
# ---------------------------------------------------------------------------

class TestLooksLikeSessionCookie:

    @pytest.mark.parametrize("name", [
        "session", "JSESSIONID", "PHPSESSID", "sid", "Auth_Token",
    ])
    def test_session_like(self, name: str) -> None:
        assert looks_like_session_cookie(name) is True

    @pytest.mark.parametrize("name", ["_ga", "utm_source", "csrf-meta"])
    def test_not_session_like(self, name: str) -> None:
        assert looks_like_session_cookie(name) is False

    def test_empty_or_none(self) -> None:
        assert looks_like_session_cookie("") is False
        assert looks_like_session_cookie(None) is False


# ---------------------------------------------------------------------------
# 5) Auth detection.
# ---------------------------------------------------------------------------

class TestRequestCarriesAuth:

    def test_authorization_header(self) -> None:
        assert request_carries_auth(
            [("Authorization", "Bearer abc")], 200,
        ) is True

    def test_authorization_header_empty_value_is_not_auth(self) -> None:
        assert request_carries_auth(
            [("Authorization", "  ")], 200,
        ) is False

    def test_session_cookie(self) -> None:
        assert request_carries_auth(
            [("Cookie", "session=abc; theme=dark")], 200,
        ) is True

    def test_non_session_cookie_only(self) -> None:
        assert request_carries_auth(
            [("Cookie", "_ga=GA1.1.x; theme=dark")], 200,
        ) is False

    def test_401_response_marks_auth_required(self) -> None:
        assert request_carries_auth([], 401) is True

    def test_403_does_not_mark_auth_required(self) -> None:
        # Deliberate: 403 means "you're identified but lack
        # permission" — different signal.
        assert request_carries_auth([], 403) is False

    def test_no_signals(self) -> None:
        assert request_carries_auth([("X-Foo", "bar")], 200) is False

    def test_malformed_cookie_does_not_raise(self) -> None:
        assert request_carries_auth(
            [("Cookie", "this-is-just-a-token-no-equals")], 200,
        ) is False


# ---------------------------------------------------------------------------
# 6) interest_level four-tuple.
# ---------------------------------------------------------------------------

class TestInterestLevel:

    def test_all_three_signals(self) -> None:
        r = _row(
            method="POST", resp_ct="application/json", status=200,
            extra_req_headers=(("Authorization", "Bearer x"),),
        )
        m, c, a, mean = interest_level(r)
        assert (m, c, a) == (1.0, 1.0, 1.0)
        assert mean == pytest.approx(1.0)

    def test_no_signals(self) -> None:
        r = _row(method="GET", resp_ct="application/octet-stream")
        m, c, a, mean = interest_level(r)
        assert (m, c, a) == (0.0, 0.0, 0.0)
        assert mean == pytest.approx(0.0)

    def test_only_method(self) -> None:
        r = _row(method="DELETE", resp_ct="image/png")
        m, c, a, mean = interest_level(r)
        assert m == 1.0 and c == 0.0 and a == 0.0
        assert mean == pytest.approx(1 / 3)

    def test_only_content_type(self) -> None:
        r = _row(method="GET", resp_ct="text/html; charset=utf-8")
        m, c, a, _ = interest_level(r)
        assert m == 0.0 and c == 1.0 and a == 0.0

    def test_json_with_suffix(self) -> None:
        r = _row(method="GET", resp_ct="application/vnd.api+json")
        _, c, _, _ = interest_level(r)
        assert c == 1.0

    def test_session_cookie_marks_auth(self) -> None:
        r = _row(
            method="GET", resp_ct="text/plain",
            extra_req_headers=(("Cookie", "JSESSIONID=xyz"),),
        )
        _, _, a, _ = interest_level(r)
        assert a == 1.0

    def test_malformed_row_returns_zeros(self) -> None:
        class Broken:
            method = "GET"
            status = 200
            req_blob = b"not-http"
            resp_blob = b"also-not-http"
        m, c, a, mean = interest_level(Broken())
        assert (m, c, a, mean) == (0.0, 0.0, 0.0, 0.0)


# ---------------------------------------------------------------------------
# 7) insertion_point_keys.
# ---------------------------------------------------------------------------

class TestInsertionPointKeys:

    def test_query_params_yield_keys(self) -> None:
        r = _row(url="https://x.y/?a=1&b=2")
        keys = insertion_point_keys(r)
        names = {n for _, _, n in keys}
        assert {"a", "b"}.issubset(names)

    def test_host_is_part_of_key(self) -> None:
        a = _row(host="a.x", url="https://a.x/?q=1")
        b = _row(host="b.x", url="https://b.x/?q=1")
        assert insertion_point_keys(a) != insertion_point_keys(b)

    def test_empty_row(self) -> None:
        # Even a bare GET has at least the path-filename insertion point,
        # so just check we don't crash and return a set.
        r = _row(url="https://x.y/")
        out = insertion_point_keys(r)
        assert isinstance(out, set)

    def test_malformed_request_blob_does_not_crash(self) -> None:
        # The blob parser (_split_http) is deliberately tolerant —
        # missing headers/body just yield empty headers and the whole
        # input as body — so insertion_point_keys never raises and
        # still surfaces any insertion points reachable from the URL
        # alone (e.g. query parameters).
        class Broken:
            host = "x.y"
            method = "GET"
            url = "https://x.y/"  # no query → URL contributes nothing
            req_blob = None       # missing blob → empty after coalesce
        out = insertion_point_keys(Broken())
        assert isinstance(out, set)
        # path-filename insertion point may exist for "/" depending on
        # iter_insertion_points; the contract is "set, no crash" only.


# ---------------------------------------------------------------------------
# 8) score_row with already-audited set.
# ---------------------------------------------------------------------------

class TestScoreRow:

    def test_novelty_drops_when_audited(self) -> None:
        r = _row(url="https://x.y/?a=1&b=2")
        before = score_row(r)
        # Audit one of the row's keys.
        audited = {next(iter(insertion_point_keys(r)))}
        after = score_row(r, already_audited=audited)
        assert after.surface_novelty == before.surface_novelty - 1
        assert after.surface_total == before.surface_total

    def test_score_starts_zero_before_normalisation(self) -> None:
        r = _row(method="POST", url="https://x.y/?a=1")
        assert score_row(r).score == 0.0

    def test_interest_populated(self) -> None:
        r = _row(method="POST", resp_ct="application/json")
        rs = score_row(r)
        assert rs.interest > 0.0

    def test_history_id_preserved(self) -> None:
        r = _row(rid=42, url="https://x.y/")
        assert score_row(r).history_id == 42

    def test_novelty_ratio(self) -> None:
        r = _row(url="https://x.y/?a=1&b=2")
        rs = score_row(r)
        # Without an audited set, novelty == total → ratio == 1.0.
        if rs.surface_total > 0:
            assert rs.novelty_ratio == 1.0
        else:
            assert rs.novelty_ratio == 0.0

    def test_novelty_ratio_zero_when_no_ips(self) -> None:
        rs = RowScore(
            history_id=1, surface_novelty=0, surface_total=0,
            method_score=0.0, content_type_score=0.0, auth_score=0.0,
            interest=0.0,
        )
        assert rs.novelty_ratio == 0.0


# ---------------------------------------------------------------------------
# 9) prioritise_queue default mode.
# ---------------------------------------------------------------------------

class TestPrioritiseQueueDefault:

    def test_empty_input(self) -> None:
        assert prioritise_queue([]) == []

    def test_high_interest_beats_low(self) -> None:
        boring = _row(rid=1, url="https://x.y/static/logo.png",
                      method="GET", resp_ct="image/png")
        interesting = _row(
            rid=2, url="https://x.y/api/users?id=1",
            method="POST", resp_ct="application/json",
            extra_req_headers=(("Authorization", "Bearer x"),),
        )
        ranked = prioritise_queue([boring, interesting])
        assert ranked[0][0].id == 2
        assert ranked[1][0].id == 1

    def test_ties_broken_by_id_ascending(self) -> None:
        # Two identical rows: lower id wins.
        a = _row(rid=10, url="https://x.y/?q=1")
        b = _row(rid=20, url="https://x.y/?q=1")
        ranked = prioritise_queue([b, a])
        assert [r.id for r, _ in ranked] == [10, 20]

    def test_already_audited_demotes_novelty(self) -> None:
        # Row A introduces three new params; row B reuses all of them.
        a = _row(rid=1, host="x.y", url="https://x.y/?p=1&q=2&r=3")
        b = _row(rid=2, host="x.y", url="https://x.y/?p=4&q=5&r=6")
        ranked = prioritise_queue([a, b])
        # Without audited set, a (lower id) ties on novelty and wins.
        assert ranked[0][0].id == 1
        # If we pretend a was already audited, b becomes novel.
        ranked2 = prioritise_queue(
            [b], already_audited=insertion_point_keys(a),
        )
        # b reuses a's surface entirely → novelty 0.
        assert ranked2[0][1].surface_novelty == 0

    def test_pure_interest_ordering_when_surface_weight_zero(self) -> None:
        boring = _row(rid=1, url="https://x.y/?same=v",
                      method="GET", resp_ct="image/png")
        interesting = _row(
            rid=2, url="https://x.y/?same=v",
            method="POST", resp_ct="text/html",
        )
        ranked = prioritise_queue(
            [boring, interesting],
            weights=ScoringWeights(surface=0.0, interest=1.0),
        )
        assert ranked[0][0].id == 2

    def test_pure_surface_ordering_when_interest_weight_zero(self) -> None:
        # Few-param GET vs many-param POST: surface-only weighting
        # should prefer the row with more novel insertion points.
        few = _row(rid=1, method="POST", url="https://x.y/?a=1")
        many = _row(rid=2, method="GET",
                    url="https://x.y/?a=1&b=2&c=3&d=4&e=5")
        ranked = prioritise_queue(
            [few, many],
            weights=ScoringWeights(surface=1.0, interest=0.0),
        )
        assert ranked[0][0].id == 2


# ---------------------------------------------------------------------------
# 10) prioritise_queue incremental mode.
# ---------------------------------------------------------------------------

class TestPrioritiseQueueIncremental:

    def test_recompute_drops_redundant_row(self) -> None:
        # Three rows. a, b share surface {p, q}; c brings a fresh
        # 'different' param. With default 0.8/0.2 weights and
        # one-pass scoring, a wins the first pick (highest surface
        # tied with b; lowest id wins). After a is audited, b's
        # remaining novelty collapses to zero, so c — which still
        # contributes brand-new surface — gets promoted ahead of b
        # by the recompute pass.
        a = _row(rid=1, host="x.y", url="https://x.y/?p=1&q=2")
        b = _row(rid=2, host="x.y", url="https://x.y/?p=3&q=4")
        c = _row(rid=3, host="x.y", url="https://x.y/?different=1",
                 method="POST", resp_ct="application/json")
        ranked = prioritise_queue(
            [a, b, c], recompute_after_row=True,
        )
        ids = [r.id for r, _ in ranked]
        assert ids[0] == 1  # a wins on surface (tie-break: lowest id)
        assert ids[1] == 3  # c jumps b because b's surface is now redundant
        assert ids[2] == 2  # b last: zero novel surface remains

    def test_single_row_no_recompute_needed(self) -> None:
        r = _row(rid=1, url="https://x.y/")
        ranked = prioritise_queue([r], recompute_after_row=True)
        assert [x.id for x, _ in ranked] == [1]


# ---------------------------------------------------------------------------
# 11) ActiveScanner.run_on_project integration.
# ---------------------------------------------------------------------------

class _ScanProj:
    """Minimal project stub with the surface ActiveScanner needs."""

    def __init__(self, rows):
        self._rows = list(rows)

    def list_history(self, *, limit, host=None):
        del limit, host
        return list(self._rows)

    def list_scope(self):
        return []

    def record_rule_run(self, **_kw):
        pass


class _RecordingCheck:
    """Active check that just records the row id it was invoked with."""

    from reqlore.scanner.rules import RuleMeta as _RM

    meta = _RM(
        id="active:probe", intensity="light",
        title="probe", default_severity="info",
    )
    name = "probe"
    description = "probe"

    def __init__(self, log: list[int]) -> None:
        self._log = log

    def run(self, ctx, send, opts=None):
        del send, opts
        self._log.append(int(ctx.history_id))
        return iter([])


class TestScannerIntegration:

    def test_prioritise_false_preserves_id_desc_order(self) -> None:
        rows = [
            _row(rid=1, url="https://x.y/?a=1"),
            _row(rid=2, url="https://x.y/?a=1&b=2"),
            _row(rid=3, url="https://x.y/?a=1&b=2&c=3",
                 method="POST", resp_ct="application/json"),
        ]
        log: list[int] = []
        scanner = ActiveScanner(
            checks=[_RecordingCheck(log)], sender=lambda req: None,
        )
        opts = ActiveOptions(
            enabled_checks=["probe"], prioritise=False,
        )
        result = scanner.run_on_project(_ScanProj(rows), options=opts)
        assert result.prioritised is False
        # When prioritise=False the order matches list_history's
        # output verbatim (test stub returns rows in id-asc here).
        assert log == [1, 2, 3]

    def test_prioritise_true_reorders_by_score(self) -> None:
        # Row 2 is high-interest (POST + JSON + auth) so should
        # be audited first when prioritise=True.
        rows = [
            _row(rid=1, url="https://x.y/static.png",
                 method="GET", resp_ct="image/png"),
            _row(rid=2, url="https://x.y/api?id=1&name=jane",
                 method="POST", resp_ct="application/json",
                 extra_req_headers=(("Authorization", "Bearer x"),)),
            _row(rid=3, url="https://x.y/about",
                 method="GET", resp_ct="text/html"),
        ]
        log: list[int] = []
        scanner = ActiveScanner(
            checks=[_RecordingCheck(log)], sender=lambda req: None,
        )
        opts = ActiveOptions(
            enabled_checks=["probe"], prioritise=True,
        )
        result = scanner.run_on_project(_ScanProj(rows), options=opts)
        assert result.prioritised is True
        assert log[0] == 2
        assert result.top_history_id == 2
        assert result.top_score > 0.0

    def test_prioritise_handles_empty_history(self) -> None:
        scanner = ActiveScanner(checks=[], sender=lambda req: None)
        opts = ActiveOptions(prioritise=True)
        result = scanner.run_on_project(_ScanProj([]), options=opts)
        # No rows → prioritised flag stays True (the queue was
        # built, just empty), top_score stays 0.
        assert result.prioritised is True
        assert result.top_history_id == 0
        assert result.top_score == 0.0

    def test_prioritise_recompute_runs(self) -> None:
        rows = [
            _row(rid=1, url="https://x.y/?p=1"),
            _row(rid=2, url="https://x.y/?p=2", method="POST",
                 resp_ct="application/json"),
        ]
        log: list[int] = []
        scanner = ActiveScanner(
            checks=[_RecordingCheck(log)], sender=lambda req: None,
        )
        opts = ActiveOptions(
            enabled_checks=["probe"],
            prioritise=True,
            prioritise_recompute_after_row=True,
        )
        result = scanner.run_on_project(_ScanProj(rows), options=opts)
        assert result.prioritised is True
        # POST/JSON row wins first.
        assert log[0] == 2


# ---------------------------------------------------------------------------
# 12) ActiveOptions validation.
# ---------------------------------------------------------------------------

class TestActiveOptionsValidation:

    def test_negative_surface_weight_rejected(self) -> None:
        with pytest.raises(ValueError):
            ActiveOptions(surface_weight=-0.1)

    def test_negative_interest_weight_rejected(self) -> None:
        with pytest.raises(ValueError):
            ActiveOptions(interest_weight=-0.1)

    def test_zero_weights_with_prioritise_rejected(self) -> None:
        with pytest.raises(ValueError):
            ActiveOptions(
                prioritise=True,
                surface_weight=0.0, interest_weight=0.0,
            )

    def test_zero_weights_without_prioritise_allowed(self) -> None:
        # Doesn't matter what the weights are if prioritise=False —
        # the scoring code never runs. Should construct cleanly.
        ActiveOptions(
            prioritise=False,
            surface_weight=0.0, interest_weight=0.0,
        )


# ---------------------------------------------------------------------------
# 13) /scanner/priority-preview Flask route.
# ---------------------------------------------------------------------------

def _make_app_with_project(tmp_path: Path) -> tuple:
    """Build a minimal Flask app wired up to a real Project."""
    from reqlore.config import Settings
    from reqlore.web import create_app
    project_path = tmp_path / "preview.rlr"
    proj = Project(project_path)
    # Seed two distinct rows so the preview has something to score.
    proj.add_history(
        host="x.y", method="POST", url="https://x.y/api/users?id=1",
        status=200, duration_ms=1, engine="test",
        raw_req=(b"POST /api/users?id=1 HTTP/1.1\r\n"
                 b"Host: x.y\r\n"
                 b"Authorization: Bearer x\r\n\r\n"),
        raw_resp=(b"HTTP/1.1 200 OK\r\n"
                  b"Content-Type: application/json\r\n\r\n"),
    )
    proj.add_history(
        host="x.y", method="GET", url="https://x.y/static/logo.png",
        status=200, duration_ms=1, engine="test",
        raw_req=b"GET /static/logo.png HTTP/1.1\r\nHost: x.y\r\n\r\n",
        raw_resp=(b"HTTP/1.1 200 OK\r\n"
                  b"Content-Type: image/png\r\n\r\n"),
    )
    app = create_app(project_path, Settings(), proxy=None)
    app.config["TESTING"] = True
    return app, proj


class TestPriorityPreviewRoute:

    def test_renders_when_history_present(self, tmp_path: Path) -> None:
        app, _ = _make_app_with_project(tmp_path)
        client = app.test_client()
        r = client.get("/scanner/priority-preview")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert "Audit priority preview" in body
        # POST row should appear ahead of the image row.
        assert body.index("api/users") < body.index("logo.png")

    def test_renders_when_history_empty(self, tmp_path: Path) -> None:
        from reqlore.config import Settings
        from reqlore.web import create_app
        project_path = tmp_path / "empty.rlr"
        Project(project_path)  # ensure file exists
        app = create_app(project_path, Settings(), proxy=None)
        app.config["TESTING"] = True
        r = app.test_client().get("/scanner/priority-preview")
        assert r.status_code == 200
        assert "No history rows" in r.get_data(as_text=True)

    def test_invalid_weights_falls_back_to_default(
        self, tmp_path: Path,
    ) -> None:
        app, _ = _make_app_with_project(tmp_path)
        client = app.test_client()
        r = client.get(
            "/scanner/priority-preview"
            "?surface_weight=-1&interest_weight=0.5"
        )
        # Negative weight rejected by ScoringWeights → flashes err
        # and falls back to defaults; page still renders 200.
        assert r.status_code == 200

    def test_host_filter_passed_through(self, tmp_path: Path) -> None:
        app, _ = _make_app_with_project(tmp_path)
        client = app.test_client()
        r = client.get(
            "/scanner/priority-preview?host=x.y&limit=50&top=5"
        )
        assert r.status_code == 200

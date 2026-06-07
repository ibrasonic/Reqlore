"""Phase 7 — importers + param miner + intruder engines + scheduler + update check."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from weblore.config import Settings
from weblore.engines import Request, Response
from weblore.har import (
    HARImportResult, build_request_blob, build_response_blob,
    import_har_data, import_har_file, parse_har,
)
from weblore.param_miner import DEFAULT_WORDS, MineOptions, mine
from weblore.scheduler import Scheduler, ScheduledJob, _deserialise, _serialise
from weblore.storage import Project
from weblore.update_check import UpdateInfo, _parse_version
from weblore.web import create_app


# ---- HAR importer ----

def _sample_har() -> dict:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "0"},
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 12,
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/api/items?n=1",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Accept", "value": "application/json"},
                        ],
                        "queryString": [{"name": "n", "value": "1"}],
                        "cookies": [],
                        "headersSize": -1, "bodySize": 0,
                    },
                    "response": {
                        "status": 200, "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "cookies": [],
                        "content": {"size": 12, "mimeType": "application/json",
                                     "text": '{"items":[]}'},
                        "redirectURL": "", "headersSize": -1, "bodySize": 12,
                    },
                    "cache": {}, "timings": {"send": 1, "wait": 10, "receive": 1},
                },
                {
                    "startedDateTime": "2026-01-01T00:00:01Z",
                    "time": 33,
                    "request": {
                        "method": "POST",
                        "url": "https://example.test/api/login",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type",
                             "value": "application/x-www-form-urlencoded"},
                        ],
                        "queryString": [],
                        "postData": {"mimeType": "application/x-www-form-urlencoded",
                                       "text": "u=a&p=b"},
                        "cookies": [], "headersSize": -1, "bodySize": 7,
                    },
                    "response": {
                        "status": 302, "statusText": "Found",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Location", "value": "/"},
                            {"name": "Set-Cookie", "value": "s=1"},
                        ],
                        "cookies": [],
                        "content": {"size": 0, "mimeType": "text/plain", "text": ""},
                        "redirectURL": "/", "headersSize": -1, "bodySize": 0,
                    },
                    "cache": {}, "timings": {"send": 1, "wait": 31, "receive": 1},
                },
            ],
        }
    }


def test_har_parse_rejects_garbage():
    with pytest.raises(ValueError):
        parse_har('{"not": "har"}')


def test_har_build_request_blob_adds_host_when_missing():
    blob = build_request_blob("GET", "https://x.test/a?n=1", "HTTP/1.1",
                              [("Accept", "*/*")], b"")
    text = blob.decode("latin-1")
    assert text.startswith("GET /a?n=1 HTTP/1.1\r\n")
    assert "Host: x.test\r\n" in text
    assert "Accept: */*\r\n" in text


def test_har_build_response_blob_terminator():
    blob = build_response_blob(200, "OK", "HTTP/1.1",
                                [("Content-Type", "text/plain")], b"hi")
    assert blob.endswith(b"\r\nhi")


def test_har_import_round_trip(tmp_path: Path):
    project = Project(tmp_path / "har.weblore")
    try:
        result = import_har_data(project, _sample_har())
        assert isinstance(result, HARImportResult)
        assert result.entries_seen == 2
        assert result.entries_imported == 2
        assert result.entries_skipped == 0
        rows = project.list_history(limit=10)
        assert len(rows) == 2
        statuses = sorted(r.status for r in rows)
        assert statuses == [200, 302]
        hosts = {r.host for r in rows}
        assert hosts == {"example.test"}
        engines = {r.engine for r in rows}
        assert engines == {"har"}
    finally:
        project.close()


def test_har_import_file_wrapper(tmp_path: Path):
    project = Project(tmp_path / "harf.weblore")
    try:
        har_path = tmp_path / "session.har"
        har_path.write_text(json.dumps(_sample_har()), encoding="utf-8")
        result = import_har_file(project, har_path)
        assert result.entries_imported == 2
    finally:
        project.close()


# ---- Param miner ----

def test_param_miner_detects_reflected_sentinel():
    seen = {}

    def fake_send(req: Request) -> Response:
        # Baseline request has no extra param, probes carry sentinel; we reflect
        # the sentinel only when the candidate name is "debug".
        if "debug=" in (req.url or ""):
            tail = req.url.split("debug=", 1)[1]
            sentinel = tail.split("&", 1)[0]
            return Response(status=200, headers=[],
                            body=("hello " + sentinel).encode())
        return Response(status=200, headers=[], body=b"hello")

    opts = MineOptions(location="query", max_words=20)
    result = mine("https://example.test/", words=list(DEFAULT_WORDS),
                   options=opts, send=fake_send)
    names = [hp.name for hp in result.found]
    assert "debug" in names
    hp = [h for h in result.found if h.name == "debug"][0]
    assert "sentinel reflected" in hp.evidence


def test_param_miner_detects_status_difference():
    def fake_send(req: Request) -> Response:
        if "admin=" in (req.url or ""):
            return Response(status=403, headers=[], body=b"forbidden")
        return Response(status=200, headers=[], body=b"hello")

    opts = MineOptions(location="query", max_words=10)
    result = mine("https://example.test/", words=list(DEFAULT_WORDS),
                   options=opts, send=fake_send)
    names = [hp.name for hp in result.found]
    assert "admin" in names


def test_param_miner_body_location_uses_form_body():
    def fake_send(req: Request) -> Response:
        # When location=body the baseline has no body, probes have form bytes.
        # Echo the sentinel back so the miner detects it via reflection.
        if req.body and b"debug=" in req.body:
            sentinel = req.body.split(b"debug=", 1)[1]
            return Response(status=200, headers=[], body=b"saw " + sentinel)
        return Response(status=200, headers=[], body=b"baseline")

    opts = MineOptions(location="body", method="POST", max_words=5)
    result = mine("https://example.test/api", words=list(DEFAULT_WORDS),
                   options=opts, send=fake_send)
    assert any(h.name == "debug" for h in result.found)


# ---- Intruder engine factory ----

def test_intruder_send_factory_picks_h3(monkeypatch):
    from weblore import intruder

    calls = {}

    def fake_h3_send(req, *, timeout):
        calls["h3"] = (req.url, timeout)
        return Response(status=200, headers=[], body=b"h3-ok")

    monkeypatch.setattr(intruder.h3_engine, "send", fake_h3_send)
    send = intruder._send_factory("h3", intruder.AttackOptions(timeout=4.0))
    resp = send(Request(method="GET", url="https://x.test/", headers=[], body=b""))
    assert resp.body == b"h3-ok"
    assert calls["h3"][0] == "https://x.test/"
    assert calls["h3"][1] == 4.0


def test_intruder_send_factory_picks_curl_cffi_profile(monkeypatch):
    from weblore import intruder

    captured = {}

    def fake_cc_send(req, *, profile, timeout, follow_redirects):
        captured["profile"] = profile
        return Response(status=200, headers=[], body=b"cc-ok")

    monkeypatch.setattr(intruder.curl_cffi_engine, "send", fake_cc_send)
    send = intruder._send_factory("curl-cffi:safari17_0",
                                   intruder.AttackOptions(timeout=2.0))
    send(Request(method="GET", url="https://x.test/", headers=[], body=b""))
    assert captured["profile"] == "safari17_0"


# ---- Scheduler ----

def test_scheduler_add_remove_persists(tmp_path: Path):
    project = Project(tmp_path / "sched.weblore")
    try:
        s = Scheduler(project)
        s.add_job(name="hourly", interval_s=60, scan_limit=5)
        assert [j.name for j in s.list_jobs()] == ["hourly"]
        # Persistence: a new Scheduler over the same project sees the job.
        s2 = Scheduler(project)
        assert [j.name for j in s2.list_jobs()] == ["hourly"]
        s2.remove_job("hourly")
        assert s2.list_jobs() == []
    finally:
        project.close()


def test_scheduler_rejects_tiny_interval(tmp_path: Path):
    project = Project(tmp_path / "tiny.weblore")
    try:
        s = Scheduler(project)
        with pytest.raises(ValueError):
            s.add_job(name="x", interval_s=5)
    finally:
        project.close()


def test_scheduler_run_now_invokes_scanner(tmp_path: Path):
    project = Project(tmp_path / "rnow.weblore")
    try:
        s = Scheduler(project)
        s.add_job(name="oneshot", interval_s=60, scan_limit=1)
        n = s.run_now("oneshot")
        # No history rows so findings_added should be 0 but the call must succeed.
        assert n == 0
        jobs = {j.name: j for j in s.list_jobs()}
        assert jobs["oneshot"].last_run_ts > 0
    finally:
        project.close()


def test_scheduler_serialise_round_trip():
    jobs = [ScheduledJob(name="a", interval_s=60, scan_limit=5),
            ScheduledJob(name="b", interval_s=120, scan_limit=10, enabled=False)]
    raw = _serialise(jobs)
    back = _deserialise(raw)
    assert [j.name for j in back] == ["a", "b"]
    assert back[1].enabled is False


# ---- Update check ----

def test_update_check_version_parser():
    assert _parse_version("0.1.0") == (0, 1, 0)
    assert _parse_version("1.10.2") == (1, 10, 2)
    assert _parse_version("2.0.0") > _parse_version("1.99.99")


def test_update_check_handles_unreachable_url():
    from weblore.update_check import check
    info = check("http://127.0.0.1:1/never", timeout_s=0.5)
    assert info.error is not None
    assert info.update_available is False


# ---- Smoke: new routes exist ----

@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "p7.weblore", Settings(), proxy=None)


def test_new_routes_render(app):
    client = app.test_client()
    for path in ("/param-miner/", "/schedule/", "/settings/"):
        r = client.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"


def test_intruder_form_lists_h3_and_curl_cffi(app):
    r = app.test_client().get("/intruder/new")
    assert r.status_code == 200
    html = r.data.decode("utf-8", errors="replace")
    assert 'value="h3"' in html
    assert 'value="curl-cffi:chrome120"' in html
    assert 'value="curl-cffi:safari17_0"' in html


def test_settings_has_update_check_toggle(app):
    r = app.test_client().get("/settings/")
    assert r.status_code == 200
    assert b'name="update_check"' in r.data

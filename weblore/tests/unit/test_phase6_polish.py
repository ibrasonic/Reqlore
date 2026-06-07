"""Phase 6 — polish & integration tests."""
from __future__ import annotations

import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from weblore.config import Settings
from weblore.engines import Response
from weblore.oast import Interaction, LocalOAST
from weblore.scanner import ActiveOptions, ActiveScanner
from weblore.scanner.active import OASTSSRFCheck
from weblore.web import create_app


# ---- Repeater engine select ----

@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "p6.weblore", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def test_repeater_form_lists_h3_and_curl_cffi(client):
    r = client.get("/repeater/")
    assert r.status_code == 200
    html = r.data.decode("utf-8", errors="replace")
    for opt in ('value="h3"',
                'value="curl-cffi:chrome120"',
                'value="curl-cffi:safari17_0"',
                'value="curl-cffi:firefox109"'):
        assert opt in html, f"missing engine option {opt}"


# ---- Plugin copy_as wiring ----

_COPY_AS_PLUGIN = textwrap.dedent('''
    PLUGIN_INFO = {"name": "fake-copy-as", "version": "0.0.1",
                   "description": "test plugin"}

    class _Renderer:
        name = "as-curl"
        def render(self, req_blob: bytes) -> str:
            return "curl 'fake'"

    def copy_as():
        return [_Renderer()]
''')


def test_active_copy_as_flattens_handlers(tmp_path: Path):
    from weblore.plugins import PluginRegistry

    plug_dir = tmp_path / "plugs"
    plug_dir.mkdir()
    (plug_dir / "fake_copy_as.py").write_text(_COPY_AS_PLUGIN, encoding="utf-8")

    reg = PluginRegistry([plug_dir])
    reg.discover()
    names = [h.name for h in reg.active_copy_as()]
    assert "as-curl" in names


def test_history_copy_as_route_renders_plugin_output(app, tmp_path: Path, monkeypatch):
    from weblore.plugins import PluginRegistry
    from weblore.web.blueprints import history as history_bp

    plug_dir = tmp_path / "plugs2"
    plug_dir.mkdir()
    (plug_dir / "fake_copy_as.py").write_text(_COPY_AS_PLUGIN, encoding="utf-8")
    reg = PluginRegistry([plug_dir])
    reg.discover()
    monkeypatch.setattr(history_bp, "get_registry", lambda: reg)

    project = app.extensions["weblore_project"]
    hid = project.add_history(
        host="x.test", method="GET", url="https://x.test/",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\nok",
    )
    client = app.test_client()
    r = client.get(f"/history/{hid}/copy-as/as-curl")
    assert r.status_code == 200
    assert r.data == b"curl 'fake'"
    assert r.mimetype == "text/plain"


def test_history_copy_as_404_for_unknown_handler(app):
    project = app.extensions["weblore_project"]
    hid = project.add_history(
        host="x.test", method="GET", url="https://x.test/",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\nok",
    )
    client = app.test_client()
    r = client.get(f"/history/{hid}/copy-as/no-such-handler")
    assert r.status_code == 404


# ---- OAST-SSRF cross-flow ----

@dataclass
class _Row:
    id: int = 1
    host: str = "x.test"
    url: str = "https://x.test/?u=orig"
    method: str = "GET"
    status: int = 200
    req_blob: bytes = b"GET /?u=orig HTTP/1.1\r\nHost: x.test\r\n\r\n"
    resp_blob: bytes = b"HTTP/1.1 200 OK\r\n\r\nok"


def test_oast_ssrf_fires_when_receiver_records_token():
    import urllib.parse as up
    oast = LocalOAST(host="127.0.0.1", port=0)
    oast.start()
    try:
        def fake_send(req):
            decoded = up.unquote(req.url)
            base = oast.base_url() + "/"
            if base in decoded:
                tail = decoded.split(base, 1)[1]
                tok = tail.split("/", 1)[0]
                oast.record(Interaction(
                    ts_ms=int(time.time() * 1000),
                    token=tok, kind="http", remote="127.0.0.1",
                    method="GET", path="/" + tail,
                    headers=[], body="", body_is_b64=False, bytes_in=0,
                ))
            return Response(status=200, headers=[], body=b"ok")

        scanner = ActiveScanner(checks=[OASTSSRFCheck()], sender=fake_send)
        opts = ActiveOptions(oast=oast, oast_wait_s=1.0)
        findings = scanner.run_on_row(_Row(), options=opts)
        assert any(f.title.startswith("Out-of-band callback triggered") for f in findings)
        f = [x for x in findings if x.cwe == "CWE-918"][0]
        assert f.severity == "high"
    finally:
        oast.stop()


def test_oast_ssrf_noops_without_receiver():
    def fail_send(req):
        raise AssertionError("must not send when oast is None")
    scanner = ActiveScanner(checks=[OASTSSRFCheck()], sender=fail_send)
    findings = scanner.run_on_row(_Row(), options=ActiveOptions(oast=None))
    assert findings == []

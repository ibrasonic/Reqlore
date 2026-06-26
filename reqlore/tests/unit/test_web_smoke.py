"""End-to-end smoke test for the Flask app: every blueprint returns 200."""
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    proj = tmp_path / "smoke.rlr"
    return create_app(proj, Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def test_dashboard_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Dashboard" in r.data
    assert b'<a class="skip-link" href="#main">' in r.data
    assert b'aria-live="polite"' in r.data


def test_history_empty(client):
    r = client.get("/history/")
    assert r.status_code == 200


def test_repeater_get(client):
    r = client.get("/repeater/")
    assert r.status_code == 200
    assert b"Repeater" in r.data


def test_decoder_get(client):
    r = client.get("/decoder/")
    assert r.status_code == 200
    assert b"Decoder" in r.data


def test_decoder_b64_encode(client):
    # First fetch a page to seed the CSRF session cookie
    client.get("/decoder/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/decoder/", data={
        "op": "b64_encode", "text_in": "hello", "_csrf": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"aGVsbG8=" in r.data


def test_decoder_jwt_decode(client):
    client.get("/decoder/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    jwt = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiJhbGljZSJ9."
    )
    r = client.post("/decoder/", data={
        "op": "jwt_decode", "text_in": jwt, "_csrf": token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"alice" in r.data


def test_settings_get(client):
    r = client.get("/settings/")
    assert r.status_code == 200
    assert b"Theme" in r.data
    assert b"Verbosity" in r.data


def test_help_get(client):
    r = client.get("/help/")
    assert r.status_code == 200
    assert b"Keyboard map" in r.data


def test_csp_header_present(client):
    r = client.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_csrf_required_on_post(client):
    r = client.post("/decoder/", data={"op": "b64_encode", "text_in": "x"})
    assert r.status_code == 400


def test_proxy_page_loads(client):
    r = client.get("/proxy/")
    assert r.status_code == 200
    assert b"Proxy" in r.data


def test_history_clear_deletes_all_rows(app, client):
    project = app.extensions["reqlore_project"]
    for i in range(3):
        project.add_history(
            host="x.test", method="GET", url=f"https://x.test/{i}",
            status=200, duration_ms=1, engine="httpx",
            raw_req=b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n",
            raw_resp=b"HTTP/1.1 200 OK\r\n\r\nok",
        )
    assert project.history_count() == 3

    # CSRF: seed the session, then submit the token
    client.get("/history/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/history/clear", data={"_csrf": token}, follow_redirects=True)
    assert r.status_code == 200
    assert project.history_count() == 0
    assert b"Cleared 3 history records" in r.data


def test_history_method_filter_is_strict(app, client):
    """method=POST must NOT match GET requests whose URL contains 'post'."""
    project = app.extensions["reqlore_project"]
    project.add_history(
        host="x.test", method="GET", url="https://x.test/blogposts",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET /blogposts HTTP/1.1\r\nHost: x.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\nok",
    )
    project.add_history(
        host="x.test", method="POST", url="https://x.test/login",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"POST /login HTTP/1.1\r\nHost: x.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\nok",
    )

    r = client.get("/history/?method=POST")
    assert r.status_code == 200
    body = r.data
    assert b"/login" in body
    assert b"/blogposts" not in body

    # URL search must no longer match the method column. Searching "POST"
    # should hit URLs containing "post" (blogposts) and miss POST /login.
    r = client.get("/history/?q=POST")
    assert r.status_code == 200
    body = r.data
    assert b"/blogposts" in body
    # /login appears in the form field 'value', so look specifically for the
    # rendered row cell.
    assert b'<span class="url">https://x.test/login</span>' not in body


def test_repeater_urlencode_body_button(client):
    """URL-encode body encodes form *values* but keeps '&' and outer '='
    literal so a SQLi payload pasted into one value doesn't break the
    field separators.
    """
    client.get("/repeater/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/repeater/", data={
        "_csrf": token, "action": "urlencode_body",
        "method": "POST", "url": "http://x.test/login", "engine": "httpx",
        "http_version": "1.1", "headers_text": "",
        "body": "username=' OR 1=1-- &password=anything",
    }, follow_redirects=True)
    assert r.status_code == 200
    # Outer '=' kept literal; '&' kept (but HTML-escaped to '&amp;' in the
    # textarea). Apostrophe, spaces, and the inner 1=1 '=' ARE encoded.
    assert b"username=%27+OR+1%3D1--+&amp;password=anything" in r.data


def test_repeater_urlencode_body_non_form_falls_back(client):
    """Non-form bodies (JSON) get whole-body encoding."""
    client.get("/repeater/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/repeater/", data={
        "_csrf": token, "action": "urlencode_body",
        "method": "POST", "url": "http://x.test/api", "engine": "httpx",
        "http_version": "1.1", "headers_text": "",
        "body": '{"username":"alice"}',
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"%7B%22username%22%3A%22alice%22%7D" in r.data


def test_repeater_urldecode_body_button(client):
    client.get("/repeater/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/repeater/", data={
        "_csrf": token, "action": "urldecode_body",
        "method": "POST", "url": "http://x.test/login", "engine": "httpx",
        "http_version": "1.1", "headers_text": "",
        "body": "username=%27+OR+1%3D1--+&password=anything",
    }, follow_redirects=True)
    assert r.status_code == 200
    # Apostrophe → &#39;, '&' → &amp; inside the textarea.
    assert b"username=&#39; OR 1=1-- &amp;password=anything" in r.data


def test_repeater_send_with_unreachable_host_does_not_500(client):
    """An engine error must render inline as an Error: panel, not a 500."""
    client.get("/repeater/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    # Unroutable address — should fail fast and surface the error in the UI.
    r = client.post("/repeater/", data={
        "_csrf": token, "action": "send",
        "method": "GET",
        "url": "http://127.0.0.1:1/",  # nothing listens on port 1
        "engine": "httpx", "http_version": "1.1",
        "headers_text": "", "body": "",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"<strong>Error:</strong>" in r.data


def test_repeater_send_strips_stale_content_length(client):
    """Edited body must not trigger 'Too much data for declared Content-Length'.
    The Repeater should drop Content-Length / Transfer-Encoding for any
    normalising engine and let the engine recompute them.
    """
    client.get("/repeater/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    # Headers claim 5 bytes; the body we send is much longer.
    long_body = "username=%27+OR+1%3D1--+&password=anything"
    assert len(long_body) > 5
    r = client.post("/repeater/", data={
        "_csrf": token, "action": "send",
        "method": "POST",
        "url": "http://127.0.0.1:1/",  # unreachable on purpose
        "engine": "httpx", "http_version": "1.1",
        "headers_text": "Content-Length: 5\nTransfer-Encoding: chunked",
        "body": long_body,
    }, follow_redirects=True)
    assert r.status_code == 200
    # We expect a connection error (port 1 is closed), NOT a
    # LocalProtocolError about Content-Length. The mere absence of that
    # specific text proves the framing headers were stripped.
    assert b"LocalProtocolError" not in r.data
    assert b"Content-Length" not in r.data or b"<strong>Error:</strong>" in r.data


def test_repeater_response_body_has_raw_and_decoded_views(client, monkeypatch):
    """A single toggle flips the response (headers + body) between Raw
    and URL-decoded views. Both versions are rendered server-side.
    """
    from reqlore.engines import Response, Timings
    from reqlore.web.blueprints import repeater as rep

    fake = Response(
        status=302, reason="Found",
        headers=[
            ("Content-Type", "text/plain"),
            ("Location", "https%3A%2F%2Fx.test%2Fnext%3Fa%3D1"),
        ],
        body=b"redirect=https%3A%2F%2Fx.test%2Fnext%3Fa%3D1",
        http_version="1.1", timings=Timings(total_ms=1), engine="httpx",
    )
    monkeypatch.setattr(rep.httpx_engine, "send", lambda *a, **k: fake)

    client.get("/repeater/")
    with client.session_transaction() as sess:
        token = sess.get("csrf", "")
    r = client.post("/repeater/", data={
        "_csrf": token, "action": "send",
        "method": "GET", "url": "http://x.test/", "engine": "httpx",
        "http_version": "1.1", "headers_text": "", "body": "",
    }, follow_redirects=True)
    assert r.status_code == 200
    html = r.data
    # Single toggle button is present and starts un-pressed (raw view).
    assert b"data-resp-view-toggle" in html
    assert b'aria-pressed="false"' in html
    assert b"URL-decode view" in html
    # Two regions (Headers, Body), each rendered as a single <pre>
    # block in both raw and decoded view modes \u2014 so 2 raw blocks
    # and 2 decoded blocks total. Each header is one line of the
    # form "Name: value" so screen readers don't split key and value.
    assert html.count(b'data-resp-view="raw"') == 2
    assert html.count(b'data-resp-view="decoded"') == 2
    # Raw view: status line + Name: value header + encoded body.
    assert b"HTTP/1.1 302 Found" in html
    assert b"Location: https%3A%2F%2Fx.test%2Fnext%3Fa%3D1" in html
    assert b"redirect=https%3A%2F%2Fx.test%2Fnext%3Fa%3D1" in html
    # Decoded view: unescaped Location header + body.
    assert b"Location: https://x.test/next?a=1" in html
    assert b"redirect=https://x.test/next?a=1" in html


def test_proxy_intercept_toggle_round_trips(tmp_path):
    """Intercept toggle: checkbox flips OFF<->ON, persists in project
    state, and re-applies to the proxy after app restart.
    """
    from reqlore.web import create_app

    class StubProxy:
        def __init__(self):
            self._on = False
            self._rules = []
        def is_running(self):
            return False
        def set_intercept(self, on):
            self._on = bool(on)
        def intercept_on(self):
            return self._on

    proxy = StubProxy()
    app = create_app(tmp_path / "p.rlr", Settings(), proxy=proxy)
    c = app.test_client()

    # Default OFF — unchecked checkbox, state strong shows OFF.
    r = c.get("/proxy/")
    assert r.status_code == 200
    assert b"Intercept" in r.data
    assert b'type="checkbox"' in r.data
    assert b'name="on"' in r.data
    assert b">OFF<" in r.data

    with c.session_transaction() as sess:
        token = sess.get("csrf", "")

    # Check the box (simulate auto-submit with from=checkbox marker).
    r = c.post("/proxy/intercept/toggle",
               data={"_csrf": token, "from": "checkbox", "on": "1"})
    assert r.status_code in (302, 303)
    assert proxy.intercept_on() is True

    r = c.get("/proxy/")
    assert b">ON<" in r.data
    assert b"checked" in r.data

    # Persistence: a fresh app over the same project restores it.
    proxy2 = StubProxy()
    app2 = create_app(tmp_path / "p.rlr", Settings(), proxy=proxy2)
    assert proxy2.intercept_on() is True
    r = app2.test_client().get("/proxy/")
    assert b">ON<" in r.data
    assert b"checked" in r.data

    # Uncheck the box (no `on` field submitted, but `from=checkbox` is).
    r = c.post("/proxy/intercept/toggle",
               data={"_csrf": token, "from": "checkbox"})
    assert r.status_code in (302, 303)
    assert proxy.intercept_on() is False


def test_proxy_controller_set_intercept_mutates_in_place(tmp_path):
    """The running mitmproxy addon holds a reference to controller.rules.
    set_intercept() must mutate that list in place — re-binding would
    leave the addon stuck on the old empty list, and nothing would hold.
    """
    from reqlore.proxy.mitm import ProxyController
    from reqlore.storage import Project

    proj = Project(tmp_path / "ictl.rlr")
    ctl = ProxyController(proj, "127.0.0.1", 0, tmp_path / "ca")
    addon_view = ctl.rules  # what the addon would capture at start()

    assert addon_view == []
    ctl.set_intercept(True)
    assert addon_view is ctl.rules, "set_intercept must NOT rebind self.rules"
    assert len(addon_view) == 1
    assert ctl.intercept_on() is True

    ctl.set_intercept(False)
    assert addon_view is ctl.rules
    assert addon_view == []
    assert ctl.intercept_on() is False


def test_proxy_addon_skips_self_ui_when_intercepting(tmp_path):
    """When intercept is ON, requests to the Reqlore UI itself must NOT
    be held — otherwise the operator's own browser tab on /proxy/ stalls
    and they can't forward or drop anything.
    """
    from reqlore.proxy.mitm import (
        _HistoryAddon, _is_self_ui, _is_self_ui_request, _host_port_from_header,
    )
    from reqlore.proxy.rules import Rule
    from reqlore.storage import Project

    # Legacy predicate covers the obvious local synonyms.
    assert _is_self_ui("127.0.0.1", 8787, 8787) is True
    assert _is_self_ui("localhost", 8787, 8787) is True
    assert _is_self_ui("::1", 8787, 8787) is True
    assert _is_self_ui("127.0.0.1", 3001, 8787) is False  # different port
    assert _is_self_ui("target.tld", 8787, 8787) is False  # different host

    # Host-header parser.
    assert _host_port_from_header("localhost:8787") == ("localhost", 8787)
    assert _host_port_from_header("127.0.0.1:8787") == ("127.0.0.1", 8787)
    assert _host_port_from_header("[::1]:8787") == ("::1", 8787)
    assert _host_port_from_header("example.com") == ("example.com", 0)

    # Full request predicate uses headers and URL as backup signals.
    class Hdrs:
        def __init__(self, d):
            self._d = {k.lower(): v for k, v in d.items()}
        def get(self, k, default=""):
            return self._d.get(k.lower(), default)
        def items(self):
            return list(self._d.items())
        def clear(self):
            self._d.clear()

    class FakeReq:
        def __init__(self, host="", port=0, headers=None, url=""):
            self.pretty_host = host
            self.port = port
            self.headers = Hdrs(headers or {})
            self.pretty_url = url
            self.method = "GET"
            self.path = "/"
            self.http_version = "HTTP/1.1"
            self.raw_content = b""
        def set_content(self, b):
            pass

    # Direct match.
    assert _is_self_ui_request(
        FakeReq(host="127.0.0.1", port=8787), 8787) is True
    # Host attribute missing but Host header gives it away.
    assert _is_self_ui_request(
        FakeReq(headers={"Host": "localhost:8787"}), 8787) is True
    # Even with weird casing.
    assert _is_self_ui_request(
        FakeReq(headers={"HOST": "LocalHost:8787"}), 8787) is True
    # URL prefix as last resort.
    assert _is_self_ui_request(
        FakeReq(url="http://127.0.0.1:8787/proxy/intercept/count"), 8787) is True
    # Different host -> not self.
    assert _is_self_ui_request(
        FakeReq(host="target.tld", port=8787,
                headers={"Host": "target.tld:8787"}), 8787) is False
    # Different port -> not self.
    assert _is_self_ui_request(
        FakeReq(host="127.0.0.1", port=3001,
                headers={"Host": "127.0.0.1:3001"}), 8787) is False

    proj = Project(tmp_path / "skip.rlr")
    rules: list[Rule] = [Rule(enabled=True, host_regex=".*")]  # catch-all
    addon = _HistoryAddon(proj, rules, sync_hold=True,
                          ui_port_fn=lambda: 8787)

    held: list[str] = []

    class FakeFlow:
        def __init__(self, host, port, host_hdr=None, url=""):
            hdrs = {"Host": host_hdr} if host_hdr else {}
            self.request = FakeReq(host=host, port=port, headers=hdrs, url=url)

    async def _fake_hold(kind, flow, raw, reason, **kw):
        held.append(flow.request.pretty_host or flow.request.pretty_url)
    addon._sync_hold = _fake_hold

    import asyncio as _asyncio

    def _run(flow):
        _asyncio.run(addon.request(flow))

    # Hit the Reqlore UI directly: must NOT be held.
    _run(FakeFlow("127.0.0.1", 8787))
    _run(FakeFlow("localhost", 8787))
    # Bypass also works when pretty_host is missing but Host header is set.
    _run(FakeFlow("", 0, host_hdr="127.0.0.1:8787",
                  url="http://127.0.0.1:8787/proxy/intercept/count"))
    assert held == []

    # A real target on a different port: MUST be held.
    _run(FakeFlow("target.tld", 80, host_hdr="target.tld"))
    assert held == ["target.tld"]


def test_proxy_intercept_forward_all_clears_pending(client, app):
    """The 'Forward all' button decides every pending intercept at once."""
    project = app.extensions["reqlore_project"]
    # Seed three pending intercepts directly via storage API.
    ids = [
        project.enqueue_intercept_sync("request", b"GET /1 HTTP/1.1\r\n\r\n", "test", "f1"),
        project.enqueue_intercept_sync("request", b"GET /2 HTTP/1.1\r\n\r\n", "test", "f2"),
        project.enqueue_intercept_sync("request", b"GET /3 HTTP/1.1\r\n\r\n", "test", "f3"),
    ]
    # Mark one as already decided so we exercise the "skip non-pending" path.
    project.decide_intercept(ids[1], "drop")

    # The UI shows the button when pending items exist (also seeds CSRF).
    r = client.get("/proxy/")
    assert r.status_code == 200
    assert b"Forward all" in r.data

    with client.session_transaction() as sess:
        token = sess.get("csrf", "")

    r = client.post("/proxy/intercept/forward_all", data={"_csrf": token},
                    follow_redirects=True)
    assert r.status_code == 200

    # Two were pending; the already-dropped one is untouched.
    assert project.get_intercept_decision(ids[0])[0] == "forward"
    assert project.get_intercept_decision(ids[1])[0] == "drop"
    assert project.get_intercept_decision(ids[2])[0] == "forward"


def test_proxy_intercept_drop_all_clears_pending(client, app):
    """The 'Drop all' button decides every pending intercept as drop."""
    project = app.extensions["reqlore_project"]
    ids = [
        project.enqueue_intercept_sync("request", b"GET /1 HTTP/1.1\r\n\r\n", "test", "d1"),
        project.enqueue_intercept_sync("request", b"GET /2 HTTP/1.1\r\n\r\n", "test", "d2"),
        project.enqueue_intercept_sync("request", b"GET /3 HTTP/1.1\r\n\r\n", "test", "d3"),
    ]
    project.decide_intercept(ids[0], "forward")

    r = client.get("/proxy/")
    assert r.status_code == 200
    assert b"Drop all" in r.data

    with client.session_transaction() as sess:
        token = sess.get("csrf", "")

    r = client.post("/proxy/intercept/drop_all", data={"_csrf": token},
                    follow_redirects=True)
    assert r.status_code == 200

    assert project.get_intercept_decision(ids[0])[0] == "forward"
    assert project.get_intercept_decision(ids[1])[0] == "drop"
    assert project.get_intercept_decision(ids[2])[0] == "drop"


def test_proxy_intercept_count_endpoint_and_watch_attrs(client, app):
    """The Proxy panel exposes a cheap JSON count for client-side polling
    and marks the queue section with data-intercept-* attrs so the
    reqlore.js poller knows when to reload.
    """
    # JSON endpoint returns 0 when nothing is held.
    r = client.get("/proxy/intercept/count")
    assert r.status_code == 200
    assert r.get_json() == {"count": 0}

    # Page is marked as not-watching when intercept is OFF.
    r = client.get("/proxy/")
    assert b'data-intercept-watch' in r.data
    assert b'data-intercept-on="0"' in r.data
    assert b'data-intercept-count="0"' in r.data
    # And no meta-refresh (we want the JS poller, not a screen-reader spam).
    assert b'http-equiv="refresh"' not in r.data


def test_intercept_config_filters_by_method_path_and_excludes():
    """The configurable filter only holds requests that match its
    method/host/path criteria AND don't hit the noise excludes.
    """
    from reqlore.proxy.rules import (
        InterceptConfig, DEFAULT_NOISE_HOST_REGEX, DEFAULT_NOISE_PATH_REGEX,
        should_hold_request,
    )

    # Default config: state-changing methods, noise excluded.
    cfg = InterceptConfig()
    rule = cfg.to_rule()

    # GET to a normal page is NOT held by default (read-only).
    assert should_hold_request([rule], "target.tld", "GET", "/") is False
    # POST IS held by default.
    assert should_hold_request([rule], "target.tld", "POST", "/login") is True
    # POST to a static asset is NOT held (path exclude).
    assert should_hold_request(
        [rule], "target.tld", "POST", "/static/app.js") is False
    # POST to a Firefox/Mozilla background host is NOT held (host exclude).
    assert should_hold_request(
        [rule], "push.services.mozilla.com", "POST", "/v1/push") is False

    # Narrowing by host: only hold target.tld.
    only_target = InterceptConfig(
        methods=["GET", "POST"], host_regex=r"^target\.tld$").to_rule()
    assert should_hold_request([only_target], "target.tld", "GET", "/") is True
    assert should_hold_request([only_target], "other.tld", "GET", "/") is False

    # Narrowing by path: only hold /api/*.
    only_api = InterceptConfig(
        methods=["GET", "POST"], path_regex=r"^/api/").to_rule()
    assert should_hold_request([only_api], "x", "GET", "/api/users") is True
    assert should_hold_request([only_api], "x", "GET", "/login") is False

    # Clearing the exclude regexes lets asset requests through. The UI
    # no longer offers a checkbox for this, but the dataclass still
    # allows programmatic callers to opt out.
    cfg_no_excl = InterceptConfig(
        methods=["GET", "POST"], exclude_host_regex="",
        exclude_path_regex="")
    rule_ne = cfg_no_excl.to_rule()
    assert should_hold_request(
        [rule_ne], "x", "GET", "/static/app.js") is True


def test_intercept_config_round_trip_and_persistence(tmp_path):
    """Saving the filter via the form survives an app restart and is
    re-applied to a fresh ProxyController on boot.
    """
    from reqlore.proxy.mitm import ProxyController
    from reqlore.proxy.rules import InterceptConfig, should_hold_request
    from reqlore.storage import Project
    from reqlore.web import create_app
    from werkzeug.datastructures import MultiDict

    proj_path = tmp_path / "icfg.rlr"
    ca_dir = tmp_path / "ca"
    ctl = ProxyController(Project(proj_path), "127.0.0.1", 0, ca_dir)
    app = create_app(proj_path, Settings(), proxy=ctl)
    client = app.test_client()

    # The Proxy panel exposes the form with the method checkboxes.
    r = client.get("/proxy/")
    assert r.status_code == 200
    assert b'name="method" value="POST"' in r.data
    # The positive / exclude host & path regex inputs have been removed
    # from the UI — they were redundant with the scope checkbox and the
    # built-in noise defaults. The backend still accepts them via POST
    # for round-trip compatibility with persisted state and external
    # callers.
    assert b'name="host_regex"' not in r.data
    assert b'name="path_regex"' not in r.data
    # The noise-skip checkbox is gone — always-on now.
    assert b'name="exclude_noise"' not in r.data

    with client.session_transaction() as sess:
        token = sess.get("csrf", "")

    r = client.post("/proxy/intercept/config", data=MultiDict([
        ("_csrf", token),
        ("method", "GET"),
        ("method", "POST"),
        ("host_regex", r"^target\.tld$"),
        ("path_regex", r"^/api/"),
    ]), follow_redirects=True)
    assert r.status_code == 200

    # State row is JSON-encoded and round-trippable into InterceptConfig.
    project = app.extensions["reqlore_project"]
    import json
    saved = json.loads(project.get_state("intercept_config"))
    cfg = InterceptConfig.from_dict(saved)
    assert cfg.methods == ["GET", "POST"]
    assert cfg.host_regex == r"^target\.tld$"
    assert cfg.path_regex == r"^/api/"
    # Excludes are still populated from defaults even when the form
    # didn't carry an exclude_noise field.
    assert cfg.exclude_host_regex
    assert cfg.exclude_path_regex

    # The live controller reflects the new config without needing a restart.
    rule_now = ctl.get_intercept_config().to_rule()
    assert should_hold_request([rule_now], "target.tld", "POST",
                               "/api/x") is True

    # A brand-new ProxyController + app over the same project picks the
    # config back up — the rule built from it must match the same way.
    ctl2 = ProxyController(Project(proj_path), "127.0.0.1", 0, ca_dir)
    create_app(proj_path, Settings(), proxy=ctl2)
    rule = ctl2.get_intercept_config().to_rule()
    assert should_hold_request([rule], "target.tld", "POST", "/api/x") is True
    assert should_hold_request([rule], "other.tld", "POST", "/api/x") is False
    assert should_hold_request([rule], "target.tld", "POST", "/login") is False


def _seed_gzip_response(project) -> int:
    import gzip
    plain = b"<html><body>Invalid username or password.</body></html>"
    body = gzip.compress(plain)
    resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    return project.add_history(
        host="x.test", method="POST", url="https://x.test/login",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"POST /login HTTP/1.1\r\nHost: x.test\r\n\r\nu=a&p=b",
        raw_resp=resp,
    )


def test_history_detail_default_decodes_compressed_body(app, client):
    """On a row with a compressed response the default view is decoded
    (so operators meet readable text, not a gzipped binary smear). The
    Body-display section still lets them flip back to raw bytes via the
    radio group.
    """
    hid = _seed_gzip_response(app.extensions["reqlore_project"])
    r = client.get(f"/history/{hid}")
    assert r.status_code == 200
    # Body-display section is rendered.
    assert b"Body display" in r.data
    assert b"Raw on-wire bytes" in r.data
    # Default view is decoded: plaintext is present.
    assert b"Invalid username or password" in r.data


def test_history_detail_raw_radio_keeps_compressed_body(app, client):
    hid = _seed_gzip_response(app.extensions["reqlore_project"])
    r = client.get(f"/history/{hid}?decode=0")
    assert r.status_code == 200
    # ?decode=0 opts out of decoding; the plaintext must not appear.
    assert b"Invalid username or password" not in r.data


def test_history_detail_decode_checkbox_reveals_plaintext(app, client):
    hid = _seed_gzip_response(app.extensions["reqlore_project"])
    r = client.get(f"/history/{hid}?decode=1")
    assert r.status_code == 200
    assert b"Invalid username or password" in r.data
    # The Content-Encoding header should be stripped from the displayed blob.
    assert b"Content-Encoding: gzip" not in r.data
    # Status note announces what was decoded.
    assert b"gzip" in r.data and b"bytes" in r.data


def test_history_detail_decode_uncompressed_hides_toggle(app, client):
    project = app.extensions["reqlore_project"]
    hid = project.add_history(
        host="x.test", method="GET", url="https://x.test/p",
        status=200, duration_ms=1, engine="httpx",
        raw_req=b"GET /p HTTP/1.1\r\nHost: x.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
    )
    # Without a Content-Encoding header the Body-display section is
    # hidden entirely \u2014 no toggle clutter on rows where it would do
    # nothing. ?decode=1 is also a no-op (idempotent URL).
    r = client.get(f"/history/{hid}?decode=1")
    assert r.status_code == 200
    assert b"hello" in r.data
    assert b"Body display" not in r.data


def test_request_only_rule_does_not_hold_responses():
    """A rule built from InterceptConfig has no response criteria — it
    must NOT match any response, otherwise the Reqlore UI's own 302
    redirects get queued the moment intercept flips ON.
    """
    from reqlore.proxy.rules import (
        InterceptConfig, Rule, should_hold_response,
    )

    rule = InterceptConfig().to_rule()  # request-only
    # Every common response status / content-type slips through.
    for status in (200, 302, 404, 500):
        for ctype in ("text/html", "application/json", "", "image/png"):
            assert should_hold_response([rule], status, ctype) is False, (
                f"request-only rule wrongly held response "
                f"status={status} ctype={ctype!r}"
            )

    # A rule that DOES have a response criterion still works normally.
    resp_rule = Rule(enabled=True, status_in=[500])
    assert should_hold_response([resp_rule], 500, "text/html") is True
    assert should_hold_response([resp_rule], 200, "text/html") is False


def test_held_flow_does_not_block_other_flows(tmp_path):
    """While one flow is parked in _sync_hold, the mitmproxy event loop
    must keep processing other flows. The hook is async and the hold
    loop awaits asyncio.sleep — a regression to time.sleep here would
    freeze every other request behind the held one (including the
    operator's own Reqlore-UI traffic), which is exactly the symptom
    that prompted this test.
    """
    import asyncio
    from reqlore.proxy.mitm import _HistoryAddon
    from reqlore.proxy.rules import InterceptConfig
    from reqlore.storage import Project

    proj = Project(tmp_path / "concurrent.rlr")
    rules = [InterceptConfig().to_rule()]  # holds POST by default
    addon = _HistoryAddon(proj, rules, sync_hold=True,
                          ui_port_fn=lambda: 8787)

    class Hdrs:
        def __init__(self, d):
            self._d = {k.lower(): v for k, v in d.items()}
        def get(self, k, default=""):
            return self._d.get(k.lower(), default)
        def items(self):
            return list(self._d.items())
        def clear(self):
            self._d.clear()

    class FakeReq:
        def __init__(self, host, port, method, path, host_hdr=None):
            self.pretty_host = host
            self.port = port
            self.method = method
            self.path = path
            self.pretty_url = f"http://{host}:{port}{path}"
            self.http_version = "HTTP/1.1"
            hdrs = {"Host": host_hdr or f"{host}:{port}"}
            self.headers = Hdrs(hdrs)
            self.raw_content = b""
        def set_content(self, b):
            pass

    class FakeFlow:
        def __init__(self, host, port, method, path, host_hdr=None):
            self.request = FakeReq(host, port, method, path, host_hdr)
        def kill(self):
            pass

    held_flow = FakeFlow("target.tld", 80, "POST", "/login")
    ui_flow = FakeFlow("127.0.0.1", 8787, "GET", "/proxy/")

    async def scenario():
        # Park a POST in the hold loop.
        hold_task = asyncio.create_task(addon.request(held_flow))
        # Give it a moment to enter _sync_hold.
        await asyncio.sleep(0.05)
        assert not hold_task.done(), "hold task should still be parked"

        # The UI request must be processed *immediately*, not behind the
        # held POST. Wrap in wait_for with a tight budget; if the event
        # loop is blocked, this raises TimeoutError.
        await asyncio.wait_for(addon.request(ui_flow), timeout=0.5)

        # Release the held flow by decisioning it.
        decided = False
        for it in proj.list_intercept():
            if proj.get_intercept_decision(it.id)[0] is None:
                proj.decide_intercept(it.id, "forward")
                decided = True
        assert decided, "expected at least one pending intercept to decide"
        await asyncio.wait_for(hold_task, timeout=2.0)

    asyncio.run(scenario())

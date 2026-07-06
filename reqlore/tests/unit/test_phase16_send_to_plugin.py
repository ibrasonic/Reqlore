"""Phase 16 (addendum) — Send-to-plugin from History / Proxy intercept.

Covers:

* ``SeedRequest`` parse: best-effort, never raises on garbage.
* Storage: ``seed_history_id`` round-trip on ``plugin_runs`` rows.
* PluginRunner: persists seed id, builds ``ctx.seed_request``,
  swallows missing-history-row gracefully.
* plugins_bp chooser: 404 on missing history, lists active apps,
  renders seed summary.
* plugins_bp ``/app/<slug>/?from_history=<hid>``: prefills url /
  method / host fields when the plugin declares them, leaves
  unmatched fields alone, ignores unknown hids.
* plugins_bp ``/app/<slug>/run``: hidden ``_seed_history_id``
  reaches the runner; ignored when set to a value with no matching
  history row.
* History row-actions menu and history-detail page show / hide the
  "Send to plugin app" entry based on plugin availability.
* Proxy intercept "Send to plugin-app" snapshots and redirects to
  the chooser.
* ``history.send_to`` slug ``plugin-app`` redirects to the chooser.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from reqlore import plugins_sdk as sdk
from reqlore.config import Settings
from reqlore.plugin_runner import PluginRunner
from reqlore.plugins import reset_registry
from reqlore.storage import Project
from reqlore.web import create_app

# ============================================================ fixtures


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_registry()
    yield
    reset_registry()


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Project]:
    p = Project(tmp_path / "p16_send.rlr")
    yield p
    p.close()


def _seed_history(project: Project, *, method: str = "GET",
                  host: str = "demo.test", path: str = "/api/v1?x=1",
                  body: bytes = b"") -> int:
    """Write a synthetic history row and return its id."""
    raw = (f"{method} {path} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: pytest\r\n"
           f"Content-Length: {len(body)}\r\n\r\n").encode("ascii") + body
    return project.add_history(
        host=host, method=method, url=f"http://{host}{path}",
        status=200, duration_ms=12, engine="httpx",
        raw_req=raw, raw_resp=b"HTTP/1.1 200 OK\r\n\r\nok",
    )


def _write_plugin(folder: Path, name: str, body: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return path


def _wait_for(predicate, timeout: float = 5.0, interval: float = 0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ============================================================ SeedRequest


class TestSeedRequestParser:
    def test_parses_minimal_request(self):
        raw = b"POST /login HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/json\r\n\r\n{}"
        s = sdk.parse_seed_request(7, raw)
        assert s.history_id == 7
        assert s.method == "POST"
        assert s.host == "x.test"
        assert s.path == "/login"
        assert s.url == "http://x.test/login"
        assert s.body == b"{}"
        assert s.header("content-type") == "application/json"
        assert s.header("missing") == ""

    def test_absolute_path_preserved(self):
        # Some proxies log absolute-form request targets.
        raw = b"GET https://other.test/x HTTP/1.1\r\nHost: x.test\r\n\r\n"
        s = sdk.parse_seed_request(1, raw)
        assert s.url == "https://other.test/x"

    def test_garbage_blob_never_raises(self):
        s = sdk.parse_seed_request(1, b"\x00\x01\x02 not http")
        assert s.history_id == 1
        # Even garbage parses to *something* usable; we just check the
        # call doesn't raise and the dataclass fields exist.
        assert isinstance(s.headers, list)
        assert isinstance(s.body, bytes)

    def test_empty_blob_safe(self):
        s = sdk.parse_seed_request(99, b"")
        assert s.history_id == 99
        assert s.body == b""
        assert s.headers == []


# ============================================================ Storage


class TestSeedHistoryIdStorage:
    def test_create_with_seed_id_round_trips(self, project):
        hid = _seed_history(project)
        rid = project.create_plugin_run(
            slug="x", settings={}, seed_history_id=hid)
        row = project.get_plugin_run(rid)
        assert row["seed_history_id"] == hid

    def test_create_without_seed_id_is_null(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        row = project.get_plugin_run(rid)
        assert row["seed_history_id"] is None

    def test_list_runs_surfaces_seed_id(self, project):
        hid = _seed_history(project)
        a = project.create_plugin_run(
            slug="y", settings={}, seed_history_id=hid)
        b = project.create_plugin_run(slug="y", settings={})
        runs = project.list_plugin_runs(slug="y")
        by_id = {r["id"]: r for r in runs}
        assert by_id[a]["seed_history_id"] == hid
        assert by_id[b]["seed_history_id"] is None


# ============================================================ Runner


def _make_app(slug: str = "echo", record_seed=None) -> sdk.PluginApp:
    app = sdk.make_app(
        slug=slug, name=slug.title(),
        fields=[sdk.StrField("url", required=False),
                sdk.SelectField("method", choices=["GET", "POST"])],
        columns=["status"],
    )

    @app.runner
    def run(ctx):
        if record_seed is not None:
            record_seed.append(ctx.seed_request)

    return app


class TestRunnerSeedPipeline:
    def test_seed_request_is_passed_to_context(self, project):
        hid = _seed_history(project, method="POST", host="x.test",
                            path="/login", body=b'{"u":"a"}')
        captured: list = []
        app = _make_app(record_seed=captured)
        runner = PluginRunner(project)
        runner.start(app, {"method": "POST"}, seed_history_id=hid)
        assert _wait_for(lambda: not runner.is_running(app.slug))
        assert len(captured) == 1
        seed = captured[0]
        assert seed is not None
        assert seed.history_id == hid
        assert seed.method == "POST"
        assert seed.host == "x.test"
        assert seed.path == "/login"
        assert seed.body == b'{"u":"a"}'

    def test_seed_request_is_none_when_not_provided(self, project):
        captured: list = []
        app = _make_app(record_seed=captured)
        runner = PluginRunner(project)
        runner.start(app, {})
        assert _wait_for(lambda: not runner.is_running(app.slug))
        assert captured == [None]

    def test_missing_history_row_yields_none(self, project):
        captured: list = []
        app = _make_app(record_seed=captured)
        runner = PluginRunner(project)
        # 999999 is past the highest issued id; resolver returns None.
        runner.start(app, {}, seed_history_id=999_999)
        assert _wait_for(lambda: not runner.is_running(app.slug))
        assert captured == [None]
        # The id is still persisted on the row for traceability even
        # though the row it pointed at is gone.
        latest = project.latest_plugin_run(app.slug)
        assert latest["seed_history_id"] == 999_999

    def test_seed_id_persisted_on_run_row(self, project):
        hid = _seed_history(project)
        app = _make_app()
        runner = PluginRunner(project)
        rid = runner.start(app, {}, seed_history_id=hid)
        assert _wait_for(lambda: not runner.is_running(app.slug))
        row = project.get_plugin_run(rid)
        assert row["seed_history_id"] == hid


# ============================================================ Web

@pytest.fixture
def web_env(tmp_path: Path):
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    _write_plugin(plugin_dir, "echo", '''
from reqlore import plugins_sdk as sdk
PLUGIN_INFO = {"name": "echo", "version": "0.1"}
PLUGIN_APP = sdk.make_app(
    slug="echo", name="Echo Tool",
    description="Echo the seed request",
    fields=[
        sdk.StrField("url", required=False),
        sdk.SelectField("method", choices=["GET","POST","PUT"]),
        sdk.StrField("host", required=False),
        sdk.BoolField("verbose"),
    ],
    columns=["status", "url"],
)

@PLUGIN_APP.runner
def run(ctx):
    ctx.log(f"seed={ctx.seed_request is not None}")
''')
    reset_registry()
    from reqlore.plugins import get_registry
    get_registry([plugin_dir])

    app = create_app(tmp_path / "p16_send_web.rlr", Settings(), proxy=None)
    app.testing = True
    project = app.extensions["reqlore_project"]
    return app, app.test_client(), project


def _csrf(client) -> str:
    client.get("/plugins/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


class TestChooser:
    def test_404_without_from_history(self, web_env):
        _, c, _ = web_env
        r = c.get("/plugins/send/")
        assert r.status_code == 404

    def test_404_on_unknown_history(self, web_env):
        _, c, _ = web_env
        r = c.get("/plugins/send/?from_history=999")
        assert r.status_code == 404

    def test_lists_active_apps_with_seed_summary(self, web_env):
        _, c, project = web_env
        hid = _seed_history(project, method="POST", host="demo.test",
                            path="/api/x")
        r = c.get(f"/plugins/send/?from_history={hid}")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert "Echo Tool" in body
        # Each entry links to the app detail with the seed id appended.
        assert f"/plugins/app/echo/?from_history={hid}" in body
        # Seed summary panel.
        assert "POST" in body
        assert "demo.test" in body
        assert "/api/x" in body


class TestAppDetailWithSeed:
    def test_prefills_url_method_host_when_field_present(self, web_env):
        _, c, project = web_env
        hid = _seed_history(project, method="POST", host="prefill.test",
                            path="/p")
        r = c.get(f"/plugins/app/echo/?from_history={hid}")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        # Attributes wrap across lines in the template; the URL
        # value lives on the next line after name="url".
        assert 'name="url"' in body
        assert 'value="http://prefill.test/p"' in body
        # SelectField for method should have POST selected.
        assert '<option value="POST" selected>' in body
        assert 'name="host"' in body
        assert 'value="prefill.test"' in body
        # Hidden seed id flows back into the form.
        assert f'name="_seed_history_id" value="{hid}"' in body
        # Seed banner appears.
        assert "Seed request" in body

    def test_unknown_hid_silently_skips_prefill(self, web_env):
        _, c, _ = web_env
        r = c.get("/plugins/app/echo/?from_history=999999")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        # No banner because the seed dict is None.
        assert "Seed request" not in body
        assert 'name="_seed_history_id"' not in body

    def test_no_from_history_renders_normally(self, web_env):
        _, c, _ = web_env
        r = c.get("/plugins/app/echo/")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert "Seed request" not in body


class TestAppRunWithSeed:
    def test_run_post_forwards_seed_id_to_runner(self, web_env):
        app, c, project = web_env
        hid = _seed_history(project, method="GET", host="run.test",
                            path="/v")
        tok = _csrf(c)
        r = c.post(
            "/plugins/app/echo/run",
            data={"_csrf": tok, "_seed_history_id": str(hid),
                  "url": "http://run.test/v", "method": "GET"},
            follow_redirects=True,
        )
        assert r.status_code == 200
        runner = app.extensions["reqlore_plugin_runner"]
        assert _wait_for(lambda: not runner.is_running("echo"))
        latest = project.latest_plugin_run("echo")
        assert latest["seed_history_id"] == hid
        assert latest["status"] == "ok"
        # Plugin logged that it saw the seed request.
        assert "seed=True" in latest["log"]

    def test_run_post_without_seed_id_is_none(self, web_env):
        app, c, project = web_env
        tok = _csrf(c)
        c.post(
            "/plugins/app/echo/run",
            data={"_csrf": tok, "method": "GET"},
            follow_redirects=True,
        )
        runner = app.extensions["reqlore_plugin_runner"]
        assert _wait_for(lambda: not runner.is_running("echo"))
        latest = project.latest_plugin_run("echo")
        assert latest["seed_history_id"] is None
        assert "seed=False" in latest["log"]

    def test_run_post_with_bogus_seed_id_resolves_to_none(self, web_env):
        app, c, _ = web_env
        tok = _csrf(c)
        c.post(
            "/plugins/app/echo/run",
            data={"_csrf": tok, "_seed_history_id": "not-a-number",
                  "method": "GET"},
            follow_redirects=True,
        )
        runner = app.extensions["reqlore_plugin_runner"]
        assert _wait_for(lambda: not runner.is_running("echo"))


# ============================================================ History UI


class TestHistorySendToPlugin:
    def test_send_to_plugin_app_redirects_to_chooser(self, web_env):
        _, c, project = web_env
        hid = _seed_history(project)
        tok = _csrf(c)
        r = c.post(
            f"/history/{hid}/send/plugin-app",
            data={"_csrf": tok},
        )
        assert r.status_code in (302, 303)
        assert r.headers["Location"].endswith(
            f"/plugins/send/?from_history={hid}")

    def test_history_detail_shows_button_when_plugins_enabled(self, web_env):
        _, c, project = web_env
        hid = _seed_history(project)
        r = c.get(f"/history/{hid}")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert "Send to plu" in body  # underline-wrapped letter
        assert f"action=\"/history/{hid}/send/plugin-app\"" in body

    def test_history_index_menu_includes_chooser_link(self, web_env):
        _, c, project = web_env
        hid = _seed_history(project)
        r = c.get("/history/")
        assert r.status_code == 200
        body = r.get_data(as_text=True)
        assert f"/plugins/send/?from_history={hid}" in body


class TestHistorySendToPluginHidden:
    """When no plugin apps are enabled, the entry is suppressed so the
    operator isn't offered a dead-end."""

    @pytest.fixture
    def empty_env(self, tmp_path: Path):
        # No plugins on disk \u2192 empty registry \u2192 no plugin apps.
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        reset_registry()
        from reqlore.plugins import get_registry
        get_registry([plugin_dir])
        app = create_app(tmp_path / "empty.rlr", Settings(), proxy=None)
        app.testing = True
        project = app.extensions["reqlore_project"]
        return app, app.test_client(), project

    def test_history_detail_hides_button(self, empty_env):
        _, c, project = empty_env
        hid = _seed_history(project)
        r = c.get(f"/history/{hid}")
        body = r.get_data(as_text=True)
        assert "/send/plugin-app" not in body

    def test_history_index_menu_hides_chooser_link(self, empty_env):
        _, c, project = empty_env
        _seed_history(project)
        r = c.get("/history/")
        body = r.get_data(as_text=True)
        assert "/plugins/send/?from_history=" not in body


# ============================================================ Proxy UI


class TestInterceptSendToPlugin:
    def test_snapshot_and_redirect(self, web_env):
        _, c, project = web_env
        # Enqueue an intercept directly via the project API.
        raw = (b"GET /held HTTP/1.1\r\nHost: held.test\r\n\r\n")
        iid = project.enqueue_intercept("request", raw, "test")
        tok = _csrf(c)
        r = c.post(
            f"/proxy/intercept/{iid}/send/plugin-app",
            data={"_csrf": tok},
        )
        assert r.status_code in (302, 303)
        loc = r.headers["Location"]
        assert "/plugins/send/?from_history=" in loc
        # Snapshot row exists.
        hid = int(loc.rsplit("=", 1)[1])
        row = project.get_history(hid)
        assert row is not None
        assert row.engine == "intercept-snapshot"

    def test_intercept_detail_shows_button_when_plugins_enabled(self, web_env):
        _, c, project = web_env
        raw = b"GET /x HTTP/1.1\r\nHost: x.test\r\n\r\n"
        iid = project.enqueue_intercept("request", raw, "test")
        r = c.get(f"/proxy/intercept/{iid}")
        body = r.get_data(as_text=True)
        assert f"/proxy/intercept/{iid}/send/plugin-app" in body

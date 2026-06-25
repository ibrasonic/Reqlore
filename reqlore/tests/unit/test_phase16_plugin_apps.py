"""Phase 16 — Plugin Apps. SDK + storage + runner + web suite.

Covers:

* SDK field validation (StrField, TextField, IntField, BoolField,
  SelectField) — happy + sad paths.
* PluginApp registration shape + duplicate / invalid-field guards.
* ScopeView correctness (include / exclude / empty / scheme).
* PluginContext callbacks survive exceptions in their on_* paths.
* Storage: ``plugin_runs`` schema migrations, CRUD, log cap,
  defensive JSON.
* PluginRegistry discovers ``PLUGIN_APP`` / ``PLUGIN_APPS`` and
  rejects malformed exports without crashing.
* PluginRunner lifecycle: ok / error / cancelled / timeout
  transitions, lock prevents same-slug double-start, shutdown.
* Web routes: index lists apps, app_detail renders the form, run
  POST starts a run, poll endpoint returns the live snapshot,
  stop POST cancels.
* Broken plugin app (missing runner) does not crash the UI.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from reqlore import plugins_sdk as sdk
from reqlore.config import Settings
from reqlore.plugin_runner import PluginRunner
from reqlore.plugins import PluginRegistry, reset_registry
from reqlore.storage import Project
from reqlore.web import create_app


# ---------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def _isolate_registry():
    reset_registry()
    yield
    reset_registry()


@pytest.fixture
def project(tmp_path: Path) -> Project:
    p = Project(tmp_path / "p16.rlr")
    yield p
    p.close()


def _write_plugin(folder: Path, name: str, body: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(body, encoding="utf-8")
    return path


# ================================================================== SDK


class TestStrField:
    def test_validates_non_empty_string(self):
        f = sdk.StrField("url", required=True)
        assert f.validate("https://x") == "https://x"

    def test_required_rejects_blank(self):
        f = sdk.StrField("url", required=True)
        with pytest.raises(ValueError, match="required"):
            f.validate("")

    def test_optional_returns_default_on_blank(self):
        f = sdk.StrField("url", default="https://default")
        assert f.validate("") == "https://default"
        assert f.validate(None) == "https://default"

    def test_rejects_overlong(self):
        f = sdk.StrField("url", max_len=4)
        with pytest.raises(ValueError, match="too long"):
            f.validate("abcdefg")

    def test_render_dict_shape(self):
        f = sdk.StrField("url", placeholder="https://", max_len=99)
        d = f.render_dict()
        assert d["kind"] == "str"
        assert d["placeholder"] == "https://"
        assert d["max_len"] == 99
        assert d["name"] == "url"


class TestTextField:
    def test_multiline_passthrough(self):
        f = sdk.TextField("wordlist")
        assert f.validate("a\nb\nc") == "a\nb\nc"

    def test_required(self):
        f = sdk.TextField("wordlist", required=True)
        with pytest.raises(ValueError):
            f.validate("   ")

    def test_max_len_enforced(self):
        f = sdk.TextField("w", max_len=3)
        with pytest.raises(ValueError):
            f.validate("xxxx")

    def test_render_includes_rows(self):
        f = sdk.TextField("w", rows=12)
        assert f.render_dict()["rows"] == 12


class TestIntField:
    def test_parses_integer(self):
        assert sdk.IntField("n", default=0).validate("42") == 42

    def test_rejects_non_numeric(self):
        with pytest.raises(ValueError, match="not an integer"):
            sdk.IntField("n").validate("abc")

    def test_min_max_enforced(self):
        f = sdk.IntField("n", min=1, max=10)
        assert f.validate("5") == 5
        with pytest.raises(ValueError, match=">="):
            f.validate("0")
        with pytest.raises(ValueError, match="<="):
            f.validate("11")

    def test_blank_returns_default(self):
        assert sdk.IntField("n", default=7).validate("") == 7

    def test_required_rejects_blank(self):
        with pytest.raises(ValueError):
            sdk.IntField("n", required=True).validate("")

    def test_invalid_min_max_rejected_at_construct(self):
        with pytest.raises(ValueError):
            sdk.IntField("n", min=10, max=1)


class TestBoolField:
    def test_truthy_values(self):
        f = sdk.BoolField("on")
        for v in ("1", "true", "on", "yes", "TRUE", "YES"):
            assert f.validate(v) is True, v

    def test_falsy_values(self):
        f = sdk.BoolField("on")
        for v in (None, "", "0", "no", "false", "off"):
            assert f.validate(v) is False, repr(v)


class TestSelectField:
    def test_accepts_choice(self):
        f = sdk.SelectField("m", choices=["GET", "POST"])
        assert f.validate("GET") == "GET"

    def test_rejects_unknown(self):
        f = sdk.SelectField("m", choices=["GET", "POST"])
        with pytest.raises(ValueError, match="not a valid choice"):
            f.validate("DELETE")

    def test_default_used_for_blank(self):
        f = sdk.SelectField("m", choices=["a", "b"], default="b")
        assert f.validate("") == "b"

    def test_required_rejects_blank(self):
        f = sdk.SelectField("m", choices=["a"], required=True)
        with pytest.raises(ValueError):
            f.validate("")

    def test_duplicates_rejected(self):
        with pytest.raises(ValueError, match="duplicate"):
            sdk.SelectField("m", choices=["a", "a"])

    def test_default_must_be_in_choices(self):
        with pytest.raises(ValueError, match="not in choices"):
            sdk.SelectField("m", choices=["a"], default="z")

    def test_empty_choices_rejected(self):
        with pytest.raises(ValueError):
            sdk.SelectField("m", choices=[])


class TestFieldNameGuards:
    def test_rejects_blank_name(self):
        with pytest.raises(ValueError):
            sdk.StrField("")

    def test_rejects_invalid_chars(self):
        with pytest.raises(ValueError, match="invalid character"):
            sdk.StrField("bad name with spaces")

    def test_label_derived_from_name(self):
        f = sdk.StrField("first_name")
        assert "First" in f.label and "Name" in f.label


class TestPluginAppShape:
    def test_make_app_basic(self):
        a = sdk.make_app(slug="echo", name="Echo", description="d",
                         fields=[sdk.StrField("url", required=True)],
                         columns=["status"], timeout_s=60)
        assert a.slug == "echo"
        assert a.name == "Echo"
        assert len(a.fields) == 1
        assert a.columns == ["status"]
        assert a.timeout_s == 60
        assert not a.is_runnable()

        @a.runner
        def _run(ctx):
            return None

        assert a.is_runnable()

    def test_slug_normalised_and_validated(self):
        a = sdk.make_app(slug="ECHO_1", name="x")
        assert a.slug == "echo_1"
        with pytest.raises(ValueError):
            sdk.make_app(slug="bad slug!", name="x")
        with pytest.raises(ValueError):
            sdk.make_app(slug="", name="x")
        with pytest.raises(ValueError):
            sdk.make_app(slug="-bad", name="x")

    def test_rejects_non_field(self):
        with pytest.raises(TypeError):
            sdk.make_app(slug="x", name="x", fields=["not a field"])

    def test_rejects_duplicate_field_names(self):
        with pytest.raises(ValueError, match="duplicate"):
            sdk.make_app(
                slug="x", name="x",
                fields=[sdk.StrField("a"), sdk.IntField("a")],
            )

    def test_validate_settings_round_trip(self):
        a = sdk.make_app(
            slug="x", name="x",
            fields=[
                sdk.StrField("url", required=True),
                sdk.IntField("n", default=3),
                sdk.BoolField("flag"),
            ],
        )
        out = a.validate_settings({"url": "https://x", "n": "7", "flag": "1"})
        assert out == {"url": "https://x", "n": 7, "flag": True}

    def test_runner_decorator_rejects_non_callable(self):
        a = sdk.make_app(slug="x", name="x")
        with pytest.raises(TypeError):
            a.runner(42)

    def test_timeout_floor(self):
        with pytest.raises(ValueError):
            sdk.make_app(slug="x", name="x", timeout_s=0)


# ============================================================ ScopeView


class TestScopeView:
    def test_empty_means_no_enabled_rules(self):
        sv = sdk.ScopeView([])
        assert sv.empty is True
        assert sv.hosts() == []

    def test_include_rule_matches_exact_host(self):
        sv = sdk.ScopeView([
            {"kind": "include", "target": "host",
             "pattern": "example.com", "enabled": True},
        ])
        assert sv.is_in_scope("example.com") is True
        assert sv.is_in_scope("other.com") is False

    def test_url_scope_uses_hostname(self):
        sv = sdk.ScopeView([
            {"kind": "include", "target": "host",
             "pattern": "example.com", "enabled": True},
        ])
        assert sv.is_url_in_scope("https://example.com/x") is True
        assert sv.is_url_in_scope("https://other.com/x") is False
        assert sv.is_url_in_scope("") is False

    def test_disabled_rules_ignored(self):
        sv = sdk.ScopeView([
            {"kind": "include", "target": "host",
             "pattern": "example.com", "enabled": False},
        ])
        assert sv.empty is True

    def test_hosts_lists_enabled_includes(self):
        sv = sdk.ScopeView([
            {"kind": "include", "target": "host",
             "pattern": "a.com", "enabled": True},
            {"kind": "include", "target": "host",
             "pattern": "b.com", "enabled": True},
            {"kind": "exclude", "target": "host",
             "pattern": "c.com", "enabled": True},
        ])
        assert sv.hosts() == ["a.com", "b.com"]

    def test_from_project_with_missing_method(self):
        class _Fake:
            pass

        sv = sdk.ScopeView.from_project(_Fake())
        assert sv.empty is True


# ============================================================ PluginContext


def test_plugin_context_log_swallows_exceptions(project):
    def _broken(level, msg):
        raise RuntimeError("boom")

    ctx = sdk.PluginContext(
        project=project, slug="x", run_id=1,
        settings={}, scope=sdk.ScopeView([]),
        stop_event=threading.Event(),
        on_log=_broken,
    )
    # Must not raise.
    ctx.log("hello")
    ctx.progress(1, 10)
    ctx.add_result({"x": 1})


def test_plugin_context_stop_signal(project):
    ev = threading.Event()
    ctx = sdk.PluginContext(
        project=project, slug="x", run_id=1,
        settings={}, scope=sdk.ScopeView([]),
        stop_event=ev,
    )
    assert ctx.stop_requested() is False
    assert ctx.sleep(0.01) is True
    ev.set()
    assert ctx.stop_requested() is True
    # sleep returns False immediately because the event is set.
    assert ctx.sleep(1.0) is False
    with pytest.raises(sdk.CancelledError):
        ctx.check_stop()


def test_plugin_context_record_finding_tags_source(project):
    ctx = sdk.PluginContext(
        project=project, slug="myplug", run_id=1,
        settings={}, scope=sdk.ScopeView([]),
        stop_event=threading.Event(),
    )
    fid = ctx.record_finding(
        title="t", severity="info", host="h",
        url="https://h/x", evidence="e",
    )
    assert fid > 0
    rows = project.list_findings()
    assert any(r.get("source") == "plugin:myplug" for r in rows)


# ================================================================ Storage


class TestPluginRunsStorage:
    def test_create_and_get(self, project):
        rid = project.create_plugin_run(
            slug="echo", settings={"url": "https://x"})
        assert rid > 0
        row = project.get_plugin_run(rid)
        assert row is not None
        assert row["slug"] == "echo"
        assert row["status"] == "pending"
        assert row["settings"] == {"url": "https://x"}
        assert row["log"] == ""
        assert row["results"] == []

    def test_update_progress_and_status(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        project.update_plugin_run(
            rid, status="running", progress_done=5,
            progress_total=10, progress_msg="halfway",
        )
        row = project.get_plugin_run(rid)
        assert row["status"] == "running"
        assert row["progress_done"] == 5
        assert row["progress_total"] == 10
        assert row["progress_msg"] == "halfway"

    def test_finalise_with_error(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        project.update_plugin_run(
            rid, status="error", finished_at=123, error="ValueError: bad",
        )
        row = project.get_plugin_run(rid)
        assert row["status"] == "error"
        assert row["finished_at"] == 123
        assert row["error"] == "ValueError: bad"

    def test_append_log_appends_with_newline(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        project.append_plugin_run_log(rid, "first")
        project.append_plugin_run_log(rid, "second")
        log = project.get_plugin_run(rid)["log"]
        assert "first\nsecond\n" in log

    def test_append_log_caps_size(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        # Push more than the 256 KiB cap so trimming engages.
        for i in range(2_000):
            project.append_plugin_run_log(rid, "x" * 200)
        log = project.get_plugin_run(rid)["log"]
        assert len(log) <= Project._PLUGIN_LOG_CAP_BYTES
        # Trimming must leave a clean tail: the most recent line is
        # always intact and ends with a newline.
        assert log.endswith("\n")

    def test_append_result_round_trip(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        project.append_plugin_run_result(rid, {"status": 200, "url": "u"})
        project.append_plugin_run_result(rid, {"status": 404})
        rows = project.get_plugin_run(rid)["results"]
        assert rows == [{"status": 200, "url": "u"}, {"status": 404}]

    def test_list_runs_filters_by_slug_and_orders_desc(self, project):
        a1 = project.create_plugin_run(slug="a", settings={})
        b1 = project.create_plugin_run(slug="b", settings={})
        a2 = project.create_plugin_run(slug="a", settings={})
        assert [r["id"] for r in project.list_plugin_runs(slug="a")] == [a2, a1]
        assert [r["id"] for r in project.list_plugin_runs(slug="b")] == [b1]
        assert {r["id"] for r in project.list_plugin_runs()} == {a1, a2, b1}

    def test_latest_run(self, project):
        a1 = project.create_plugin_run(slug="a", settings={})
        a2 = project.create_plugin_run(slug="a", settings={})
        assert project.latest_plugin_run("a")["id"] == a2
        assert project.latest_plugin_run("never") is None

    def test_delete_run(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        project.delete_plugin_run(rid)
        assert project.get_plugin_run(rid) is None

    def test_corrupt_results_json_recovered(self, project):
        rid = project.create_plugin_run(slug="x", settings={})
        # Directly mangle results_json to simulate a corrupted DB.
        with project._cursor() as cur:
            cur.execute("UPDATE plugin_runs SET results_json=? WHERE id=?",
                        ("not json", rid))
        # Appending should still work — corrupt becomes empty list first.
        project.append_plugin_run_result(rid, {"ok": True})
        assert project.get_plugin_run(rid)["results"] == [{"ok": True}]


# ====================================================== Plugin registry


def test_registry_discovers_plugin_app(tmp_path):
    _write_plugin(tmp_path, "echo", '''
from reqlore import plugins_sdk as sdk
PLUGIN_INFO = {"name": "echo", "version": "0.1", "description": "d"}
PLUGIN_APP = sdk.make_app(slug="echo", name="Echo",
                          fields=[sdk.StrField("url", required=True)],
                          columns=["status"])

@PLUGIN_APP.runner
def run(ctx):
    return None
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    apps = reg.active_plugin_apps()
    assert len(apps) == 1
    assert apps[0].slug == "echo"
    assert reg.get_plugin_app("echo") is apps[0]
    assert reg.get_plugin_app("missing") is None


def test_registry_supports_plugin_apps_list(tmp_path):
    _write_plugin(tmp_path, "multi", '''
from reqlore import plugins_sdk as sdk
PLUGIN_INFO = {"name": "multi", "version": "0.1"}
a = sdk.make_app(slug="aa", name="A")
b = sdk.make_app(slug="bb", name="B")

@a.runner
def _ra(ctx): pass

@b.runner
def _rb(ctx): pass

PLUGIN_APPS = [a, b]
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    slugs = {a.slug for a in reg.active_plugin_apps()}
    assert slugs == {"aa", "bb"}


def test_registry_rejects_runner_less_app(tmp_path):
    _write_plugin(tmp_path, "broken", '''
from reqlore import plugins_sdk as sdk
PLUGIN_INFO = {"name": "broken", "version": "0.1"}
PLUGIN_APP = sdk.make_app(slug="broken", name="Broken")
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    p = reg.list()[0]
    assert p.status == "error"
    assert "@runner" in p.error or "runner" in p.error
    assert reg.active_plugin_apps() == []


def test_registry_disabled_plugin_hides_apps(tmp_path):
    _write_plugin(tmp_path, "echo", '''
from reqlore import plugins_sdk as sdk
PLUGIN_INFO = {"name": "echo", "version": "0.1"}
PLUGIN_APP = sdk.make_app(slug="echo", name="Echo")

@PLUGIN_APP.runner
def run(ctx): pass
''')
    reg = PluginRegistry([tmp_path])
    reg.discover()
    assert len(reg.active_plugin_apps()) == 1
    reg.toggle("echo")
    assert reg.active_plugin_apps() == []


# ====================================================== PluginRunner


def _wait_for(predicate, timeout=5.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_runner_ok_path(project):
    runner = PluginRunner(project)
    app = sdk.make_app(slug="ok", name="Ok",
                       fields=[sdk.StrField("greet", default="hi")])

    @app.runner
    def _run(ctx):
        ctx.log("starting")
        ctx.progress(1, 1, "done")
        ctx.add_result({"greet": ctx.settings["greet"]})

    rid = runner.start(app, {"greet": "hello"})
    assert _wait_for(lambda: not runner.is_running("ok"))
    row = project.get_plugin_run(rid)
    assert row["status"] == "ok"
    assert row["results"] == [{"greet": "hello"}]
    assert "starting" in row["log"]
    assert row["progress_done"] == 1


def test_runner_error_path(project):
    runner = PluginRunner(project)
    app = sdk.make_app(slug="err", name="Err")

    @app.runner
    def _run(ctx):
        raise RuntimeError("boom")

    rid = runner.start(app, {})
    assert _wait_for(lambda: not runner.is_running("err"))
    row = project.get_plugin_run(rid)
    assert row["status"] == "error"
    assert "RuntimeError" in row["error"]
    assert "boom" in row["error"]
    assert "Traceback" in row["log"] or "boom" in row["log"]


def test_runner_cancelled_path(project):
    runner = PluginRunner(project)
    started = threading.Event()
    app = sdk.make_app(slug="long", name="Long")

    @app.runner
    def _run(ctx):
        started.set()
        # Will block up to 5s; we send stop almost immediately.
        ctx.sleep(5.0)
        if ctx.stop_requested():
            return

    rid = runner.start(app, {})
    assert started.wait(2.0)
    assert runner.stop("long") is True
    assert _wait_for(lambda: not runner.is_running("long"))
    row = project.get_plugin_run(rid)
    assert row["status"] == "cancelled"


def test_runner_timeout_path(project):
    runner = PluginRunner(project)
    app = sdk.make_app(slug="slow", name="Slow", timeout_s=5)
    # Force-shrink the timeout so the test is fast; the SDK floor is
    # 5s but the runner uses whatever the PluginApp says.
    app.timeout_s = 1

    started = threading.Event()

    @app.runner
    def _run(ctx):
        started.set()
        # Honour cancel only after a long delay so the watchdog
        # has to fire to terminate us.
        ctx.sleep(10.0)

    rid = runner.start(app, {})
    assert started.wait(2.0)
    assert _wait_for(lambda: not runner.is_running("slow"), timeout=8.0)
    row = project.get_plugin_run(rid)
    assert row["status"] == "timeout"
    assert "timeout" in row["log"].lower()


def test_runner_lock_prevents_double_start(project):
    runner = PluginRunner(project)
    app = sdk.make_app(slug="locked", name="Locked")
    gate = threading.Event()

    @app.runner
    def _run(ctx):
        gate.wait(timeout=3.0)

    runner.start(app, {})
    with pytest.raises(RuntimeError, match="already running"):
        runner.start(app, {})
    gate.set()
    assert _wait_for(lambda: not runner.is_running("locked"))


def test_runner_invalid_settings_rejected(project):
    runner = PluginRunner(project)
    app = sdk.make_app(slug="iv", name="Iv",
                       fields=[sdk.IntField("n", required=True)])

    @app.runner
    def _run(ctx):
        pass

    with pytest.raises(ValueError):
        runner.start(app, {"n": "not a number"})


def test_runner_shutdown_signals_all(project):
    runner = PluginRunner(project)
    app1 = sdk.make_app(slug="a", name="A")
    app2 = sdk.make_app(slug="b", name="B")

    @app1.runner
    def _a(ctx):
        ctx.sleep(5.0)

    @app2.runner
    def _b(ctx):
        ctx.sleep(5.0)

    runner.start(app1, {})
    runner.start(app2, {})
    runner.shutdown()
    assert _wait_for(lambda: not runner.is_running("a"))
    assert _wait_for(lambda: not runner.is_running("b"))


# ============================================================ Web routes


@pytest.fixture
def web_env(tmp_path: Path):
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    _write_plugin(plugin_dir, "echo", '''
from reqlore import plugins_sdk as sdk
PLUGIN_INFO = {"name": "echo", "version": "0.1", "description": "Echo a URL"}
PLUGIN_APP = sdk.make_app(
    slug="echo", name="Echo Tool",
    description="Send one request and report its status",
    fields=[
        sdk.StrField("url", required=True),
        sdk.SelectField("method", choices=["GET", "POST"]),
        sdk.BoolField("verbose"),
    ],
    columns=["status", "url"],
)

@PLUGIN_APP.runner
def run(ctx):
    ctx.log("running")
    ctx.add_result({"status": 200, "url": ctx.settings["url"]})
''')
    # Seed the singleton registry from our private plugin dir BEFORE
    # create_app boots — the blueprint reads from get_registry().
    reset_registry()
    from reqlore.plugins import get_registry
    get_registry([plugin_dir])

    app = create_app(tmp_path / "p16_web.rlr", Settings(), proxy=None)
    app.testing = True
    return app, app.test_client()


def _csrf(client) -> str:
    client.get("/plugins/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_index_lists_plugin_apps(web_env):
    _, c = web_env
    r = c.get("/plugins/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Plugin Apps" in body
    assert "Echo Tool" in body
    assert "/plugins/app/echo/" in body


def test_app_detail_renders_form(web_env):
    _, c = web_env
    r = c.get("/plugins/app/echo/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Echo Tool" in body
    assert 'name="url"' in body
    assert 'name="method"' in body
    assert 'name="verbose"' in body
    assert "<option value=\"GET\"" in body


def test_app_detail_404_for_unknown_slug(web_env):
    _, c = web_env
    r = c.get("/plugins/app/missing/")
    assert r.status_code == 404


def test_run_post_starts_execution(web_env):
    app, c = web_env
    tok = _csrf(c)
    r = c.post(
        "/plugins/app/echo/run",
        data={"_csrf": tok, "url": "https://x", "method": "GET"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    # Wait for the daemon thread to finish.
    runner = app.extensions["reqlore_plugin_runner"]
    assert _wait_for(lambda: not runner.is_running("echo"))
    project = app.extensions["reqlore_project"]
    latest = project.latest_plugin_run("echo")
    assert latest is not None
    assert latest["status"] == "ok"
    assert latest["results"] == [{"status": 200, "url": "https://x"}]


def test_run_post_invalid_settings_returns_to_form(web_env):
    _, c = web_env
    tok = _csrf(c)
    r = c.post(
        "/plugins/app/echo/run",
        data={"_csrf": tok, "url": "", "method": "GET"},
        follow_redirects=True,
    )
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Invalid settings" in body or "required" in body.lower()


def test_poll_endpoint_shape(web_env):
    app, c = web_env
    tok = _csrf(c)
    c.post("/plugins/app/echo/run",
           data={"_csrf": tok, "url": "https://x", "method": "GET"},
           follow_redirects=True)
    runner = app.extensions["reqlore_plugin_runner"]
    assert _wait_for(lambda: not runner.is_running("echo"))
    project = app.extensions["reqlore_project"]
    rid = project.latest_plugin_run("echo")["id"]
    r = c.get(f"/plugins/app/echo/runs/{rid}/poll")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert data["is_running"] is False
    assert isinstance(data["log_tail"], str)
    assert data["new_results"] == [{"status": 200, "url": "https://x"}]


def test_stop_post_cancels_active_run(web_env):
    app, c = web_env
    runner = app.extensions["reqlore_plugin_runner"]

    # Replace the echo app with a long-running one so we can stop it.
    long_app = sdk.make_app(slug="echo", name="Long",
                            fields=[sdk.StrField("url")])

    @long_app.runner
    def _r(ctx):
        ctx.sleep(5.0)

    from reqlore.plugins import get_registry
    reg = get_registry()
    # Replace the cached PluginApp on the loaded record.
    rec = next(iter(reg._plugins.values()))
    rec.plugin_apps = [long_app]

    tok = _csrf(c)
    c.post("/plugins/app/echo/run",
           data={"_csrf": tok, "url": "https://x"},
           follow_redirects=True)
    assert _wait_for(lambda: runner.is_running("echo"))
    r = c.post("/plugins/app/echo/stop",
               data={"_csrf": tok}, follow_redirects=True)
    assert r.status_code == 200
    assert _wait_for(lambda: not runner.is_running("echo"))
    project = app.extensions["reqlore_project"]
    assert project.latest_plugin_run("echo")["status"] == "cancelled"


def test_run_detail_renders_with_results(web_env):
    app, c = web_env
    tok = _csrf(c)
    c.post("/plugins/app/echo/run",
           data={"_csrf": tok, "url": "https://x", "method": "GET"},
           follow_redirects=True)
    runner = app.extensions["reqlore_plugin_runner"]
    assert _wait_for(lambda: not runner.is_running("echo"))
    project = app.extensions["reqlore_project"]
    rid = project.latest_plugin_run("echo")["id"]
    r = c.get(f"/plugins/app/echo/runs/{rid}/")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "Run" in body
    assert "https://x" in body
    assert "status" in body

"""Tests for the DOM Hunter (DOM XSS) module: storage, helpers, and the
Flask blueprint (UI pages + bridge endpoints)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reqlore import dom_hunter as S
from reqlore.config import Settings
from reqlore.storage import Project
from reqlore.web import create_app


@pytest.fixture
def project(tmp_path: Path) -> Project:
    return Project(tmp_path / "dom_hunter.rlr")


@pytest.fixture
def app_and_client(tmp_path: Path):
    proj = tmp_path / "dom_hunter_app.rlr"
    app = create_app(proj, Settings(), proxy=None)
    app.testing = True
    return app, app.test_client()


# ---------------------------------------------------------------------------
# helpers + storage
# ---------------------------------------------------------------------------

def test_canary_and_token_are_generated_once(project: Project):
    c1 = S.get_or_make_canary(project)
    c2 = S.get_or_make_canary(project)
    assert c1 == c2 and c1.startswith("rqdomh") and len(c1) >= 16
    t1 = S.get_or_make_token(project)
    t2 = S.get_or_make_token(project)
    assert t1 == t2 and len(t1) >= 32


def test_severity_normalisation():
    assert S.normalise_severity("HIGH") == "high"
    assert S.normalise_severity(None) == "medium"
    assert S.normalise_severity("bogus") == "medium"


def test_host_in_scope_wildcards():
    scope = ["*.example.com", "exact.test"]
    assert S.host_in_scope("a.example.com", scope)
    assert S.host_in_scope("example.com", scope)
    assert S.host_in_scope("EXACT.test", scope)
    assert not S.host_in_scope("evil.com", scope)
    # Empty scope means "any host".
    assert S.host_in_scope("anything", [])


def test_normalize_scope_entry_accepts_urls_and_wildcards():
    """Users naturally paste URLs (with scheme/path/port) into the scope
    box. Strip everything but host[:port]. Wildcards survive intact."""
    n = S.normalize_scope_entry
    assert n("example.com") == "example.com"
    assert n(" EXAMPLE.COM ") == "example.com"
    assert n("http://example.com/path?x=1") == "example.com"
    assert n("https://localhost:3001/") == "localhost:3001"
    assert n("//example.com") == "example.com"
    assert n("example.com/foo") == "example.com"
    assert n("*.example.com") == "*.example.com"
    assert n("https://*.example.com/login") == "*.example.com"
    assert n("") == ""
    assert n("   ") == ""


def test_set_scope_normalizes_url_form(project: Project):
    """Reported bug: user types 'http://localhost:3001' as scope, the
    extension's per-tab gate compares host 'localhost:3001' against
    pattern 'http://localhost:3001', returns out-of-scope, no canary
    is injected, panel shows 'off'."""
    S.set_scope(project, ["http://localhost:3001", "https://*.example.com/path"])
    stored = S.get_scope(project)
    assert stored == ["localhost:3001", "*.example.com"]
    assert S.host_in_scope("localhost:3001", stored)
    assert S.host_in_scope("api.example.com", stored)
    assert not S.host_in_scope("localhost", stored)  # port mismatch is strict
    assert not S.host_in_scope("example.org", stored)


def test_get_scope_normalizes_legacy_entries(project: Project):
    """Old projects may have raw URLs stored from before the
    normalizer. get_scope() must clean them up on read so we don't
    require a forced re-save."""
    project.set_state(S.SCOPE_KEY, "http://localhost:3001,HTTPS://Foo.com/x")
    assert S.get_scope(project) == ["localhost:3001", "foo.com"]


def test_dedupe_key_is_stable_and_distinguishing():
    a = S.dedupe_key(sink="eval", source="location.hash",
                     page_url="https://x/", stack="at f (a:1)\n", canary_seen=True)
    b = S.dedupe_key(sink="eval", source="location.hash",
                     page_url="https://x/", stack="at f (a:1)\n", canary_seen=True)
    c = S.dedupe_key(sink="eval", source="location.hash",
                     page_url="https://x/", stack="at f (a:1)\n", canary_seen=False)
    assert a == b
    assert a != c


def test_add_and_list_findings_with_dedupe(project: Project):
    args = dict(
        page_url="https://x/", frame_url="https://x/", sink="eval",
        source="location.hash", severity="critical", canary_seen=True,
        value="alert(1)", stack="at f", dedupe_key="kEY-1",
    )
    fid1 = project.add_dom_hunter_finding(**args)
    fid2 = project.add_dom_hunter_finding(**args)
    assert fid1 == fid2  # dedupe by key
    rows = project.list_dom_hunter_findings()
    assert len(rows) == 1
    assert rows[0]["hit_count"] == 2
    assert rows[0]["sink"] == "eval"
    assert rows[0]["canary_seen"] is True


def test_findings_min_severity_filter(project: Project):
    project.add_dom_hunter_finding(page_url="u", frame_url="u", sink="eval",
        source="unknown", severity="low", canary_seen=False,
        value="", stack="", dedupe_key="k-low")
    project.add_dom_hunter_finding(page_url="u", frame_url="u", sink="eval",
        source="unknown", severity="high", canary_seen=False,
        value="", stack="", dedupe_key="k-high")
    rows = project.list_dom_hunter_findings(min_severity="medium")
    assert {r["severity"] for r in rows} == {"high"}


def test_messages_log(project: Project):
    mid = project.add_dom_hunter_message(
        page_url="https://x/", origin="https://evil/",
        data='{"a":1}', has_canary=True, handler_stack="at h",
    )
    assert mid > 0
    rows = project.list_dom_hunter_messages()
    assert len(rows) == 1 and rows[0]["has_canary"] is True
    only = project.list_dom_hunter_messages(only_canary=True)
    assert len(only) == 1


# ---------------------------------------------------------------------------
# blueprint -- human UI
# ---------------------------------------------------------------------------

def test_index_renders_empty(app_and_client):
    _, c = app_and_client
    r = c.get("/dom-hunter/")
    assert r.status_code == 200
    assert b"DOM Hunter" in r.data
    # AAA-ish a11y essentials present.
    assert b'class="skip-link"' in r.data
    assert b"<h1>DOM Hunter" in r.data


def test_settings_save_and_rotate(app_and_client):
    app, c = app_and_client
    # Initial GET seeds the canary + token.
    r = c.get("/dom-hunter/settings")
    assert r.status_code == 200
    proj = app.extensions["reqlore_project"]
    before_canary = S.get_or_make_canary(proj)
    before_token = S.get_or_make_token(proj)

    # Save settings via the form (CSRF required for normal routes).
    with c.session_transaction() as sess:
        token = sess.get("csrf", "")
    assert token
    r = c.post("/dom-hunter/settings", data={
        "_csrf": token,
        "action": "save",
        "enabled": "1",
        "scope": "example.com\n*.acme.test",
        "auto_inject": "location.hash",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert S.is_enabled(proj) is True
    assert sorted(S.get_scope(proj)) == sorted(["example.com", "*.acme.test"])
    assert S.get_auto_inject(proj) == ["location.hash"]

    # Rotate canary -- value should change.
    r = c.post("/dom-hunter/settings", data={
        "_csrf": token, "action": "rotate_canary",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert S.get_or_make_canary(proj) != before_canary

    # Rotate token -- value should change.
    r = c.post("/dom-hunter/settings", data={
        "_csrf": token, "action": "rotate_token",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert S.get_or_make_token(proj) != before_token


# ---------------------------------------------------------------------------
# blueprint -- bridge endpoints (token-auth, CSRF-exempt)
# ---------------------------------------------------------------------------

def test_bridge_requires_token(app_and_client):
    _, c = app_and_client
    r = c.get("/dom-hunter/__bridge/config")
    assert r.status_code == 401
    r = c.post("/dom-hunter/__bridge/report", json={"kind": "finding"})
    assert r.status_code == 401


def test_bridge_config_with_correct_token(app_and_client):
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    canary = S.get_or_make_canary(proj)
    S.set_enabled(proj, True)
    S.set_scope(proj, ["example.com"])
    S.set_auto_inject(proj, ["location.hash"])

    r = c.get("/dom-hunter/__bridge/config",
              headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    body = r.get_json()
    assert body["enabled"] is True
    assert body["canary"] == canary
    assert body["scope"] == ["example.com"]
    assert body["auto_inject"] == ["location.hash"]
    assert isinstance(body["sinks"], list) and "eval" in body["sinks"]


def test_bridge_report_finding_inserts_and_dedupes(app_and_client):
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    payload = {
        "kind": "finding",
        "sink": "eval",
        "source": "location.hash",
        "severity": "critical",
        "canary_seen": True,
        "page_url": "https://x/",
        "frame_url": "https://x/",
        "value": "alert(1)",
        "stack": "Error\n    at f (a.js:1:1)",
    }
    r1 = c.post("/dom-hunter/__bridge/report", json=payload,
                headers={"X-DOMHunter-Token": token})
    assert r1.status_code == 200
    r2 = c.post("/dom-hunter/__bridge/report", json=payload,
                headers={"X-DOMHunter-Token": token})
    assert r2.status_code == 200
    rows = proj.list_dom_hunter_findings()
    assert len(rows) == 1
    assert rows[0]["hit_count"] == 2


def test_bridge_report_unknown_sink_rejected(app_and_client):
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    r = c.post("/dom-hunter/__bridge/report",
               json={"kind": "finding", "sink": ""},
               headers={"X-DOMHunter-Token": token})
    assert r.status_code == 400


def test_bridge_report_message_inserts(app_and_client):
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    payload = {
        "kind": "message",
        "page_url": "https://x/",
        "origin": "https://attacker/",
        "data": '{"a":1}',
        "has_canary": False,
        "handler_stack": "at h (a.js:1)",
    }
    r = c.post("/dom-hunter/__bridge/report", json=payload,
               headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    rows = proj.list_dom_hunter_messages()
    assert len(rows) == 1
    assert rows[0]["origin"] == "https://attacker/"


def test_bridge_findings_json(app_and_client):
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    proj.add_dom_hunter_finding(
        page_url="u", frame_url="u", sink="eval", source="unknown",
        severity="high", canary_seen=False, value="x", stack="",
        dedupe_key="kJSON",
    )
    r = c.get("/dom-hunter/__bridge/findings.json?limit=10",
              headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    body = r.get_json()
    assert body["total"] == 1
    assert body["findings"][0]["sink"] == "eval"


def test_nav_link_appears_in_base_template(app_and_client):
    _, c = app_and_client
    r = c.get("/")
    assert r.status_code == 200
    assert b"/dom-hunter/" in r.data
    assert b"DOM Hunter" in r.data


# ---------------------------------------------------------------------------
# extension packager + browser policy
# ---------------------------------------------------------------------------

def test_packager_finds_extension_source():
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    assert (src / "manifest.json").exists()
    assert (src / "background" / "service_worker.js").exists()
    assert (src / "devtools" / "devtools.html").exists()


def test_packager_builds_xpi(tmp_path: Path):
    import zipfile
    from reqlore.dom_hunter.packager import build_xpi
    out = build_xpi(out_path=tmp_path / "out.xpi")
    assert out.exists()
    assert out.stat().st_size > 1000
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    # Core resources present, test fixtures excluded.
    assert "manifest.json" in names
    assert "background/service_worker.js" in names
    assert "devtools/panel.html" in names
    assert "ui/styles.css" in names
    assert not any(n.startswith("tests/") for n in names)
    assert "README.md" not in names


def test_devtools_panel_path_is_root_absolute() -> None:
    """`browser.devtools.panels.create(title, iconPath, pagePath)`:
    Firefox resolves both paths RELATIVE TO THE DEVTOOLS PAGE
    (/devtools/devtools.html), while Chromium/Safari resolve them
    as extension-root absolute. The portable form -- MDN's own
    canonical example -- is a leading-slash path. Anything else
    breaks on at least one engine:

      "devtools/panel.html"             -> 404 on Firefox
      "panel.html"                      -> wrong root on Chromium
      browser.runtime.getURL("...")     -> rejected by MV3 panels.create

    See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/devtools/panels/create
    """
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    js = (src / "devtools" / "devtools.js").read_text(encoding="utf-8")
    # Must use the leading-slash absolute form for cross-browser support.
    assert '"/devtools/panel.html"' in js
    assert '"/icons/icon.svg"' in js
    # The actual create() call must not use any of the broken forms.
    # We isolate the call by stripping the leading block comment so the
    # substring checks don't trip on documentation that mentions them.
    code = js.split("*/", 1)[1] if "*/" in js else js
    assert 'browser.runtime.getURL(' not in code
    assert '"devtools/panel.html"' not in code   # bare relative -- 404 on Firefox
    assert '"panel.html"' not in code            # sibling-relative -- breaks Chromium


def test_browser_policy_embeds_dom_hunter(tmp_path: Path):
    from reqlore.browser import _policies_dict
    fake_ca = tmp_path / "ca.pem"
    fake_ca.write_text("dummy")
    fake_xpi = tmp_path / "dom.xpi"
    fake_xpi.write_bytes(b"PK\x03\x04")

    pol = _policies_dict(
        ca_path=fake_ca, proxy_host="127.0.0.1", proxy_port=8080,
        homepage_url="http://127.0.0.1:8080/",
        dom_hunter_xpi=fake_xpi,
        dom_hunter_bridge_url="http://127.0.0.1:8080",
        dom_hunter_token="testtoken",
    )["policies"]

    ext_id = "reqlore-dom-hunter@reqlore.local"
    assert "ExtensionSettings" in pol
    assert pol["ExtensionSettings"][ext_id]["installation_mode"] == "force_installed"
    assert pol["ExtensionSettings"][ext_id]["install_url"].startswith("file:")
    assert pol["ExtensionSettings"][ext_id]["install_url"].endswith("dom.xpi")
    assert pol["3rdparty"]["Extensions"][ext_id] == {
        "baseUrl": "http://127.0.0.1:8080",
        "token": "testtoken",
    }


def test_browser_policy_without_extension(tmp_path: Path):
    from reqlore.browser import _policies_dict
    fake_ca = tmp_path / "ca.pem"
    fake_ca.write_text("dummy")
    pol = _policies_dict(
        ca_path=fake_ca, proxy_host="127.0.0.1", proxy_port=8080,
        homepage_url="http://127.0.0.1:8080/",
    )["policies"]
    assert "ExtensionSettings" not in pol
    assert "3rdparty" not in pol


def test_packager_missing_src_raises(tmp_path: Path):
    """build_xpi must fail loudly when the source folder is absent --
    silent skipping would leave the operator wondering why the DevTools
    panel never appeared."""
    from reqlore.dom_hunter.packager import build_xpi
    missing = tmp_path / "no-such-dir"
    with pytest.raises(FileNotFoundError):
        build_xpi(out_path=tmp_path / "out.xpi", src_dir=missing)


def test_install_policies_writes_valid_json(tmp_path: Path):
    """End-to-end check: the JSON Firefox actually reads round-trips
    cleanly and contains the DOM Hunter blocks when an XPI is given.
    Failure mode: malformed JSON -> Firefox silently ignores ALL policies."""
    from reqlore.browser import install_policies
    fake_ca = tmp_path / "ca.pem"
    fake_ca.write_text("dummy")
    fake_xpi = tmp_path / "dom.xpi"
    fake_xpi.write_bytes(b"PK\x03\x04")
    fake_exe = tmp_path / "firefox.exe"
    fake_exe.write_bytes(b"")

    out = install_policies(
        exe=fake_exe, ca_path=fake_ca,
        proxy_host="127.0.0.1", proxy_port=8080,
        homepage_url="http://127.0.0.1:8787/",
        dom_hunter_xpi=fake_xpi,
        dom_hunter_bridge_url="http://127.0.0.1:8787",
        dom_hunter_token="abc",
    )
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    ext_id = "reqlore-dom-hunter@reqlore.local"
    assert data["policies"]["ExtensionSettings"][ext_id]["installation_mode"] \
        == "force_installed"
    assert data["policies"]["3rdparty"]["Extensions"][ext_id]["token"] == "abc"


def test_cmd_browser_with_project_passes_through_and_closes(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`reqlore browser --project foo.rlr` must:
      - resolve the project,
      - hand it to run_browser as project=,
      - close it after the launch returns.
    Failure mode: project not forwarded -> XPI never built ->
    no extension auto-install."""
    from reqlore import browser as fxmod
    from reqlore import cli as reqlore_cli
    from reqlore.storage import Project

    # Create a real project file so _resolve_project succeeds.
    proj_path = tmp_path / "demo.rlr"
    Project(proj_path).close()

    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(fxmod, "is_wsl", lambda: False)

    captured: dict[str, object] = {}

    class _FakeResult:
        pid = 1234
        exe = Path("/usr/bin/firefox")
        profile = Path("/tmp/profile")
        policies = Path("/tmp/policies.json")

    def fake_run_browser(**kwargs):
        captured.update(kwargs)
        proj = kwargs.get("project")
        assert proj is not None, "project must be forwarded to run_browser"
        # Project is open here -- close happens in cmd_browser after launch.
        assert Path(proj.path) == proj_path
        return _FakeResult()

    monkeypatch.setattr(fxmod, "run_browser", fake_run_browser)

    import argparse
    args = argparse.Namespace(
        proxy_port=None, url=None, firefox_zip=None,
        firefox_version=None, use_system=False, wait=False,
        project=str(proj_path), channel=None,
    )
    rc = reqlore_cli.cmd_browser(args)

    assert rc == 0
    assert captured.get("project") is not None
    # With --project, the channel must default to devedition so the DOM
    # Hunter sideload (unsigned XPI) actually loads -- Release/Beta enforce
    # signing and silently drop it.
    assert captured.get("channel") == "devedition"
    # Project must be closed after launch -- otherwise SQLite locks linger.
    proj = captured["project"]
    # Re-opening must work (i.e., the file isn't write-locked by us).
    Project(proj_path).close()


def test_cmd_browser_without_project_uses_release_channel(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No --project -> small Release Firefox is fine; no need for the
    larger Dev Edition + sideload workaround."""
    from reqlore import browser as fxmod
    from reqlore import cli as reqlore_cli

    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(fxmod, "is_wsl", lambda: False)

    captured: dict[str, object] = {}

    class _FakeResult:
        pid = 1
        exe = Path("/usr/bin/firefox")
        profile = Path("/tmp/p")
        policies = Path("/tmp/pol")

    monkeypatch.setattr(fxmod, "run_browser",
                        lambda **kw: captured.update(kw) or _FakeResult())

    import argparse
    args = argparse.Namespace(
        proxy_port=None, url=None, firefox_zip=None,
        firefox_version=None, use_system=False, wait=False,
        project=None, channel=None,
    )
    rc = reqlore_cli.cmd_browser(args)
    assert rc == 0
    assert captured.get("channel") == "release"


def test_cached_install_segregates_channels(tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    """Release stays at <cache>/<version>; Dev Edition lives under
    <cache>/devedition/<version> so the two coexist without colliding."""
    from reqlore import browser as fxmod
    monkeypatch.setattr(fxmod, "cache_root", lambda: tmp_path)
    release = fxmod.cached_install("127.0", channel="release")
    devedition = fxmod.cached_install("143.0b9", channel="devedition")
    assert release == tmp_path / "127.0"
    assert devedition == tmp_path / "devedition" / "143.0b9"


def test_run_browser_with_project_builds_xpi_and_installs_policies(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end (mocked Firefox) check that run_browser with project=:
      - calls build_xpi,
      - forwards the resulting XPI + bridge URL + token to install_policies.
    Failure mode regression: any of these dropped -> extension shows up
    in Firefox unconfigured, options page editable, no auto-install."""
    from reqlore import browser as fxmod
    from reqlore.storage import Project

    proj_path = tmp_path / "demo.rlr"
    Project(proj_path).close()
    project = Project(proj_path)

    ca = tmp_path / "ca.pem"
    ca.write_text("dummy")

    # Pretend firefox is already installed.
    fake_exe = tmp_path / "firefox.exe"
    fake_exe.write_bytes(b"")
    monkeypatch.setattr(fxmod, "find_firefox",
                        lambda prefer_cache=True, channel=None: fake_exe)
    monkeypatch.setattr(fxmod, "ensure_linux_runtime", lambda exe: [])
    monkeypatch.setattr(fxmod, "ensure_profile", lambda *a, **k: tmp_path / "profile")
    monkeypatch.setattr(fxmod, "profile_root", lambda: tmp_path / "profile_root")

    install_calls: dict[str, object] = {}

    def fake_install_policies(**kwargs):
        install_calls.update(kwargs)
        return tmp_path / "policies.json"

    monkeypatch.setattr(fxmod, "install_policies", fake_install_policies)

    launch_calls: dict[str, object] = {}

    def fake_launch(**kwargs):
        launch_calls.update(kwargs)

        class _R:
            pid = 99
            exe = kwargs["exe"]
            profile = kwargs["profile_dir"]
            policies = tmp_path / "policies.json"
        return _R()

    monkeypatch.setattr(fxmod, "launch", fake_launch)

    fxmod.run_browser(
        ca_path=ca,
        proxy_host="127.0.0.1", proxy_port=8080,
        ui_url="http://127.0.0.1:8787/",
        prefer_cache=True, wait=False,
        project=project,
    )
    project.close()

    # XPI was built and handed to install_policies.
    xpi = install_calls["dom_hunter_xpi"]
    assert xpi is not None
    assert isinstance(xpi, Path)
    assert xpi.exists(), f"XPI not actually written to disk: {xpi}"
    # Bridge URL is the UI URL stripped of trailing slashes.
    assert install_calls["dom_hunter_bridge_url"] == "http://127.0.0.1:8787"
    # Token is non-empty and looks like a real secret.
    token = install_calls["dom_hunter_token"]
    assert isinstance(token, str) and len(token) >= 32

    # Belt-and-suspenders sideload: XPI must also be in the profile, and
    # user.js must enable unsigned-XPI loading. Without this, a corporate
    # HKLM ExtensionSettings policy (which replaces our distribution
    # policies.json entry wholesale) would leave the user with no add-on
    # at all.
    sideloaded = tmp_path / "profile" / "extensions" / \
        f"{fxmod.DOM_HUNTER_EXT_ID}.xpi"
    assert sideloaded.exists(), \
        f"DOM Hunter not sideloaded into profile: {sideloaded}"
    user_js = (tmp_path / "profile" / "user.js").read_text(encoding="utf-8")
    assert 'xpinstall.signatures.required' in user_js
    assert 'extensions.autoDisableScopes' in user_js


def test_sideload_dom_hunter_is_idempotent(tmp_path: Path) -> None:
    """Re-running `reqlore browser --project` must not duplicate the
    user.js block or fail on an existing XPI. Failure mode: garbage user.js
    accumulates and eventually breaks parsing."""
    from reqlore import browser as fxmod
    profile = tmp_path / "p"
    profile.mkdir()
    xpi = tmp_path / "src.xpi"
    xpi.write_bytes(b"PK\x03\x04")
    (profile / "user.js").write_text("// existing\n", encoding="utf-8")

    dest1 = fxmod.sideload_dom_hunter(profile_dir=profile, xpi_path=xpi)
    dest2 = fxmod.sideload_dom_hunter(profile_dir=profile, xpi_path=xpi)
    assert dest1 == dest2 == profile / "extensions" / \
        f"{fxmod.DOM_HUNTER_EXT_ID}.xpi"
    user_js = (profile / "user.js").read_text(encoding="utf-8")
    # Marker appears exactly once even after two runs.
    assert user_js.count("// >>> reqlore: DOM Hunter sideload prefs") == 1


def test_run_browser_without_project_does_not_install_extension(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No --project -> no XPI -> install_policies must receive None
    for the DOM Hunter args (so we don't ship a broken policy)."""
    from reqlore import browser as fxmod

    ca = tmp_path / "ca.pem"
    ca.write_text("dummy")
    fake_exe = tmp_path / "firefox.exe"
    fake_exe.write_bytes(b"")
    monkeypatch.setattr(fxmod, "find_firefox",
                        lambda prefer_cache=True, channel=None: fake_exe)
    monkeypatch.setattr(fxmod, "ensure_linux_runtime", lambda exe: [])
    monkeypatch.setattr(fxmod, "ensure_profile", lambda *a, **k: tmp_path / "profile")

    install_calls: dict[str, object] = {}
    monkeypatch.setattr(fxmod, "install_policies",
                        lambda **kw: install_calls.update(kw) or tmp_path / "p.json")
    monkeypatch.setattr(fxmod, "launch",
                        lambda **kw: type("R", (), {"pid": 1, "exe": kw["exe"],
                                                    "profile": kw["profile_dir"],
                                                    "policies": tmp_path / "p.json"})())

    fxmod.run_browser(ca_path=ca, proxy_host="127.0.0.1", proxy_port=8080,
                      ui_url="http://127.0.0.1:8787/")

    assert install_calls["dom_hunter_xpi"] is None
    assert install_calls["dom_hunter_bridge_url"] is None
    assert install_calls["dom_hunter_token"] is None


def test_bridge_endpoints_bypass_csrf_with_missing_token(
        app_and_client) -> None:
    """The bridge endpoints MUST NOT be rejected by the global CSRF
    before_request, because the extension has no Reqlore session cookie.
    Without the exemption, the request would 400 with 'CSRF token mismatch'
    instead of the bridge's own 401, and findings would silently never
    arrive in Reqlore."""
    _, c = app_and_client
    r = c.post("/dom-hunter/__bridge/report",
               json={"kind": "finding"})
    # 401 from the bridge auth check (no token), NOT 400 from CSRF.
    assert r.status_code == 401, (
        "CSRF exemption broken: bridge POST without token returned "
        f"{r.status_code} (body={r.data!r})"
    )



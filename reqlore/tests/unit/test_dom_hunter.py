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


def test_extension_extension_pages_dont_use_per_tab_scope_check() -> None:
    """Regression for the bug where the DevTools panel always showed
    'Tracer: off / Canary: (none yet)' even when DOM Hunter was enabled
    in Reqlore.

    Root cause: extension pages (panel / popup / options) sent the
    `dom_hunter.requestConfig` message to the background service worker.
    For content scripts, `sender.tab.url` carries the inspected URL and
    the background runs the configured scope filter against it. For an
    extension PAGE, `sender.tab` is undefined and `sender.url` is the
    moz-extension:// URL of the page itself -- the extension UUID host
    never matches any user-defined scope like 'localhost:3001', so the
    background returns `{enabled: false}` and the panel falsely reports
    the tracer as off.

    The fix is twofold:

      1. The background MUST expose a `dom_hunter.getProjectConfig`
         message that returns the raw bridge config (no per-tab scope
         filter). Extension pages use it for project-level UI.
      2. `dom_hunter.requestConfig` MUST honor caller-supplied
         {tabId, url} overrides so the DevTools panel can ask
         'is the INSPECTED tab in scope?' rather than 'is the panel
         page in scope?' (which it never is).
    """
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None

    sw = (src / "background" / "service_worker.js").read_text(encoding="utf-8")
    # 1) Background advertises the new message.
    assert '"dom_hunter.getProjectConfig"' in sw, (
        "background/service_worker.js must handle dom_hunter.getProjectConfig "
        "so extension pages can read project state without per-tab scope "
        "gating that would always fail on moz-extension:// URLs."
    )
    # 2) requestConfig honors caller-supplied tab info.
    assert "msg.tabId" in sw and "msg.url" in sw, (
        "background/service_worker.js requestConfig handler must accept "
        "{tabId, url} overrides from the caller so the DevTools panel "
        "can target the INSPECTED tab, not the panel page."
    )

    # 3) Panel asks for project state, not the panel page's state.
    panel = (src / "devtools" / "panel.js").read_text(encoding="utf-8")
    assert '"dom_hunter.getProjectConfig"' in panel, (
        "devtools/panel.js must use dom_hunter.getProjectConfig for the "
        "global Tracer/Canary status. Otherwise it scope-filters against "
        "its own moz-extension:// URL and falsely reports 'off'."
    )
    # 4) When the panel does call requestConfig it must pass the
    #    inspected tab's id and URL, not let the background guess.
    assert "INSPECTED_TAB_ID" in panel
    assert "tabId: INSPECTED_TAB_ID" in panel
    assert "url: inspectedUrl" in panel

    # 5) Options + popup must not rely on per-tab requestConfig for
    #    project-level reads either (same reason -- extension pages).
    options_js = (src / "ui" / "options.js").read_text(encoding="utf-8")
    popup_js = (src / "ui" / "popup.js").read_text(encoding="utf-8")
    assert '"dom_hunter.getProjectConfig"' in options_js
    assert '"dom_hunter.getProjectConfig"' in popup_js


def test_extension_options_default_base_url_is_ui_port() -> None:
    """The options page falls back to a default base URL when the user
    hasn't saved anything. That default MUST be the Reqlore UI port
    (8787), not the proxy port (8080). The bridge lives on the UI.
    """
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    options_js = (src / "ui" / "options.js").read_text(encoding="utf-8")
    assert '"http://127.0.0.1:8787"' in options_js
    assert '"http://127.0.0.1:8080"' not in options_js


def test_extension_panel_reloads_via_devtools_api_not_browser_tabs() -> None:
    """The DevTools panel must NOT call browser.tabs.reload(): in Firefox
    `browser.tabs` is undefined inside a devtools page even with the
    `tabs` permission, so the Apply-and-reload button blew up with
    'browser.tabs is undefined'. The correct API is
    browser.devtools.inspectedWindow.reload(), with a background-mediated
    fallback for engines that don't expose it.
    """
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    panel = (src / "devtools" / "panel.js").read_text(encoding="utf-8")
    assert "browser.devtools.inspectedWindow.reload" in panel, (
        "panel.js must reload via devtools.inspectedWindow.reload()"
    )
    assert "browser.tabs.reload" not in panel, (
        "panel.js must not call browser.tabs.reload() directly -- "
        "browser.tabs is undefined inside a Firefox devtools page"
    )
    sw = (src / "background" / "service_worker.js").read_text(encoding="utf-8")
    assert '"dom_hunter.reloadTab"' in sw


def test_extension_diagnose_surfaces_real_failure_reason() -> None:
    """When the bridge call returns null the panel must NOT just say
    'cannot reach Reqlore' -- the most common cause is a token mismatch
    (different --project between `reqlore web` and `reqlore browser`,
    or a token rotation since launch), which manifests as an HTTP 401
    and is invisible to the user otherwise. Surface the actual reason
    via a fresh uncached probe (`dom_hunter.diagnose`).
    """
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    sw = (src / "background" / "service_worker.js").read_text(encoding="utf-8")
    # The background must expose a diagnose handler that does an
    # uncached probe and reports the failure kind.
    assert '"dom_hunter.diagnose"' in sw
    assert "diagnoseBridge" in sw
    assert '"no-token"' in sw
    assert '"http"' in sw
    assert '"network"' in sw

    # The DevTools panel must call diagnose and surface 401/404
    # specifically (the two most common, most actionable errors).
    panel = (src / "devtools" / "panel.js").read_text(encoding="utf-8")
    assert '"dom_hunter.diagnose"' in panel
    assert "describeBridgeFailure" in panel
    assert "HTTP 401" in panel
    assert "HTTP 404" in panel
    assert "token mismatch" in panel

    # The options page's "Test connection" button must also do this --
    # users debug their config there, not in the DevTools panel.
    opts = (src / "ui" / "options.js").read_text(encoding="utf-8")
    assert '"dom_hunter.diagnose"' in opts
    assert "HTTP 401" in opts


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

    from reqlore.browser import DOM_HUNTER_EXT_ID
    ext_id = DOM_HUNTER_EXT_ID
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
    from reqlore.browser import DOM_HUNTER_EXT_ID
    ext_id = DOM_HUNTER_EXT_ID
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


def test_sideload_dom_hunter_skips_replace_when_already_up_to_date(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When the on-disk XPI is byte-identical to the source, sideload
    must not touch the file -- so a managed Firefox holding the XPI
    open (Windows: WinError 5) does not break re-launch.

    Regression: `reqlore browser --project foo.rlr` then re-running it
    while the first browser was still open used to raise
    PermissionError on `tmp.replace(dest)` and log a cryptic
    'sideload skipped' line even though the XPI on disk was correct."""
    from reqlore import browser as fxmod
    profile = tmp_path / "p"
    profile.mkdir()
    xpi = tmp_path / "src.xpi"
    xpi.write_bytes(b"PK\x03\x04hello")
    # Prime the profile with the right XPI.
    fxmod.sideload_dom_hunter(profile_dir=profile, xpi_path=xpi)

    # Now simulate Firefox holding the file open: any attempt to copy
    # or replace would raise PermissionError. The function must NOT
    # call into shutil/Path.replace at all on the second invocation.
    def _explode(*_a, **_kw):
        raise AssertionError(
            "sideload must not copy/replace when XPI is already up to date"
        )

    monkeypatch.setattr(fxmod.shutil, "copy2", _explode)
    monkeypatch.setattr(fxmod.Path, "replace", _explode)

    dest = fxmod.sideload_dom_hunter(profile_dir=profile, xpi_path=xpi)
    assert dest.exists() and dest.read_bytes() == b"PK\x03\x04hello"


def test_sideload_dom_hunter_locked_xpi_raises_actionable_error(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """When the on-disk XPI is *different* from the source AND the
    replace fails with PermissionError (typical Windows 'file in use'),
    sideload must surface an error message that names the cause and
    the fix, and must not leave a stale .xpi.tmp behind."""
    from reqlore import browser as fxmod
    profile = tmp_path / "p"
    profile.mkdir()
    xpi = tmp_path / "src.xpi"
    xpi.write_bytes(b"PK\x03\x04NEW-CONTENT")
    # Existing dest XPI with DIFFERENT content -- forces the copy path.
    ext_dir = profile / "extensions"
    ext_dir.mkdir()
    dest = ext_dir / f"{fxmod.DOM_HUNTER_EXT_ID}.xpi"
    dest.write_bytes(b"PK\x03\x04OLD")

    # Simulate Firefox holding the dest file open.
    real_replace = fxmod.Path.replace

    def _locked_replace(self, target):
        if str(target).endswith(f"{fxmod.DOM_HUNTER_EXT_ID}.xpi"):
            raise PermissionError(
                13, "Access is denied",
                str(self), None, str(target),
            )
        return real_replace(self, target)

    monkeypatch.setattr(fxmod.Path, "replace", _locked_replace)

    with pytest.raises(PermissionError) as exc_info:
        fxmod.sideload_dom_hunter(profile_dir=profile, xpi_path=xpi)

    # The message must name the real cause + the fix.
    msg = str(exc_info.value)
    assert "file is in use" in msg
    assert "reqlore browser" in msg
    # And no stale tmp leftover.
    assert not (ext_dir / f"{fxmod.DOM_HUNTER_EXT_ID}.xpi.tmp").exists()


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




# ---------------------------------------------------------------------------
# Proxy-side Referer canary injection (document.referrer auto-inject)
# ---------------------------------------------------------------------------


def test_inject_referer_canary_appends_to_existing_query() -> None:
    headers = [("Host", "example.com"), ("Referer", "https://a.test/x?q=1")]
    out = S.inject_referer_canary(headers, "rl_abc")
    ref = dict(out)["Referer"]
    assert ref == "https://a.test/x?q=1&rqdomh=rl_abc"
    # Original list untouched (function returns a copy).
    assert dict(headers)["Referer"] == "https://a.test/x?q=1"


def test_inject_referer_canary_adds_question_mark_when_no_query() -> None:
    headers = [("Referer", "https://a.test/path")]
    out = S.inject_referer_canary(headers, "rl_abc")
    assert dict(out)["Referer"] == "https://a.test/path?rqdomh=rl_abc"


def test_inject_referer_canary_preserves_fragment() -> None:
    headers = [("Referer", "https://a.test/x?q=1#section")]
    out = S.inject_referer_canary(headers, "rl_abc")
    assert dict(out)["Referer"] == "https://a.test/x?q=1&rqdomh=rl_abc#section"


def test_inject_referer_canary_is_idempotent() -> None:
    headers = [("Referer", "https://a.test/x?rqdomh=rl_abc")]
    out = S.inject_referer_canary(headers, "rl_abc")
    # Already present -- must not double-append.
    assert dict(out)["Referer"] == "https://a.test/x?rqdomh=rl_abc"


def test_inject_referer_canary_skips_when_no_referer_header() -> None:
    """Deliberately do NOT synthesise a Referer header when the browser
    omitted one. Adding one would leak origin info the user's
    Referrer-Policy explicitly suppressed."""
    headers = [("Host", "example.com")]
    out = S.inject_referer_canary(headers, "rl_abc")
    assert out == headers
    assert "Referer" not in dict(out)


def test_inject_referer_canary_skips_when_canary_empty() -> None:
    headers = [("Referer", "https://a.test/x")]
    assert S.inject_referer_canary(headers, "") == headers


def test_inject_referer_canary_only_first_referer_rewritten() -> None:
    """RFC 7230 forbids duplicate Referer, but proxies see broken
    clients. Be deterministic: rewrite the first, leave the rest."""
    headers = [
        ("Referer", "https://a.test/x"),
        ("Referer", "https://b.test/y"),
    ]
    out = S.inject_referer_canary(headers, "rl_abc")
    refs = [v for k, v in out if k.lower() == "referer"]
    assert refs == ["https://a.test/x?rqdomh=rl_abc", "https://b.test/y"]


def test_inject_referer_canary_case_insensitive_header_name() -> None:
    headers = [("referer", "https://a.test/x")]
    out = S.inject_referer_canary(headers, "rl_abc")
    # Preserve the original casing of the header name; only the value
    # changes.
    assert out == [("referer", "https://a.test/x?rqdomh=rl_abc")]


def test_should_inject_referer_requires_enabled_and_target_and_scope(
        tmp_path: Path) -> None:
    proj_path = tmp_path / "x.rlr"
    Project(proj_path).close()
    proj = Project(proj_path)

    # Default: nothing enabled -> False.
    assert S.should_inject_referer(proj, "example.com") is False

    # Enabled but no auto-inject target -> still False.
    S.set_enabled(proj, True)
    assert S.should_inject_referer(proj, "example.com") is False

    # Wrong target -> False.
    S.set_auto_inject(proj, ["location.hash"])
    assert S.should_inject_referer(proj, "example.com") is False

    # Right target, empty scope (means "all hosts") -> True.
    S.set_auto_inject(proj, ["document.referrer"])
    assert S.should_inject_referer(proj, "example.com") is True

    # Right target, scope mismatch -> False.
    S.set_scope(proj, ["only.test"])
    assert S.should_inject_referer(proj, "example.com") is False

    # Right target, scope match -> True.
    assert S.should_inject_referer(proj, "only.test") is True

    # Disabled overrides everything.
    S.set_enabled(proj, False)
    assert S.should_inject_referer(proj, "only.test") is False
    proj.close()


def test_proxy_request_hook_injects_referer_canary(tmp_path: Path) -> None:
    """End-to-end-ish: build a fake mitmproxy flow, run the addon's
    request hook against it, and assert the Referer header now carries
    the canary. Verifies the wiring between dom_hunter and proxy.mitm."""
    import asyncio
    from reqlore.proxy.mitm import _HistoryAddon

    proj_path = tmp_path / "y.rlr"
    Project(proj_path).close()
    proj = Project(proj_path)
    S.set_enabled(proj, True)
    S.set_auto_inject(proj, ["document.referrer"])
    canary = S.get_or_make_canary(proj)

    class _Headers(dict):
        def items(self):
            return list(super().items())
        def clear(self):
            super().clear()
    class _Req:
        def __init__(self):
            self.pretty_host = "example.com"
            self.pretty_url = "https://example.com/a"
            self.path = "/a"
            self.method = "GET"
            self.http_version = "HTTP/1.1"
            self.headers = _Headers({
                "Host": "example.com",
                "Referer": "https://example.com/prev",
            })
            self.raw_content = b""
        def set_content(self, b):
            self.raw_content = b
    class _Flow:
        def __init__(self):
            self.request = _Req()

    addon = _HistoryAddon(proj, rules=[], sync_hold=False, ui_port=8787)
    flow = _Flow()
    asyncio.run(addon.request(flow))
    assert flow.request.headers["Referer"] == \
        f"https://example.com/prev?rqdomh={canary}"
    proj.close()


def test_proxy_request_hook_leaves_referer_alone_when_disabled(
        tmp_path: Path) -> None:
    import asyncio
    from reqlore.proxy.mitm import _HistoryAddon

    proj_path = tmp_path / "z.rlr"
    Project(proj_path).close()
    proj = Project(proj_path)
    # Enabled but auto-inject does NOT include document.referrer.
    S.set_enabled(proj, True)
    S.set_auto_inject(proj, ["location.hash"])

    class _Headers(dict):
        def items(self):
            return list(super().items())
        def clear(self):
            super().clear()
    class _Req:
        pretty_host = "example.com"
        pretty_url = "https://example.com/a"
        path = "/a"
        method = "GET"
        http_version = "HTTP/1.1"
        def __init__(self):
            self.headers = _Headers({"Referer": "https://example.com/prev"})
            self.raw_content = b""
        def set_content(self, b):
            self.raw_content = b
    class _Flow:
        def __init__(self):
            self.request = _Req()

    addon = _HistoryAddon(proj, rules=[], sync_hold=False, ui_port=8787)
    flow = _Flow()
    asyncio.run(addon.request(flow))
    # Untouched.
    assert flow.request.headers["Referer"] == "https://example.com/prev"
    proj.close()


def test_agent_js_no_longer_claims_referer_is_unsupported() -> None:
    """The agent.js comment used to say document.referrer is read-only
    and could not be auto-injected; that's now handled by the proxy.
    Make sure the comment reflects the new reality so future readers
    don't think the checkbox is dead."""
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    agent = (src / "content" / "agent.js").read_text(encoding="utf-8")
    assert "inject_referer_canary" in agent, (
        "agent.js comment must point readers at the proxy-side helper "
        "now that document.referrer auto-inject actually works."
    )


# Source attribution -- detectSource() in agent.js
#
# Before this fix the agent hardcoded "unknown" as the source on every
# sink-fire report, so the UI always showed "Source: unknown" even when
# the canary obviously came from location.hash. agent.js now runs a
# precedence-ordered detectSource(value) at sink-fire time. These tests
# guard the wiring at the text level (we have no JS runtime in CI).


def _read_agent_js() -> str:
    from reqlore.dom_hunter.packager import find_extension_source
    src = find_extension_source()
    assert src is not None
    return (src / "content" / "agent.js").read_text(encoding="utf-8")


def test_agent_js_defines_detect_source() -> None:
    agent = _read_agent_js()
    assert "function detectSource(" in agent, (
        "agent.js must define detectSource(value) to attribute sink "
        "hits to a DOM source instead of always emitting 'unknown'."
    )
    assert "function _rqdomhSourceScore(" in agent, (
        "detectSource relies on _rqdomhSourceScore() to rank "
        "candidate sources by overlap with the sink value."
    )


def test_agent_js_sink_reports_use_detect_source() -> None:
    """Every report('finding', ...) call inside a sink wrapper MUST
    pass detectSource(...) as the source argument. Any remaining
    hardcoded 'unknown' would mean the finding UI shows 'Source:
    unknown' even when the canary clearly came from a known source."""
    agent = _read_agent_js()
    import re
    # Match: report("finding", <sink-expr>, <source-expr>, ...)
    pattern = re.compile(
        r'report\(\s*"finding"\s*,\s*[^,]+,\s*([^,]+?)\s*,',
        re.MULTILINE,
    )
    matches = pattern.findall(agent)
    assert matches, "expected at least one report('finding', ...) call"
    bad = [m for m in matches if "detectSource(" not in m]
    assert not bad, (
        "every sink-fire report must use detectSource() for source "
        f"attribution; found hardcoded source expressions: {bad!r}"
    )


def test_agent_js_detect_source_precedence_documented() -> None:
    """The precedence order survives as the DISPLAY order when more
    than one source contains the canary that reached the sink. The
    comment must still call out precedence so a future reader does
    not reshuffle the candidate list and silently change attribution
    order in the UI."""
    agent = _read_agent_js()
    assert "precedence" in agent.lower(), (
        "detectSource() must document its precedence-ordered display."
    )
    # When more than one source matches, ALL must be reported (joined),
    # not just the highest-precedence one.
    assert 'matched.join(",")' in agent, (
        "detectSource() must join every matching source id, not pick "
        "one winner -- otherwise the user who ticks every auto-inject "
        "toggle sees only one of the channels the canary travelled "
        "through."
    )


def test_agent_js_detect_source_emits_only_known_source_ids() -> None:
    """Every literal source id detectSource() can put into a finding
    MUST exist in reqlore.dom_hunter.SOURCE_INDEX -- otherwise the
    bridge will drop it on insert and the attribution is silently
    lost. The agent now collects matches into matched[] and joins
    them, so we scan the whole function body for source-id literals,
    not just literal `return "...";` statements."""
    from reqlore.dom_hunter import SOURCE_INDEX
    agent = _read_agent_js()
    import re
    body_match = re.search(
        r"function detectSource\([^)]*\)\s*\{(.+?)\n\s*\}\s*\n",
        agent, re.DOTALL,
    )
    assert body_match, "could not locate detectSource() body in agent.js"
    body = body_match.group(1)
    # Every double-quoted string in the function body. We then filter
    # to the ones that look like a source id (dotted identifier, or
    # one of the bare source ids). The body contains many empty `""`
    # placeholders inside try/catch lines, so the literal-extraction
    # regex must reject anything containing whitespace -- otherwise
    # a pair of empty quotes on consecutive statements gets joined
    # into one fake "literal" that spans them.
    literals = set(re.findall(r'"([^"\s]+)"', body))
    candidates = {
        s for s in literals
        if "." in s
        or s in {"postMessage", "localStorage", "sessionStorage",
                 "window.name"}
    }
    assert candidates, "detectSource() defines no source-id literals?"
    allowed = set(SOURCE_INDEX) | {"unknown"}
    bogus = candidates - allowed
    assert not bogus, (
        f"detectSource() emits source id(s) {sorted(bogus)!r} which "
        f"are not in SOURCE_INDEX; the bridge will drop them."
    )


def test_agent_js_source_score_tolerates_decoded_source() -> None:
    """Pages frequently decodeURIComponent(location.hash) before piping
    it into a sink, so the raw `location.hash` string still has the
    canary URL-encoded while the value at the sink is decoded. The
    matcher must try the decoded form of every source variant -- if
    it does not, `location.hash` is silently dropped from the
    attribution and the user sees `location.search` (or worse,
    `unknown`) for a hash-sourced bug."""
    agent = _read_agent_js()
    assert "_rqdomhSafeDecode" in agent, (
        "_rqdomhSourceScore must consult a decoded variant of each "
        "source value so URL-decoded payloads still attribute back to "
        "the source they came from."
    )
    assert "decodeURIComponent" in agent, (
        "agent.js must call decodeURIComponent somewhere in the "
        "source-matching path."
    )


def test_agent_js_tracks_postmessage_canary_for_attribution() -> None:
    """A sink that fires inside a postMessage handler chain should be
    attributable to 'postMessage'. The agent keeps a small ring buffer
    of recent canary-bearing payloads (not a single slot, so concurrent
    handlers don't race) for detectSource() to scan."""
    agent = _read_agent_js()
    assert "messageCanaryBuffer" in agent, (
        "agent.js must keep a ring buffer of canary-bearing "
        "postMessage data so detectSource() can attribute sinks "
        "fired inside a message handler chain."
    )
    assert "_rqdomhPushMessageCanary" in agent, (
        "the buffer must be populated through the push helper from "
        "the wrapped message listener."
    )


def test_agent_js_wraps_removeeventlistener_for_message() -> None:
    """Wrapping addEventListener(\"message\", fn) means the listener
    actually registered is a wrapper, not fn. removeEventListener(
    \"message\", fn) then silently fails unless we also wrap it to
    look up the wrapper through the WeakMap. Without this fix, long-
    lived SPAs accumulate stale message handlers."""
    agent = _read_agent_js()
    assert "messageListenerWrapMap" in agent, (
        "agent.js must maintain a WeakMap of original message "
        "listeners to their wrappers so removeEventListener can find "
        "the right registration to remove."
    )
    assert "removeEventListener" in agent, (
        "agent.js must wrap removeEventListener to look up the "
        "wrapper via messageListenerWrapMap."
    )
    assert "_rqdomh_remove" in agent, (
        "the removeEventListener wrapper must be named _rqdomh_remove "
        "so its frames are trimmed from reported stacks like the rest."
    )


def test_agent_js_snapshots_initial_source_values() -> None:
    """Pages frequently read e.g. location.hash then call
    history.replaceState(...) to clean the URL. By the time a later
    sink fires, the live source no longer contains the canary --
    attribution would fall through to 'unknown'. The agent must
    snapshot initial values at document_start and consult them as a
    fallback in detectSource()."""
    agent = _read_agent_js()
    assert "const initial = {" in agent or "const initial = { " in agent, (
        "agent.js must snapshot initial.hash / search / pathname / "
        "referrer / name at load time."
    )
    for field in ("initial.hash", "initial.search", "initial.pathname",
                  "initial.referrer", "initial.name"):
        assert field in agent, f"missing snapshot field: {field}"


def test_agent_js_uses_overlap_scoring_for_source_attribution() -> None:
    """When the canary is present in multiple sources (e.g. user has
    auto-inject ticked for both hash and search) the agent must
    surface EVERY matching source instead of guessing a single
    winner. The score helper still exists so we can drop a source
    with no verified overlap."""
    agent = _read_agent_js()
    assert "_rqdomhSourceScore" in agent, (
        "agent.js must define a source-score helper used by "
        "detectSource() to gate each candidate."
    )
    # Each candidate with a positive score is pushed into matched[]
    # rather than being passed through a single-winner comparison.
    assert "matched.push(" in agent, (
        "detectSource() must collect every matching source id "
        "(matched.push) -- not pick one winner -- so all channels "
        "the canary travelled through are visible in the finding."
    )


def test_agent_js_report_recaptures_page_url() -> None:
    """SPA route changes between hook fire and report would otherwise
    leave the stored finding pointing at a stale URL. report() must
    recapture location.href right before posting."""
    agent = _read_agent_js()
    # Look inside the report() function body.
    import re
    body = re.search(r"function report\([^)]*\)\s*\{(.+?)\n  \}\n",
                     agent, re.DOTALL)
    assert body, "could not locate report() body in agent.js"
    text = body.group(1)
    assert "location.href" in text, (
        "report() must recapture location.href so SPA route changes "
        "between sink fire and report show the right page_url."
    )


def test_agent_js_truncates_stack_for_relay() -> None:
    """The relay postMessage must stay well under the structured-clone\n    limit on huge minified pages. Stack must be capped before send."""
    agent = _read_agent_js()
    assert "trimmed.slice(0, 8000)" in agent or "slice(0, 8000)" in agent, (
        "report() must cap the stack length before relaying."
    )


def test_agent_js_hooks_new_high_impact_sinks() -> None:
    """Professional-grade DOM-XSS coverage requires more than just\n    innerHTML. These sinks are commonly exploited but were missing."""
    agent = _read_agent_js()
    for sink_id, hook_marker in [
        ("HTMLIFrameElement.srcdoc", "\"srcdoc\""),
        ("DOMParser.parseFromString", "\"parseFromString\""),
        ("Range.createContextualFragment", "\"createContextualFragment\""),
        ("Worker", "ProxiedWorker"),
    ]:
        assert sink_id in agent, (
            f"agent.js must report sink id {sink_id!r}"
        )
        assert hook_marker in agent, (
            f"agent.js must install a hook for {sink_id!r} "
            f"(looking for marker {hook_marker!r})"
        )


def test_dom_hunter_sink_index_contains_new_sinks() -> None:
    """Every literal sink id agent.js can emit MUST exist in\n    SINK_INDEX or the bridge will refuse the finding."""
    from reqlore.dom_hunter import SINK_INDEX
    required = {
        "Element.innerHTML", "Element.outerHTML",
        "Element.insertAdjacentHTML", "Element.setAttribute(on*)",
        "document.write", "document.writeln",
        "HTMLScriptElement.src", "HTMLIFrameElement.src",
        "HTMLIFrameElement.srcdoc",
        "DOMParser.parseFromString", "Range.createContextualFragment",
        "Worker",
        "eval", "Function", "setTimeout(string)", "setInterval(string)",
    }
    missing = required - set(SINK_INDEX)
    assert not missing, (
        f"SINK_INDEX missing ids that agent.js can emit: {missing!r}"
    )


def test_dom_hunter_source_index_contains_all_attributable_sources() -> None:
    """detectSource() emits these ids; SOURCE_INDEX must know them so
    the bridge accepts and the UI labels them correctly."""
    from reqlore.dom_hunter import SOURCE_INDEX
    required = {
        "location.hash", "location.search", "location.pathname",
        "document.referrer", "window.name", "document.cookie",
        "postMessage", "localStorage", "sessionStorage", "unknown",
    }
    missing = required - set(SOURCE_INDEX)
    assert not missing, (
        f"SOURCE_INDEX missing ids that detectSource() can emit: {missing!r}"
    )


# Findings table UX (commit before this one shipped raw unix ts and a
# verbose "View finding N" link that overflowed the Action column).


def _seed_finding_for_ui(app, c, ts: int = 1781551861) -> int:
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    r = c.post("/dom-hunter/__bridge/report", json={
        "kind": "finding",
        "sink": "Element.innerHTML",
        "source": "location.hash",
        "severity": "high",
        "canary_seen": True,
        "page_url": "http://localhost:3001/login",
        "frame_url": "http://localhost:3001/login",
        "value": "rqdomh=x",
        "stack": "applyHashMessage@app.js:21:5",
    }, headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    fid = r.get_json()["id"]
    # Backfill the ts so we exercise the formatter on a known value.
    with proj._cursor() as cur:  # noqa: SLF001 - test helper
        cur.execute(
            "UPDATE dom_hunter_findings SET ts=? WHERE id=?", (ts, fid),
        )
    proj._conn.commit()  # noqa: SLF001 - test helper
    return fid


def test_findings_table_formats_unix_timestamp_for_humans(app_and_client):
    """A pentester reading the findings table should see a real
    timestamp (e.g. '2026-06-15 21:51:01 UTC'), not the raw integer.
    The <time> element must still carry an ISO 8601 datetime= attr for
    screen readers and machine consumers."""
    app, c = app_and_client
    _seed_finding_for_ui(app, c, ts=1781551861)
    page = c.get("/dom-hunter/")
    assert page.status_code == 200
    body = page.data.decode("utf-8")
    # Human-readable text inside the <time>.
    assert "2026-06-15 19:31:01 UTC" in body, (
        "findings table must format unix ts as a readable UTC string, "
        "not show the raw integer."
    )
    # ISO 8601 in the datetime attribute.
    assert 'datetime="2026-06-15T19:31:01Z"' in body, (
        "<time datetime=...> must be ISO 8601 for screen readers and "
        "machine consumers."
    )
    # The raw integer must NOT appear as bare visible text in the row.
    assert ">1781551861<" not in body, (
        "raw unix integer should never appear as visible cell text."
    )


def test_findings_table_action_link_is_short_with_descriptive_aria(app_and_client):
    """The Action column should display a short label ('View'); the
    full descriptive context belongs in aria-label so the column stays
    readable on narrow viewports without losing accessibility."""
    app, c = app_and_client
    fid = _seed_finding_for_ui(app, c)
    page = c.get("/dom-hunter/")
    body = page.data.decode("utf-8")
    # Visible text is the short label.
    assert ">\n             View</a>" in body or ">View</a>" in body, (
        "Action column link text must be the short 'View' label."
    )
    # And no longer the verbose visible text.
    assert f"View finding {fid}</a>" not in body, (
        "Verbose 'View finding N' text must move out of the visible "
        "column and into aria-label only."
    )
    # aria-label gives the screen reader the finding id so the user knows
    # which row they are activating; full details belong on the detail page.
    assert f'aria-label="View finding {fid}"' in body


def test_unixtime_filters_are_safe_on_bad_input(app_and_client):
    """The template filters must never blow up a template render --
    fall back to a string form on garbage input."""
    app, _ = app_and_client
    iso = app.jinja_env.filters["unixtime_iso"]
    human = app.jinja_env.filters["unixtime_human"]
    # Happy path.
    assert iso(1781551861) == "2026-06-15T19:31:01Z"
    assert human(1781551861) == "2026-06-15 19:31:01 UTC"
    # Garbage in, garbage-but-safe out.
    assert iso(None) == ""
    assert human(None) == ""
    assert iso("not-a-number") == "not-a-number"
    assert human("not-a-number") == "not-a-number"


def test_detail_page_formats_unix_timestamp(app_and_client):
    """Same fix applies to the 'First reported' field on the detail
    page; otherwise users see a raw integer there too."""
    app, c = app_and_client
    fid = _seed_finding_for_ui(app, c, ts=1781548517)
    page = c.get(f"/dom-hunter/finding/{fid}")
    assert page.status_code == 200
    body = page.data.decode("utf-8")
    assert "2026-06-15 18:35:17 UTC" in body
    assert ">1781548517<" not in body


# Multi-source attribution -- bridge accepts comma-joined source ids
#
# When the user ticks every auto-inject toggle and the page reads
# more than one of them, detectSource() now emits e.g.
# "location.hash,location.search" instead of picking one winner. The
# bridge must validate each part independently against SOURCE_INDEX
# and the UI must render each part as its own chip.


def test_bridge_accepts_comma_joined_multi_source(app_and_client):
    """Bridge must store every known source id from a comma-joined
    'source' value, in the order received, deduped."""
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    r = c.post("/dom-hunter/__bridge/report", json={
        "kind": "finding",
        "sink": "Element.innerHTML",
        "source": "location.hash,location.search",
        "severity": "high",
        "canary_seen": True,
        "page_url": "https://x/",
        "value": "rqdomh-test",
        "stack": "Error\n    at f (a.js:1:1)",
    }, headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    rows = proj.list_dom_hunter_findings()
    assert len(rows) == 1
    assert rows[0]["source"] == "location.hash,location.search"


def test_bridge_drops_unknown_parts_from_multi_source(app_and_client):
    """Unknown source ids in the middle of a comma-joined value must
    be silently dropped, leaving the known parts. If nothing
    survives, fall back to 'unknown' (not '')."""
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)

    # Mixed known + unknown.
    r = c.post("/dom-hunter/__bridge/report", json={
        "kind": "finding",
        "sink": "eval",
        "source": "location.hash,not-a-real-source,location.search",
        "page_url": "https://x/a",
        "value": "y", "stack": "",
    }, headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200

    # All-unknown.
    r = c.post("/dom-hunter/__bridge/report", json={
        "kind": "finding",
        "sink": "eval",
        "source": "nope,bogus",
        "page_url": "https://x/b",
        "value": "y2", "stack": "",
    }, headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200

    rows = proj.list_dom_hunter_findings()
    by_url = {r["page_url"]: r["source"] for r in rows}
    assert by_url["https://x/a"] == "location.hash,location.search"
    assert by_url["https://x/b"] == "unknown"


def test_bridge_dedupes_repeated_source_ids(app_and_client):
    """`location.hash,location.hash` must collapse to `location.hash`
    -- otherwise the live + snapshot pair the agent passes for
    robustness would double-print on the UI."""
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    r = c.post("/dom-hunter/__bridge/report", json={
        "kind": "finding",
        "sink": "eval",
        "source": "location.hash,location.hash,location.search",
        "page_url": "https://x/",
        "value": "z", "stack": "",
    }, headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    rows = proj.list_dom_hunter_findings()
    assert rows[0]["source"] == "location.hash,location.search"


def _seed_multi_source_finding(app, c, *, source: str = "location.hash,location.search"):
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    r = c.post("/dom-hunter/__bridge/report", json={
        "kind": "finding",
        "sink": "Element.innerHTML",
        "source": source,
        "severity": "high",
        "canary_seen": True,
        "page_url": "https://example.test/p",
        "value": "<img src=x onerror=alert(1)>",
        "stack": "Error\n    at f (page.js:1:1)",
    }, headers={"X-DOMHunter-Token": token})
    assert r.status_code == 200
    return proj.list_dom_hunter_findings()[0]["id"]


def test_findings_index_renders_each_source_as_its_own_chip(app_and_client):
    """A finding with `source = "location.hash,location.search"` must
    show BOTH source ids as separate <code> chips in the table, not
    a single chip with a comma in it."""
    app, c = app_and_client
    _seed_multi_source_finding(app, c)
    page = c.get("/dom-hunter/")
    body = page.data.decode("utf-8")
    assert "<code>location.hash</code>" in body
    assert "<code>location.search</code>" in body
    # Never as a single fused chip.
    assert "<code>location.hash,location.search</code>" not in body


def test_detail_page_lists_every_source_in_plain_language(app_and_client):
    """Detail page must render the plain-language explanation for
    EACH matched source, so the user can see what each channel
    means without leaving the page."""
    app, c = app_and_client
    fid = _seed_multi_source_finding(app, c)
    page = c.get(f"/dom-hunter/finding/{fid}")
    body = page.data.decode("utf-8")
    # Chip for each id appears in the summary dl.
    assert "<code>location.hash</code>" in body
    assert "<code>location.search</code>" in body
    # Plain-language line per source.
    assert "URL fragment (after #)" in body
    assert "URL query (after ?)" in body
    # Plural label so the user knows multiple sources matched.
    assert "Sources" in body


def test_detail_page_keeps_singular_label_for_one_source(app_and_client):
    """The 'Source' label must stay singular for the common single-
    source case; only switches to 'Sources' when more than one is
    attributed."""
    app, c = app_and_client
    fid = _seed_multi_source_finding(app, c, source="location.hash")
    page = c.get(f"/dom-hunter/finding/{fid}")
    body = page.data.decode("utf-8")
    assert ">Source<" in body  # singular dt label
    assert ">Sources<" not in body



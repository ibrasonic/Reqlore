"""Scanner 4-page redesign: section nav + run-page presets/groups."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.plugins import reset_registry
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path, monkeypatch):
    from reqlore import plugins as plugins_mod
    monkeypatch.setattr(
        plugins_mod, "default_plugin_dirs", lambda: [tmp_path / "plugins"]
    )
    reset_registry()
    return create_app(tmp_path / "layout.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


# ---------- section nav ----------

NAV_LINKS = (
    ("/scanner/", "findings"),
    ("/scanner/run", "run"),
    ("/scanner/coverage", "coverage"),
    ("/scanner/suppressions", "suppressions"),
)


def _section_nav_html(body: str) -> str:
    """Extract just the <nav class="section-nav">...</nav> region so we
    don't false-match on the global app nav at the top of every page."""
    start = body.find('<nav class="section-nav"')
    assert start != -1, "section-nav missing from page"
    end = body.find("</nav>", start)
    assert end != -1
    return body[start:end + len("</nav>")]


@pytest.mark.parametrize("path,_active", NAV_LINKS)
def test_each_scanner_page_renders_section_nav(client, path, _active):
    body = client.get(path).data.decode()
    nav = _section_nav_html(body)
    assert 'aria-label="Scanner sections"' in nav
    for href, _ in NAV_LINKS:
        assert f'href="{href}"' in nav, f"{path} missing nav link {href}"


@pytest.mark.parametrize("path,active", NAV_LINKS)
def test_active_link_is_marked_aria_current(client, path, active):
    body = client.get(path).data.decode()
    nav = _section_nav_html(body)
    for href, label in NAV_LINKS:
        snippet = f'href="{href}"'
        idx = nav.find(snippet)
        assert idx != -1
        link_end = nav.find(">", idx)
        link_open = nav[idx:link_end]
        if label == active:
            assert 'aria-current="page"' in link_open, \
                f"{path}: link to {href} should be current"
        else:
            assert 'aria-current="page"' not in link_open, \
                f"{path}: link to {href} should NOT be current"


def test_findings_detail_inherits_findings_section(client, app):
    proj = app.extensions["reqlore_project"]
    fid = proj.add_finding(
        rule_id="manual:nav", title="t", severity="low",
        host="h", url="https://h/x",
    )
    body = client.get(f"/scanner/{fid}").data.decode()
    nav = _section_nav_html(body)
    idx = nav.find('href="/scanner/"')
    link_end = nav.find(">", idx)
    assert 'aria-current="page"' in nav[idx:link_end]


def test_manual_page_inherits_findings_section(client):
    body = client.get("/scanner/manual").data.decode()
    nav = _section_nav_html(body)
    idx = nav.find('href="/scanner/"')
    link_end = nav.find(">", idx)
    assert 'aria-current="page"' in nav[idx:link_end]


# ---------- run page presets + groups ----------

def test_run_page_renders_preset_radios(client):
    body = client.get("/scanner/run").data.decode()
    for value in ("quick", "standard", "full", "custom"):
        assert f'value="{value}"' in body
    # standard is the default-checked one.
    assert 'value="standard"\n                   checked' in body \
        or 'value="standard" checked' in body \
        or ('value="standard"' in body and 'checked' in body)


def test_run_page_has_collapsed_customise_details(client):
    body = client.get("/scanner/run").data.decode()
    # Still a <details> for progressive disclosure (and as a fallback when
    # CSS :has() is unsupported); the customise-checks class is what
    # the stylesheet hides unless the Custom preset is active.
    assert 'class="customise-checks"' in body
    assert "<summary>Customise checks</summary>" in body


def test_run_page_groups_checks_into_fieldsets(client):
    body = client.get("/scanner/run").data.decode()
    # Each labeled family renders as a fieldset legend. Note Jinja
    # HTML-escapes `&` to `&amp;` and ` / ` survives unchanged.
    for label in ("Injection", "File / OS", "Auth &amp; Logic",
                  "API &amp; CORS", "SSRF / OAST"):
        assert f"<legend>{label}" in body, f"missing group {label!r}"

def test_index_no_longer_renders_scan_forms(client):
    body = client.get("/scanner/").data.decode()
    assert "Run passive scan" not in body
    assert "Run active scan" not in body
    assert 'name="checks"' not in body


# ---------- preset resolution (backend) ----------

def test_preset_quick_runs_only_five_checks(client, app, monkeypatch):
    captured = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["enabled"] = list(options.enabled_checks or [])
        from reqlore.scanner.active import ActiveScanResult
        return ActiveScanResult()

    from reqlore.scanner.active import ActiveScanner
    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)

    token = _csrf(client)
    r = client.post("/scanner/run-active",
                    data={"_csrf": token, "preset": "quick"})
    assert r.status_code == 302
    assert set(captured["enabled"]) == {
        "xss-reflected", "sqli-error", "ssti",
        "jwt-alg-none", "open-redirect",
    }


def test_preset_standard_drops_oast(client, app, monkeypatch):
    captured = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["enabled"] = list(options.enabled_checks or [])
        from reqlore.scanner.active import ActiveScanResult
        return ActiveScanResult()

    from reqlore.scanner.active import ActiveScanner
    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)

    token = _csrf(client)
    r = client.post("/scanner/run-active",
                    data={"_csrf": token, "preset": "standard"})
    assert r.status_code == 302
    assert "oast-ssrf" not in captured["enabled"]
    assert "xss-reflected" in captured["enabled"]


def test_preset_full_enables_all_checks(client, app, monkeypatch):
    captured = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["enabled"] = options.enabled_checks
        from reqlore.scanner.active import ActiveScanResult
        return ActiveScanResult()

    from reqlore.scanner.active import ActiveScanner
    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)

    token = _csrf(client)
    r = client.post("/scanner/run-active",
                    data={"_csrf": token, "preset": "full"})
    assert r.status_code == 302
    # full ⇒ pass None so the scanner enables everything itself.
    assert captured["enabled"] is None


def test_preset_custom_respects_posted_checkboxes(client, app, monkeypatch):
    from werkzeug.datastructures import MultiDict
    captured = {}

    def fake_run(self, project, *, options, host=None, limit=20):
        captured["enabled"] = list(options.enabled_checks or [])
        from reqlore.scanner.active import ActiveScanResult
        return ActiveScanResult()

    from reqlore.scanner.active import ActiveScanner
    monkeypatch.setattr(ActiveScanner, "run_on_project", fake_run)

    token = _csrf(client)
    data = MultiDict([
        ("_csrf", token), ("preset", "custom"),
        ("checks", "sqli-error"), ("checks", "open-redirect"),
    ])
    r = client.post("/scanner/run-active", data=data)
    assert r.status_code == 302
    assert captured["enabled"] == ["sqli-error", "open-redirect"]

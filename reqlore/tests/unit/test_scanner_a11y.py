"""Scanner UI WCAG AAA polish — guards the a11y contract added after the
A.0-A.6 / B.0-B.5 rollout.

Covers:
- index h1 is the panel name (not a section name).
- severity values render as `.sev` badges with `aria-label` (not bare text).
- finding URLs are emitted in full and wrap via `.url`, no `[:80]` slice.
- "Add manual finding" carries an accesskey with the matching `<u>` hint.
- Active-scan checks render as a list.
- Coverage form uses explicit `for=`/`id=` label association.
- Suppressions row Delete buttons no longer collide on `accesskey="d"`.
- Destructive actions sit behind a `<details class="confirm">` two-step.
"""
from __future__ import annotations

import re
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
    return create_app(tmp_path / "a11y.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


# ---------- index ----------

def test_index_h1_is_scanner_not_passive_scanner(client):
    body = client.get("/scanner/").data.decode()
    assert "<h1>Scanner</h1>" in body
    assert "<h1>Passive scanner</h1>" not in body


def test_index_active_checks_render_as_a_list(client):
    body = client.get("/scanner/").data.decode()
    assert 'class="check-list"' in body
    # At least one builtin check wraps in <li>, not <p>.
    assert re.search(r'<li>\s*<input type="checkbox" id="chk-', body)


def test_manual_link_has_accesskey_and_visual_hint(client):
    body = client.get("/scanner/").data.decode()
    assert 'accesskey="m"' in body
    assert "<u>m</u>anual" in body


def test_findings_table_shows_severity_badge_with_aria_label(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding(
        rule_id="manual:test", title="t", severity="high",
        host="h", url="https://h/x",
    )
    body = client.get("/scanner/").data.decode()
    assert 'class="sev sev-high"' in body
    assert 'aria-label="Severity: high"' in body


def test_findings_table_emits_full_url_without_truncation(client, app):
    proj = app.extensions["reqlore_project"]
    long_path = "/" + ("a" * 200)
    proj.add_finding(
        rule_id="manual:url-len", title="t", severity="info",
        host="long.test", url=f"https://long.test{long_path}",
    )
    body = client.get("/scanner/").data.decode()
    assert long_path in body
    assert 'class="url"' in body


# ---------- detail ----------

def test_detail_severity_badge_and_pre_wrap(client, app):
    proj = app.extensions["reqlore_project"]
    fid = proj.add_finding(
        rule_id="manual:e", title="t", severity="critical",
        host="d.test", url="https://d.test/p",
        evidence="X" * 300, payload="payload-data",
    )
    body = client.get(f"/scanner/{fid}").data.decode()
    assert 'class="sev sev-critical"' in body
    assert 'aria-label="Severity: critical"' in body
    # Long evidence wraps instead of horizontal-scrolling.
    assert 'class="wrap-pre"' in body


def test_detail_delete_is_behind_confirm_details(client, app):
    proj = app.extensions["reqlore_project"]
    fid = proj.add_finding(
        rule_id="manual:e2", title="t", severity="info",
        host="d.test", url="https://d.test/p",
    )
    body = client.get(f"/scanner/{fid}").data.decode()
    assert 'details class="confirm"' in body or 'class="confirm"' in body
    # The bare button label disappears; the confirm form has a stronger label.
    assert "Yes, delete finding" in body


def test_detail_delete_still_works_after_confirm_post(client, app):
    proj = app.extensions["reqlore_project"]
    fid = proj.add_finding(
        rule_id="manual:e3", title="t", severity="info",
        host="d.test", url="https://d.test/p",
    )
    token = _csrf(client)
    r = client.post(
        f"/scanner/{fid}/delete", data={"_csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert proj.get_finding(fid) is None


# ---------- coverage ----------

def test_coverage_filter_uses_explicit_label_for(client):
    body = client.get("/scanner/coverage").data.decode()
    assert 'for="cov-rule"' in body
    assert 'id="cov-rule"' in body
    assert 'for="cov-host"' in body
    assert 'id="cov-host"' in body
    assert 'accesskey="a"' in body
    assert "<u>A</u>pply" in body


# ---------- suppressions ----------

def test_suppressions_rows_do_not_collide_on_accesskey_d(client, app):
    proj = app.extensions["reqlore_project"]
    for i in range(3):
        proj.add_finding_suppression(
            rule_id=f"manual:r{i}", host=f"h{i}.test",
            url_pattern="", reason="fp",
        )
    body = client.get("/scanner/suppressions").data.decode()
    # The old implementation rendered `accesskey="d"` on every row's Delete
    # button — N rows would all claim the same shortcut, which violates
    # WCAG 2.1.1 "consistent identification" expectations and is ambiguous
    # for AT users. The replacement uses a two-step confirm with no per-row
    # accesskey.
    assert body.count('accesskey="d"') == 0
    assert body.count('class="confirm"') >= 3


def test_suppression_delete_still_works_via_confirm(client, app):
    proj = app.extensions["reqlore_project"]
    proj.add_finding_suppression(
        rule_id="manual:keep-me", host="h.test",
        url_pattern="", reason="fp",
    )
    token = _csrf(client)
    r = client.post(
        "/scanner/suppressions/delete",
        data={
            "_csrf": token, "rule_id": "manual:keep-me",
            "host": "h.test", "url_pattern": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    rows = proj.list_finding_suppressions()
    assert not any(
        s["rule_id"] == "manual:keep-me" and s["host"] == "h.test"
        for s in rows
    )

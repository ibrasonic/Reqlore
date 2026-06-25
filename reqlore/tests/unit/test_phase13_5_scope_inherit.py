"""Phase 13.5 — DOM Hunter scope inheritance from project sitemap scope.

The pre-Phase-13.5 contract is preserved: DOM Hunter's explicit scope
list is the only thing that matters unless the operator opts in via
``set_inherit_sitemap``. With inheritance on, the effective scope
unions the explicit list with hosts derived from the project's
``include`` + ``host``-target scope rules.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore import dom_hunter as S
from reqlore.config import Settings
from reqlore.storage import Project
from reqlore.web import create_app


@pytest.fixture
def project(tmp_path: Path) -> Project:
    return Project(tmp_path / "phase13_5.rlr")


@pytest.fixture
def app_and_client(tmp_path: Path):
    app = create_app(tmp_path / "phase13_5_app.rlr", Settings(), proxy=None)
    app.testing = True
    return app, app.test_client()


# ---------------------------------------------------------------------------
# state keys + accessors
# ---------------------------------------------------------------------------


def test_inherit_default_is_off(project: Project) -> None:
    assert S.is_inherit_sitemap(project) is False


def test_set_inherit_round_trips(project: Project) -> None:
    S.set_inherit_sitemap(project, True)
    assert S.is_inherit_sitemap(project) is True
    S.set_inherit_sitemap(project, False)
    assert S.is_inherit_sitemap(project) is False


def test_inherit_key_constant_is_documented() -> None:
    assert S.SCOPE_INHERIT_KEY == "dom_hunter_scope_inherit_sitemap"


# ---------------------------------------------------------------------------
# derive_sitemap_hosts
# ---------------------------------------------------------------------------


def test_derive_empty_when_no_sitemap_rules(project: Project) -> None:
    assert S.derive_sitemap_hosts(project) == []


def test_derive_picks_only_enabled_include_host_rules(project: Project) -> None:
    project.add_scope("include", "alpha.example.com", target="host")
    project.add_scope("include", "*.beta.example.com", target="host")
    sid_excl = project.add_scope("exclude", "blocked.example.com", target="host")
    sid_url = project.add_scope("include", "https://gamma.example.com/api", target="url")
    sid_disabled = project.add_scope("include", "disabled.example.com", target="host")
    project.toggle_scope(sid_disabled)

    hosts = S.derive_sitemap_hosts(project)
    assert hosts == ["alpha.example.com", "*.beta.example.com"]
    # Excludes must NOT leak into the DOM Hunter list (no exclude semantics
    # on the client side).
    assert "blocked.example.com" not in hosts
    # URL-target rules must NOT leak — DOM Hunter is host-scoped.
    assert "gamma.example.com" not in hosts
    # Sanity: the negative IDs really exist.
    rules = {r["id"] for r in project.list_scope()}
    assert sid_excl in rules and sid_url in rules and sid_disabled in rules


def test_derive_normalizes_legacy_url_form_patterns(project: Project) -> None:
    project.add_scope("include", "http://localhost:3001/path", target="host")
    project.add_scope("include", "HTTPS://Foo.com/x", target="host")
    assert S.derive_sitemap_hosts(project) == ["localhost:3001", "foo.com"]


def test_derive_dedupes_within_sitemap(project: Project) -> None:
    project.add_scope("include", "example.com", target="host")
    project.add_scope("include", "EXAMPLE.COM", target="host")
    assert S.derive_sitemap_hosts(project) == ["example.com"]


def test_derive_drops_empty_patterns(project: Project) -> None:
    project.add_scope("include", "", target="host")
    project.add_scope("include", "real.example.com", target="host")
    assert S.derive_sitemap_hosts(project) == ["real.example.com"]


def test_derive_defensive_on_project_without_list_scope() -> None:
    class _FakeProject:
        def get_state(self, k, default=""):
            return default

    assert S.derive_sitemap_hosts(_FakeProject()) == []


# ---------------------------------------------------------------------------
# get_effective_scope
# ---------------------------------------------------------------------------


def test_effective_scope_off_returns_explicit_only(project: Project) -> None:
    S.set_scope(project, ["a.example.com"])
    project.add_scope("include", "b.example.com", target="host")
    assert S.is_inherit_sitemap(project) is False
    assert S.get_effective_scope(project) == ["a.example.com"]


def test_effective_scope_off_with_empty_explicit_stays_empty(project: Project) -> None:
    """Behaviour parity: with inheritance OFF, empty explicit means
    'every host' (the legacy contract). The function returns ``[]`` and
    ``host_in_scope`` treats that as permissive."""
    project.add_scope("include", "b.example.com", target="host")
    assert S.get_effective_scope(project) == []
    assert S.host_in_scope("anything.test", S.get_effective_scope(project)) is True


def test_effective_scope_on_unions_explicit_and_sitemap(project: Project) -> None:
    S.set_inherit_sitemap(project, True)
    S.set_scope(project, ["explicit.example.com"])
    project.add_scope("include", "sitemap.example.com", target="host")
    project.add_scope("include", "*.api.example.com", target="host")
    eff = S.get_effective_scope(project)
    assert eff == [
        "explicit.example.com",
        "sitemap.example.com",
        "*.api.example.com",
    ]


def test_effective_scope_on_with_empty_explicit_takes_sitemap(project: Project) -> None:
    S.set_inherit_sitemap(project, True)
    project.add_scope("include", "only.example.com", target="host")
    assert S.get_effective_scope(project) == ["only.example.com"]


def test_effective_scope_on_with_empty_sitemap_falls_back_to_explicit(
    project: Project,
) -> None:
    S.set_inherit_sitemap(project, True)
    S.set_scope(project, ["explicit.example.com"])
    assert S.get_effective_scope(project) == ["explicit.example.com"]


def test_effective_scope_on_with_both_empty_is_empty(project: Project) -> None:
    """Permissive ('every host') stays the final fallback so an opt-in
    user with neither list configured isn't suddenly locked out."""
    S.set_inherit_sitemap(project, True)
    assert S.get_effective_scope(project) == []


def test_effective_scope_dedupes_overlapping_entries(project: Project) -> None:
    S.set_inherit_sitemap(project, True)
    S.set_scope(project, ["shared.example.com", "only-explicit.example.com"])
    project.add_scope("include", "shared.example.com", target="host")
    project.add_scope("include", "only-sitemap.example.com", target="host")
    eff = S.get_effective_scope(project)
    # First-seen wins: 'shared' appears once, in explicit position.
    assert eff == [
        "shared.example.com",
        "only-explicit.example.com",
        "only-sitemap.example.com",
    ]
    assert eff.count("shared.example.com") == 1


# ---------------------------------------------------------------------------
# should_inject_referer uses the EFFECTIVE scope (not the explicit one)
# ---------------------------------------------------------------------------


def test_proxy_hook_respects_inherited_sitemap_scope(project: Project) -> None:
    S.set_enabled(project, True)
    S.set_auto_inject(project, ["document.referrer"])
    S.set_inherit_sitemap(project, True)
    # NO explicit DOM Hunter scope. Only the sitemap.
    project.add_scope("include", "target.example.com", target="host")

    assert S.should_inject_referer(project, "target.example.com") is True
    assert S.should_inject_referer(project, "outside.example.com") is False


def test_proxy_hook_ignores_sitemap_when_inheritance_off(project: Project) -> None:
    S.set_enabled(project, True)
    S.set_auto_inject(project, ["document.referrer"])
    # Inheritance OFF (the default).
    project.add_scope("include", "target.example.com", target="host")
    # Empty explicit + inheritance off ⇒ legacy 'every host' contract.
    assert S.should_inject_referer(project, "target.example.com") is True
    assert S.should_inject_referer(project, "anywhere.test") is True


def test_proxy_hook_explicit_narrower_than_sitemap_wins(project: Project) -> None:
    """When inheritance is OFF and an explicit list is set, the proxy
    hook must NOT silently widen to sitemap entries."""
    S.set_enabled(project, True)
    S.set_auto_inject(project, ["document.referrer"])
    S.set_scope(project, ["narrow.example.com"])
    project.add_scope("include", "wider.example.com", target="host")

    assert S.should_inject_referer(project, "narrow.example.com") is True
    assert S.should_inject_referer(project, "wider.example.com") is False


# ---------------------------------------------------------------------------
# bridge config exposes effective scope
# ---------------------------------------------------------------------------


def test_bridge_config_returns_effective_scope_when_inherit_on(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    S.set_enabled(proj, True)
    S.set_scope(proj, ["explicit.example.com"])
    S.set_inherit_sitemap(proj, True)
    proj.add_scope("include", "from-sitemap.example.com", target="host")

    r = c.get(
        "/dom-hunter/__bridge/config", headers={"X-DOMHunter-Token": token},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["scope"] == [
        "explicit.example.com", "from-sitemap.example.com",
    ]


def test_bridge_config_omits_sitemap_when_inherit_off(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    token = S.get_or_make_token(proj)
    S.set_enabled(proj, True)
    S.set_scope(proj, ["explicit.example.com"])
    # No set_inherit_sitemap call ⇒ default off.
    proj.add_scope("include", "from-sitemap.example.com", target="host")

    body = c.get(
        "/dom-hunter/__bridge/config", headers={"X-DOMHunter-Token": token},
    ).get_json()
    assert body["scope"] == ["explicit.example.com"]


def test_bridge_config_does_not_leak_inherit_toggle(app_and_client) -> None:
    """The extension never needs the toggle directly — it receives the
    final flat host list. Keeping the response shape stable avoids a
    new field the existing client wouldn't know what to do with."""
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    S.set_inherit_sitemap(proj, True)
    token = S.get_or_make_token(proj)
    body = c.get(
        "/dom-hunter/__bridge/config", headers={"X-DOMHunter-Token": token},
    ).get_json()
    assert "inherit_sitemap" not in body
    assert "scope_inherit" not in body


# ---------------------------------------------------------------------------
# settings POST persists inheritance toggle
# ---------------------------------------------------------------------------


def _csrf(client) -> str:
    # Seed the session by hitting the settings page first.
    client.get("/dom-hunter/settings")
    with client.session_transaction() as sess:
        tok = sess.get("csrf", "")
    assert tok, "settings GET must seed a CSRF token in the session"
    return tok


def test_settings_post_enables_inheritance(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    tok = _csrf(c)

    r = c.post(
        "/dom-hunter/settings",
        data={
            "_csrf": tok,
            "action": "save",
            "enabled": "1",
            "scope": "explicit.example.com",
            "inherit_sitemap": "1",
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert S.is_inherit_sitemap(proj) is True
    assert S.get_scope(proj) == ["explicit.example.com"]


def test_settings_post_disables_inheritance_when_checkbox_omitted(
    app_and_client,
) -> None:
    """An unchecked checkbox is omitted from form data — the POST must
    treat that as 'turn off', not 'leave unchanged'."""
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    # Pre-enable so the test exercises the OFF transition.
    S.set_inherit_sitemap(proj, True)
    tok = _csrf(c)

    r = c.post(
        "/dom-hunter/settings",
        data={
            "_csrf": tok,
            "action": "save",
            "enabled": "1",
            "scope": "explicit.example.com",
            # no inherit_sitemap key at all
        },
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert S.is_inherit_sitemap(proj) is False


def test_settings_get_exposes_inherit_state_and_preview(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    S.set_inherit_sitemap(proj, True)
    proj.add_scope("include", "preview.example.com", target="host")
    proj.add_scope("include", "*.api.example.com", target="host")

    r = c.get("/dom-hunter/settings")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    # The checkbox is rendered checked.
    assert 'name="inherit_sitemap"' in html
    assert "checked" in html
    # The preview lists the derived hosts so the operator can verify
    # what they'd be opting into.
    assert "preview.example.com" in html
    assert "*.api.example.com" in html
    assert "Hosts inherited from sitemap (2)" in html


def test_settings_get_hides_preview_when_inheritance_off(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    # Inheritance off (default) but sitemap is populated.
    proj.add_scope("include", "preview.example.com", target="host")

    html = c.get("/dom-hunter/settings").get_data(as_text=True)
    # Checkbox exists, but is NOT checked.
    assert 'name="inherit_sitemap"' in html
    # The preview block is gated behind `inherit_sitemap` — must be absent.
    assert "Hosts inherited from sitemap" not in html


# ---------------------------------------------------------------------------
# index page shows inheritance state
# ---------------------------------------------------------------------------


def test_index_shows_inheritance_annotation_when_on(app_and_client) -> None:
    app, c = app_and_client
    proj = app.extensions["reqlore_project"]
    S.set_inherit_sitemap(proj, True)
    proj.add_scope("include", "from-sitemap.example.com", target="host")

    html = c.get("/dom-hunter/").get_data(as_text=True)
    assert "from-sitemap.example.com" in html
    assert "inheriting 1 host from sitemap scope" in html


def test_index_says_every_host_when_both_empty(app_and_client) -> None:
    _, c = app_and_client
    html = c.get("/dom-hunter/").get_data(as_text=True)
    assert "every host" in html

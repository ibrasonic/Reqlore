"""Tests for the Match & Replace Quick Presets feature."""
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app
from reqlore.web.blueprints.matchreplace_bp import (
    PRESET_MAP,
    PRESETS,
    _active_presets,
    _parse_preset_slug,
    _preset_comment,
)


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "mr_presets.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/match-replace/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


# ---- helpers -------------------------------------------------------------

def test_preset_comment_round_trip():
    c = _preset_comment("reveal-hidden", "Reveal hidden form fields")
    assert _parse_preset_slug(c) == "reveal-hidden"


def test_parse_preset_slug_returns_empty_for_non_preset():
    assert _parse_preset_slug("just a user comment") == ""
    assert _parse_preset_slug("") == ""
    assert _parse_preset_slug("__preset:") == ""


def test_every_preset_has_required_keys():
    for p in PRESETS:
        assert set(p) >= {"slug", "title", "description", "rules"}
        assert p["slug"] in PRESET_MAP
        assert p["rules"], f"preset {p['slug']} has no rules"
        for rule in p["rules"]:
            assert rule["where"] in {
                "req_header", "req_body", "resp_header", "resp_body",
            }


def test_active_presets_groups_by_slug_and_host():
    rules = [
        {"comment": _preset_comment("reveal-hidden", "T"), "host_regex": "^a$"},
        {"comment": _preset_comment("reveal-hidden", "T"), "host_regex": "^a$"},
        {"comment": _preset_comment("reveal-hidden", "T"), "host_regex": "^b$"},
        {"comment": "user comment", "host_regex": "^a$"},
    ]
    out = _active_presets(rules)
    keys = sorted((p["slug"], p["host"], p["count"]) for p in out)
    assert keys == [
        ("reveal-hidden", "^a$", 2),
        ("reveal-hidden", "^b$", 1),
    ]


# ---- HTTP surface --------------------------------------------------------

def test_index_renders_presets_section(client):
    r = client.get("/match-replace/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", errors="replace")
    assert "Quick presets" in body
    assert "Reveal hidden form fields" in body
    assert "Disable Content Security Policy" in body
    # accessibility: each preset has a programmatic description.
    assert 'aria-describedby="preset-reveal-hidden-desc"' in body
    assert 'id="preset-reveal-hidden-desc"' in body
    assert "Apply selected presets" in body


def test_apply_preset_inserts_tagged_rules(client):
    token = _csrf(client)
    r = client.post(
        "/match-replace/preset/apply",
        data={
            "_csrf": token,
            "host_regex": r"^app\.example\.com$",
            "preset": "reveal-hidden",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    r2 = client.get("/match-replace/")
    body = r2.data.decode("utf-8", errors="replace")
    assert "__preset:reveal-hidden__" in body
    assert r"^app\.example\.com$" in body
    # Active presets section should now appear.
    assert "Active presets" in body


def test_apply_preset_rejects_empty_host(client):
    token = _csrf(client)
    r = client.post(
        "/match-replace/preset/apply",
        data={"_csrf": token, "host_regex": "", "preset": "reveal-hidden"},
        follow_redirects=True,
    )
    body = r.data.decode("utf-8", errors="replace")
    assert "Choose a host filter" in body


def test_apply_preset_rejects_invalid_regex(client):
    token = _csrf(client)
    r = client.post(
        "/match-replace/preset/apply",
        data={"_csrf": token, "host_regex": "[unclosed",
              "preset": "reveal-hidden"},
        follow_redirects=True,
    )
    body = r.data.decode("utf-8", errors="replace")
    assert "not a valid regular expression" in body


def test_apply_preset_warns_when_unanchored(client):
    token = _csrf(client)
    r = client.post(
        "/match-replace/preset/apply",
        data={"_csrf": token, "host_regex": "example.com",
              "preset": "reveal-hidden"},
        follow_redirects=True,
    )
    body = r.data.decode("utf-8", errors="replace")
    assert "not anchored" in body


def test_apply_preset_with_no_selection(client):
    token = _csrf(client)
    r = client.post(
        "/match-replace/preset/apply",
        data={"_csrf": token, "host_regex": "^a$"},
        follow_redirects=True,
    )
    body = r.data.decode("utf-8", errors="replace")
    assert "No presets selected" in body


def test_remove_preset_deletes_only_matching_rules(client):
    token = _csrf(client)
    # Apply two presets for the same host.
    client.post(
        "/match-replace/preset/apply",
        data={
            "_csrf": token,
            "host_regex": r"^app\.example\.com$",
            "preset": ["reveal-hidden", "disable-csp"],
        },
        follow_redirects=True,
    )
    body = client.get("/match-replace/").data.decode("utf-8", errors="replace")
    assert "__preset:reveal-hidden__" in body
    assert "__preset:disable-csp__" in body

    # Remove just the reveal-hidden preset.
    r = client.post(
        "/match-replace/preset/remove",
        data={
            "_csrf": token,
            "slug": "reveal-hidden",
            "host_regex": r"^app\.example\.com$",
        },
        follow_redirects=True,
    )
    body = r.data.decode("utf-8", errors="replace")
    assert "__preset:reveal-hidden__" not in body
    assert "__preset:disable-csp__" in body


def test_remove_preset_unknown_slug(client):
    token = _csrf(client)
    r = client.post(
        "/match-replace/preset/remove",
        data={"_csrf": token, "slug": "nope", "host_regex": "^a$"},
        follow_redirects=True,
    )
    body = r.data.decode("utf-8", errors="replace")
    assert "Unknown preset" in body

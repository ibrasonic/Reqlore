"""Smoke-test that every documented Intruder accesskey renders correctly.

Each toolbar/form button must carry an ``accesskey="<letter>"`` attribute
and a ``<u><Letter></u>`` underline marker so sighted users know which
letter to press with Alt (Windows) / Ctrl+Opt (macOS).

The list of expected shortcuts is kept in sync with help_bp.KEYMAP — if
either side changes, this test must change too. That tight coupling is
intentional: it forces the keyboard map page to stay accurate.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app
from reqlore.web.blueprints.help_bp import KEYMAP


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "ak.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_attack(app, status: str = "queued") -> int:
    proj = app.extensions["reqlore_project"]
    aid = proj.create_intruder(
        name="ak-test", attack_type="sniper",
        template=b"GET / HTTP/1.1\r\n\r\n", positions=[(8, 9)],
        payloads=[["a"]], options={"grep": []},
        url="http://x/", engine="httpx",
    )
    if status != "queued":
        proj.set_intruder_status(aid, status)
    return aid


def _has_accesskey_button(html: bytes, letter: str) -> bool:
    """Detect either order: accesskey before or after other attrs."""
    pattern = (
        rb'<button[^>]*accesskey="' + letter.encode() + rb'"[^>]*>'
        rb'.*?<u>' + letter.upper().encode() + rb'</u>'
    )
    return re.search(pattern, html, re.IGNORECASE | re.DOTALL) is not None


def _has_accesskey_link(html: bytes, letter: str) -> bool:
    pattern = (
        rb'<a[^>]*accesskey="' + letter.encode() + rb'"[^>]*>'
        rb'.*?<u>' + letter.upper().encode() + rb'</u>'
    )
    return re.search(pattern, html, re.IGNORECASE | re.DOTALL) is not None


# ---------- list page ----------

def test_intruder_list_has_new_attack_accesskey(client):
    r = client.get("/intruder/")
    assert r.status_code == 200
    assert _has_accesskey_link(r.data, "n"), \
        "Intruder list should expose Alt+N for 'New attack'"


# ---------- new attack form ----------

def test_intruder_new_form_has_create_accesskey(client):
    r = client.get("/intruder/new")
    assert r.status_code == 200
    assert _has_accesskey_button(r.data, "c"), \
        "New-attack form should expose Alt+C for 'Create attack'"


# ---------- detail page toolbar ----------

@pytest.mark.parametrize("letter,label", [
    ("s", "Start / Restart"),
    ("p", "Pause"),
    ("r", "Resume"),
    ("c", "Cancel"),
    ("d", "Delete"),
])
def test_intruder_detail_toolbar_accesskeys(app, client, letter, label):
    # Status "paused" guarantees all five buttons are enabled in different
    # combinations across runs; visibility of the attribute does not depend
    # on the disabled state — disabled buttons still carry accesskey.
    aid = _seed_attack(app, status="paused")
    r = client.get(f"/intruder/{aid}")
    assert r.status_code == 200
    assert _has_accesskey_button(r.data, letter), \
        f"Detail toolbar should expose Alt+{letter.upper()} for '{label}'"


def test_intruder_detail_filter_apply_accesskey(app, client):
    aid = _seed_attack(app)
    r = client.get(f"/intruder/{aid}")
    assert _has_accesskey_button(r.data, "a"), \
        "Filter form should expose Alt+A for 'Apply'"


# ---------- detail-page accesskeys are unique within the page ----------

def test_intruder_detail_accesskeys_do_not_collide(app, client):
    """No two interactive elements on the detail page should share a key."""
    aid = _seed_attack(app, status="paused")
    r = client.get(f"/intruder/{aid}")
    keys = re.findall(rb'accesskey="([a-z0-9])"', r.data)
    keys_str = [k.decode() for k in keys]
    duplicates = {k for k in keys_str if keys_str.count(k) > 1}
    assert not duplicates, (
        f"Duplicate accesskeys on /intruder/{aid}: {sorted(duplicates)}. "
        f"All keys present: {sorted(set(keys_str))}"
    )


# ---------- help keymap is in sync ----------

def _keymap_letters_for_scope(scope: str) -> set[str]:
    out: set[str] = set()
    for shortcut, action in KEYMAP:
        if scope in action and shortcut.startswith("Alt+"):
            out.add(shortcut.removeprefix("Alt+").lower())
    return out


def test_keymap_documents_intruder_list_shortcuts():
    keys = _keymap_letters_for_scope("Intruder list")
    assert keys == {"n"}, f"Intruder list keymap drift: {keys}"


def test_keymap_documents_intruder_detail_shortcuts():
    keys = _keymap_letters_for_scope("Intruder detail")
    assert keys == {"s", "p", "r", "c", "d", "a"}, \
        f"Intruder detail keymap drift: {keys}"


def test_keymap_documents_intruder_new_shortcut():
    keys = _keymap_letters_for_scope("Intruder new")
    assert keys == {"c"}, f"Intruder new-form keymap drift: {keys}"


def test_help_page_renders_intruder_shortcuts(client):
    r = client.get("/help/")
    assert r.status_code == 200
    body = r.data.decode("utf-8")
    # A few sentinel strings only — full coverage is given by the
    # _keymap_letters_for_scope tests above.
    for needle in ("Start / Restart attack",
                   "Pause attack", "Resume attack", "Cancel attack",
                   "Delete attack", "Apply filter",
                   "New attack (Intruder list)",
                   "Create attack (Intruder new)"):
        assert needle in body, f"Help page missing keymap entry: {needle}"

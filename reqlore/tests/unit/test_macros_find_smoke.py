"""Smoke tests for find-in-body on the Macros detail page.

The macro definition lives in a ``<textarea>`` that the browser's
Ctrl+F cannot search. The find form is a SEPARATE GET form rendered
below the POST edit form so submitting Find never accidentally saves
or runs the macro.
"""
from __future__ import annotations

import html

import pytest

from reqlore.config import Settings
from reqlore.macros import Macro, MacroStep
from reqlore.storage import Project
from reqlore.web import create_app


@pytest.fixture
def client(tmp_path):
    db = tmp_path / "macros.rlr"
    project = Project(db)
    macro = Macro(name="login-admin")
    macro.steps.append(MacroStep(
        name="login", method="POST",
        url="http://example.test/login",
        body="username=admin&password=admin",
    ))
    project.set_state("macro:next_id", "2")
    project.set_state("macro:1", macro.to_json())
    settings = Settings()
    app = create_app(db, settings)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _text(client, url):
    r = client.get(url)
    assert r.status_code == 200, r.get_data(as_text=True)[:500]
    raw = r.get_data(as_text=True)
    return raw, html.unescape(raw)


def test_macro_detail_renders_without_query(client):
    raw, _ = _text(client, "/macros/1")
    assert 'id="def-find-q"' in raw
    assert "<mark" not in raw


def test_macro_find_marks_admin(client):
    raw, body = _text(client, "/macros/1?def_find=admin")
    # "admin" appears in the macro name and twice in the step body.
    assert ' for "admin" in definition.' in body
    assert 'id="def-m1"' in raw


def test_find_form_is_separate_from_edit_form(client):
    """The Find form must sit OUTSIDE the POST edit form so submitting it
    cannot trip the save/run actions on the textarea."""
    raw, _ = _text(client, "/macros/1")
    edit_form_start = raw.find('<form method="post"')
    edit_form_end = raw.find("</form>", edit_form_start)
    find_form_pos = raw.find('class="find-form"')
    assert edit_form_start != -1
    assert find_form_pos != -1
    assert find_form_pos > edit_form_end

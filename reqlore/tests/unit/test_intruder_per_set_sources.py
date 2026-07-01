"""Per-position payload-type dropdowns for Pitchfork / Cluster Bomb.

Bug fixed: the Intruder new-attack form only rendered ONE source
dropdown, forcing every marker (§) position to share the same payload
type. Multi-position attacks (pitchfork, clusterbomb) now render an
independent Source select for each of Sets 2-4 so an operator can
pair, e.g., a text list at position 1 with a number range at position
2 and a wordlist at position 3.

These tests exercise the blueprint end-to-end (POST -> stored payload
records) rather than the template markup itself: the assertion is on
the shape of ``project.get_intruder(aid)["payloads"]`` because that's
what the runner actually consumes. Template assertions live in
``test_intruder_bp_payloads.py`` (the "form lists source X" tests).
"""
from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.intruder import DEFAULT_MARKER
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "perset.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/intruder/new")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _tpl_two_markers() -> str:
    m = DEFAULT_MARKER
    return (
        f"POST /login HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        f"\r\nu={m}user{m}&id={m}1{m}"
    )


def _tpl_three_markers() -> str:
    m = DEFAULT_MARKER
    return (
        f"GET /?a={m}a{m}&b={m}b{m}&c={m}c{m} HTTP/1.1\r\nHost: x.test\r\n\r\n"
    )


# ---------------------------------------------------------------------------
# The form now renders one Source dropdown per position
# ---------------------------------------------------------------------------

def test_new_form_renders_per_set_source_dropdowns(client):
    r = client.get("/intruder/new")
    assert r.status_code == 200
    # Set 1 select is still called "source" for backward compat.
    assert b'name="source"' in r.data
    # Sets 2-4 each get their own namespaced Source select.
    for n in (2, 3, 4):
        assert (f'name="source_set{n}"').encode() in r.data
    # Per-set input groups carry a data-source-scope attribute so the JS
    # toggle handles each set independently.
    assert b'data-source-scope="set2"' in r.data
    assert b'data-source-scope="set3"' in r.data
    assert b'data-source-scope="set4"' in r.data
    # The "Sets 2-4" wrapper is present but marked multi-only so
    # Sniper / Battering render without those blocks visible.
    assert b'data-multi-only' in r.data


# ---------------------------------------------------------------------------
# Pitchfork: mixed sources per position
# ---------------------------------------------------------------------------

def test_pitchfork_text_plus_numbers(client, app):
    """Position 1 = text list, position 2 = number range."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "pf-mixed", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        # Set 1: text
        "source": "text", "payloads_text": "alice\nbob\ncarol",
        # Set 2: numbers (INDEPENDENT source type, this is the fix)
        "source_set2": "numbers",
        "num_start_set2": "10", "num_end_set2": "12", "num_step_set2": "1",
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert len(detail["payloads"]) == 2
    assert detail["payloads"][0] == ["alice", "bob", "carol"]
    assert detail["payloads"][1] == ["10", "11", "12"]


def test_pitchfork_numbers_plus_wordlist(client, app):
    """Set 1 numbers, Set 2 built-in wordlist — proves the Set 1
    source can be non-text and Set 2 still contributes an
    independent set (regression check for the original bug where the
    single global source dropdown forced everything to numbers)."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "pf-num-wl", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        # Set 1: numbers (NOT text) — this used to swallow all sets.
        "source": "numbers",
        "num_start": "1", "num_end": "3", "num_step": "1",
        # Set 2: wordlist
        "source_set2": "wordlist", "wordlist_name_set2": "sqli_payloads",
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert len(detail["payloads"]) == 2
    assert detail["payloads"][0] == ["1", "2", "3"]
    assert len(detail["payloads"][1]) >= 10
    assert any("'" in p for p in detail["payloads"][1])


def test_clusterbomb_three_positions_three_source_types(client, app):
    """Cluster bomb with three markers and three DIFFERENT source
    types per position. Verifies the stored payload shape and that
    Set 3 is preserved (regression: earlier bug ignored Set 3
    entirely when the global source was non-text)."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "cb-three-mixed", "attack_type": "clusterbomb", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_three_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "100", "processors": "", "grep": "",
        # Set 1: text
        "source": "text", "payloads_text": "foo\nbar",
        # Set 2: numbers (inclusive of end)
        "source_set2": "numbers",
        "num_start_set2": "1", "num_end_set2": "2", "num_step_set2": "1",
        # Set 3: brute (small alphabet + length so it stays bounded)
        "source_set3": "brute",
        "brute_alphabet_set3": "ab", "brute_min_set3": "1", "brute_max_set3": "1",
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert len(detail["payloads"]) == 3
    assert detail["payloads"][0] == ["foo", "bar"]
    assert detail["payloads"][1] == ["1", "2"]
    assert set(detail["payloads"][2]) == {"a", "b"}


def test_pitchfork_set2_wordlist_file_upload(client, app):
    """Set 1 text + Set 2 file upload. Confirms multipart namespacing
    (``wordlist_upload_set2``) is picked up by ``_collect_one_set``."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "pf-text-file", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "text", "payloads_text": "u1\nu2",
        "source_set2": "wordlist_file",
        "wordlist_upload_set2": (BytesIO(b"one\ntwo\nthree\n"), "wl2.txt"),
        "_csrf": token,
    }, content_type="multipart/form-data", follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert len(detail["payloads"]) == 2
    assert detail["payloads"][0] == ["u1", "u2"]
    assert detail["payloads"][1] == ["one", "two", "three"]


def test_pitchfork_set2_wordlist_path_streaming(client, app, tmp_path):
    """Server-path streaming source on Set 2 — the stored entry must
    be the ``{kind:path, path:...}`` metadata dict, not a materialised
    list, matching the Set 1 wordlist_path behaviour."""
    token = _csrf(client)
    wl = tmp_path / "s2.lst"
    wl.write_text("aa\nbb\ncc\n", encoding="utf-8")
    r = client.post("/intruder/new", data={
        "name": "pf-text-path", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "text", "payloads_text": "u1\nu2",
        "source_set2": "wordlist_path",
        "wordlist_path_set2": str(wl),
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert detail["payloads"][0] == ["u1", "u2"]
    assert detail["payloads"][1] == {"kind": "path", "path": str(wl)}


# ---------------------------------------------------------------------------
# Backward compatibility: existing text-only workflow still works
# ---------------------------------------------------------------------------

def test_pitchfork_legacy_text_only_still_works(client, app):
    """Operators who don't touch the new source_setN dropdowns and
    just fill payloads_text + payloads_set2 (the pre-fix workflow)
    must still get two text sets. Regression guard for existing docs
    and screenshots."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "pf-legacy", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "text",
        "payloads_text": "a\nb", "payloads_set2": "x\ny\nz",
        # No source_set2 -> falls back to reading payloads_set2 as text
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert detail["payloads"] == [["a", "b"], ["x", "y", "z"]]


def test_pitchfork_set2_unused_skips_position(client, app):
    """An explicitly-empty source_set2 with a numbers-Set-1 (so the
    text-fallback doesn't trigger) skips Set 2 entirely, yielding a
    single-source pitchfork. Documents the "unused" option in the
    per-set dropdown."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "pf-skip", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "numbers",
        "num_start": "1", "num_end": "2", "num_step": "1",
        "source_set2": "",  # explicit "unused"
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert detail["payloads"] == [["1", "2"]]


# ---------------------------------------------------------------------------
# Sniper / Battering Ram: per-set fields ignored
# ---------------------------------------------------------------------------

def test_sniper_ignores_set2_source(client, app):
    """Sniper uses one payload set; any source_set2 the operator
    accidentally filled must be ignored, not appended."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "sn-ignore", "attack_type": "sniper", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "text", "payloads_text": "one\ntwo",
        "source_set2": "numbers",
        "num_start_set2": "1", "num_end_set2": "100",
        "_csrf": token,
    }, follow_redirects=False)
    assert r.status_code == 302, r.data
    proj = app.extensions["reqlore_project"]
    detail = proj.get_intruder(proj.list_intruder()[0]["id"])
    assert detail["payloads"] == [["one", "two"]]


# ---------------------------------------------------------------------------
# Error surfacing for per-set sources
# ---------------------------------------------------------------------------

def test_set2_wordlist_file_missing_surfaces_labelled_error(client):
    """Per-set errors mention which set failed so the operator knows
    where to look (WCAG 3.3.1 error-identification, applied per-set)."""
    token = _csrf(client)
    r = client.post("/intruder/new", data={
        "name": "pf-badfile", "attack_type": "pitchfork", "engine": "httpx",
        "url": "http://127.0.0.1/", "template": _tpl_two_markers(),
        "marker": DEFAULT_MARKER, "concurrency": "1", "delay_ms": "0",
        "max_requests": "10", "processors": "", "grep": "",
        "source": "text", "payloads_text": "u1",
        "source_set2": "wordlist_file",  # no upload attached
        "_csrf": token,
    }, content_type="multipart/form-data", follow_redirects=False)
    assert r.status_code == 200
    assert b"set 2" in r.data.lower()
    assert b"No wordlist file selected" in r.data

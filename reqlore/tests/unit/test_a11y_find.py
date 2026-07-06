"""Unit tests for the server-side find-in-text helper.

`reqlore.a11y.find_in_text` is the foundation of the find-in-body
widget on History detail, Repeater response, and Intercept detail —
the only AAA-clean way to point screen-reader users at a substring in
a long request or response body without making them read it
linearly. These tests cover the contract the templates rely on:
1-based contiguous indexes, accurate line numbers, regex error
fall-through, the zero-width-match guard, and the truncation flag.
"""
from __future__ import annotations

from reqlore.a11y import (
    FindResult,
    FindSegment,
    build_find_context,
    find_in_text,
    find_segments,
    find_status_sentence,
)

# ---------- find_in_text ----------

def test_empty_query_returns_no_matches():
    r = find_in_text("hello world", "")
    assert r.q == ""
    assert r.matches == ()
    assert r.truncated is False
    assert r.error is None


def test_literal_match_case_insensitive():
    r = find_in_text("Admin login by admin user", "ADMIN")
    assert len(r.matches) == 2
    assert [m.index for m in r.matches] == [1, 2]
    assert (r.matches[0].start, r.matches[0].end) == (0, 5)
    assert (r.matches[1].start, r.matches[1].end) == (15, 20)


def test_literal_query_does_not_treat_metachars_as_regex():
    # ``a.c`` literal must only match exactly that string, not "abc".
    r = find_in_text("abc and a.c", "a.c", regex=False)
    assert len(r.matches) == 1
    assert r.matches[0].start == 8


def test_regex_match_with_groups():
    r = find_in_text("id=42 then id=7", r"id=\d+", regex=True)
    assert [m.end - m.start for m in r.matches] == [5, 4]


def test_regex_invalid_returns_error_no_matches():
    r = find_in_text("body", "(unclosed", regex=True)
    assert r.matches == ()
    assert r.error is not None
    assert r.truncated is False


def test_zero_width_regex_match_skipped():
    # ``a*`` would otherwise match an empty string at every offset
    # and turn the page into a sea of empty <mark> tags. The helper
    # silently skips zero-width hits.
    r = find_in_text("aaa bbb", "a*", regex=True)
    # Only the runs of one-or-more "a" should remain.
    assert all(m.end > m.start for m in r.matches)
    assert all(m.start <= m.end for m in r.matches)


def test_line_numbers_are_1_based_and_track_newlines():
    text = "first\nsecond hit\nthird hit\nfourth"
    r = find_in_text(text, "hit")
    assert [m.line_no for m in r.matches] == [2, 3]
    assert r.matches[0].line_text == "second hit"
    assert r.matches[1].line_text == "third hit"


def test_match_in_last_line_without_trailing_newline():
    r = find_in_text("alpha\nbeta", "beta")
    assert len(r.matches) == 1
    assert r.matches[0].line_no == 2
    assert r.matches[0].line_text == "beta"


def test_truncation_flag_set_when_cap_reached():
    text = "x" * 1000
    r = find_in_text(text, "x", max_matches=10)
    assert len(r.matches) == 10
    assert r.truncated is True


def test_no_truncation_when_under_cap():
    r = find_in_text("xxx", "x", max_matches=10)
    assert r.truncated is False


def test_match_indexes_are_contiguous_starting_at_1():
    r = find_in_text("aaa", "a")
    assert [m.index for m in r.matches] == [1, 2, 3]


def test_no_match_returns_empty_tuple_not_error():
    r = find_in_text("hello", "absent")
    assert r.matches == ()
    assert r.error is None


# ---------- find_segments ----------

def test_segments_for_empty_text_and_no_matches_is_empty():
    assert find_segments("", ()) == []


def test_segments_passthrough_when_no_matches():
    segs = find_segments("hello", ())
    assert segs == [FindSegment(kind="text", text="hello", index=None)]


def test_segments_interleave_text_and_matches():
    text = "abc XYZ def XYZ"
    r = find_in_text(text, "XYZ")
    segs = find_segments(text, r.matches)
    # Expect: "abc " | "XYZ" | " def " | "XYZ"
    assert [s.kind for s in segs] == ["text", "match", "text", "match"]
    assert "".join(s.text for s in segs) == text
    assert [s.index for s in segs if s.kind == "match"] == [1, 2]


def test_segments_when_match_is_at_start_or_end():
    text = "XYZ middle XYZ"
    r = find_in_text(text, "XYZ")
    segs = find_segments(text, r.matches)
    # First seg should be a match, last seg should be a match.
    assert segs[0].kind == "match"
    assert segs[-1].kind == "match"
    assert "".join(s.text for s in segs) == text


# ---------- find_status_sentence ----------

def test_status_empty_when_no_query():
    r = FindResult(q="", regex=False, matches=(),
                   truncated=False, error=None)
    assert find_status_sentence(r) == ""


def test_status_singular_match():
    r = find_in_text("alpha beta", "beta")
    assert find_status_sentence(r, region="response") == \
        '1 match for "beta" in response.'


def test_status_plural_matches():
    r = find_in_text("aaa", "a")
    assert find_status_sentence(r) == '3 matches for "a" in body.'


def test_status_zero_matches():
    r = find_in_text("hello", "absent")
    assert find_status_sentence(r, region="request body") == \
        'No matches for "absent" in request body.'


def test_status_regex_error():
    r = find_in_text("body", "(bad", regex=True)
    s = find_status_sentence(r, region="response body")
    assert s.startswith('Regex error in response body:')
    assert s.endswith('.')


def test_status_truncated_advises_user():
    r = find_in_text("x" * 100, "x", max_matches=10)
    s = find_status_sentence(r, region="body")
    assert "Stopped after 10 matches" in s
    assert "refine" in s


# ---------- build_find_context ----------

def test_build_find_context_empty_query_produces_no_segments():
    ctx = build_find_context(
        "hello world", prefix="req", q="", regex=False,
        region_label="request", action="/x",
    )
    assert ctx["prefix"] == "req"
    assert ctx["q"] == ""
    assert ctx["regex"] is False
    assert ctx["segments"] == []
    assert ctx["status"] == ""
    assert ctx["action"] == "/x"
    assert ctx["region_label"] == "request"


def test_build_find_context_with_query_builds_segments_and_status():
    ctx = build_find_context(
        "alpha beta beta", prefix="resp", q="beta", regex=False,
        region_label="response body", action="/y",
    )
    assert ctx["q"] == "beta"
    assert ctx["regex"] is False
    assert ctx["result"].matches[0].index == 1
    assert ctx["status"] == '2 matches for "beta" in response body.'
    # Segments must round-trip the original text.
    assert "".join(s.text for s in ctx["segments"]) == "alpha beta beta"


def test_build_find_context_regex_flag_propagated():
    ctx = build_find_context(
        "id=1 id=22", prefix="resp", q=r"id=\d+", regex=True,
        region_label="body", action="/z",
    )
    assert ctx["regex"] is True
    assert len(ctx["result"].matches) == 2
    assert ctx["result"].error is None

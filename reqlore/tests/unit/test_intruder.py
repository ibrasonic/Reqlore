"""Unit tests for intruder module: parsing, scheduling, processors."""
from reqlore.intruder import (
    DEFAULT_MARKER,
    apply_payloads,
    apply_processors,
    find_positions,
    grep_extract,
    iterate,
    payloads_from_text,
    payloads_numbers,
    strip_markers,
)


def test_find_positions_single():
    tpl = f"GET /?q={DEFAULT_MARKER}admin{DEFAULT_MARKER} HTTP/1.1".encode()
    pos = find_positions(tpl)
    assert len(pos) == 1
    a, b = pos[0]
    # The span includes the marker bytes themselves
    assert tpl[a:b].startswith(DEFAULT_MARKER.encode())
    assert tpl[a:b].endswith(DEFAULT_MARKER.encode())


def test_find_positions_multiple():
    tpl = (f"POST /a={DEFAULT_MARKER}1{DEFAULT_MARKER}&b="
           f"{DEFAULT_MARKER}2{DEFAULT_MARKER} HTTP/1.1").encode()
    pos = find_positions(tpl)
    assert len(pos) == 2


def test_strip_markers():
    tpl = f"x{DEFAULT_MARKER}y{DEFAULT_MARKER}z".encode()
    assert strip_markers(tpl) == b"xyz"


def test_apply_payloads():
    tpl = f"GET /?q={DEFAULT_MARKER}X{DEFAULT_MARKER} HTTP/1.1".encode()
    pos = find_positions(tpl)
    out = apply_payloads(tpl, pos, ["root"])
    assert out == b"GET /?q=root HTTP/1.1"


def test_apply_payloads_two_positions():
    tpl = (f"x={DEFAULT_MARKER}A{DEFAULT_MARKER}&y={DEFAULT_MARKER}B{DEFAULT_MARKER}").encode()
    pos = find_positions(tpl)
    out = apply_payloads(tpl, pos, ["1", "2"])
    assert out == b"x=1&y=2"


def test_processors_chain():
    out = apply_processors("hello", ["upper", "b64"])
    assert out == "SEVMTE8="


def test_payloads_from_text():
    assert payloads_from_text("a\nb\n\nc") == ["a", "b", "", "c"]


def test_payloads_numbers():
    assert payloads_numbers(1, 5) == ["1", "2", "3", "4", "5"]
    assert payloads_numbers(0, 10, 5) == ["0", "5", "10"]
    assert payloads_numbers(5, 1, -2) == ["5", "3", "1"]


def test_iterate_sniper():
    payloads = [["a", "b"]]
    out = list(iterate("sniper", payloads, n_positions=2))
    # 2 positions × 2 payloads = 4 rows
    assert out == [["a", ""], ["b", ""], ["", "a"], ["", "b"]]


def test_iterate_battering():
    out = list(iterate("battering", [["x", "y"]], n_positions=3))
    assert out == [["x", "x", "x"], ["y", "y", "y"]]


def test_iterate_pitchfork():
    out = list(iterate("pitchfork", [["a", "b", "c"], ["1", "2"]], n_positions=2))
    assert out == [["a", "1"], ["b", "2"]]


def test_iterate_clusterbomb():
    out = list(iterate("clusterbomb", [["a", "b"], ["1", "2"]], n_positions=2))
    assert out == [["a", "1"], ["a", "2"], ["b", "1"], ["b", "2"]]


def test_grep_extract_first_match_returns_matched_flag():
    hits, matched = grep_extract(b"hello world hello", ["hello"])
    assert matched is True
    assert "hello" in hits


def test_grep_extract_no_match_flag_false():
    hits, matched = grep_extract(b"nothing here", ["missing"])
    assert hits == ""
    assert matched is False


def test_grep_extract_count_mode():
    hits, matched = grep_extract(b"abc abc abc abc", ["=count:abc"])
    assert matched is True
    assert "4" in hits


def test_grep_extract_all_mode_joins_matches():
    hits, matched = grep_extract(b"a1 a2 a3", ["=all:a\\d"])
    assert matched is True
    assert "a1" in hits and "a2" in hits and "a3" in hits


def test_grep_extract_invalid_regex_is_silently_skipped():
    hits, matched = grep_extract(b"abc", ["(unclosed"])
    assert hits == ""
    assert matched is False


def test_grep_extract_empty_patterns_returns_no_match():
    hits, matched = grep_extract(b"abc", [])
    assert hits == ""
    assert matched is False


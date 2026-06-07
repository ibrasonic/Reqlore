"""Tests for diff helpers in a11y."""
from weblore.a11y import byte_diff_summary, diff_lines, diff_summary, summarise_jwt


def test_diff_summary_identical():
    s = diff_summary("a\nb\nc", "a\nb\nc")
    assert s.added == 0 and s.removed == 0 and s.changed == 0
    assert "No differences" in s.sentence()


def test_diff_summary_add_remove_change():
    s = diff_summary("a\nb\nc", "a\nx\nc\nd")
    assert s.changed == 1
    assert s.added == 1
    assert "B" in s.sentence("A", "B")


def test_diff_lines_emits_per_line_records():
    rows = diff_lines("x\ny", "x\nz")
    tags = [r[0] for r in rows]
    assert "same" in tags
    assert "del" in tags and "add" in tags


def test_byte_diff_summary_identical():
    assert "Identical" in byte_diff_summary(b"abc", b"abc")


def test_byte_diff_summary_length_change():
    s = byte_diff_summary(b"abc", b"abcd")
    assert "+1" in s or "delta" in s


def test_jwt_summary_alg_none_warning():
    s = summarise_jwt({"alg": "none", "typ": "JWT"}, {"sub": "alice"})
    assert "alg=none" in s

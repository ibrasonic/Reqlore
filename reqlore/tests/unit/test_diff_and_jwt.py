"""Tests for diff helpers in a11y."""
from reqlore.a11y import (
    byte_diff_summary,
    diff_lines,
    diff_summary,
    pair_diff_lines,
    summarise_jwt,
)


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


def test_pair_diff_lines_pairs_replace_block_into_chg():
    # Two del rows followed by two add rows (a replace opcode) should
    # become two chg rows with both sides populated.
    flat = diff_lines("x\ny\nz", "x\nY\nZ")
    paired = pair_diff_lines(flat)
    # Same line is preserved.
    assert paired[0] == ("same", 1, "x", 1, "x")
    chg_rows = [r for r in paired if r[0] == "chg"]
    assert len(chg_rows) == 2
    # Each chg row has both an A side and a B side.
    for tag, la, atext, lb, btext in chg_rows:
        assert la is not None and lb is not None
        assert atext and btext


def test_pair_diff_lines_pure_add_and_pure_del():
    flat = diff_lines("a\nb", "a\nb\nc")
    paired = pair_diff_lines(flat)
    add_rows = [r for r in paired if r[0] == "add"]
    assert add_rows and add_rows[0][3] is not None and add_rows[0][1] is None

    flat = diff_lines("a\nb\nc", "a\nb")
    paired = pair_diff_lines(flat)
    del_rows = [r for r in paired if r[0] == "del"]
    assert del_rows and del_rows[0][1] is not None and del_rows[0][3] is None


def test_pair_diff_lines_unequal_replace_block():
    # 3 dels paired with 1 add: 1 chg + 2 pure del rows.
    flat = diff_lines("a\nb\nc", "X")
    paired = pair_diff_lines(flat)
    tags = [r[0] for r in paired]
    assert tags.count("chg") == 1
    assert tags.count("del") == 2


def test_byte_diff_summary_identical():
    assert "Identical" in byte_diff_summary(b"abc", b"abc")


def test_byte_diff_summary_length_change():
    s = byte_diff_summary(b"abc", b"abcd")
    assert "+1" in s or "delta" in s


def test_jwt_summary_alg_none_warning():
    s = summarise_jwt({"alg": "none", "typ": "JWT"}, {"sub": "alice"})
    assert "alg=none" in s

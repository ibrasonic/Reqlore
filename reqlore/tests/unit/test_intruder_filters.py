"""Tests for the result filter / dedupe helper in intruder_bp."""
from reqlore.web.blueprints.intruder_bp import _apply_filters, _parse_filters


def _row(seq: int, *, status: int = 200, length: int = 100, md5: str = "",
         matched: bool = False, payloads=None, grep: str = "") -> dict:
    return {
        "id": seq, "seq": seq, "payloads": payloads or [f"p{seq}"],
        "status": status, "len_resp": length, "duration_ms": 10,
        "grep_hits": grep, "history_id": None, "body_md5": md5,
        "matched": matched,
    }


def _f(**overrides) -> dict:
    base = {"sc": "", "len_min": None, "len_max": None, "q": "",
            "matched": "", "dedup": False}
    base.update(overrides)
    return base


def test_filter_status_class():
    rows = [_row(1, status=200), _row(2, status=404), _row(3, status=500)]
    out, _ = _apply_filters(rows, _f(sc="4xx"))
    assert [r["seq"] for r in out] == [2]


def test_filter_length_bounds():
    rows = [_row(1, length=50), _row(2, length=150), _row(3, length=250)]
    out, _ = _apply_filters(rows, _f(len_min=100, len_max=200))
    assert [r["seq"] for r in out] == [2]


def test_filter_matched_yes_no():
    rows = [_row(1, matched=True), _row(2, matched=False)]
    out_yes, _ = _apply_filters(rows, _f(matched="yes"))
    out_no, _ = _apply_filters(rows, _f(matched="no"))
    assert [r["seq"] for r in out_yes] == [1]
    assert [r["seq"] for r in out_no] == [2]


def test_filter_search_payloads_and_grep():
    rows = [_row(1, payloads=["admin"]), _row(2, payloads=["guest"], grep="root")]
    out_a, _ = _apply_filters(rows, _f(q="admin"))
    out_b, _ = _apply_filters(rows, _f(q="root"))
    assert [r["seq"] for r in out_a] == [1]
    assert [r["seq"] for r in out_b] == [2]


def test_filter_dedupe_keeps_first_only_and_counts_hidden():
    rows = [_row(1, md5="aa"), _row(2, md5="aa"), _row(3, md5="bb"), _row(4, md5="aa")]
    out, hidden = _apply_filters(rows, _f(dedup=True))
    assert [r["seq"] for r in out] == [1, 3]
    assert hidden == 2


def test_filter_dedupe_off_by_default():
    rows = [_row(1, md5="aa"), _row(2, md5="aa")]
    out, hidden = _apply_filters(rows, _f())
    assert [r["seq"] for r in out] == [1, 2]
    assert hidden == 0


def test_filter_dedupe_ignores_empty_md5():
    rows = [_row(1, md5=""), _row(2, md5="")]
    out, hidden = _apply_filters(rows, _f(dedup=True))
    assert [r["seq"] for r in out] == [1, 2]
    assert hidden == 0


def test_parse_filters_invalid_status_class_falls_back_to_empty():
    f = _parse_filters({"sc": "bogus"})
    assert f["sc"] == ""


def test_parse_filters_invalid_int_becomes_none():
    f = _parse_filters({"len_min": "abc", "len_max": ""})
    assert f["len_min"] is None
    assert f["len_max"] is None


def test_parse_filters_dedup_toggle():
    assert _parse_filters({"dedup": "1"})["dedup"] is True
    assert _parse_filters({})["dedup"] is False

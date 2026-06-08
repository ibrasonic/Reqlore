"""Tests for proxy.matchreplace (text-level transforms only; mitmproxy not invoked)."""
from reqlore.proxy.matchreplace import MRRule, apply_request, apply_response


def _rule(**kw) -> MRRule:
    defaults = dict(id=0, enabled=True, where="req_header", is_regex=False,
                    host_regex="", pattern="", replacement="")
    defaults.update(kw)
    return MRRule(**defaults)


def test_literal_request_header_replace():
    r = _rule(where="req_header", pattern="User-Agent: old", replacement="User-Agent: reqlore")
    h, b = apply_request([r], "example.com",
                         [("User-Agent", "old"), ("Host", "example.com")], b"")
    assert dict(h)["User-Agent"] == "reqlore"


def test_regex_response_body_replace():
    r = _rule(where="resp_body", is_regex=True, pattern=r"\bfoo\b", replacement="bar")
    h, b = apply_response([r], "example.com", [("Content-Type", "text/plain")], b"foo foobar")
    assert b == b"bar foobar"


def test_host_filter_skips_other_hosts():
    r = _rule(where="req_body", pattern="x", replacement="y", host_regex=r"example\.com")
    _, body = apply_request([r], "other.com", [], b"xxx")
    assert body == b"xxx"


def test_disabled_rule_is_skipped():
    r = _rule(where="req_body", pattern="a", replacement="b", enabled=False)
    _, body = apply_request([r], "any", [], b"aaa")
    assert body == b"aaa"

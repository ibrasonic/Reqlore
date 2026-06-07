from weblore.engines import Request
from weblore.engines.curl_render import render as curl_render


def test_request_dataclass_header_accessors():
    r = Request("GET", "http://x/", [("X-A", "1"), ("X-B", "2")])
    assert r.header("x-a") == "1"
    assert r.header("missing") is None
    r2 = r.with_header("X-A", "9")
    assert r2.header("X-A") == "9"
    assert dict(r2.headers).get("X-A") == "9"


def test_curl_render_engine_returns_string():
    r = Request("POST", "http://x.test/", [("Content-Type", "application/json")], b'{"a":1}')
    s = curl_render(r)
    assert s.startswith("curl ")
    assert "POST" in s
    assert "http://x.test/" in s

from reqlore.a11y import (
    ResponseSummaryInput,
    contrast_ratio,
    hex_to_rgb,
    render_curl,
    render_fetch,
    render_httpx,
    render_raw_http,
    render_requests,
    summarise_response,
    wcag_pass,
)


def test_contrast_ratio_black_white():
    assert round(contrast_ratio((0, 0, 0), (255, 255, 255)), 2) == 21.0


def test_wcag_pass_light_theme_body_text():
    ok, ratio = wcag_pass("#14181f", "#ffffff")
    assert ok
    assert ratio >= 4.5


def test_wcag_pass_dark_theme_body_text():
    ok, ratio = wcag_pass("#e7ebf2", "#0e1116")
    assert ok
    assert ratio >= 4.5


def test_wcag_pass_high_contrast_theme():
    ok, ratio = wcag_pass("#ffffff", "#000000")
    assert ok
    assert ratio == 21.0


def test_hex_to_rgb_short():
    assert hex_to_rgb("#abc") == (0xaa, 0xbb, 0xcc)


def test_summarise_response_basic():
    body = b"<html><script>x</script></html>"
    headers = [("Content-Type", "text/html"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")]
    s = summarise_response(ResponseSummaryInput(
        status=200, reason="OK", headers=headers, body=body, duration_ms=123,
    ))
    assert "HTTP 200 OK" in s
    assert "text/html" in s
    assert "took 123 ms" in s
    assert "2 cookies" in s
    assert "script tags" in s
    assert "missing" in s   # no CSP / X-Content-Type-Options


def test_summarise_response_reflection():
    s = summarise_response(
        ResponseSummaryInput(200, "OK", [], b"", 1),
        reflected=["q"],
    )
    assert "reflects parameter q" in s


def test_render_curl_get():
    out = render_curl("GET", "http://x.test/a?b=1", [("X-A", "v"), ("Host", "x.test")], None)
    assert out.startswith("curl -sS -i -X GET")
    assert "'X-A: v'" in out
    assert "'http://x.test/a?b=1'" in out


def test_render_curl_post_with_body():
    out = render_curl("POST", "http://x/", [("Content-Type", "application/json")], b'{"a":1}')
    assert "--data-raw '{\"a\":1}'" in out
    assert "POST" in out


def test_render_raw_http_includes_host_and_body():
    raw = render_raw_http("POST", "http://x.test:8080/api",
                          [("X-A", "v")], b"hello")
    assert raw.startswith("POST /api HTTP/1.1\r\n")
    assert "Host: x.test:8080" in raw
    assert raw.endswith("\r\n\r\nhello")


def test_render_httpx_and_requests_and_fetch_have_method_and_url():
    for r in (render_httpx, render_requests, render_fetch):
        out = r("DELETE", "http://x/a", [("X-A", "1")], b"body")
        assert "DELETE" in out
        assert "http://x/a" in out

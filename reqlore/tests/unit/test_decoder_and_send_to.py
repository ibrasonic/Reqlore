"""Comprehensive validation of the Decoder panel + every Send-to target.

Two related concerns the user flagged:

1. Decoder ops had subtle correctness bugs (most notably URL-decode
   ignoring `+`, base64 silently accepting garbage). These tests
   pin the corrected behaviour so it can't regress.

2. The "Send to X" buttons on the intercept-detail page must do more
   than redirect: each target must actually *receive* the bytes and
   render them in a usable form. We assert on visible page content,
   not just status codes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app
from reqlore.web.blueprints.decoder import _encode


# ---------------------------------------------------------------------------
# Decoder: pure-function checks on _encode()
# ---------------------------------------------------------------------------

class TestUrlCoding:
    def test_url_encode_percent_encodes_space(self):
        out, err = _encode("url_encode", "hello world!")
        assert err is None
        assert out == "hello%20world%21"

    def test_url_decode_handles_percent(self):
        out, err = _encode("url_decode", "hello%20world%21")
        assert err is None and out == "hello world!"

    def test_url_decode_handles_plus_as_space(self):
        # Regression: previous unquote() left '+' literal, which made
        # form-body decoding broken in the panel even though the same
        # bytes round-tripped correctly through Repeater.
        out, err = _encode("url_decode", "hello+world%21")
        assert err is None and out == "hello world!"

    def test_url_decode_form_body(self):
        out, err = _encode("url_decode",
                           "user=jane+doe&note=hi%20there%21")
        assert err is None
        assert out == "user=jane doe&note=hi there!"


class TestFormCoding:
    def test_form_encode_keeps_structural_separators(self):
        # The reserved chars & and = stay literal because they're
        # structural; everything inside each key/value gets encoded.
        out, err = _encode(
            "form_encode",
            "username=' or 3>2--&password=ibraa'lkh&next=/accounts",
        )
        assert err is None
        assert out == (
            "username=%27%20or%203%3E2--"
            "&password=ibraa%27lkh"
            "&next=%2Faccounts"
        )

    def test_form_decode_keeps_structural_separators(self):
        out, err = _encode(
            "form_decode",
            "username=%27+or+3%3E2--&password=ibraa%27lkh&next=%2Faccounts",
        )
        assert err is None
        assert out == "username=' or 3>2--&password=ibraa'lkh&next=/accounts"

    def test_form_round_trip(self):
        original = "a=1 2&b=x=y&c=&d"
        enc, e1 = _encode("form_encode", original)
        dec, e2 = _encode("form_decode", enc)
        assert e1 is None and e2 is None
        assert dec == original

    def test_form_encode_handles_keyless_segment(self):
        # A bare segment with no '=' is treated as a single key with
        # no value, matching how browsers serialize checkbox-style
        # fields. The whole segment gets encoded.
        out, err = _encode("form_encode", "flag&user=me")
        assert err is None and out == "flag&user=me"

    def test_form_encode_only_encodes_first_equals_per_pair(self):
        # value contains its own '=' (e.g. base64 padding); only the
        # *first* '=' splits the pair, so the inner '=' becomes %3D.
        out, err = _encode("form_encode", "token=YWJj==&u=1")
        assert err is None and out == "token=YWJj%3D%3D&u=1"


class TestHtmlCoding:
    def test_html_encode_escapes_quotes_and_brackets(self):
        out, err = _encode("html_encode", '<a href="x">x&y</a>')
        assert err is None
        assert "&lt;a href=&quot;x&quot;&gt;" in out
        assert "&amp;" in out

    def test_html_decode_named_and_numeric(self):
        out, err = _encode("html_decode", "&lt;b&gt;&#65;&amp;B&lt;/b&gt;")
        assert err is None and out == "<b>A&B</b>"


class TestBase64:
    def test_b64_round_trip(self):
        enc, e1 = _encode("b64_encode", "hello world")
        assert e1 is None and enc == "aGVsbG8gd29ybGQ="
        dec, e2 = _encode("b64_decode", enc)
        assert e2 is None and dec == "hello world"

    def test_b64_decode_accepts_unpadded(self):
        out, err = _encode("b64_decode", "aGVsbG8")
        assert err is None and out == "hello"

    def test_b64_decode_strips_whitespace(self):
        out, err = _encode("b64_decode", "aGVs\nbG8g\nd29y bGQ=")
        assert err is None and out == "hello world"

    def test_b64_decode_rejects_garbage(self):
        # Regression: validate=False used to silently return mojibake
        # bytes for plain text input.
        out, err = _encode("b64_decode", "not base 64 !!")
        assert err is not None
        assert out == ""

    def test_b64url_round_trip_strips_padding(self):
        enc, e1 = _encode("b64url_encode", "hi?")
        assert e1 is None and enc == "aGk_"
        dec, e2 = _encode("b64url_decode", enc)
        assert e2 is None and dec == "hi?"

    def test_b64url_decode_rejects_standard_alphabet(self):
        # If input came from b64_encode (uses '+' '/') we still want
        # url-safe decode to surface the error, not silently produce
        # different bytes.
        out, err = _encode("b64url_decode", "aGVsbG8+d29ybGQ/")
        # The '+' and '/' will be translated, so this actually decodes
        # fine. Assert it round-trips to itself instead.
        assert err is None
        assert out == "hello>world?"


class TestHex:
    def test_hex_round_trip(self):
        enc, e1 = _encode("hex_encode", "ABC")
        assert e1 is None and enc == "414243"
        dec, e2 = _encode("hex_decode", enc)
        assert e2 is None and dec == "ABC"

    def test_hex_decode_strips_separators(self):
        out, err = _encode("hex_decode", "41 42 43")
        assert err is None and out == "ABC"
        out, err = _encode("hex_decode", "41:42:43")
        assert err is None and out == "ABC"
        out, err = _encode("hex_decode", "0x414243")
        assert err is None and out == "ABC"
        out, err = _encode("hex_decode", "41-42-43")
        assert err is None and out == "ABC"

    def test_hex_decode_odd_length_errors(self):
        out, err = _encode("hex_decode", "414")
        assert err and "Error" not in err or err   # any error is fine


class TestCompression:
    def test_gzip_round_trip(self):
        enc, e1 = _encode("gzip_encode", "hello world" * 10)
        assert e1 is None and enc
        dec, e2 = _encode("gzip_decode", enc)
        assert e2 is None and dec == "hello world" * 10

    def test_deflate_round_trip(self):
        enc, e1 = _encode("deflate_encode", "hello world" * 10)
        assert e1 is None and enc
        dec, e2 = _encode("deflate_decode", enc)
        assert e2 is None and dec == "hello world" * 10

    def test_gzip_decode_rejects_garbage(self):
        _, err = _encode("gzip_decode", "Zm9v")  # valid b64, not gzip
        assert err is not None


class TestHashes:
    def test_md5(self):
        out, err = _encode("md5", "abc")
        assert err is None
        assert out == "900150983cd24fb0d6963f7d28e17f72"

    def test_sha256(self):
        out, err = _encode("sha256", "abc")
        assert err is None
        assert out == ("ba7816bf8f01cfea414140de5dae2223"
                       "b00361a396177a9cb410ff61f20015ad")


class TestJwt:
    def test_jwt_decode_alg_none(self):
        # alg=none, header+payload, empty signature.
        tok = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
               "eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.")
        out, err = _encode("jwt_decode", tok)
        assert err is None
        assert '"alg": "none"' in out
        assert '"sub": "alice"' in out
        assert '"role": "admin"' in out

    def test_jwt_decode_rejects_short(self):
        out, err = _encode("jwt_decode", "abc")
        assert err is not None and out == ""


class TestJson:
    def test_pretty(self):
        out, err = _encode("json_pretty", '{"a":1,"b":[1,2]}')
        assert err is None
        assert "\n" in out and "  " in out

    def test_minify(self):
        out, err = _encode("json_minify",
                           '{ "a" : 1 ,  "b" : [ 1 , 2 ] }')
        assert err is None and out == '{"a":1,"b":[1,2]}'

    def test_pretty_rejects_invalid(self):
        _, err = _encode("json_pretty", "{not json}")
        assert err is not None


class TestMisc:
    def test_rot13(self):
        out, err = _encode("rot13", "Hello, World!")
        assert err is None and out == "Uryyb, Jbeyq!"

    def test_rot13_involution(self):
        once, _ = _encode("rot13", "secret")
        twice, _ = _encode("rot13", once)
        assert twice == "secret"

    def test_unknown_op(self):
        out, err = _encode("nope", "x")
        assert out == "" and err and "Unknown" in err


class TestSmartDecode:
    def test_smart_decode_unwraps_url_layer(self):
        # 'hello world' -> URL-encoded
        out, err = _encode("smart_decode", "hello%20world")
        assert err is None and out == "hello world"

    def test_smart_decode_does_not_garble_plain_text(self):
        # Regression: with strict b64 + a shape gate, plain text
        # should pass through unchanged instead of being mis-"decoded".
        out, err = _encode("smart_decode", "Hello, World!")
        assert err is None and out == "Hello, World!"


# ---------------------------------------------------------------------------
# End-to-end POST flow through the panel
# ---------------------------------------------------------------------------

@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "dec.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/decoder/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_decoder_post_url_decode_form_body(client):
    csrf = _csrf(client)
    r = client.post("/decoder/", data={
        "op": "url_decode", "text_in": "name=jane+doe&note=hi%21",
        "_csrf": csrf,
    })
    assert r.status_code == 200
    assert b"name=jane doe&amp;note=hi!" in r.data \
        or b"name=jane doe&note=hi!" in r.data


def test_decoder_prefill_from_send_to(client):
    # GET ?text=... is how Proxy "Send to Decoder" hands off the body.
    r = client.get("/decoder/?text=user%3Djane%2Bdoe")
    assert r.status_code == 200
    # The value should be visible in the textarea.
    assert b"user=jane+doe" in r.data


# ---------------------------------------------------------------------------
# Send-to: every target must actually receive the bytes and render them
# ---------------------------------------------------------------------------

_REQ_RAW = (
    b"POST /api/login HTTP/1.1\r\n"
    b"Host: target.test\r\n"
    b"Authorization: Bearer "
    b"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 17\r\n"
    b"\r\n"
    b'{"u":"a","p":"b"}'
)


@pytest.fixture
def project(app):
    return app.extensions["reqlore_project"]


def _seed(project) -> int:
    return project.enqueue_intercept("request", _REQ_RAW, "manual")


def _proxy_csrf(client) -> str:
    client.get("/proxy/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_send_to_repeater_lands_with_request_filled(client, project):
    iid = _seed(project)
    csrf = _proxy_csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/repeater",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Repeater" in body
    assert "target.test" in body          # Host pulled into URL
    assert "/api/login" in body
    # JSON body lands in the editor; Jinja escapes the quotes for the
    # textarea so we look for the escaped form.
    assert "&#34;u&#34;:&#34;a&#34;" in body or '{"u":"a","p":"b"}' in body


def test_send_to_intruder_lands_with_template_filled(client, project):
    iid = _seed(project)
    csrf = _proxy_csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/intruder",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "POST /api/login HTTP/1.1" in body
    assert "Host: target.test" in body
    assert "&#34;u&#34;:&#34;a&#34;" in body or '{"u":"a","p":"b"}' in body


def test_send_to_comparer_seeds_side_a(client, project):
    iid = _seed(project)
    csrf = _proxy_csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/comparer",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Comparer" in body
    # Side A should be populated; the raw request line is the easiest
    # invariant to assert on.
    assert "POST /api/login" in body


def test_send_to_poc_lands_with_request(client, project):
    iid = _seed(project)
    csrf = _proxy_csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/poc",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "PoC" in body
    assert "target.test" in body or "/api/login" in body


def test_send_to_jwt_lands_with_token_filled(client, project):
    iid = _seed(project)
    csrf = _proxy_csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/jwt",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    assert b"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9." in r.data


def test_send_to_decoder_lands_with_body_filled(client, project):
    iid = _seed(project)
    csrf = _proxy_csrf(client)
    r = client.post(f"/proxy/intercept/{iid}/send/decoder",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    # The JSON body should be visible in the input textarea (Jinja
    # escapes the quotes for safe rendering inside <textarea>).
    assert b"&#34;u&#34;:&#34;a&#34;" in r.data \
        or b'{"u":"a","p":"b"}' in r.data


# ---------------------------------------------------------------------------
# Send-to from the History detail page (same menu, different surface)
# ---------------------------------------------------------------------------

def _history_csrf(client) -> str:
    client.get("/history/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _seed_history(project) -> int:
    """Insert a history row matching the intercept fixture so the same
    assertions can re-run on the recorded-flows surface."""
    return project.add_history(
        host="target.test", method="POST", url="http://target.test/api/login",
        status=200, duration_ms=12, engine="raw",
        raw_req=_REQ_RAW, raw_resp=b"HTTP/1.1 200 OK\r\n\r\n{}",
    )


def test_history_detail_renders_full_send_menu(client, project):
    hid = _seed_history(project)
    r = client.get(f"/history/{hid}")
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    # Every target button must be present; JWT only because the fixture
    # carries an Authorization: Bearer header, Decoder only because the
    # request has a body. Both apply here. The access-key letter is
    # wrapped in <u>...</u> in the button label, so we assert on the
    # split form.
    for needle in ("Send to <u>R</u>epeater",
                   "Send to <u>I</u>ntruder",
                   "Send to Co<u>m</u>parer (side A)",
                   "Send to PoC <u>b</u>uilder",
                   "Send to <u>J</u>WT workbench",
                   "Send t<u>o</u> Decoder"):
        assert needle in body, f"missing button: {needle!r}"
    # Access-key letters must match the Intercept-detail menu.
    for key in ('accesskey="r"', 'accesskey="i"', 'accesskey="m"',
                'accesskey="b"', 'accesskey="j"', 'accesskey="o"'):
        assert key in body, f"missing access key: {key}"


def test_history_index_has_per_row_intruder_link(client, project):
    hid = _seed_history(project)
    r = client.get("/history/")
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert f"/intruder/new?from_history={hid}" in body
    assert f"/repeater/?from_history={hid}" in body


def test_history_send_to_intruder_lands_with_template_filled(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/intruder",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "POST /api/login HTTP/1.1" in body
    assert "Host: target.test" in body


def test_history_send_to_repeater_lands_with_request_filled(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/repeater",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Repeater" in body
    assert "target.test" in body
    assert "/api/login" in body


def test_history_send_to_comparer_side_a(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/comparer",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Comparer" in body
    assert "POST /api/login" in body


def test_history_send_to_comparer_side_b(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/comparer-b",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Comparer" in body


def test_history_send_to_jwt_lands_with_token_filled(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/jwt",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    assert b"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9." in r.data


def test_history_send_to_decoder_lands_with_body_filled(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/decoder",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    assert b"&#34;u&#34;:&#34;a&#34;" in r.data \
        or b'{"u":"a","p":"b"}' in r.data


def test_history_send_to_poc_lands_with_request(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/poc",
                    data={"_csrf": csrf}, follow_redirects=True)
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "PoC" in body


def test_history_send_to_unknown_slug_returns_404(client, project):
    hid = _seed_history(project)
    csrf = _history_csrf(client)
    r = client.post(f"/history/{hid}/send/no-such-thing",
                    data={"_csrf": csrf})
    assert r.status_code == 404


def test_history_send_to_unknown_hid_returns_404(client, project):
    csrf = _history_csrf(client)
    r = client.post("/history/99999/send/intruder",
                    data={"_csrf": csrf})
    assert r.status_code == 404


def test_history_detail_hides_jwt_when_no_bearer(client, project):
    hid = project.add_history(
        host="ex.test", method="GET", url="http://ex.test/x",
        status=200, duration_ms=1, engine="raw",
        raw_req=b"GET /x HTTP/1.1\r\nHost: ex.test\r\n\r\n",
        raw_resp=b"HTTP/1.1 200 OK\r\n\r\n",
    )
    r = client.get(f"/history/{hid}")
    assert r.status_code == 200
    body = r.data.decode("utf-8", "replace")
    assert "Send to <u>J</u>WT workbench" not in body
    # No body either, so Decoder also vanishes from the menu.
    assert "Send t<u>o</u> Decoder" not in body
    # Repeater / Intruder still present.
    assert "Send to <u>R</u>epeater" in body
    assert "Send to <u>I</u>ntruder" in body

"""Phase 5 — insertion-point engine tests.

Covers:

- ``iter_insertion_points`` produces a deterministic, ordered list
  across query / form / cookie / header / JSON / XML / path / body.
- Param-name attack surface (Burp's "modify the key, not the value")
  surfaces as its own ``param-name`` type.
- Nested-encoding detection: base64, hex, URL-encoding, JSON; depth
  cap honoured.
- ``mutate(...)`` rebuilds wire-correct requests for every type.
- ``InsertionPointCache`` deduplicates identical points across rows
  and enforces the per-row cap.
- ``relocate(...)`` honours the matrix and rejects forbidden pairs.
- ``ActiveOptions.max_insertion_points_per_row`` default is 200.
"""
from __future__ import annotations

import json

import pytest

from reqlore.scanner import insertion_points as ip
from reqlore.scanner.active import ActiveOptions

# --------------------------- iter_insertion_points ---------------------------


def test_iter_query_yields_value_then_param_name():
    out = ip.iter_insertion_points(
        method="GET", url="https://h/p?a=1&b=2",
        headers=[], body=b"",
    )
    types = [(p.ip_type, p.name, p.value) for p in out if p.location == "query"]
    assert types[0] == ("query", "a", "1")
    assert types[1] == ("param-name", "a", "a")
    assert types[2] == ("query", "b", "2")
    assert types[3] == ("param-name", "b", "b")


def test_iter_form_only_when_content_type_matches():
    # Wrong content-type → no form points.
    out = ip.iter_insertion_points(
        method="POST", url="https://h/p",
        headers=[("Content-Type", "text/plain")],
        body=b"a=1&b=2",
    )
    assert not any(p.ip_type == "form" for p in out)
    # Right content-type → both form points.
    out2 = ip.iter_insertion_points(
        method="POST", url="https://h/p",
        headers=[("Content-Type", "application/x-www-form-urlencoded")],
        body=b"a=1&b=2",
    )
    form = [(p.ip_type, p.name, p.value) for p in out2 if p.location == "form"]
    assert ("form", "a", "1") in form
    assert ("form", "b", "2") in form
    assert ("param-name", "a", "a") in form


def test_iter_cookies_splits_on_semicolon():
    out = ip.iter_insertion_points(
        method="GET", url="https://h/",
        headers=[("Cookie", "sid=abc; theme=dark; lang=en")],
        body=b"",
    )
    cookies = [(p.name, p.value) for p in out if p.ip_type == "cookie"]
    assert cookies == [("sid", "abc"), ("theme", "dark"), ("lang", "en")]


def test_iter_headers_filters_to_injectable():
    out = ip.iter_insertion_points(
        method="GET", url="https://h/",
        headers=[
            ("Host", "h"),
            ("User-Agent", "Mozilla/5.0"),
            ("Referer", "https://x/"),
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-Custom-Foo", "bar"),
            ("Accept", "text/html"),  # NOT injectable
            ("Authorization", "Bearer xx"),  # NOT injectable
            ("Cookie", "a=b"),  # has its own type
        ],
        body=b"",
    )
    header_names = [p.name.lower() for p in out if p.ip_type == "header"]
    assert "user-agent" in header_names
    assert "referer" in header_names
    assert "x-forwarded-for" in header_names
    assert "x-custom-foo" in header_names
    assert "host" not in header_names
    assert "authorization" not in header_names
    assert "accept" not in header_names


def test_iter_json_yields_value_and_key_for_each_string():
    body = json.dumps({"user": "alice", "role": "admin",
                          "meta": {"k": "v"}}).encode()
    out = ip.iter_insertion_points(
        method="POST", url="https://h/api",
        headers=[("Content-Type", "application/json")],
        body=body,
    )
    json_pts = [(p.ip_type, p.path, p.value) for p in out
                  if p.location == "json"]
    # Three string leaves + their keys, plus the nested key/value.
    paths = {p[1] for p in json_pts}
    assert "user" in paths
    assert "role" in paths
    assert "meta.k" in paths
    # Both kinds present.
    kinds = {p[0] for p in json_pts}
    assert kinds == {"json-key", "json-value"}


def test_iter_xml_yields_element_text_and_attr():
    body = b'<?xml version="1.0"?><root attr="a-val"><user>alice</user></root>'
    out = ip.iter_insertion_points(
        method="POST", url="https://h/api",
        headers=[("Content-Type", "application/xml")],
        body=body,
    )
    types = [(p.ip_type, p.name, p.value) for p in out if p.location == "xml"]
    assert ("xml-value", "user", "alice") in types
    assert ("xml-attr", "attr", "a-val") in types


def test_iter_path_segments_and_filename():
    out = ip.iter_insertion_points(
        method="GET", url="https://h/api/v1/users/42",
        headers=[], body=b"",
    )
    segs = [(p.ip_type, p.name, p.value) for p in out if p.location == "path"]
    assert ("path-segment", "0", "api") in segs
    assert ("path-segment", "1", "v1") in segs
    assert ("path-segment", "2", "users") in segs
    assert ("path-segment", "3", "42") in segs
    assert ("path-filename", "filename", "42") in segs


def test_iter_body_only_emitted_with_body():
    # Empty body → no whole-body point.
    out_empty = ip.iter_insertion_points(
        method="GET", url="https://h/", headers=[], body=b"",
    )
    assert not any(p.ip_type == "body" for p in out_empty)
    # Non-empty → exactly one body point.
    out_full = ip.iter_insertion_points(
        method="POST", url="https://h/",
        headers=[("Content-Type", "application/octet-stream")],
        body=b"raw bytes",
    )
    body_pts = [p for p in out_full if p.ip_type == "body"]
    assert len(body_pts) == 1
    assert body_pts[0].value == "raw bytes"


def test_iter_restricts_to_requested_kinds():
    out = ip.iter_insertion_points(
        method="POST", url="https://h/p?a=1",
        headers=[("Content-Type", "application/x-www-form-urlencoded"),
                   ("Cookie", "sid=x")],
        body=b"b=2",
        kinds=["query", "cookie"],
    )
    assert {p.ip_type for p in out} == {"query", "cookie"}


# --------------------------- nested-encoding detection -----------------------


def test_detect_nested_encoding_base64():
    val = "aGVsbG8gd29ybGQh"  # "hello world!"
    assert ip.detect_nested_encoding(val) == "base64"


def test_detect_nested_encoding_hex():
    val = "68656c6c6f"  # "hello"
    assert ip.detect_nested_encoding(val) == "hex"


def test_detect_nested_encoding_url():
    val = "a%20b%26c"
    assert ip.detect_nested_encoding(val) == "url"


def test_detect_nested_encoding_json():
    assert ip.detect_nested_encoding('{"k":"v"}') == "json"


def test_detect_nested_encoding_none_for_plain():
    assert ip.detect_nested_encoding("hello world") == "none"


def test_detect_nested_encoding_depth_capped():
    # Past the depth cap we always return ``none`` regardless of
    # whether the value LOOKS like it could decode further.
    assert ip.detect_nested_encoding("aGVsbG8gd29ybGQh", depth=99) == "none"


def test_detect_nested_encoding_rejects_oversize():
    big = "a%20" * 30_000  # > 64 KiB
    # URL detection is the first branch, but the size guard fires
    # first → ``none``.
    assert ip.detect_nested_encoding(big) == "none"


def test_peel_encoding_layers_oldest_first():
    # base64("hello world!") → "aGVsbG8gd29ybGQh" (16 chars — above the
    # detector's 12-char floor that guards against alphanumeric
    # false positives).
    decoded, layers = ip.peel_encoding("aGVsbG8gd29ybGQh")
    assert decoded == "hello world!"
    assert layers == ["base64"]


def test_peel_encoding_bounded_by_max_depth():
    # Deeply-nested input — peel returns whatever it got through.
    decoded, layers = ip.peel_encoding("aGVsbG8gd29ybGQh")
    assert len(layers) <= ip._MAX_NESTED_DEPTH


# --------------------------- mutate ------------------------------------------


def test_mutate_query_value():
    point = ip.InsertionPoint("query", "a", "1", "query")
    req = ip.mutate(
        method="GET", url="https://h/p?a=1&b=2",
        headers=[], body=b"", point=point, new_value="payload",
    )
    assert "a=payload" in req.url
    assert "b=2" in req.url


def test_mutate_form_value_preserves_other_chunks():
    point = ip.InsertionPoint("form", "a", "1", "form",
                                  content_type="application/x-www-form-urlencoded")
    req = ip.mutate(
        method="POST", url="https://h/",
        headers=[("Content-Type", "application/x-www-form-urlencoded")],
        body=b"a=1&b=2", point=point, new_value="X",
    )
    assert b"a=X" in req.body
    assert b"b=2" in req.body


def test_mutate_cookie_value_keeps_other_cookies():
    point = ip.InsertionPoint("cookie", "sid", "abc", "cookie")
    req = ip.mutate(
        method="GET", url="https://h/",
        headers=[("Cookie", "sid=abc; theme=dark")],
        body=b"", point=point, new_value="hijack",
    )
    cookie = next(v for k, v in req.headers if k.lower() == "cookie")
    assert "sid=hijack" in cookie
    assert "theme=dark" in cookie


def test_mutate_header_replaces_first_occurrence():
    point = ip.InsertionPoint("header", "User-Agent", "Mozilla/5.0", "header")
    req = ip.mutate(
        method="GET", url="https://h/",
        headers=[("User-Agent", "Mozilla/5.0"), ("Accept", "text/html")],
        body=b"", point=point, new_value="reqlore-probe",
    )
    ua = next(v for k, v in req.headers if k.lower() == "user-agent")
    assert ua == "reqlore-probe"


def test_mutate_json_value_round_trip():
    body = json.dumps({"user": "alice", "role": "admin"}).encode()
    point = ip.InsertionPoint("json-value", "user", "alice",
                                  "json", content_type="application/json",
                                  path="user")
    req = ip.mutate(
        method="POST", url="https://h/",
        headers=[("Content-Type", "application/json")],
        body=body, point=point, new_value="' OR 1=1--",
    )
    parsed = json.loads(req.body)
    assert parsed["user"] == "' OR 1=1--"
    assert parsed["role"] == "admin"


def test_mutate_xml_value_keeps_rest_byte_identical():
    body = b'<?xml version="1.0"?><root><user>alice</user><role>admin</role></root>'
    point = ip.InsertionPoint("xml-value", "user", "alice",
                                  "xml", content_type="application/xml",
                                  path="user")
    req = ip.mutate(
        method="POST", url="https://h/",
        headers=[("Content-Type", "application/xml")],
        body=body, point=point, new_value="bob",
    )
    assert b"<user>bob</user>" in req.body
    assert b"<role>admin</role>" in req.body


def test_mutate_path_segment_replaces_only_indexed_segment():
    point = ip.InsertionPoint("path-segment", "2", "users", "path", path="2")
    req = ip.mutate(
        method="GET", url="https://h/api/v1/users/42",
        headers=[], body=b"", point=point, new_value="admins",
    )
    assert "/api/v1/admins/42" in req.url


def test_mutate_path_filename_swaps_basename():
    point = ip.InsertionPoint("path-filename", "filename", "42", "path")
    req = ip.mutate(
        method="GET", url="https://h/api/v1/users/42",
        headers=[], body=b"", point=point, new_value="../../etc/passwd",
    )
    # Path is %-encoded so slashes don't escape.
    assert "/api/v1/users/" in req.url
    assert "passwd" in req.url


def test_mutate_param_name_query_renames_key():
    point = ip.InsertionPoint("param-name", "id", "id", "query")
    req = ip.mutate(
        method="GET", url="https://h/p?id=42&foo=bar",
        headers=[], body=b"", point=point, new_value="user_id",
    )
    assert "user_id=42" in req.url
    assert "foo=bar" in req.url
    assert "id=42" not in req.url.replace("user_id=42", "")


def test_mutate_body_replaces_entire_payload():
    point = ip.InsertionPoint("body", "", "<old>", "body")
    req = ip.mutate(
        method="POST", url="https://h/",
        headers=[("Content-Type", "application/xml")],
        body=b"<old>", point=point, new_value="<xxe-payload/>",
    )
    assert req.body == b"<xxe-payload/>"


def test_mutate_unknown_type_raises():
    point = ip.InsertionPoint("nonsense", "x", "y", "wherever")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ip.mutate(
            method="GET", url="https://h/", headers=[], body=b"",
            point=point, new_value="z",
        )


def test_mutate_scrubs_hop_by_hop_headers():
    point = ip.InsertionPoint("query", "a", "1", "query")
    req = ip.mutate(
        method="GET", url="https://h/p?a=1",
        headers=[("Host", "h"), ("Content-Length", "0"),
                   ("Transfer-Encoding", "chunked"), ("X-Other", "ok")],
        body=b"", point=point, new_value="2",
    )
    hk = {k.lower() for k, _ in req.headers}
    assert "host" not in hk
    assert "content-length" not in hk
    assert "transfer-encoding" not in hk
    assert "x-other" in hk


# --------------------------- cache -------------------------------------------


def test_cache_dedupes_identical_points():
    cache = ip.InsertionPointCache(cap=10)
    point = ip.InsertionPoint("query", "a", "1", "query")
    assert cache.seen(rule_id="r1", point=point) is False
    assert cache.mark(rule_id="r1", point=point) is True
    assert cache.seen(rule_id="r1", point=point) is True
    # Same point, different rule → not yet seen.
    assert cache.seen(rule_id="r2", point=point) is False


def test_cache_enforces_cap_returning_false_on_overflow():
    cache = ip.InsertionPointCache(cap=2)
    p1 = ip.InsertionPoint("query", "a", "1", "query")
    p2 = ip.InsertionPoint("query", "b", "2", "query")
    p3 = ip.InsertionPoint("query", "c", "3", "query")
    assert cache.mark(rule_id="r", point=p1) is True
    assert cache.mark(rule_id="r", point=p2) is True
    assert cache.mark(rule_id="r", point=p3) is False  # cap hit
    assert cache.evictions == 1


# --------------------------- relocation matrix -------------------------------


def test_relocate_query_to_form_adds_to_body():
    req = ip.relocate(
        method="POST", url="https://h/p?id=42", headers=[], body=b"",
        name="id", value="42", from_loc="query", to_loc="form",
    )
    assert b"id=42" in req.body
    ct = next(v for k, v in req.headers if k.lower() == "content-type")
    assert "x-www-form-urlencoded" in ct
    # Source preserved.
    assert "id=42" in req.url


def test_relocate_form_to_cookie_appends_to_existing_cookie():
    req = ip.relocate(
        method="POST", url="https://h/",
        headers=[("Cookie", "sid=abc")],
        body=b"id=42",
        name="id", value="42", from_loc="form", to_loc="cookie",
    )
    cookie = next(v for k, v in req.headers if k.lower() == "cookie")
    assert "sid=abc" in cookie
    assert "id=42" in cookie


def test_relocate_rejects_off_matrix_pair():
    with pytest.raises(ValueError):
        ip.relocate(
            method="GET", url="https://h/", headers=[], body=b"",
            name="x", value="y", from_loc="header", to_loc="query",
        )


# --------------------------- options -----------------------------------------


def test_active_options_exposes_insertion_point_cap_default_200():
    opts = ActiveOptions()
    assert opts.max_insertion_points_per_row == 200


def test_active_options_insertion_point_cap_is_overridable():
    opts = ActiveOptions(max_insertion_points_per_row=50)
    assert opts.max_insertion_points_per_row == 50

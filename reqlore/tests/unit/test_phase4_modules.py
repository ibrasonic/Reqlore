"""Phase 4 — GraphQL parsing, SAML decoding, PoC generators, macros."""
from __future__ import annotations

import base64
import json
import zlib

import pytest

from reqlore.engines import Request, Response
from reqlore.graphql import parse_schema
from reqlore.macros import Macro, MacroStep, run as run_macro
from reqlore.poc import clickjacking_poc, csrf_fetch_poc, csrf_form_poc
from reqlore.saml import inspect as saml_inspect


# ---- GraphQL ----

def test_parse_schema_flattens_types():
    introspection = {
        "data": {"__schema": {
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "user",
                     "type": {"kind": "NON_NULL",
                              "ofType": {"kind": "OBJECT", "name": "User"}},
                     "args": [{"name": "id",
                                "type": {"kind": "NON_NULL",
                                          "ofType": {"kind": "SCALAR", "name": "ID"}}}],
                     "description": "Look up a user"}]},
                {"kind": "OBJECT", "name": "User", "fields": [
                    {"name": "email", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
                {"kind": "OBJECT", "name": "__Skip", "fields": []},   # filtered
            ]
        }}
    }
    types = parse_schema(introspection)
    names = [t.name for t in types]
    assert "Query" in names and "User" in names
    assert "__Skip" not in names
    q = next(t for t in types if t.name == "Query")
    assert q.fields[0].name == "user"
    assert q.fields[0].type_str == "User!"
    assert q.fields[0].args[0]["type"] == "ID!"


# ---- SAML ----

def test_saml_inspect_post_binding_unsigned():
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        'ID="r1" Destination="https://sp.example/acs">'
        '<saml:Issuer>https://idp.example</saml:Issuer>'
        '<saml:Assertion ID="a1">'
        '<saml:Conditions>'
        '</saml:Conditions>'
        '</saml:Assertion>'
        '</samlp:Response>'
    )
    b64 = base64.b64encode(xml.encode()).decode()
    r = saml_inspect(b64)
    assert r.error == ""
    assert r.binding == "http-post"
    assert r.issuer == "https://idp.example"
    titles = {f.title for f in r.findings}
    assert "SAML message is not signed" in titles
    assert any("AudienceRestriction" in t for t in titles)
    assert any("expiry" in t.lower() for t in titles)


def test_saml_inspect_redirect_binding_deflate():
    xml = '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x"/>'
    raw = zlib.compress(xml.encode())
    # Strip the 2-byte zlib header + 4-byte adler32 to get raw DEFLATE.
    deflated = raw[2:-4]
    b64 = base64.b64encode(deflated).decode()
    r = saml_inspect(b64)
    assert r.error == ""
    assert r.binding == "http-redirect"


def test_saml_inspect_weak_algorithm_flag():
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x">'
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        '<ds:SignedInfo>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        '</ds:SignedInfo></ds:Signature>'
        '</samlp:Response>'
    )
    r = saml_inspect(base64.b64encode(xml.encode()).decode())
    assert any("SHA1" in f.title for f in r.findings)


# ---- PoC ----

def test_csrf_form_poc_renders_inputs():
    poc = csrf_form_poc(
        "POST", "https://x.test/transfer",
        headers=[("Content-Type", "application/x-www-form-urlencoded")],
        body=b"to=bob&amount=999",
    )
    assert "<form" in poc.html
    assert 'action="https://x.test/transfer"' in poc.html
    assert 'name="to"' in poc.html and 'value="bob"' in poc.html
    assert 'name="amount"' in poc.html and 'value="999"' in poc.html


def test_csrf_fetch_poc_credentials_include():
    poc = csrf_fetch_poc("POST", "https://x.test/api",
                          headers=[("Content-Type", "application/json")],
                          body=b'{"a":1}')
    assert "credentials: 'include'" in poc.html
    # Body is JSON-encoded inside the JS, so quotes are backslash-escaped.
    assert '\\"a\\":1' in poc.html


def test_clickjacking_poc_iframes_target():
    poc = clickjacking_poc("https://x.test/", overlay_text="<script>")
    assert "<iframe" in poc.html
    assert 'src="https://x.test/"' in poc.html
    # Overlay must be HTML-escaped.
    assert "&lt;script&gt;" in poc.html
    assert "<script>" not in poc.html


# ---- Macros ----

def test_macro_runs_with_variable_capture_and_substitution():
    calls: list[Request] = []

    def fake_sender(req: Request) -> Response:
        calls.append(req)
        if req.url.endswith("/login"):
            return Response(
                status=200,
                headers=[("Set-Cookie", "session=AAA"),
                          ("Content-Type", "text/html")],
                body=b'<form><input name="csrf_token" value="TOKEN42"></form>',
                engine="fake",
            )
        return Response(status=200, headers=[], body=b"ok", engine="fake")

    macro = Macro(name="test", steps=[
        MacroStep(name="login", method="POST", url="https://x.test/login",
                  body="u=a&p=b", capture={
                      "session": {"source": "header", "name": "Set-Cookie"},
                      "csrf": {"source": "regex", "where": "body",
                                "pattern": 'csrf_token" value="([^"]+)"'}}),
        MacroStep(name="act", method="POST", url="https://x.test/api",
                  headers={"Cookie": "{{session}}",
                            "X-CSRF": "{{csrf}}"},
                  body=""),
    ])
    run = run_macro(macro, sender=fake_sender)
    assert len(run.steps) == 2
    assert run.variables["session"] == "session=AAA"
    assert run.variables["csrf"] == "TOKEN42"
    second = calls[1]
    assert ("Cookie", "session=AAA") in second.headers
    assert ("X-CSRF", "TOKEN42") in second.headers


def test_macro_stops_on_error():
    def fake_sender(req: Request) -> Response:
        return Response(status=0, headers=[], body=b"",
                         engine="fake", error="boom")

    macro = Macro(name="t", steps=[
        MacroStep(name="a", method="GET", url="https://x.test/"),
        MacroStep(name="b", method="GET", url="https://x.test/"),
    ])
    run = run_macro(macro, sender=fake_sender)
    assert len(run.steps) == 1
    assert run.steps[0].error == "boom"


def test_macro_json_round_trip():
    macro = Macro(name="m", base_headers={"X-A": "1"},
                   variables={"foo": "bar"},
                   steps=[MacroStep(name="s1", method="GET", url="x")])
    blob = macro.to_json()
    back = Macro.from_json(blob)
    assert back.name == "m"
    assert back.base_headers == {"X-A": "1"}
    assert back.variables == {"foo": "bar"}
    assert len(back.steps) == 1 and back.steps[0].url == "x"


def test_macro_capture_json_path():
    """JSON-path capture should walk dotted paths."""
    from reqlore.macros import _capture

    resp = Response(
        status=200, headers=[("Content-Type", "application/json")],
        body=b'{"data":{"token":"abc","user":{"id":7}}}',
        engine="fake",
    )
    out = _capture(resp, {
        "tok": {"source": "json", "path": "data.token"},
        "uid": {"source": "json", "path": "data.user.id"},
        "missing": {"source": "json", "path": "no.such"},
    })
    assert out == {"tok": "abc", "uid": "7", "missing": ""}

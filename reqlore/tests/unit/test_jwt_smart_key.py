"""Unit tests for the JWT workbench smart-key-input (JWK / JWKS / URL).

Covers:
* jwk_resolver.resolve_public_key format detection
* Kid selection precedence
* Non-RSA rejection
* Security guards (scheme allow-list, size caps, empty input)
* Web-integration: POST /jwt/ with action=key_confusion using PEM, JWK,
  JWKS document, and JWKS URL (mocked fetcher / real httpx via a local
  Flask app pointing at a fake JWKS endpoint)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from reqlore.config import Settings
from reqlore.jwk_resolver import resolve_public_key
from reqlore.web import create_app

# ---------------------------------------------------------------- fixtures ----

@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_pem(rsa_key):
    return rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


@pytest.fixture(scope="module")
def rsa_jwk(rsa_key):
    """Build a valid RSA JWK dict from the fixture key."""
    from jwt.algorithms import RSAAlgorithm
    pub = rsa_key.public_key()
    # PyJWT ships to_jwk on the algorithm; returns a JSON string.
    return json.loads(RSAAlgorithm.to_jwk(pub))


@pytest.fixture(scope="module")
def rsa_jwk_with_kid(rsa_jwk):
    d = dict(rsa_jwk)
    d["kid"] = "primary-2024"
    return d


@pytest.fixture(scope="module")
def second_rsa_jwk():
    from jwt.algorithms import RSAAlgorithm
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    d = json.loads(RSAAlgorithm.to_jwk(k.public_key()))
    d["kid"] = "secondary-2024"
    return d


# ---------------------------------------------------------------- pure unit ----

class TestPemPassthrough:
    def test_pem_returned_verbatim(self, rsa_pem):
        pem, label = resolve_public_key(rsa_pem)
        assert pem == rsa_pem
        assert label == "PEM (as-provided)"

    def test_pem_with_surrounding_whitespace_still_passes(self, rsa_pem):
        # Whitespace around a PEM must not break the passthrough path.
        pem, label = resolve_public_key("\n\n  " + rsa_pem + "\n")
        # We return the original text unchanged (pyjwt is tolerant of
        # surrounding whitespace).
        assert "BEGIN PUBLIC KEY" in pem
        assert label == "PEM (as-provided)"


class TestSingleJwk:
    def test_single_jwk_converts_to_spki_pem(self, rsa_jwk):
        pem, label = resolve_public_key(json.dumps(rsa_jwk))
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.rstrip().endswith("-----END PUBLIC KEY-----")
        assert label == "JWK"

    def test_single_jwk_ec_rejected_with_clear_error(self):
        ec_jwk = {"kty": "EC", "crv": "P-256",
                   "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                   "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
        with pytest.raises(ValueError, match="Only RSA"):
            resolve_public_key(json.dumps(ec_jwk))

    def test_single_jwk_oct_rejected(self):
        with pytest.raises(ValueError, match="Only RSA"):
            resolve_public_key(json.dumps({"kty": "oct", "k": "AAAA"}))

    def test_malformed_jwk_json(self):
        with pytest.raises(ValueError, match="Not valid JSON"):
            resolve_public_key('{"kty":"RSA",')


class TestJwksDocument:
    def test_jwks_picks_by_kid(self, rsa_jwk_with_kid, second_rsa_jwk):
        jwks = {"keys": [second_rsa_jwk, rsa_jwk_with_kid]}
        pem, label = resolve_public_key(json.dumps(jwks), kid="primary-2024")
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert "kid=primary-2024" in label
        assert "2 keys" in label

    def test_jwks_kid_missing_uses_first_rsa(self, rsa_jwk, second_rsa_jwk):
        jwks = {"keys": [rsa_jwk, second_rsa_jwk]}  # first has no kid
        pem, label = resolve_public_key(json.dumps(jwks))
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        # Neither given kid nor first-key-has-kid; label reports "first RSA key".
        assert "first RSA key" in label

    def test_jwks_kid_missing_prefers_first_kid_if_present(
        self, rsa_jwk_with_kid, second_rsa_jwk
    ):
        jwks = {"keys": [rsa_jwk_with_kid, second_rsa_jwk]}
        pem, label = resolve_public_key(json.dumps(jwks))
        # First entry has a kid, so label surfaces it.
        assert "kid=primary-2024" in label

    def test_jwks_skips_non_rsa_when_no_kid(self, second_rsa_jwk):
        jwks = {"keys": [
            {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"},
            second_rsa_jwk,
        ]}
        pem, label = resolve_public_key(json.dumps(jwks))
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert "kid=secondary-2024" in label

    def test_jwks_kid_pointing_at_non_rsa_key_errors_clearly(self, rsa_jwk_with_kid):
        # If the kid names an EC key, don't silently fall through; report the kty.
        jwks = {"keys": [
            {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB", "kid": "ec-1"},
            rsa_jwk_with_kid,
        ]}
        with pytest.raises(ValueError, match="Only RSA"):
            resolve_public_key(json.dumps(jwks), kid="ec-1")

    def test_jwks_kid_not_found_lists_available(self, rsa_jwk_with_kid):
        jwks = {"keys": [rsa_jwk_with_kid]}
        with pytest.raises(ValueError) as ei:
            resolve_public_key(json.dumps(jwks), kid="does-not-exist")
        msg = str(ei.value)
        assert "does-not-exist" in msg
        assert "primary-2024" in msg  # available kids listed

    def test_jwks_no_rsa_keys_at_all(self):
        jwks = {"keys": [
            {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "BBBB"},
        ]}
        with pytest.raises(ValueError, match="no RSA keys"):
            resolve_public_key(json.dumps(jwks))

    def test_jwks_empty_keys_array(self):
        with pytest.raises(ValueError, match="empty or malformed"):
            resolve_public_key(json.dumps({"keys": []}))

    def test_jwks_keys_wrong_type(self):
        with pytest.raises(ValueError, match="not an array"):
            resolve_public_key(json.dumps({"keys": "not-a-list"}))


class TestUrlSecurityGuards:
    def test_file_scheme_rejected(self):
        with pytest.raises(ValueError, match="http:// and https://"):
            resolve_public_key("file:///etc/passwd", fetcher=lambda u: b"")

    def test_ftp_scheme_rejected(self):
        with pytest.raises(ValueError, match="http:// and https://"):
            resolve_public_key("ftp://target/jwks.json", fetcher=lambda u: b"")

    def test_gopher_scheme_rejected(self):
        with pytest.raises(ValueError, match="http:// and https://"):
            resolve_public_key("gopher://x/", fetcher=lambda u: b"")

    def test_javascript_scheme_rejected(self):
        with pytest.raises(ValueError, match="http:// and https://"):
            resolve_public_key("javascript:alert(1)", fetcher=lambda u: b"")

    def test_data_scheme_rejected(self):
        with pytest.raises(ValueError, match="http:// and https://"):
            resolve_public_key("data:application/json,{\"keys\":[]}",
                                fetcher=lambda u: b"")

    def test_scheme_relative_not_treated_as_url(self):
        # //target/jwks isn't a legal URL for us -- must be flagged as
        # "unrecognised format", NOT fetched.
        with pytest.raises(ValueError, match="Unrecognised format"):
            resolve_public_key("//target/jwks.json", fetcher=lambda u: b"")

    def test_http_url_no_host_rejected(self):
        with pytest.raises(ValueError, match="no host"):
            resolve_public_key("http:///path", fetcher=lambda u: b"")


class TestUrlFetch:
    def test_url_fetches_and_selects_by_kid(
        self, rsa_jwk_with_kid, second_rsa_jwk
    ):
        jwks = {"keys": [second_rsa_jwk, rsa_jwk_with_kid]}
        called: list[str] = []

        def fetcher(url: str) -> bytes:
            called.append(url)
            return json.dumps(jwks).encode()

        pem, label = resolve_public_key(
            "https://target/.well-known/jwks.json",
            kid="primary-2024", fetcher=fetcher,
        )
        assert called == ["https://target/.well-known/jwks.json"]
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert label.startswith("JWKS URL")
        assert "kid=primary-2024" in label

    def test_url_body_too_large_rejected(self):
        big = b"x" * (2 * 1024 * 1024)  # 2 MB > 1 MB cap
        with pytest.raises(ValueError, match="exceeds"):
            resolve_public_key("https://target/jwks", fetcher=lambda u: big)

    def test_url_fetch_exception_wrapped(self):
        def boom(url: str) -> bytes:
            raise ConnectionError("connection refused")
        with pytest.raises(ValueError, match="Fetch failed"):
            resolve_public_key("https://target/jwks", fetcher=boom)

    def test_url_fetch_valueerror_passthrough(self):
        # Fetcher already raised a user-safe ValueError -- pass through
        # verbatim rather than double-wrapping.
        def refuse(url: str) -> bytes:
            raise ValueError("JWKS URL returned HTTP 404.")
        with pytest.raises(ValueError, match="HTTP 404"):
            resolve_public_key("https://target/jwks", fetcher=refuse)

    def test_url_body_not_utf8(self):
        with pytest.raises(ValueError, match="UTF-8"):
            resolve_public_key(
                "https://target/jwks",
                fetcher=lambda u: b"\xff\xfe\x00garbage",
            )

    def test_url_body_not_json(self):
        with pytest.raises(ValueError, match="Not valid JSON"):
            resolve_public_key(
                "https://target/jwks",
                fetcher=lambda u: b"<html>404</html>",
            )

    def test_url_without_fetcher_errors(self):
        with pytest.raises(ValueError, match="internal error"):
            resolve_public_key("https://target/jwks")


class TestInputSizeGuards:
    def test_empty_input(self):
        with pytest.raises(ValueError, match="empty"):
            resolve_public_key("")

    def test_whitespace_only_input(self):
        with pytest.raises(ValueError, match="empty"):
            resolve_public_key("   \n\t   ")

    def test_none_input(self):
        with pytest.raises(ValueError, match="empty"):
            resolve_public_key(None)  # type: ignore[arg-type]

    def test_paste_larger_than_cap_rejected(self):
        huge = "x" * (200 * 1024)  # 200 KB > 128 KB cap
        with pytest.raises(ValueError, match="too large"):
            resolve_public_key(huge)


class TestUnrecognised:
    def test_arbitrary_text_rejected(self):
        with pytest.raises(ValueError, match="Unrecognised format"):
            resolve_public_key("this is just some notes I made about the target")


# ---------------------------------------------------------- web integration ----

@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "smart.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client):
    client.get("/jwt/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _sample_token() -> str:
    # kid=primary-2024 in the header so the resolver picks it out of a JWKS.
    return ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InByaW1hcnktMjAyNCJ9"
            ".eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9"
            ".signature_ignored_for_smart_key_test")


class TestKeyConfusionSmartInputWeb:
    def test_pem_still_works_unchanged(self, client, rsa_pem):
        # Regression: a plain PEM must behave exactly as it did before.
        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": rsa_pem, "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"Forged token" in r.data
        assert b"PEM (as-provided)" in r.data

    def test_single_jwk_accepted(self, client, rsa_jwk):
        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": json.dumps(rsa_jwk), "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"Forged token" in r.data
        # source label appears in the muted paragraph
        assert b"JWK" in r.data

    def test_jwks_doc_selects_by_token_kid(
        self, client, rsa_jwk_with_kid, second_rsa_jwk
    ):
        jwks = {"keys": [second_rsa_jwk, rsa_jwk_with_kid]}
        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": json.dumps(jwks), "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"Forged token" in r.data
        assert b"primary-2024" in r.data

    def test_missing_public_key_error_mentions_all_formats(self, client):
        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": "", "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        # Error paragraph mentions the new accepted formats.
        assert b"PEM" in r.data
        assert b"JWK" in r.data
        assert b"URL" in r.data

    def test_file_url_rejected_via_web(self, client):
        # SSRF guard reachable through the HTTP route.
        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": "file:///etc/passwd", "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"http:// and https://" in r.data

    def test_jwks_url_logs_fetch_to_history(
        self, client, app, rsa_jwk_with_kid, monkeypatch
    ):
        """URL input must go through httpx and land in http_history."""
        # Fake httpx_engine.send so we don't hit the network.
        from reqlore.engines import Response, Timings
        captured: dict = {}

        def fake_send(req, **kwargs):
            captured["url"] = req.url
            captured["kwargs"] = kwargs
            body = json.dumps({"keys": [rsa_jwk_with_kid]}).encode()
            return Response(
                status=200, reason="OK",
                headers=[("Content-Type", "application/json"),
                         ("Content-Length", str(len(body)))],
                body=body, http_version="1.1",
                timings=Timings(total_ms=5), engine="httpx",
            )

        import reqlore.web.blueprints.jwt_bp as jwt_bp_mod
        monkeypatch.setattr(jwt_bp_mod.httpx_engine, "send", fake_send)

        proj = app.extensions["reqlore_project"]
        before = len(proj.list_history(limit=1000))

        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": "https://target.example/.well-known/jwks.json",
            "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"Forged token" in r.data
        assert b"JWKS URL" in r.data
        # Fetch was actually made
        assert captured["url"] == "https://target.example/.well-known/jwks.json"
        # Redirects disabled + timeout applied
        assert captured["kwargs"].get("follow_redirects") is False
        assert isinstance(captured["kwargs"].get("timeout"), (int, float))
        # History gained exactly one row tagged jwt/jwks-fetch
        after = proj.list_history(limit=1000)
        assert len(after) == before + 1
        newest = after[0]
        assert newest.engine == "jwt/jwks-fetch"
        assert newest.method == "GET"
        assert newest.url == "https://target.example/.well-known/jwks.json"

    def test_jwks_url_non_2xx_shows_error(self, client, monkeypatch):
        from reqlore.engines import Response, Timings

        def fake_send(req, **kwargs):
            return Response(
                status=404, reason="Not Found",
                headers=[("Content-Type", "text/plain")],
                body=b"nope", http_version="1.1",
                timings=Timings(total_ms=1), engine="httpx",
            )

        import reqlore.web.blueprints.jwt_bp as jwt_bp_mod
        monkeypatch.setattr(jwt_bp_mod.httpx_engine, "send", fake_send)

        token = _csrf(client)
        r = client.post("/jwt/", data={
            "action": "key_confusion", "token": _sample_token(),
            "public_key": "https://target.example/jwks",
            "_csrf": token,
            "header_text": "", "payload_text": "", "alg": "HS256",
            "secret": "", "private_key": "", "kid_values": "",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"HTTP 404" in r.data

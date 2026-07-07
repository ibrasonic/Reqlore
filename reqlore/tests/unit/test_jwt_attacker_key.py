"""Unit tests for the JWT workbench "Generate attacker key" feature.

Covers the jwk / jku header-injection sinks (action=attacker_key):

* embedded-jwk path produces a token that verifies against the generated key
* jku path hosts a JWK Set, the header jku points at it, and fetch-then-verify
  succeeds
* both RSA-2048 and EC P-256 work
* the session keypair is reused across repeated presses
* the two named error cases surface as friendly 200 responses, not 500s
* publish + fetch are logged to History as jwt/jwks-host
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import jwt as pyjwt
import pytest
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from reqlore.config import Settings
from reqlore.web import create_app

TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.ignored_signature"  # noqa: S105  # sample JWT test fixture, not a credential


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "atk.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client) -> str:
    client.get("/jwt/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def _gen(client, *, key_type="RSA", advertise="jwk", header_text=""):
    """Press "Generate attacker key" and return the redirected page."""
    return client.post("/jwt/", data={
        "action": "attacker_key", "key_type": key_type, "advertise": advertise,
        "token": TOKEN, "header_text": header_text,
        "payload_text": '{"sub":"alice"}', "alg": "HS256",
        "secret": "", "private_key": "", "public_key": "", "kid_values": "",
        "_csrf": _csrf(client),
    }, follow_redirects=True)


def _record(client, key_type="RSA"):
    """Return the server-side keypair record for this client's session.

    Calling keypair() with the same key type returns the existing record
    (no regeneration), so this is a read-through accessor.
    """
    import reqlore.web.blueprints.jwt_bp as m
    with client.session_transaction() as sess:
        sid = sess["jwt_sid"]
    return m._attacker_state.keypair(sid, key_type)


def _public_key_from_jwk(jwk: dict):
    s = json.dumps(jwk)
    if jwk.get("kty") == "EC":
        return ECAlgorithm.from_jwk(s)
    return RSAAlgorithm.from_jwk(s)


def _sign(client, *, alg, header, payload, private_pem) -> str:
    r = client.post("/jwt/", data={
        "action": "sign", "alg": alg,
        "header_text": json.dumps(header), "payload_text": json.dumps(payload),
        "private_key": private_pem, "secret": "", "token": "",
        "public_key": "", "kid_values": "", "key_type": "RSA", "advertise": "jwk",
        "_csrf": _csrf(client),
    }, follow_redirects=True)
    assert r.status_code == 200
    m = re.search(
        rb"Signed token</h2>.*?<code>([A-Za-z0-9_\-.]+)</code>", r.data, re.S
    )
    assert m, "signed token not found in response"
    return m.group(1).decode()


# ---------------------------------------------------------------- jwk mode ----

@pytest.mark.parametrize("key_type,alg", [("RSA", "RS256"), ("EC", "ES256")])
def test_embedded_jwk_token_verifies(client, key_type, alg):
    r = _gen(client, key_type=key_type, advertise="jwk")
    assert r.status_code == 200
    assert b"embedded as jwk" in r.data
    # private key was written into the form
    assert b"BEGIN PRIVATE KEY" in r.data
    # header now carries a jwk member
    assert b'"jwk"' in r.data

    rec = _record(client, key_type)
    assert rec["alg"] == alg
    header = {"alg": rec["alg"], "jwk": rec["public_jwk"]}
    token = _sign(client, alg=rec["alg"], header=header,
                  payload={"sub": "alice", "role": "admin"},
                  private_pem=rec["private_pem"])
    claims = pyjwt.decode(
        token, _public_key_from_jwk(rec["public_jwk"]), algorithms=[rec["alg"]]
    )
    assert claims["sub"] == "alice"
    assert claims["role"] == "admin"


# ---------------------------------------------------------------- jku mode ----

@pytest.mark.parametrize("key_type", ["RSA", "EC"])
def test_jku_hosts_serves_and_verifies(client, app, key_type):
    r = _gen(client, key_type=key_type, advertise="jku")
    assert r.status_code == 200
    assert b"JWK Set hosted" in r.data
    # the header's jku member is present
    assert b'"jku"' in r.data

    m = re.search(rb"(/jwt/keys/[0-9a-f]+/jwks\.json)", r.data)
    assert m, "hosted jku path not found"
    path = m.group(1).decode()

    # The hosted endpoint serves the public JWK Set.
    fr = client.get(path)
    assert fr.status_code == 200
    assert "jwk-set+json" in fr.headers["Content-Type"]
    jwks = json.loads(fr.data)
    assert "keys" in jwks and jwks["keys"]
    served = jwks["keys"][0]
    assert served["kty"] == ("EC" if key_type == "EC" else "RSA")
    # never leaks the private half
    assert "d" not in served

    # fetch-then-verify: sign with our key, verify against the served public key.
    rec = _record(client, key_type)
    header = {"alg": rec["alg"], "jku": "http://lab.example" + path, "kid": rec["kid"]}
    token = _sign(client, alg=rec["alg"], header=header,
                  payload={"sub": "alice"}, private_pem=rec["private_pem"])
    claims = pyjwt.decode(
        token, _public_key_from_jwk(served), algorithms=[rec["alg"]]
    )
    assert claims["sub"] == "alice"


def test_jku_publish_and_fetch_logged_to_history(client, app):
    proj = app.extensions["reqlore_project"]
    before = len(proj.list_history(limit=1000))

    r = _gen(client, key_type="RSA", advertise="jku")
    assert r.status_code == 200
    # publish logged
    after_publish = proj.list_history(limit=1000)
    assert len(after_publish) == before + 1
    assert after_publish[0].engine == "jwt/jwks-host"
    assert after_publish[0].method == "PUT"

    m = re.search(rb"(/jwt/keys/[0-9a-f]+/jwks\.json)", r.data)
    path = m.group(1).decode()
    client.get(path)
    # fetch logged as a second jwt/jwks-host row
    after_fetch = proj.list_history(limit=1000)
    assert len(after_fetch) == before + 2
    assert after_fetch[0].engine == "jwt/jwks-host"
    assert after_fetch[0].method == "GET"


# --------------------------------------------------------------- reuse --------

def test_keypair_reused_across_presses(client):
    _gen(client, key_type="RSA", advertise="jwk")
    rec1 = _record(client, "RSA")
    _gen(client, key_type="RSA", advertise="jwk")
    rec2 = _record(client, "RSA")
    assert rec1["private_pem"] == rec2["private_pem"]
    assert rec1["kid"] == rec2["kid"]


def test_jku_url_stable_across_presses(client):
    r1 = _gen(client, key_type="RSA", advertise="jku")
    u1 = re.search(rb"(/jwt/keys/[0-9a-f]+/jwks\.json)", r1.data).group(1)
    r2 = _gen(client, key_type="RSA", advertise="jku")
    u2 = re.search(rb"(/jwt/keys/[0-9a-f]+/jwks\.json)", r2.data).group(1)
    assert u1 == u2


def test_key_type_switch_regenerates(client):
    _gen(client, key_type="RSA", advertise="jwk")
    rec_rsa = _record(client, "RSA")
    assert rec_rsa["kty"] == "RSA"
    _gen(client, key_type="EC", advertise="jwk")
    rec_ec = _record(client, "EC")
    assert rec_ec["kty"] == "EC"
    assert rec_ec["private_pem"] != rec_rsa["private_pem"]


# --------------------------------------------------------- error handling -----

def test_missing_advertise_is_friendly_200(client):
    r = client.post("/jwt/", data={
        "action": "attacker_key", "key_type": "RSA", "advertise": "",
        "token": TOKEN, "header_text": "", "payload_text": "", "alg": "HS256",
        "secret": "", "private_key": "", "public_key": "", "kid_values": "",
        "_csrf": _csrf(client),
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Choose an advertise-via option (jwk or jku)." in r.data


def test_bad_advertise_value_is_friendly_200(client):
    r = client.post("/jwt/", data={
        "action": "attacker_key", "key_type": "RSA", "advertise": "banana",
        "token": TOKEN, "header_text": "", "payload_text": "", "alg": "HS256",
        "secret": "", "private_key": "", "public_key": "", "kid_values": "",
        "_csrf": _csrf(client),
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b"Choose an advertise-via option (jwk or jku)." in r.data


def test_host_endpoint_failure_is_friendly_200(client, monkeypatch):
    import reqlore.web.blueprints.jwt_bp as m

    def boom(_sid):
        raise RuntimeError("simulated host failure")

    monkeypatch.setattr(m._attacker_state, "publish_jwks", boom)
    r = _gen(client, key_type="RSA", advertise="jku")
    assert r.status_code == 200
    assert b"Could not start the key-host endpoint" in r.data


def test_unknown_hosted_id_404(client):
    assert client.get("/jwt/keys/deadbeef/jwks.json").status_code == 404

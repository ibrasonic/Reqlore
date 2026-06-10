"""Intruder JWT processor: mint a fresh JWT per payload."""
from __future__ import annotations

import base64
import json

import jwt as pyjwt
import pytest

from reqlore.intruder import (
    ARG_PROCESSORS, apply_processors, processor_names, _proc_jwt,
)


# ---- helpers --------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _split(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    assert len(parts) >= 2
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


# ---- registration ---------------------------------------------------------

def test_jwt_processor_is_registered():
    assert "jwt" in ARG_PROCESSORS
    assert ARG_PROCESSORS["jwt"] is _proc_jwt


def test_jwt_appears_in_processor_names_list():
    names = processor_names()
    assert "jwt:<arg>" in names


# ---- alg=none -------------------------------------------------------------

def test_jwt_none_claim_sub_emits_trailing_dot():
    out = _proc_jwt("admin", "none claim=sub")
    assert out.endswith(".")
    h, p, sig = _split(out)
    assert h["alg"] == "none"
    assert p == {"sub": "admin"}
    assert sig == ""


def test_jwt_none_header_kid_writes_into_header():
    out = _proc_jwt("../../etc/passwd", "none header=kid")
    h, p, _ = _split(out)
    assert h["alg"] == "none"
    assert h["kid"] == "../../etc/passwd"
    assert p == {}


# ---- HS256/384/512 --------------------------------------------------------

@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_jwt_hs_verifies_with_supplied_secret(alg):
    secret = "topsecret"
    out = _proc_jwt("alice", f"{alg} secret={secret} claim=sub")
    # Round-trip: pyjwt must accept the token with the same secret.
    decoded = pyjwt.decode(out, secret, algorithms=[alg])
    assert decoded["sub"] == "alice"
    h, _, _ = _split(out)
    assert h["alg"] == alg


def test_jwt_hs_rejects_with_wrong_secret():
    out = _proc_jwt("alice", "HS256 secret=topsecret claim=sub")
    with pytest.raises(pyjwt.InvalidSignatureError):
        pyjwt.decode(out, "WRONG", algorithms=["HS256"])


def test_jwt_hs_secret_with_spaces_via_quoted_arg():
    out = _proc_jwt(
        "alice",
        'HS256 secret="my long secret with spaces" claim=sub',
    )
    decoded = pyjwt.decode(
        out, "my long secret with spaces", algorithms=["HS256"],
    )
    assert decoded["sub"] == "alice"


# ---- base= seeds claims ---------------------------------------------------

def test_jwt_base_token_seeds_payload_and_header():
    base = pyjwt.encode(
        {"sub": "guest", "role": "user", "exp": 9999999999},
        "k", algorithm="HS256",
        headers={"kid": "key-1"},
    )
    out = _proc_jwt("admin", f"HS256 secret=k claim=sub base={base}")
    decoded = pyjwt.decode(out, "k", algorithms=["HS256"])
    # The named claim is overwritten; other claims survive.
    assert decoded["sub"] == "admin"
    assert decoded["role"] == "user"
    assert decoded["exp"] == 9999999999
    # Header is preserved (kid still there) and alg is forced.
    h, _, _ = _split(out)
    assert h["alg"] == "HS256"
    assert h["kid"] == "key-1"


def test_jwt_base_none_then_header_target_overwrites_kid():
    base = pyjwt.encode({"sub": "guest"}, "k", algorithm="HS256",
                        headers={"kid": "original"})
    out = _proc_jwt("../../dev/null", f"none header=kid base={base}")
    h, p, sig = _split(out)
    assert h["alg"] == "none"
    assert h["kid"] == "../../dev/null"
    assert p == {"sub": "guest"}
    assert sig == ""


# ---- error / fallback paths ----------------------------------------------

def test_jwt_unknown_alg_returns_payload_unchanged():
    assert _proc_jwt("alice", "RS256 claim=sub") == "alice"


def test_jwt_missing_target_returns_payload_unchanged():
    # Neither claim= nor header= supplied.
    assert _proc_jwt("alice", "HS256 secret=k") == "alice"


def test_jwt_both_claim_and_header_returns_payload_unchanged():
    # Ambiguous: exactly one target is required.
    out = _proc_jwt("alice", "HS256 secret=k claim=sub header=kid")
    assert out == "alice"


def test_jwt_empty_arg_returns_payload_unchanged():
    assert _proc_jwt("alice", "") == "alice"


def test_jwt_bad_base_token_falls_back_to_minimal_payload():
    out = _proc_jwt("alice", "none claim=sub base=not-a-jwt")
    h, p, _ = _split(out)
    assert h["alg"] == "none"
    assert p == {"sub": "alice"}


# ---- pipeline integration -------------------------------------------------

def test_apply_processors_runs_jwt_inline():
    out = apply_processors("alice", ["jwt:none claim=sub"])
    h, p, _ = _split(out)
    assert h["alg"] == "none"
    assert p == {"sub": "alice"}


def test_apply_processors_jwt_then_prefix_concatenates_bearer():
    # Common real-world chain: produce a token, then prepend "Bearer ".
    out = apply_processors(
        "alice",
        ["jwt:none claim=sub", "prefix:Bearer "],
    )
    assert out.startswith("Bearer ")
    h, p, _ = _split(out[len("Bearer "):])
    assert h["alg"] == "none"
    assert p["sub"] == "alice"


# ---- claim-bruteforce end-to-end (sniper over a tiny wordlist) -----------

def test_jwt_sniper_walk_produces_one_token_per_username():
    users = ["admin", "alice", "bob"]
    secret = "k"
    spec = f"jwt:HS256 secret={secret} claim=sub"
    tokens = [apply_processors(u, [spec]) for u in users]
    decoded = [pyjwt.decode(t, secret, algorithms=["HS256"]) for t in tokens]
    assert [d["sub"] for d in decoded] == users

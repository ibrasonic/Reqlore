"""Detect PEM / JWK / JWKS / JWKS-URL and return an SPKI PEM string.

Used by the JWT workbench so its ``public_key`` field accepts more than a
raw PEM. The module is deliberately tiny and pure-Python (no Flask, no
project globals) so it is trivially unit-testable and safe to reason
about.

Security posture (input is user-controlled, may be pasted from untrusted
material or point at an attacker-controlled URL):

* Raw textarea input is capped at ``_MAX_INPUT_BYTES`` (128 KB).
* Fetched body is capped at ``_MAX_FETCH_BYTES`` (1 MB) and only decoded
  if the response was 2xx.
* URLs are only followed when the scheme is ``http`` or ``https``.
  ``file://``, ``ftp://``, ``gopher://``, ``data:``, ``javascript:`` and
  scheme-less inputs are rejected before any I/O.
* Redirects are the caller's responsibility (the injected fetcher
  disables them so a JWKS URL cannot be redirected to ``file://`` or an
  internal host the tester didn't approve).
* ``RSAAlgorithm.from_jwk`` and the ``cryptography`` serializer perform
  the actual key parsing / validation; we only assemble the JSON and
  pick which key from a JWKS is used.
* Only ``kty="RSA"`` keys are accepted for the RS->HS forge. Other key
  types (``EC``, ``OKP``, ``oct``) raise a clear ``ValueError`` naming
  the offending kty.
* Every failure path raises ``ValueError`` with a short, user-safe
  message. Untrusted fragments (URLs, kids) that appear in messages are
  truncated to ``_MAX_LABEL_LEN`` to keep the error render bounded.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Iterable

from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm


_MAX_INPUT_BYTES = 128 * 1024          # 128 KB paste cap
_MAX_FETCH_BYTES = 1024 * 1024         # 1 MB fetched-JWKS cap
_MAX_LABEL_LEN = 120                   # truncate untrusted fragments in errors
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# RFC 3986 URI scheme grammar: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
# Used to decide whether an input is URL-shaped ("scheme:...") so we can
# route it through _validate_url and reject non-http(s) schemes with a
# clear, security-visible message instead of a generic "unrecognised
# format" error.
_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:")

Fetcher = Callable[[str], bytes]


def _safe(s: str) -> str:
    """Truncate a string for inclusion in a user-visible error message."""
    s = (s or "").strip().replace("\n", " ").replace("\r", " ")
    if len(s) > _MAX_LABEL_LEN:
        return s[:_MAX_LABEL_LEN] + "..."
    return s


def _jwk_to_pem(jwk: dict) -> str:
    """Convert a single JWK dict to an SPKI PEM string. Only RSA is accepted."""
    kty = jwk.get("kty")
    if kty != "RSA":
        raise ValueError(
            f"Only RSA keys are supported for RS->HS forge (got kty={_safe(str(kty))})."
        )
    try:
        # from_jwk accepts a JSON string; re-serialise so we control the payload.
        pub = RSAAlgorithm.from_jwk(json.dumps(jwk))
    except Exception as e:  # noqa: BLE001 - surface a short summary, never the traceback
        raise ValueError(f"Invalid JWK: {type(e).__name__}") from None
    try:
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as e:  # noqa: BLE001 - defensive; from_jwk normally guarantees success
        raise ValueError(f"Could not encode key as PEM: {type(e).__name__}") from None
    return pem.decode("ascii")


def _pick_from_jwks(keys: Iterable[dict], *, kid: str | None) -> tuple[dict, str]:
    """Choose a single JWK from a JWKS ``keys`` list.

    Precedence:
      1. If the token supplied a ``kid`` and the JWKS has a matching entry,
         use it (even if it's non-RSA -- ``_jwk_to_pem`` will reject with a
         precise error naming the kty, which is more useful than a silent
         fallback).
      2. Otherwise return the first RSA key in list order.
      3. If neither applies, raise ``ValueError``.
    """
    key_list = [k for k in keys if isinstance(k, dict)]
    if not key_list:
        raise ValueError("JWKS 'keys' array is empty or malformed.")

    if kid:
        for k in key_list:
            if k.get("kid") == kid:
                return k, f"kid={_safe(kid)}"
        available = ", ".join(_safe(str(k.get("kid", ""))) for k in key_list if k.get("kid"))
        raise ValueError(
            f"kid '{_safe(kid)}' not found in JWKS"
            + (f" (available: {available})" if available else "")
            + "."
        )

    for k in key_list:
        if k.get("kty") == "RSA":
            picked_kid = k.get("kid")
            label = f"kid={_safe(str(picked_kid))}" if picked_kid else "first RSA key"
            return k, label

    raise ValueError("JWKS contains no RSA keys.")


def _parse_json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Not valid JSON: line {e.lineno} col {e.colno}.") from None


def _validate_url(url: str) -> str:
    """Return the URL unchanged after allow-listing scheme + requiring a host."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        raise ValueError("Malformed URL.") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"Only http:// and https:// URLs are allowed (got scheme={_safe(scheme) or '<empty>'})."
        )
    if not parts.hostname:
        raise ValueError("URL has no host component.")
    return url


def _looks_like_url(text: str) -> bool:
    """True if the input matches a URI scheme prefix (scheme:...).

    Used to route URL-shaped input through the scheme allow-list rather
    than the "unrecognised format" branch, so a paste of ``file://…`` or
    ``javascript:…`` is rejected with a visible security message instead
    of a generic error.
    """
    return bool(_URI_SCHEME_RE.match(text))


def _handle_jwks_doc(doc: object, *, kid: str | None, prefix: str) -> tuple[str, str]:
    if not isinstance(doc, dict):
        raise ValueError("Expected a JSON object (JWK or JWKS).")
    if "keys" in doc:
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise ValueError("JWKS 'keys' field is not an array.")
        jwk, label = _pick_from_jwks(keys, kid=kid)
        pem = _jwk_to_pem(jwk)
        return pem, f"{prefix} ({len(keys)} keys, {label})"
    if "kty" in doc:
        pem = _jwk_to_pem(doc)
        return pem, prefix
    raise ValueError("Object is neither a JWK (needs 'kty') nor a JWKS (needs 'keys').")


def resolve_public_key(
    text: str,
    *,
    kid: str | None = None,
    fetcher: Fetcher | None = None,
) -> tuple[str, str]:
    """Detect the input format and return ``(pem_str, source_label)``.

    ``source_label`` is a short, human-readable description of what the
    resolver did -- e.g. ``"PEM (as-provided)"``, ``"JWK"``,
    ``"JWKS URL (2 keys, kid=abc)"``. Callers surface this in the UI so
    the operator sees which key was picked.

    Raises ``ValueError`` on any failure with a short, user-safe message.
    """
    if text is None:
        raise ValueError("Public key is empty.")
    if len(text.encode("utf-8", errors="ignore")) > _MAX_INPUT_BYTES:
        raise ValueError(f"Input too large (max {_MAX_INPUT_BYTES // 1024} KB).")
    stripped = text.strip()
    if not stripped:
        raise ValueError("Public key is empty.")

    # PEM: pass through unchanged (existing behaviour). We do NOT re-parse
    # or normalise it -- pyjwt.encode() validates it downstream.
    if stripped.startswith("-----BEGIN "):
        return text, "PEM (as-provided)"

    # URL-shaped input (scheme:...): route through the allow-list.
    # This catches both ``scheme://host/path`` (http/https/file/ftp/...)
    # and scheme-only forms (``javascript:...``, ``data:...``) so that a
    # tester who pastes a dangerous scheme gets an explicit, visible
    # rejection rather than a vague "unrecognised format" error.
    if _looks_like_url(stripped):
        url = _validate_url(stripped)
        if fetcher is None:
            raise ValueError("URL input requires a fetcher (internal error).")
        try:
            body = fetcher(url)
        except ValueError:
            raise
        except Exception as e:  # noqa: BLE001 - normalise to a user-safe message
            raise ValueError(f"Fetch failed: {type(e).__name__}") from None
        if not isinstance(body, (bytes, bytearray)):
            raise ValueError("Fetcher returned non-bytes payload (internal error).")
        if len(body) > _MAX_FETCH_BYTES:
            raise ValueError(f"Fetched body exceeds {_MAX_FETCH_BYTES // 1024} KB limit.")
        try:
            decoded = body.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Fetched body is not valid UTF-8.") from None
        doc = _parse_json(decoded)
        return _handle_jwks_doc(doc, kid=kid, prefix="JWKS URL")

    # JSON: single JWK or JWKS document pasted verbatim.
    if stripped.startswith("{") or stripped.startswith("["):
        doc = _parse_json(stripped)
        return _handle_jwks_doc(doc, kid=kid, prefix="JWKS" if isinstance(doc, dict) and "keys" in doc else "JWK")

    raise ValueError(
        "Unrecognised format. Expected PEM (-----BEGIN...-----), a JWK "
        "({\"kty\":\"RSA\",...}), a JWKS ({\"keys\":[...]}), or a "
        "https://.../.well-known/jwks.json URL."
    )

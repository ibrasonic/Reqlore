"""Phase 22 — secret scanning in JS bundles + new bundle-friendly patterns.

Extends Phase 20 (`rule_pii_secrets`) coverage:

1. ``_is_text_response`` now accepts ``application/javascript``,
   ``application/x-javascript`` and ``application/ecmascript`` so secrets
   that live inside webpack / vite / rollup bundles are no longer skipped.

2. Five new high-confidence patterns: Stripe live / restricted / test
   secrets, Mapbox secret tokens, SendGrid API keys, Twilio API key SIDs
   and bare JWT tokens with an entropy floor.
"""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.scanner import run_passive
from reqlore.scanner.passive import (
    _is_text_response,
    _SECRET_PATTERNS,
    rule_pii_secrets,
)


@dataclass
class _Row:
    id: int
    host: str
    url: str
    method: str
    status: int
    req_blob: bytes
    resp_blob: bytes


def _req(method: str, url: str, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"{method} {url} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _resp(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or []
    head = f"HTTP/1.1 {status} OK\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _row(url="https://cdn.test/static/app.js", host="cdn.test",
         status=200, resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host=host, url=url, method="GET", status=status,
        req_blob=_req("GET", url),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


def _findings(row):
    return list(run_passive(row, rules=[rule_pii_secrets]))


# ---- content-type gate -----------------------------------------------------


def test_application_javascript_now_scanned():
    assert _is_text_response([("Content-Type", "application/javascript")])
    assert _is_text_response(
        [("Content-Type", "application/javascript; charset=utf-8")])


def test_legacy_x_javascript_scanned():
    assert _is_text_response([("Content-Type", "application/x-javascript")])


def test_application_ecmascript_scanned():
    assert _is_text_response([("Content-Type", "application/ecmascript")])


def test_text_javascript_still_works():
    # text/* was already covered in Phase 20; regression guard.
    assert _is_text_response([("Content-Type", "text/javascript")])


def test_binary_still_skipped():
    assert not _is_text_response([("Content-Type", "image/png")])
    assert not _is_text_response([("Content-Type", "application/wasm")])
    assert not _is_text_response([("Content-Type", "application/octet-stream")])


# ---- secret detection inside a JS bundle -----------------------------------


def test_aws_key_in_webpack_bundle_is_flagged():
    # Phase 22 headline behaviour — exactly the case that used to slip
    # through Phase 20 because the content-type gate rejected JS.
    body = (b'!function(e){var AWS_KEY="AKIAIOSFODNN7EXAMPLE";'
            b'e.exports={key:AWS_KEY}}();')
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert any("AWS access key id" in f.title for f in findings)


def test_aws_key_in_bundle_was_previously_skipped():
    """Regression guard: confirm a plain old `application/octet-stream`
    bundle is still skipped, even with the same secret. Encoding the
    old vs. new behaviour in tests."""
    body = b'var AWS_KEY="AKIAIOSFODNN7EXAMPLE";'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert findings == []


# ---- new patterns ----------------------------------------------------------


def test_stripe_live_secret_flagged_in_bundle():
    # Split secret literal across adjacent bytes literals so the on-disk
    # text does not match GitHub's push-protection regex; runtime bytes are
    # identical so the detector still fires.
    body = b'const STRIPE_SECRET="sk_live' b'_4eC39HqLyjWDarjtT1zdp7dc";'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    titles = [f.title for f in findings]
    assert any("Stripe live secret key" in t for t in titles)
    f = next(f for f in findings if "Stripe live secret" in f.title)
    assert f.severity == "critical"
    # Evidence is redacted.
    assert "4eC39HqLyjWDarjtT1zdp7dc" not in f.evidence
    assert f.evidence.startswith("stripe-live-secret=sk_l")


def test_stripe_restricted_key_flagged():
    body = b'{"key":"rk_live' b'_4eC39HqLyjWDarjtT1zdp7dc"}'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    assert any("Stripe restricted" in f.title for f in findings)


def test_stripe_test_secret_lower_severity():
    body = b'STRIPE_TEST="sk_test' b'_4eC39HqLyjWDarjtT1zdp7dc"'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "text/javascript")],
        resp_body=body,
    ))
    f = next(f for f in findings if "Stripe test" in f.title)
    assert f.severity == "medium"


def test_stripe_publishable_pk_not_flagged():
    # `pk_live_…` is designed to be shipped to the browser; flagging it
    # would generate noise on every Stripe-using site.
    body = b'const PK="pk_live_4eC39HqLyjWDarjtT1zdp7dc";'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert not any("Stripe" in f.title for f in findings)


def test_mapbox_secret_token_flagged():
    body = (b'mapboxgl.accessToken="' b'sk' b'.eyJ1IjoidGVzdCIsImEiOiJjbGFiY2QxMjMifQ.'
            b'AbCdEfGhIjKlMnOpQrStUv";')
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert any("Mapbox secret" in f.title for f in findings)


def test_mapbox_public_pk_not_flagged():
    # Mapbox public tokens are designed to ship in the client.
    body = b'mapboxgl.accessToken="pk.eyJ1IjoidGVzdCIsImEiOiJjbGFiY2QxMjMifQ.AbCdEfGh";'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert not any("Mapbox" in f.title for f in findings)


def test_sendgrid_api_key_flagged():
    # Real SendGrid key format: SG.<22-char>.<43-char>
    body = b'SENDGRID_KEY="' b'SG' b'.aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfG"'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert any("SendGrid" in f.title for f in findings)


def test_twilio_api_sid_flagged():
    # Twilio API key SID: SK + 32 hex chars.
    body = b'TWILIO_SID="' b'SK' b'abcdef0123456789abcdef0123456789"'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert any("Twilio" in f.title for f in findings)


def test_twilio_account_sid_not_flagged():
    # AC-prefixed Account SID is documented as non-secret; do not flag.
    body = b'TWILIO_ACCOUNT="' b'AC' b'abcdef0123456789abcdef0123456789"'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert not any("Twilio" in f.title for f in findings)


def test_jwt_token_in_bundle_flagged():
    # Typical 3-segment base64url JWT with realistic-entropy payloads.
    jwt = (b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3"
           b"ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
           b"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    body = b'const TOKEN="' + jwt + b'";'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert any("JWT" in f.title for f in findings)


def test_jwt_low_entropy_placeholder_skipped():
    # Documentation-shaped JWT (long but very low-entropy) should fall
    # under the 3.5-bit entropy floor.
    jwt = b"eyJaaaaaaaa.eyJaaaaaaaa.aaaaaaaa"
    body = b'const T="' + jwt + b'";'
    findings = _findings(_row(
        resp_headers=[("Content-Type", "application/javascript")],
        resp_body=body,
    ))
    assert not any("JWT" in f.title for f in findings)


# ---- _SECRET_PATTERNS table invariants -------------------------------------


def test_phase22_patterns_registered():
    slugs = {row[0] for row in _SECRET_PATTERNS}
    for new in (
        "stripe-live-secret",
        "stripe-restricted-key",
        "stripe-test-secret",
        "mapbox-secret-token",
        "sendgrid-api-key",
        "twilio-api-key",
        "jwt-token",
    ):
        assert new in slugs, new


def test_secret_pattern_table_invariants():
    """Every row: 8 fields, severity in known band, OWASP non-empty."""
    valid_sev = {"info", "low", "medium", "high", "critical"}
    for row in _SECRET_PATTERNS:
        assert len(row) == 8, row
        slug, _regex, sev, cwe, owasp, label, entropy, luhn = row
        assert slug == slug.lower()
        assert sev in valid_sev
        assert cwe.startswith("CWE-")
        assert owasp.startswith("A0")
        assert label
        assert entropy is None or 0.0 < float(entropy) <= 8.0
        assert isinstance(luhn, bool)

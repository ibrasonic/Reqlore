"""Phase 20 — PII / secrets passive scan (item 3.4)."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.scanner import run_passive
from reqlore.scanner.passive import (
    _is_text_response,
    _luhn_ok,
    _redact,
    _shannon_entropy,
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


def _row(url="https://x.test/api/data", status=200,
         resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host="x.test", url=url, method="GET", status=status,
        req_blob=_req("GET", url),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


# ---- helpers ----------------------------------------------------------------


def test_luhn_accepts_known_valid_cards():
    # Standard test PANs.
    assert _luhn_ok("4111111111111111")  # Visa
    assert _luhn_ok("5500000000000004")  # MasterCard
    assert _luhn_ok("340000000000009")   # Amex (15-digit)


def test_luhn_rejects_invalid_or_short():
    assert not _luhn_ok("4111111111111112")
    # All-zeros is technically Luhn-valid but obviously not a real card;
    # the rule filters it via the unique-digit gate, not via _luhn_ok.
    assert _luhn_ok("0000000000000000")
    assert not _luhn_ok("12345")
    assert not _luhn_ok("abc")


def test_shannon_entropy_bounds():
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaaa") == 0.0
    # Two symbols equally likely → 1 bit/char.
    assert 0.99 < _shannon_entropy("abab") < 1.01
    # Mixed alphanumerics should well exceed our 3.5 threshold.
    assert _shannon_entropy("sk-AbCdEfGh1234567890XyZ0987654321Mn") > 3.5


def test_redact_short_and_long():
    assert _redact("") == ""
    assert _redact("abc") == "\u2022\u2022\u2022"
    out = _redact("AKIAIOSFODNN7EXAMPLE")
    assert out.startswith("AKIA")
    assert out.endswith("MPLE")
    assert "\u2022" in out
    # No secret chars in the middle.
    assert "OSFODNN" not in out


def test_is_text_response_recognises_text_and_json_variants():
    assert _is_text_response([("Content-Type", "text/html; charset=utf-8")])
    assert _is_text_response([("Content-Type", "application/json")])
    assert _is_text_response([("Content-Type", "application/vnd.api+json")])
    assert _is_text_response([("Content-Type", "application/xml")])
    assert _is_text_response([("Content-Type", "application/atom+xml")])
    assert not _is_text_response([("Content-Type", "image/png")])
    assert not _is_text_response([("Content-Type", "application/octet-stream")])
    assert not _is_text_response([])


# ---- rule positives ---------------------------------------------------------


def _findings_only(row):
    return list(run_passive(row, rules=[rule_pii_secrets]))


def test_detects_aws_access_key():
    body = b'{"key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    assert any(f.title.startswith("AWS access key id") for f in findings)
    f = next(f for f in findings if "AWS" in f.title)
    assert f.severity == "critical"
    assert f.cwe == "CWE-798"
    # Evidence is redacted, never the raw secret.
    assert "OSFODNN" not in f.evidence
    assert f.evidence.startswith("aws-access-key=AKIA")


def test_detects_github_token():
    # Split literal so GitHub's push-protection scanner doesn't match the
    # contiguous prefix; adjacent bytes literals concatenate at compile time
    # so the detector still sees the full token at runtime.
    body = b'{"token":"ghp' b'_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"}'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    assert any("GitHub token" in f.title for f in findings)


def test_detects_slack_token():
    body = b'{"webhook":"xoxb' b'-123456789012-abcdefghijklmnopqrstuvwx"}'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    assert any("Slack token" in f.title for f in findings)


def test_detects_private_key_pem_block():
    body = (b"-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
            b"-----END RSA PRIVATE KEY-----")
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "text/plain")],
        resp_body=body,
    ))
    assert any("Private key block" in f.title for f in findings)


def test_detects_luhn_valid_credit_card_with_separators():
    # 4111 1111 1111 1111 is Luhn-valid.
    body = b'<p>Card on file: 4111 1111 1111 1111</p>'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=body,
    ))
    cc = [f for f in findings if "Credit-card" in f.title]
    assert len(cc) == 1
    # Stored as digit-only redaction.
    assert cc[0].evidence.startswith("credit-card=4111")
    assert "1111111111" not in cc[0].evidence


def test_detects_us_ssn_format():
    body = b'<p>Patient SSN: 123-45-6789</p>'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=body,
    ))
    assert any("Social-Security" in f.title for f in findings)


# ---- rule negatives ---------------------------------------------------------


def test_skips_non_text_response():
    body = b'\x00\x01AKIAIOSFODNN7EXAMPLE\x00\x02'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert findings == []


def test_skips_when_no_content_type():
    body = b'{"key":"AKIAIOSFODNN7EXAMPLE"}'
    findings = _findings_only(_row(resp_body=body))
    assert findings == []


def test_skips_credit_card_failing_luhn():
    # 4111 1111 1111 1112 fails Luhn by one digit.
    body = b'<p>Order ref: 4111 1111 1111 1112</p>'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=body,
    ))
    assert not any("Credit-card" in f.title for f in findings)


def test_skips_low_cardinality_card_even_if_luhn_valid():
    # All-zeros is Luhn-valid but obviously not a card; same for
    # all-same-digit runs. The unique-digit guard drops them.
    body = b'<p>Token: 0000 0000 0000 0000</p>'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=body,
    ))
    assert not any("Credit-card" in f.title for f in findings)


def test_skips_ssn_with_disallowed_prefix():
    # 000-xx-xxxx and 666-xx-xxxx and 9xx-xx-xxxx are never assigned.
    body = b'<p>NumA: 000-12-3456  NumB: 666-12-3456  NumC: 900-12-3456</p>'
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "text/html")],
        resp_body=body,
    ))
    assert not any("Social-Security" in f.title for f in findings)


def test_dedupes_repeated_secret_in_same_body():
    body = (b'{"k1":"AKIAIOSFODNN7EXAMPLE","k2":"AKIAIOSFODNN7EXAMPLE",'
            b'"k3":"AKIAIOSFODNN7EXAMPLE"}')
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    aws = [f for f in findings if "AWS" in f.title]
    assert len(aws) == 1


def test_multiple_distinct_secrets_yield_multiple_findings():
    body = (b'{"aws":"AKIAIOSFODNN7EXAMPLE",'
            b'"gh":"ghp' b'_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"}')
    findings = _findings_only(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    titles = {f.title.split(" exposed")[0] for f in findings}
    assert "AWS access key id" in titles
    assert "GitHub token" in titles


def test_rule_runs_via_run_passive_with_default_rules():
    """Confirm the rule is registered in BUILTIN_RULES."""
    body = b'{"key": "AKIAIOSFODNN7EXAMPLE"}'
    findings = run_passive(_row(
        resp_headers=[("Content-Type", "application/json")],
        resp_body=body,
    ))
    assert any(f.cwe == "CWE-798" and "AWS" in f.title for f in findings)

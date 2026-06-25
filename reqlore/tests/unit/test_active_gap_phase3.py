"""Phase 3 (Tier C) tests: StoredXSSCheck, IDORAltIdentityCheck,
RaceConditionCheck.

Each check needs more than one round-trip per probe, so the fake
sender in these tests tracks call sequence and reacts accordingly.
"""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.engines import Request, Response
from reqlore.scanner import ActiveOptions, ActiveScanner
from reqlore.scanner.active import (
    IDORAltIdentityCheck,
    RaceConditionCheck,
    StoredXSSCheck,
    _byte_3gram_jaccard,
)


# --------------------------- shared helpers ---------------------------------


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
    head = f"HTTP/1.1 {status} OK\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    return head.encode("latin-1") + b"\r\n" + body


def _row(*, url="https://x.test/comments", host="x.test", method="POST",
          req_headers=None, req_body=b"comment=hi",
          resp_status=200, resp_headers=None, resp_body=b"saved"):
    return _Row(
        id=1, host=host, url=url, method=method, status=resp_status,
        req_blob=_req(method, url, req_headers or [], req_body),
        resp_blob=_resp(resp_status, resp_headers or [], resp_body),
    )


def _scan_one(check, row, *, sender, opts=None) -> list:
    scanner = ActiveScanner(checks=[check], sender=sender)
    # Naming the check explicitly bypasses the intensity gate —
    # these tests intentionally exercise intrusive-tier checks one
    # at a time.
    base = opts or ActiveOptions()
    base.enabled_checks = base.enabled_checks or [check.name]
    return scanner.run_on_row(row, options=base)


# ----------------------------- helper unit ----------------------------------


def test_byte_3gram_jaccard_extremes():
    assert _byte_3gram_jaccard(b"", b"abcdef") == 0.0
    assert _byte_3gram_jaccard(b"abcdef", b"") == 0.0
    assert _byte_3gram_jaccard(b"abcdefghij",
                                  b"abcdefghij") == 1.0
    assert _byte_3gram_jaccard(b"abcdef", b"xyzpqr") == 0.0


def test_byte_3gram_jaccard_partial_overlap():
    sim = _byte_3gram_jaccard(b"abcdefghij", b"abcdefXXXX")
    assert 0.0 < sim < 1.0


# ----------------------------- StoredXSSCheck -------------------------------


def test_stored_xss_skips_get_methods():
    """Only state-changing methods get the inject + re-fetch cycle."""

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not probe GET requests")

    row = _row(method="GET",
                url="https://x.test/profile?bio=hello",
                req_body=b"")
    findings = _scan_one(StoredXSSCheck(), row, sender=fail_send)
    assert findings == []


def test_stored_xss_fires_when_marker_persists_to_get():

    state: dict[str, bytes] = {"stored": b""}

    def responder(req: Request) -> Response:
        if req.method == "POST":
            # Decode the form value the way a real server would, then
            # echo it back to GET callers (the bug).
            from urllib.parse import parse_qsl
            text = (req.body or b"").decode("utf-8", errors="replace")
            pairs = dict(parse_qsl(text, keep_blank_values=True))
            state["stored"] = pairs.get("comment", "").encode("utf-8")
            return Response(status=201, headers=[], body=b"created",
                             engine="fake")
        # Subsequent GET re-fetches the comment list.
        return Response(status=200, headers=[],
                         body=(b"<html>" + state["stored"] + b"</html>"),
                         engine="fake")

    row = _row(
        method="POST",
        url="https://x.test/comments",
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"comment=hi",
    )
    findings = _scan_one(StoredXSSCheck(), row, sender=responder)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert "Stored XSS" in f.title
    # Probe payload must contain a marker prefix and round-trip cleanly.
    assert "wbr-stored-" in (f.payload or "")


def test_stored_xss_quiet_when_input_is_escaped():

    def responder(req: Request) -> Response:
        if req.method == "POST":
            return Response(status=201, headers=[], body=b"ok", engine="fake")
        # Server escapes everything before rendering it back.
        return Response(status=200, headers=[],
                         body=b"<html>nothing user-controlled</html>",
                         engine="fake")

    row = _row(
        method="POST",
        url="https://x.test/comments",
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body=b"comment=hi",
    )
    findings = _scan_one(StoredXSSCheck(), row, sender=responder)
    assert findings == []


def test_stored_xss_handles_query_param_on_post():
    state: dict[str, str] = {"q": ""}

    def responder(req: Request) -> Response:
        if req.method == "POST":
            # Capture the query param value.
            from urllib.parse import urlsplit, parse_qsl
            qs = dict(parse_qsl(urlsplit(req.url).query, keep_blank_values=True))
            state["q"] = qs.get("note", "")
            return Response(status=200, headers=[], body=b"ok", engine="fake")
        body = f"<html>last note: {state['q']}</html>".encode("utf-8")
        return Response(status=200, headers=[], body=body, engine="fake")

    row = _row(
        method="POST",
        url="https://x.test/notes?note=hello",
        req_body=b"",
    )
    findings = _scan_one(StoredXSSCheck(), row, sender=responder)
    assert len(findings) == 1


# -------------------------- IDORAltIdentityCheck ----------------------------


def test_idor_off_when_alt_identity_unset():

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not probe without alt_identity")

    row = _row(method="GET", url="https://x.test/account/123",
                req_body=b"", resp_status=200, resp_body=b"hello user 123")
    findings = _scan_one(IDORAltIdentityCheck(), row, sender=fail_send)
    assert findings == []


def test_idor_fires_when_alt_identity_returns_similar_body():

    baseline = b"<html><h1>welcome</h1><p>balance: $100</p></html>"

    def responder(req: Request) -> Response:
        # Alt identity also sees the same record.
        return Response(status=200, headers=[], body=baseline, engine="fake")

    row = _row(method="GET", url="https://x.test/account/123",
                req_body=b"", resp_status=200, resp_body=baseline)
    opts = ActiveOptions(alt_identity={"Cookie": "session=other"})
    findings = _scan_one(IDORAltIdentityCheck(), row,
                          sender=responder, opts=opts)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert "Cookie" in (f.payload or "")
    # Evidence reports similarity but never the cookie value itself.
    assert "session=other" not in (f.payload or "")
    assert "session=other" not in (f.evidence or "")


def test_idor_quiet_when_alt_identity_gets_403():

    def responder(req: Request) -> Response:
        return Response(status=403, headers=[], body=b"forbidden",
                         engine="fake")

    row = _row(method="GET", url="https://x.test/account/123",
                req_body=b"", resp_status=200, resp_body=b"hello")
    opts = ActiveOptions(alt_identity={"Cookie": "session=other"})
    findings = _scan_one(IDORAltIdentityCheck(), row,
                          sender=responder, opts=opts)
    assert findings == []


def test_idor_quiet_when_alt_body_differs():

    def responder(req: Request) -> Response:
        return Response(status=200, headers=[],
                         body=b"<html>your account is empty</html>",
                         engine="fake")

    baseline = b"<html><h1>welcome user 123</h1><p>balance: $100</p></html>"
    row = _row(method="GET", url="https://x.test/account/123",
                req_body=b"", resp_status=200, resp_body=baseline)
    opts = ActiveOptions(alt_identity={"Cookie": "session=other"})
    findings = _scan_one(IDORAltIdentityCheck(), row,
                          sender=responder, opts=opts)
    assert findings == []


# --------------------------- RaceConditionCheck -----------------------------


def test_race_check_off_by_default():

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not probe without allow_race_probes")

    row = _row(method="POST", url="https://x.test/promo/redeem",
                req_body=b"code=GIFT", resp_status=201, resp_body=b"redeemed")
    findings = _scan_one(RaceConditionCheck(), row, sender=fail_send)
    assert findings == []


def test_race_check_skips_get():

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not probe GET")

    row = _row(method="GET", url="https://x.test/profile",
                req_body=b"", resp_status=200, resp_body=b"hi")
    opts = ActiveOptions(allow_race_probes=True)
    findings = _scan_one(RaceConditionCheck(), row,
                          sender=fail_send, opts=opts)
    assert findings == []


def test_race_check_fires_when_parallel_creates_duplicates():
    """Server is buggy: every concurrent POST creates a new redemption."""

    def responder(req: Request) -> Response:
        return Response(status=201, headers=[], body=b"redeemed",
                         engine="fake")

    row = _row(method="POST", url="https://x.test/promo/redeem",
                req_body=b"code=GIFT",
                resp_status=201, resp_body=b"redeemed")
    opts = ActiveOptions(allow_race_probes=True)
    findings = _scan_one(RaceConditionCheck(), row,
                          sender=responder, opts=opts)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert "Race condition" in f.title


def test_race_check_quiet_when_only_one_succeeds():
    """Properly-locked endpoint: first call wins, the rest get 409."""

    counter = {"n": 0}

    def responder(req: Request) -> Response:
        counter["n"] += 1
        if counter["n"] == 1:
            return Response(status=201, headers=[], body=b"redeemed",
                             engine="fake")
        return Response(status=409, headers=[], body=b"already redeemed",
                         engine="fake")

    row = _row(method="POST", url="https://x.test/promo/redeem",
                req_body=b"code=GIFT",
                resp_status=201, resp_body=b"redeemed")
    opts = ActiveOptions(allow_race_probes=True)
    findings = _scan_one(RaceConditionCheck(), row,
                          sender=responder, opts=opts)
    assert findings == []


def test_race_check_quiet_when_baseline_was_4xx():
    """Nothing to race against if the original request failed."""

    def fail_send(req: Request) -> Response:
        raise AssertionError("must not probe; baseline was 4xx")

    row = _row(method="POST", url="https://x.test/promo/redeem",
                req_body=b"code=GIFT",
                resp_status=400, resp_body=b"bad code")
    opts = ActiveOptions(allow_race_probes=True)
    findings = _scan_one(RaceConditionCheck(), row,
                          sender=fail_send, opts=opts)
    assert findings == []

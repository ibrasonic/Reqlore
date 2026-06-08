"""Phase 5 - smuggling payload generators + timing detector."""
from __future__ import annotations

import time

from reqlore.engines import Request, Response
from reqlore.smuggling import (PAYLOAD_BUILDERS, cl_te_payload, detect,
                                 te_cl_payload, te_te_payload)


def _resp(status: int = 200, *, sleep: float = 0.0) -> Response:
    if sleep:
        time.sleep(sleep)
    return Response(status=status, headers=[], body=b"", engine="fake")


def test_cl_te_payload_has_both_headers():
    p = cl_te_payload("https://x.test/")
    text = p.bytes_.decode("latin-1")
    assert "Content-Length:" in text
    assert "Transfer-Encoding: chunked" in text
    assert "Host: x.test" in text
    assert text.endswith("x=")


def test_te_cl_payload_carries_small_cl():
    p = te_cl_payload("https://x.test/path")
    text = p.bytes_.decode("latin-1")
    assert "Transfer-Encoding: chunked" in text
    assert "Content-Length: 4" in text


def test_te_te_payload_obfuscates_second_te():
    p = te_te_payload("https://x.test/")
    text = p.bytes_.decode("latin-1")
    assert "Transfer-Encoding: chunked" in text
    # The lower-case duplicate with space-before-colon is the obfuscation.
    assert "Transfer-encoding : x" in text


def test_smuggled_path_and_method_propagate():
    p = cl_te_payload("https://x.test/", smuggled_method="DELETE",
                       smuggled_path="/admin/api")
    assert b"DELETE /admin/api HTTP/1.1" in p.bytes_


def test_payload_registry_keys():
    assert set(PAYLOAD_BUILDERS.keys()) == {"cl.te", "te.cl", "te.te"}


def test_detect_flags_pause():
    # Baseline fast, probe slow by 1.6s -> over the 1500ms threshold.
    calls = {"n": 0}

    def fake(req: Request) -> Response:
        calls["n"] += 1
        # First call (baseline) instant; second (probe) sleeps.
        return _resp(sleep=0.0 if calls["n"] == 1 else 1.6)

    out = detect("https://x.test/", "cl.te", sender=fake)
    assert out.technique == "cl.te"
    assert out.likely_vulnerable
    assert out.delta_ms >= 1500


def test_detect_quiet_baseline_does_not_flag():
    def fake(req: Request) -> Response:
        return _resp()

    out = detect("https://x.test/", "cl.te", sender=fake)
    assert not out.likely_vulnerable


def test_detect_unknown_technique_returns_clean_error():
    out = detect("https://x.test/", "wat", sender=lambda r: _resp())
    assert out.reason == "unknown technique"
    assert not out.likely_vulnerable

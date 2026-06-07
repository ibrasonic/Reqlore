"""Phase 5 - Optional engines: H/3 and curl-cffi availability + safe fallback."""
from __future__ import annotations

from weblore.engines import Request
from weblore.engines import curl_cffi_engine, h3_engine


def test_h3_availability_flag_is_boolean():
    assert isinstance(h3_engine.H3_AVAILABLE, bool)


def test_h3_send_when_missing_returns_clear_error():
    if h3_engine.H3_AVAILABLE:
        return  # nothing to assert; integration test would need a server
    resp = h3_engine.send(Request(method="GET", url="https://example.invalid/"))
    assert resp.status == 0
    assert resp.engine == "h3"
    assert resp.error and "aioquic" in resp.error


def test_curl_cffi_availability_flag_is_boolean():
    assert isinstance(curl_cffi_engine.CFFI_AVAILABLE, bool)


def test_curl_cffi_send_when_missing_returns_clear_error():
    if curl_cffi_engine.CFFI_AVAILABLE:
        return
    resp = curl_cffi_engine.send(Request(method="GET", url="https://example.invalid/"))
    assert resp.status == 0
    assert resp.engine == "curl-cffi"
    assert resp.error and "curl_cffi" in resp.error


def test_curl_cffi_supported_profiles_contains_chrome120():
    assert "chrome120" in curl_cffi_engine.SUPPORTED_PROFILES

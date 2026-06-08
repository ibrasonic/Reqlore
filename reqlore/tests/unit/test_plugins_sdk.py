"""Phase 5 - Plugin SDK helpers + bundled example plugins."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.plugins_sdk import (
    SDK_VERSION, CopyAsHandler, assert_compatible, make_info,
    make_passive_rule,
)


def test_make_info_returns_required_keys():
    info = make_info(name="ex", version="1.2", description="hi")
    assert info["name"] == "ex"
    assert info["version"] == "1.2"
    assert info["description"] == "hi"
    assert info["sdk_version"] == SDK_VERSION


def test_make_passive_rule_tags_callable():
    @make_passive_rule("my-rule", severity="medium")
    def fn(ctx):
        return []

    assert fn.reqlore_rule_name == "my-rule"
    assert fn.reqlore_rule_severity == "medium"


def test_assert_compatible_rejects_missing_name():
    with pytest.raises(ValueError, match="name"):
        assert_compatible({"version": "1"})


def test_assert_compatible_rejects_mismatched_sdk_major():
    bad = {"name": "x", "sdk_version": "99.0"}
    with pytest.raises(ValueError, match="SDK"):
        assert_compatible(bad)


def test_assert_compatible_accepts_same_major():
    ok = {"name": "x", "sdk_version": SDK_VERSION}
    assert_compatible(ok)


def test_copy_as_handler_dataclass():
    h = CopyAsHandler(name="x", render=lambda b: b.decode())
    assert h.name == "x"
    assert h.render(b"hi") == "hi"


def test_example_extra_headers_rule_yields_finding(tmp_path: Path):
    """Importing the example file and running its rule against a
    response missing Server-Timing produces a finding."""
    import importlib.util
    here = Path(__file__).resolve().parents[3] / "examples" / "plugins" / "extra_headers.py"
    if not here.exists():
        pytest.skip("example plugin pack missing")
    spec = importlib.util.spec_from_file_location("ex_eh", here)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rules = mod.scanner_rules()
    assert len(rules) == 1

    from reqlore.scanner.passive import RuleContext

    ctx = RuleContext(
        history_id=1, host="x.test", url="https://x.test/",
        method="GET", status=200,
        req_start_line="GET / HTTP/1.1", req_headers=[], req_body=b"",
        resp_start_line="HTTP/1.1 200 OK",
        resp_headers=[("Content-Type", "text/html")],
        resp_body=b"",
    )
    findings = list(rules[0](ctx))
    assert len(findings) == 1
    assert "Server-Timing" in findings[0].title


def test_example_copy_as_php_renders_php(tmp_path: Path):
    import importlib.util
    here = Path(__file__).resolve().parents[3] / "examples" / "plugins" / "copy_as_php.py"
    if not here.exists():
        pytest.skip("example plugin pack missing")
    spec = importlib.util.spec_from_file_location("ex_cap", here)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    handlers = mod.copy_as()
    assert len(handlers) == 1
    raw = b"POST /api HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/json\r\n\r\n{\"a\":1}"
    out = handlers[0].render(raw)
    assert "<?php" in out
    assert "curl_init()" in out
    assert "curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');" in out
    assert "/api" in out

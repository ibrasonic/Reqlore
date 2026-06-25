"""Phase 21 — known-CVE / EOL fingerprint passive rule (item 3.3)."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.scanner import run_passive
from reqlore.scanner.passive import (
    _KNOWN_CVES,
    _parse_version_tokens,
    _ver_between,
    _ver_lt,
    rule_cve_server_fingerprint,
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


def _row(url="https://x.test/", host="x.test", status=200,
         resp_headers=None, resp_body=b"") -> _Row:
    return _Row(
        id=1, host=host, url=url, method="GET", status=status,
        req_blob=_req("GET", url),
        resp_blob=_resp(status, resp_headers or [], resp_body),
    )


def _findings(row):
    return list(run_passive(row, rules=[rule_cve_server_fingerprint]))


# ---- predicate helpers ------------------------------------------------------


def test_ver_lt_strict():
    p = _ver_lt((2, 4, 49))
    assert p((2, 4, 48))
    assert p((1, 9, 99))
    assert not p((2, 4, 49))
    assert not p((2, 4, 50))


def test_ver_between_half_open():
    p = _ver_between((2, 4, 0), (2, 4, 49))
    assert p((2, 4, 0))
    assert p((2, 4, 48))
    assert not p((2, 4, 49))  # exclusive upper bound
    assert not p((2, 3, 99))  # below lower
    assert not p((2, 5, 0))


def test_ver_between_handles_shorter_tuples():
    # `(2, 4)` is strictly less than `(2, 4, 0)` in Python tuple order,
    # so a bare "Apache/2.4" without a patch level is intentionally NOT
    # matched by a `(2, 4, 0)`-anchored range. Documents the precision
    # decision so a future change does not silently break it.
    p = _ver_between((2, 4, 0), (2, 4, 49))
    assert not p((2, 4))


# ---- version-token parser ---------------------------------------------------


def test_parse_simple_apache_token():
    out = _parse_version_tokens("Apache/2.4.59 (Ubuntu)")
    assert ("apache", (2, 4, 59)) in out


def test_parse_chained_server_header():
    header = "Apache/2.4.59 (Ubuntu) OpenSSL/1.1.1f PHP/8.0.30"
    out = _parse_version_tokens(header)
    assert ("apache", (2, 4, 59)) in out
    assert ("openssl", (1, 1, 1)) in out
    assert ("php", (8, 0, 30)) in out


def test_parse_lowercases_product():
    out = _parse_version_tokens("NGINX/1.18.0")
    assert out == [("nginx", (1, 18, 0))]


def test_parse_empty_and_no_version():
    assert _parse_version_tokens("") == []
    assert _parse_version_tokens("cloudflare") == []
    assert _parse_version_tokens("Microsoft-HTTPAPI/2.0") == [("microsoft-httpapi", (2, 0))]


# ---- rule positives ---------------------------------------------------------


def test_apache_2_4_48_flags_path_traversal_cve():
    f = _findings(_row(
        resp_headers=[("Server", "Apache/2.4.48 (Ubuntu)")],
    ))
    titles = [x.title for x in f]
    assert any("CVE-2021-41773" in t for t in titles)


def test_apache_2_4_49_flags_incomplete_fix_cve():
    f = _findings(_row(
        resp_headers=[("Server", "Apache/2.4.49 (Ubuntu)")],
    ))
    assert any("CVE-2021-42013" in x.title for x in f)
    # The original path-traversal CVE is excluded by its upper bound.
    assert not any("CVE-2021-41773" in x.title for x in f)


def test_nginx_old_flags_resolver_cve():
    f = _findings(_row(
        resp_headers=[("Server", "nginx/1.18.0")],
    ))
    assert any("CVE-2021-23017" in x.title for x in f)


def test_php_7_flagged_as_eol():
    f = _findings(_row(
        resp_headers=[("X-Powered-By", "PHP/7.3.33")],
    ))
    assert any("EOL-PHP-7.3" in x.title for x in f)
    assert any(x.cwe == "CWE-1104" for x in f)


def test_chained_server_yields_multiple_findings():
    # Vulnerable Apache AND EOL PHP in one header.
    f = _findings(_row(
        resp_headers=[("Server", "Apache/2.4.48 (Ubuntu) PHP/7.2.0")],
    ))
    ids = {x.title.split(" affects")[0] for x in f}
    assert "CVE-2021-41773" in ids
    assert "EOL-PHP-7.3" in ids


# ---- rule negatives ---------------------------------------------------------


def test_patched_apache_yields_nothing():
    f = _findings(_row(
        resp_headers=[("Server", "Apache/2.4.62 (Ubuntu)")],
    ))
    assert f == []


def test_modern_nginx_yields_nothing():
    f = _findings(_row(
        resp_headers=[("Server", "nginx/1.25.4")],
    ))
    assert f == []


def test_no_server_header_yields_nothing():
    f = _findings(_row(resp_headers=[("Content-Type", "text/html")]))
    assert f == []


def test_unknown_product_yields_nothing():
    f = _findings(_row(
        resp_headers=[("Server", "MysteryServer/9.9.9")],
    ))
    assert f == []


def test_bare_major_version_not_flagged():
    # "Apache/2" lacks the precision to match any predicate.
    f = _findings(_row(
        resp_headers=[("Server", "Apache/2")],
    ))
    # _VERSION_TOKEN_RE requires at least one dot, so no token is even
    # extracted. Confirm zero findings either way.
    assert f == []


# ---- dedupe and registration ------------------------------------------------


def test_dedup_per_host_for_same_advisory():
    # Same CVE-bearing server appears under two header names — the rule
    # already de-dups per (advisory_id, host), so we should still see
    # exactly one finding for CVE-2021-41773.
    f = _findings(_row(
        resp_headers=[
            ("Server", "Apache/2.4.48"),
            ("X-Powered-By", "Apache/2.4.48"),
        ],
    ))
    matches = [x for x in f if "CVE-2021-41773" in x.title]
    assert len(matches) == 1


def test_rule_runs_through_default_run_passive():
    """Confirms `rule_cve_server_fingerprint` is wired into BUILTIN_RULES."""
    f = list(run_passive(_row(resp_headers=[("Server", "Apache/2.4.48")])))
    assert any("CVE-2021-41773" in x.title for x in f)


def test_known_cves_table_invariants():
    """Each entry: 7 fields; severity is a known band; predicate callable."""
    valid_sev = {"info", "low", "medium", "high", "critical"}
    for entry in _KNOWN_CVES:
        assert len(entry) == 7, entry
        product, predicate, advisory_id, severity, cvss, summary, cwe = entry
        assert product == product.lower()
        assert callable(predicate)
        assert advisory_id.startswith(("CVE-", "EOL-"))
        assert severity in valid_sev
        assert 0.0 <= float(cvss) <= 10.0
        assert summary and cwe.startswith("CWE-")

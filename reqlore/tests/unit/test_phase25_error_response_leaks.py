"""Phase 25 — internal infrastructure leaks in error responses."""
from __future__ import annotations

from dataclasses import dataclass

from reqlore.scanner import run_passive
from reqlore.scanner.passive import (
    _ERROR_LEAK_PATTERNS,
    _redact_leak,
    rule_error_response_leaks,
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


def _req(url: str) -> bytes:
    return (f"GET {url} HTTP/1.1\r\n\r\n").encode("latin-1")


def _resp(status: int, headers=None, body: bytes = b"") -> bytes:
    headers = headers or [("Content-Type", "text/html")]
    head = f"HTTP/1.1 {status} Internal Server Error\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    return head.encode("latin-1") + b"\r\n" + body


def _row(status=500, resp_headers=None, resp_body=b"",
         url="https://target.test/api/widget"):
    return _Row(
        id=1, host="target.test", url=url, method="GET", status=status,
        req_blob=_req(url),
        resp_blob=_resp(status, resp_headers, resp_body),
    )


def _findings(row):
    return list(run_passive(row, rules=[rule_error_response_leaks]))


# ---- positives: DB URIs and connection strings -----------------------------


def test_jdbc_with_creds_flagged_critical():
    body = (b"<pre>java.sql.SQLException: Connection refused for "
            b"jdbc:postgresql://app:hunter2@db-prod.corp:5432/orders</pre>")
    f = _findings(_row(resp_body=body))
    db = [x for x in f if "Database connection URI" in x.title]
    assert len(db) >= 1
    assert db[0].severity == "critical"
    assert "jdbc:postgresql" in db[0].evidence


def test_mongodb_srv_uri_flagged():
    body = (b"<pre>Error: connection failed to "
            b"mongodb+srv://svc:p%40ss@cluster0.mongo.internal/orders</pre>")
    f = _findings(_row(resp_body=body))
    assert any("Database connection URI" in x.title for x in f)


def test_postgres_uri_flagged():
    body = b"Error: postgres://app:secret@10.0.0.5:5432/db"
    f = _findings(_row(resp_body=body))
    assert any("Database connection URI" in x.title for x in f)


def test_redis_uri_flagged():
    body = b"<pre>RedisError: cannot connect to redis://:authpass@redis.lan:6379/0</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Database connection URI" in x.title for x in f)


def test_dotnet_connection_string_flagged_critical():
    body = (b"<pre>System.Data.SqlClient.SqlException: "
            b"Server=db01.corp;Database=Orders;User Id=svc;Password=hunter2!;"
            b" Connection Timeout=30</pre>")
    f = _findings(_row(resp_body=body))
    conn = [x for x in f if "connection string" in x.title.lower()
            and "URI" not in x.title]
    assert len(conn) >= 1
    assert conn[0].severity == "critical"


def test_dotnet_conn_without_password_not_flagged_as_conn_string():
    # No Password= -> the .NET-style pattern must NOT fire (other rules
    # may still hit on hostname / IP).
    body = (b"Server=db01.corp;Database=Orders;Integrated Security=SSPI")
    f = _findings(_row(resp_body=body))
    assert not any("connection string" in x.title.lower()
                   and "URI" not in x.title for x in f)


# ---- positives: internal IPs -----------------------------------------------


def test_rfc1918_10_dot_flagged():
    body = b"<pre>ConnectException: tried 10.42.7.13:8443</pre>"
    f = _findings(_row(resp_body=body))
    ip = [x for x in f if "Internal IP" in x.title]
    assert ip and "10.42.7.13" in ip[0].evidence
    assert ip[0].severity == "medium"


def test_rfc1918_172_in_range_flagged():
    body = b"upstream 172.20.5.4:80 timed out"
    f = _findings(_row(resp_body=body))
    assert any("Internal IP" in x.title for x in f)


def test_rfc1918_172_out_of_range_not_flagged():
    # 172.15.x.x and 172.32.x.x are public, must not fire.
    body = b"backend 172.15.5.4:80 and 172.32.5.4:80 unreachable"
    f = _findings(_row(resp_body=body))
    assert not any("Internal IP" in x.title for x in f)


def test_rfc1918_192_168_flagged():
    body = b"<pre>SSRF target 192.168.1.50:8080 refused</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Internal IP" in x.title for x in f)


def test_loopback_flagged():
    body = b"<pre>java.net.ConnectException: connect to 127.0.0.1:5432 refused</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Internal IP" in x.title for x in f)


def test_link_local_flagged():
    body = b"AWS metadata endpoint 169.254.169.254 unreachable"
    f = _findings(_row(resp_body=body))
    assert any("Internal IP" in x.title for x in f)


def test_public_ip_not_flagged():
    body = b"upstream 8.8.8.8:53 unreachable"
    f = _findings(_row(resp_body=body))
    assert not any("Internal IP" in x.title for x in f)


# ---- positives: internal hostnames -----------------------------------------


def test_dot_local_hostname_flagged():
    body = b"<pre>UnknownHostException: db-prod.corp.local</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Internal hostname" in x.title for x in f)


def test_dot_internal_hostname_flagged():
    body = b"<pre>cannot resolve api.svc.internal</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Internal hostname" in x.title for x in f)


def test_public_hostname_not_flagged_as_internal():
    body = b"cannot resolve api.example.com"
    f = _findings(_row(resp_body=body))
    assert not any("Internal hostname" in x.title for x in f)


# ---- positives: filesystem paths -------------------------------------------


def test_windows_path_flagged():
    body = (b"<pre>System.IO.FileNotFoundException: "
            b"Could not find file 'C:\\inetpub\\wwwroot\\app\\config.json'</pre>")
    f = _findings(_row(resp_body=body))
    win = [x for x in f if "Windows filesystem path" in x.title]
    assert win and "C:" in win[0].evidence


def test_unix_path_var_www_flagged():
    body = b"<pre>PHP Fatal error in /var/www/html/admin/users.php on line 42</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Unix filesystem path" in x.title for x in f)


def test_unix_path_home_flagged():
    body = b"<pre>Errno 2: no such file '/home/deploy/app/secrets.yml'</pre>"
    f = _findings(_row(resp_body=body))
    assert any("Unix filesystem path" in x.title for x in f)


def test_unrelated_unix_path_not_flagged():
    # Bare /tmp/file.txt is not under a known webroot prefix -> skip.
    body = b"Could not write /tmp/scratch.log"
    f = _findings(_row(resp_body=body))
    assert not any("Unix filesystem path" in x.title for x in f)


# ---- gates and negatives ---------------------------------------------------


def test_status_under_400_not_flagged():
    # Same payload, but status 200 -> rule must skip entirely.
    body = b"<pre>jdbc:postgresql://app:hunter2@10.0.0.5:5432/db</pre>"
    f = _findings(_row(status=200, resp_body=body))
    assert f == []


def test_binary_response_skipped():
    body = b"jdbc:postgresql://app:hunter2@10.0.0.5:5432/db"
    f = _findings(_row(
        resp_headers=[("Content-Type", "application/octet-stream")],
        resp_body=body,
    ))
    assert f == []


def test_empty_error_body_skipped():
    f = _findings(_row(resp_body=b""))
    assert f == []


# ---- dedupe, redaction, evidence, registration -----------------------------


def test_dedupe_per_response_same_token():
    body = b"upstream 10.0.0.5:80 retry 10.0.0.5:80 retry 10.0.0.5:80"
    f = _findings(_row(resp_body=body))
    ip = [x for x in f if "Internal IP" in x.title]
    assert len(ip) == 1


def test_distinct_internal_ips_yield_distinct_findings():
    body = b"upstream 10.0.0.5:80 failed, fallback 192.168.1.50:80 failed"
    f = _findings(_row(resp_body=body))
    ip = [x for x in f if "Internal IP" in x.title]
    assert len(ip) == 2


def test_redact_leak_short_pass_through():
    assert _redact_leak(b"10.0.0.5") == "10.0.0.5"


def test_redact_leak_long_truncated():
    raw = b"jdbc:postgresql://" + b"a" * 100 + b":pw@host/db"
    out = _redact_leak(raw)
    assert "..." in out
    assert len(out) <= 60


def test_evidence_contains_status_code():
    body = b"<pre>upstream 10.0.0.5:80 failed</pre>"
    f = _findings(_row(status=503, resp_body=body))
    ip = [x for x in f if "Internal IP" in x.title]
    assert ip and "status 503" in ip[0].evidence


def test_rule_runs_via_default_run_passive():
    body = b"<pre>jdbc:mysql://app:hunter2@db.internal:3306/orders</pre>"
    f = list(run_passive(_row(resp_body=body)))
    assert any("Database connection URI" in x.title for x in f)


def test_error_leak_pattern_table_invariants():
    seen_slugs: set[str] = set()
    valid_severities = {"info", "low", "medium", "high", "critical"}
    for entry in _ERROR_LEAK_PATTERNS:
        assert len(entry) == 6, entry
        slug, regex, severity, title, description, remediation = entry
        assert slug not in seen_slugs, f"duplicate slug {slug}"
        seen_slugs.add(slug)
        assert severity in valid_severities
        assert hasattr(regex, "search")
        assert regex.pattern.__class__ is bytes
        assert title and description and remediation

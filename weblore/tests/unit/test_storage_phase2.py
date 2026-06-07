"""Tests for new Phase 2 storage methods."""
from pathlib import Path

from weblore.storage import Project


def _p(tmp: Path) -> Project:
    return Project(tmp / "p2.weblore")


def test_match_replace_crud(tmp_path: Path):
    p = _p(tmp_path)
    mid = p.add_mr(where="req_header", pattern="x", replacement="y", is_regex=False)
    rows = p.list_mr()
    assert any(r["id"] == mid and r["enabled"] for r in rows)
    p.toggle_mr(mid)
    assert any(r["id"] == mid and not r["enabled"] for r in p.list_mr())
    p.delete_mr(mid)
    assert not any(r["id"] == mid for r in p.list_mr())


def test_scope_crud(tmp_path: Path):
    p = _p(tmp_path)
    sid = p.add_scope("include", "example.com", "host")
    assert any(r["id"] == sid for r in p.list_scope())
    p.delete_scope(sid)
    assert not any(r["id"] == sid for r in p.list_scope())


def test_search_finds_url_match(tmp_path: Path):
    p = _p(tmp_path)
    p.add_history(host="h", method="GET", url="http://h/secret", status=200,
                   duration_ms=1, engine="t", raw_req=b"GET /\r\n\r\n",
                   raw_resp=b"HTTP/1.1 200 OK\r\n\r\n")
    out = p.search("secret")
    assert len(out) == 1
    assert "url" in out[0]["where"]


def test_search_finds_body_match(tmp_path: Path):
    p = _p(tmp_path)
    p.add_history(host="h", method="GET", url="http://h/", status=200,
                   duration_ms=1, engine="t", raw_req=b"GET /\r\n\r\n",
                   raw_resp=b"HTTP/1.1 200 OK\r\n\r\nhello world")
    out = p.search("world", where="resp")
    assert len(out) == 1


def test_intruder_crud_and_results(tmp_path: Path):
    p = _p(tmp_path)
    aid = p.create_intruder(
        name="t", attack_type="sniper",
        template=b"GET /?x=A HTTP/1.1\r\n\r\n",
        positions=[(7, 10)],
        payloads=[["a", "b"]],
        options={"concurrency": 1, "max_requests": 10},
        url="http://h/", engine="httpx",
    )
    p.add_intruder_result(attack_id=aid, seq=0, payloads=["a"], status=200,
                           len_resp=12, duration_ms=3, grep_hits="", history_id=None)
    p.add_intruder_result(attack_id=aid, seq=1, payloads=["b"], status=404,
                           len_resp=5, duration_ms=4, grep_hits="", history_id=None)
    res = p.list_intruder_results(aid, sort="status", desc=True)
    assert [r["status"] for r in res] == [404, 200]
    p.delete_intruder(aid)
    assert not p.list_intruder_results(aid)


def test_sync_intercept_decision_roundtrip(tmp_path: Path):
    p = _p(tmp_path)
    iid = p.enqueue_intercept_sync("request", b"GET / HTTP/1.1\r\n\r\n",
                                    "rule:test", "flow-1")
    d, edited = p.get_intercept_decision(iid)
    assert d is None and edited is None
    p.decide_intercept(iid, "forward_edited", b"GET /new HTTP/1.1\r\n\r\n")
    d, edited = p.get_intercept_decision(iid)
    assert d == "forward_edited"
    assert edited == b"GET /new HTTP/1.1\r\n\r\n"


def test_sitemap_groups_by_endpoint(tmp_path: Path):
    p = _p(tmp_path)
    for _ in range(3):
        p.add_history(host="h", method="GET", url="http://h/a", status=200,
                       duration_ms=1, engine="t",
                       raw_req=b"GET /a\r\n\r\n", raw_resp=b"HTTP/1.1 200 OK\r\n\r\n")
    p.add_history(host="h", method="POST", url="http://h/a", status=201,
                   duration_ms=1, engine="t",
                   raw_req=b"POST /a\r\n\r\n", raw_resp=b"HTTP/1.1 201\r\n\r\n")
    rows = p.sitemap()
    assert len(rows) == 2
    counts = {r["method"]: r["count"] for r in rows}
    assert counts["GET"] == 3 and counts["POST"] == 1

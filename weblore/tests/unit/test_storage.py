from pathlib import Path

from weblore.storage import Project


def test_project_create_and_meta(tmp_path: Path):
    p = Project(tmp_path / "x.weblore")
    meta = p.meta()
    assert meta["name"] == "x"
    assert meta["schema_version"] >= 1
    p.close()


def test_history_add_list_get(tmp_path: Path):
    p = Project(tmp_path / "h.weblore")
    raw_req = b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"
    raw_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi"
    hid = p.add_history(
        host="x.test", method="GET", url="http://x.test/",
        status=200, duration_ms=15, engine="test",
        raw_req=raw_req, raw_resp=raw_resp,
    )
    assert hid > 0
    rows = p.list_history(limit=10)
    assert len(rows) == 1
    assert rows[0].url == "http://x.test/"
    assert rows[0].len_req == len(raw_req)
    fetched = p.get_history(hid)
    assert fetched is not None
    assert fetched.req_blob == raw_req
    assert fetched.resp_blob == raw_resp
    p.close()


def test_intercept_enqueue_drop_count(tmp_path: Path):
    p = Project(tmp_path / "i.weblore")
    iid = p.enqueue_intercept("request", b"GET / HTTP/1.1\r\n\r\n", "test")
    assert p.intercept_count() == 1
    item = p.get_intercept(iid)
    assert item is not None and item.kind == "request"
    p.drop_intercept(iid)
    assert p.intercept_count() == 0
    p.close()


def test_state_get_set(tmp_path: Path):
    p = Project(tmp_path / "s.weblore")
    assert p.get_state("theme", "default") == "default"
    p.set_state("theme", "dark")
    assert p.get_state("theme") == "dark"
    p.set_state("theme", "light")
    assert p.get_state("theme") == "light"
    p.close()


def test_history_search(tmp_path: Path):
    p = Project(tmp_path / "s2.weblore")
    for u in ("/login", "/dashboard", "/api/users"):
        p.add_history(host="x", method="GET", url=u, status=200,
                      duration_ms=1, engine="t", raw_req=b"", raw_resp=b"")
    rows = p.list_history(q="api")
    assert len(rows) == 1 and rows[0].url == "/api/users"
    p.close()

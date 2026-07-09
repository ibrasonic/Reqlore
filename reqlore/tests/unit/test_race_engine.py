"""Race engine + race Intruder attack: synchronized request groups.

Covers the two transports (HTTP/2 single-packet framing, HTTP/1.1
last-byte-sync) and the ``race`` Intruder attack type end to end.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.engines import Request, race_engine
from reqlore.intruder import AttackRunner, find_positions
from reqlore.storage import Project

h2 = pytest.importorskip("h2")
from h2.config import H2Configuration  # noqa: E402
from h2.connection import H2Connection  # noqa: E402
from h2.events import (  # noqa: E402
    DataReceived,
    RequestReceived,
    StreamEnded,
)

# --------------------------------------------------------------------------
# HTTP/2 single-packet framing (in-memory, no sockets)
# --------------------------------------------------------------------------

def test_single_packet_framing_withholds_end_stream() -> None:
    """The prime blob opens every stream but never ends it; the release
    blob (one ``sendall`` on the wire) carries END_STREAM for all streams.

    Driving a server-side ``H2Connection`` with the two blobs proves the
    single-packet property without any network: after prime the server
    sees N request headers and zero stream-ends; after release it sees
    every stream complete with the correct body."""
    requests = [
        Request(method="GET", url="https://example.test/a", headers=[], body=b""),
        Request(method="POST", url="https://example.test/b", headers=[],
                body=b"amount=100"),
        Request(method="POST", url="https://example.test/c", headers=[],
                body=b"x"),  # 1-byte body: whole body is the withheld byte
    ]

    server = H2Connection(
        config=H2Configuration(client_side=False, header_encoding="utf-8"))
    server.initiate_connection()
    client = H2Connection(
        config=H2Configuration(client_side=True, header_encoding="utf-8"))
    client.initiate_connection()
    # Exchange connection preface / settings.
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())

    stream_ids, prime, release = race_engine._prime_and_release_frames(
        client, requests, "example.test")
    assert len(stream_ids) == 3

    prime_events = server.receive_data(prime)
    got_headers = [e for e in prime_events if isinstance(e, RequestReceived)]
    ended = [e for e in prime_events if isinstance(e, StreamEnded)]
    assert len(got_headers) == 3
    assert ended == []  # END_STREAM withheld → nothing completes yet

    bodies: dict[int, bytearray] = {sid: bytearray() for sid in stream_ids}
    for ev in prime_events:
        if isinstance(ev, DataReceived):
            bodies[ev.stream_id] += ev.data

    release_events = server.receive_data(release)
    ended_ids = {e.stream_id for e in release_events
                 if isinstance(e, StreamEnded)}
    assert ended_ids == set(stream_ids)  # every request completes on release
    for ev in release_events:
        if isinstance(ev, DataReceived):
            bodies[ev.stream_id] += ev.data

    assert bytes(bodies[stream_ids[0]]) == b""
    assert bytes(bodies[stream_ids[1]]) == b"amount=100"
    assert bytes(bodies[stream_ids[2]]) == b"x"


def test_single_packet_h2_requires_https() -> None:
    """Auto-fallback hinges on this: an http:// target must raise
    RaceUnsupported so send_group drops to last-byte-sync."""
    with pytest.raises(race_engine.RaceUnsupported):
        race_engine.single_packet_h2(
            [Request(method="GET", url="http://127.0.0.1:1/", headers=[],
                     body=b"")],
            timeout=1.0,
        )


def test_h2_headers_strip_connection_specific() -> None:
    req = Request(
        method="POST", url="https://h.test/p?x=1",
        headers=[("Host", "h.test"), ("Connection", "close"),
                 ("Transfer-Encoding", "chunked"), ("X-Keep", "1")],
        body=b"ab",
    )
    hdrs = race_engine._h2_headers(req, "h.test")
    keys = [k for k, _ in hdrs]
    assert keys[:4] == [":method", ":authority", ":scheme", ":path"]
    assert ("x-keep", "1") in hdrs
    # HTTP/2 forbids these hop-by-hop headers.
    assert not any(k in ("host", "connection", "transfer-encoding")
                   for k, _ in hdrs)
    # Content-length synthesised from the body.
    assert ("content-length", "2") in hdrs


# --------------------------------------------------------------------------
# HTTP/1.1 last-byte-sync (real loopback sockets)
# --------------------------------------------------------------------------

_HITS = threading.Semaphore(0)


class _Counter(BaseHTTPRequestHandler):
    lock = threading.Lock()
    count = 0

    def do_GET(self):  # noqa: N802
        with _Counter.lock:
            _Counter.count += 1
            n = _Counter.count
        body = f"ok-{n}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_a, **_k):
        pass


@pytest.fixture
def server():
    _Counter.count = 0
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Counter)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()
    srv.server_close()


def test_last_byte_sync_all_requests_land(server: int) -> None:
    reqs = [
        Request(method="GET", url=f"http://127.0.0.1:{server}/r{i}",
                headers=[("Host", f"127.0.0.1:{server}")], body=b"")
        for i in range(5)
    ]
    result = race_engine.last_byte_sync_h1(reqs, timeout=5.0)
    assert result.transport == "last-byte"
    assert len(result.items) == 5
    for item in result.items:
        assert item.error == "", item.error
        assert item.response is not None
        assert item.response.status == 200
    # All five reached the server.
    assert _Counter.count == 5


def test_last_byte_sync_posts_deliver_body(server: int) -> None:
    reqs = [
        Request(method="POST", url=f"http://127.0.0.1:{server}/pay",
                headers=[("Host", f"127.0.0.1:{server}")],
                body=f"amount={i}".encode())
        for i in range(3)
    ]
    result = race_engine.last_byte_sync_h1(reqs, timeout=5.0)
    bodies = sorted(
        (it.response.body for it in result.items if it.response), key=len)
    assert b"amount=0" in bodies
    assert b"amount=1" in bodies
    assert b"amount=2" in bodies


def test_send_group_auto_falls_back_to_last_byte_on_http(server: int) -> None:
    """Plain http:// can't do single-packet, so ``auto`` must pick the
    last-byte transport and still deliver every request."""
    reqs = [
        Request(method="GET", url=f"http://127.0.0.1:{server}/a{i}",
                headers=[("Host", f"127.0.0.1:{server}")], body=b"")
        for i in range(4)
    ]
    result = race_engine.send_group(reqs, mode="auto", timeout=5.0)
    assert result.transport == "last-byte"
    assert all(it.response and it.response.status == 200 for it in result.items)


def test_send_group_empty_is_noop() -> None:
    result = race_engine.send_group([], timeout=1.0)
    assert result.transport == "none"
    assert result.items == []


# --------------------------------------------------------------------------
# Race Intruder attack — end to end
# --------------------------------------------------------------------------

def test_race_attack_unmarked_group(tmp_path: Path, server: int) -> None:
    """No markers → N identical requests fired as one synchronized group."""
    p = Project(tmp_path / "race.rlr")
    tpl = (
        f"GET /race HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server}\r\n"
        f"\r\n"
    ).encode()
    aid = p.create_intruder(
        name="double-spend", attack_type="race",
        template=tpl, positions=[], payloads=[],
        options={"race_mode": "last-byte", "race_count": 6, "timeout": 5.0},
        url=f"http://127.0.0.1:{server}/",
        engine="raw",
    )
    r = AttackRunner(p, aid)
    r.start()
    assert r.wait(timeout=30)
    results = p.list_intruder_results(aid)
    assert len(results) == 6
    assert all(x["status"] == 200 for x in results)
    attack = p.get_intruder(aid)
    assert attack is not None
    assert attack["status"] == "done"
    assert r.stop_reason.startswith("race [last-byte]")
    assert "6\u00d7 2xx" in r.stop_reason


def test_race_attack_marked_group_one_request_per_payload(
    tmp_path: Path, server: int,
) -> None:
    """With a marker the first payload set becomes the group: one distinct
    request per payload, all fired together."""
    p = Project(tmp_path / "race2.rlr")
    marker = "\u00a7"
    tpl = (
        f"POST /buy HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{server}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"\r\n"
        f"code={marker}X{marker}"
    ).encode()
    positions = find_positions(tpl)
    aid = p.create_intruder(
        name="coupon-race", attack_type="race",
        template=tpl, positions=positions,
        payloads=[["AAA", "BBB", "CCC"]],
        options={"race_mode": "last-byte", "timeout": 5.0},
        url=f"http://127.0.0.1:{server}/",
        engine="raw",
    )
    r = AttackRunner(p, aid)
    r.start()
    assert r.wait(timeout=30)
    results = p.list_intruder_results(aid)
    assert len(results) == 3
    assert all(x["status"] == 200 for x in results)
    # The server echoes the POST body; each coupon code should appear.
    seen = set()
    for res in results:
        row = p.get_history(res["history_id"])
        assert row is not None
        seen.add(row.resp_blob)
    joined = b"".join(seen)
    assert b"code=AAA" in joined
    assert b"code=BBB" in joined
    assert b"code=CCC" in joined


def test_race_group_capped(tmp_path: Path, server: int) -> None:
    """The hard _RACE_CAP ceiling bounds an over-large unmarked group."""
    from reqlore import intruder as intr
    p = Project(tmp_path / "cap.rlr")
    tpl = (
        f"GET /c HTTP/1.1\r\nHost: 127.0.0.1:{server}\r\n\r\n"
    ).encode()
    aid = p.create_intruder(
        name="cap", attack_type="race",
        template=tpl, positions=[], payloads=[],
        options={"race_mode": "last-byte",
                 "race_count": intr._RACE_CAP + 50, "timeout": 5.0},
        url=f"http://127.0.0.1:{server}/",
        engine="raw",
    )
    r = AttackRunner(p, aid)
    r.start()
    assert r.wait(timeout=60)
    results = p.list_intruder_results(aid)
    assert len(results) == intr._RACE_CAP

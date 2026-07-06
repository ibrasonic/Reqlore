"""Phase 5 - HTTP/2 frame parser + builders."""
from __future__ import annotations

from reqlore.h2_tool import (
    H2_PREFACE,
    build_goaway,
    build_ping,
    build_rst_stream,
    build_settings,
    build_window_update,
    parse_frames,
    parse_hex,
    to_hex,
)


def test_parse_settings_with_preface():
    data = H2_PREFACE + build_settings([(2, 0), (5, 16384)])
    stream = parse_frames(data)
    assert stream.preface_seen
    assert len(stream.frames) == 1
    f = stream.frames[0]
    assert f.type == "SETTINGS"
    assert f.stream_id == 0
    params = f.detail["params"]
    assert {p["id"]: p["value"] for p in params} == {2: 0, 5: 16384}
    assert {p["name"] for p in params} == {"ENABLE_PUSH", "MAX_FRAME_SIZE"}


def test_settings_ack_frame_decoded():
    data = build_settings(ack=True)
    s = parse_frames(data)
    assert s.frames[0].type == "SETTINGS"
    assert "ACK/END_STREAM" in s.frames[0].flags
    assert s.frames[0].detail.get("settings_ack") is True


def test_ping_round_trip():
    data = build_ping(b"reqlore!")
    s = parse_frames(data)
    f = s.frames[0]
    assert f.type == "PING"
    assert f.length == 8
    assert f.detail["opaque_hex"] == b"reqlore!".hex()


def test_goaway_decodes_last_stream_and_code():
    data = build_goaway(last_stream_id=42, error_code=5, debug=b"why")
    s = parse_frames(data)
    f = s.frames[0]
    assert f.type == "GOAWAY"
    assert f.detail["last_stream_id"] == 42
    assert f.detail["error_code"] == 5
    assert f.detail["debug"] == "why"


def test_rst_stream():
    data = build_rst_stream(7, error_code=3)
    s = parse_frames(data)
    f = s.frames[0]
    assert f.type == "RST_STREAM"
    assert f.stream_id == 7
    assert f.detail["error_code"] == 3


def test_window_update():
    data = build_window_update(1, 65535)
    s = parse_frames(data)
    f = s.frames[0]
    assert f.type == "WINDOW_UPDATE"
    assert f.detail["increment"] == 65535


def test_multiple_frames_in_one_buffer():
    data = build_settings(ack=True) + build_ping(b"abcdefgh") + build_window_update(0, 100)
    s = parse_frames(data)
    assert [f.type for f in s.frames] == ["SETTINGS", "PING", "WINDOW_UPDATE"]


def test_truncated_frame_reports_error():
    data = build_ping(b"reqlore!")[:-3]
    s = parse_frames(data)
    assert s.frames[0].error == "frame extends past buffer"


def test_parse_hex_accepts_whitespace_and_0x():
    raw = parse_hex("00 00 08\n06\t01 00 00 00 00 00 00 00 00 00 00 00")
    assert isinstance(raw, bytes)
    assert raw[3] == 0x06   # PING type code


def test_to_hex_wraps_lines():
    out = to_hex(b"\x00\x11\x22\x33\x44\x55", width=2)
    assert out == "00 11\n22 33\n44 55"

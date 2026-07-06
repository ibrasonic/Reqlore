"""HTTP/2 frame inspector + crafter.

Uses the ``hyperframe`` library (a hard dep via ``h2``) to parse and
serialise raw HTTP/2 frames. The blueprint pairs with this module to let
users paste a hex dump of frames, inspect them, or assemble a custom
frame stream (handy for testing rapid-reset / 0-day-ish behaviour).

Hyperframe is unrelated to the live H2 connection in ``httpx`` — this
tool produces raw byte sequences. Sending those bytes on the wire is
outside the module's scope (and intentionally so).
"""
from __future__ import annotations

import binascii
import contextlib
from dataclasses import dataclass, field
from typing import Any

try:
    HYPERFRAME_AVAILABLE = True
except Exception:                  # pragma: no cover - hyperframe is on deps
    HYPERFRAME_AVAILABLE = False

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_TYPES = {
    0x0: "DATA",
    0x1: "HEADERS",
    0x2: "PRIORITY",
    0x3: "RST_STREAM",
    0x4: "SETTINGS",
    0x5: "PUSH_PROMISE",
    0x6: "PING",
    0x7: "GOAWAY",
    0x8: "WINDOW_UPDATE",
    0x9: "CONTINUATION",
}


@dataclass
class ParsedFrame:
    index: int
    offset: int                 # byte offset into input
    type: str                   # "DATA", "HEADERS", ...
    type_code: int
    length: int
    flags: list[str] = field(default_factory=list)
    stream_id: int = 0
    detail: dict[str, Any] = field(default_factory=dict)
    raw_hex: str = ""
    error: str = ""


@dataclass
class FrameStream:
    frames: list[ParsedFrame] = field(default_factory=list)
    preface_seen: bool = False
    trailing_bytes: int = 0
    total_bytes: int = 0


def parse_frames(data: bytes) -> FrameStream:
    """Walk a byte buffer and yield typed frames.

    Honours the H2 connection preface if present.
    """
    stream = FrameStream(total_bytes=len(data))
    i = 0
    if data[:len(H2_PREFACE)] == H2_PREFACE:
        stream.preface_seen = True
        i = len(H2_PREFACE)

    idx = 0
    while i + 9 <= len(data):
        # 24-bit length, 8-bit type, 8-bit flags, 32-bit (R + stream id)
        length = int.from_bytes(data[i:i + 3], "big")
        type_code = data[i + 3]
        flags = data[i + 4]
        stream_id = int.from_bytes(data[i + 5:i + 9], "big") & 0x7FFFFFFF
        end = i + 9 + length
        if end > len(data):
            stream.frames.append(ParsedFrame(
                index=idx, offset=i,
                type=FRAME_TYPES.get(type_code, f"0x{type_code:02x}"),
                type_code=type_code,
                length=length, flags=_decode_flags(type_code, flags),
                stream_id=stream_id,
                raw_hex=binascii.hexlify(data[i:end]).decode(),
                error="frame extends past buffer",
            ))
            i = end
            idx += 1
            break

        payload = data[i + 9:end]
        pf = ParsedFrame(
            index=idx, offset=i,
            type=FRAME_TYPES.get(type_code, f"0x{type_code:02x}"),
            type_code=type_code,
            length=length,
            flags=_decode_flags(type_code, flags),
            stream_id=stream_id,
            raw_hex=binascii.hexlify(data[i:end]).decode(),
        )
        pf.detail = _decode_payload(type_code, payload, stream_id, flags)
        stream.frames.append(pf)
        idx += 1
        i = end

    stream.trailing_bytes = len(data) - i
    return stream


def _decode_flags(type_code: int, flags: int) -> list[str]:
    out: list[str] = []
    # Generic ones first
    if flags & 0x1:
        out.append("ACK/END_STREAM")
    if flags & 0x4:
        out.append("END_HEADERS")
    if flags & 0x8:
        out.append("PADDED")
    if flags & 0x20:
        out.append("PRIORITY")
    return out


def _decode_payload(type_code: int, payload: bytes,
                     stream_id: int, flags: int) -> dict[str, Any]:
    out: dict[str, Any] = {"size": len(payload)}
    if type_code == 0x0:                                # DATA
        out["body_hex"] = binascii.hexlify(payload[:64]).decode()
        with contextlib.suppress(Exception):
            out["body_preview"] = payload[:64].decode("utf-8", "replace")
    elif type_code == 0x4:                              # SETTINGS
        if flags & 0x1:
            out["settings_ack"] = True
        else:
            params = []
            for j in range(0, len(payload), 6):
                if j + 6 > len(payload):
                    break
                pid = int.from_bytes(payload[j:j + 2], "big")
                val = int.from_bytes(payload[j + 2:j + 6], "big")
                params.append({"id": pid, "value": val,
                                "name": _settings_name(pid)})
            out["params"] = params
    elif type_code == 0x6:                              # PING
        out["opaque_hex"] = binascii.hexlify(payload).decode()
        out["ack"] = bool(flags & 0x1)
    elif type_code == 0x7:                              # GOAWAY
        if len(payload) >= 8:
            last = int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF
            code = int.from_bytes(payload[4:8], "big")
            debug = payload[8:].decode("utf-8", "replace")
            out["last_stream_id"] = last
            out["error_code"] = code
            out["debug"] = debug
    elif type_code == 0x3:                              # RST_STREAM
        if len(payload) >= 4:
            out["error_code"] = int.from_bytes(payload[:4], "big")
    elif type_code == 0x8:                              # WINDOW_UPDATE
        if len(payload) >= 4:
            out["increment"] = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
    elif type_code == 0x1 or type_code == 0x9:                              # HEADERS (HPACK)
        out["hpack_hex"] = binascii.hexlify(payload[:64]).decode()
    return out


_SETTINGS = {
    1: "HEADER_TABLE_SIZE",
    2: "ENABLE_PUSH",
    3: "MAX_CONCURRENT_STREAMS",
    4: "INITIAL_WINDOW_SIZE",
    5: "MAX_FRAME_SIZE",
    6: "MAX_HEADER_LIST_SIZE",
}


def _settings_name(pid: int) -> str:
    return _SETTINGS.get(pid, f"UNKNOWN_{pid}")


# ---- builders ----

def build_settings(params: list[tuple[int, int]] | None = None,
                    *, ack: bool = False) -> bytes:
    """Build a SETTINGS frame.

    Pass ``ack=True`` for an empty acknowledgement frame, else a list of
    ``(id, value)`` pairs.
    """
    if ack:
        return _serialise(type_code=0x4, flags=0x1, stream_id=0, payload=b"")
    body = b""
    for pid, val in (params or []):
        body += pid.to_bytes(2, "big") + val.to_bytes(4, "big")
    return _serialise(type_code=0x4, flags=0x0, stream_id=0, payload=body)


def build_ping(opaque: bytes = b"reqlore!", *, ack: bool = False) -> bytes:
    opaque = (opaque + b"\x00" * 8)[:8]
    return _serialise(type_code=0x6, flags=(0x1 if ack else 0x0),
                       stream_id=0, payload=opaque)


def build_goaway(last_stream_id: int = 0, error_code: int = 0,
                  debug: bytes = b"") -> bytes:
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big") + \
              error_code.to_bytes(4, "big") + debug
    return _serialise(type_code=0x7, flags=0x0, stream_id=0, payload=payload)


def build_rst_stream(stream_id: int, error_code: int = 8) -> bytes:
    return _serialise(type_code=0x3, flags=0x0, stream_id=stream_id,
                       payload=error_code.to_bytes(4, "big"))


def build_window_update(stream_id: int, increment: int) -> bytes:
    return _serialise(type_code=0x8, flags=0x0, stream_id=stream_id,
                       payload=(increment & 0x7FFFFFFF).to_bytes(4, "big"))


def _serialise(*, type_code: int, flags: int, stream_id: int,
                payload: bytes) -> bytes:
    length = len(payload)
    if length > 0xFFFFFF:
        raise ValueError("frame payload exceeds 16 MiB")
    return (length.to_bytes(3, "big") + bytes([type_code, flags]) +
            (stream_id & 0x7FFFFFFF).to_bytes(4, "big") + payload)


def parse_hex(text: str) -> bytes:
    """Lenient hex parser: ignores whitespace and any ``0x`` prefixes."""
    cleaned = "".join(c for c in text if c not in " \r\n\t:,")
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    cleaned = cleaned.replace("0x", "")
    return binascii.unhexlify(cleaned)


def to_hex(data: bytes, *, width: int = 32) -> str:
    """Format bytes as ``ab cd ef`` groups, wrapped to ``width`` per line."""
    hexs = binascii.hexlify(data).decode()
    pairs = [hexs[i:i + 2] for i in range(0, len(hexs), 2)]
    lines = []
    for k in range(0, len(pairs), width):
        lines.append(" ".join(pairs[k:k + width]))
    return "\n".join(lines)

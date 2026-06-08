"""WebSocket client + transcript helpers.

A WS conversation is stored as a JSON document in the ``project_state`` table
under key ``ws:<id>``. Each message is a dict::

    {"dir": "send"|"recv", "ts": <epoch_seconds>, "kind": "text"|"binary",
     "data": <utf-8 str or base64 str>, "size": <int>}

The blueprint reads / writes that table; this module is purely transport.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass, field

try:
    import websockets
    from websockets.sync.client import connect as _ws_connect
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False


@dataclass
class WSMessage:
    direction: str   # 'send' | 'recv'
    ts: int
    kind: str        # 'text' | 'binary'
    data: str        # utf-8 text or base64 string
    size: int = 0

    def to_dict(self) -> dict:
        return {"dir": self.direction, "ts": self.ts,
                "kind": self.kind, "data": self.data, "size": self.size}

    @classmethod
    def from_dict(cls, d: dict) -> "WSMessage":
        return cls(direction=d.get("dir", ""), ts=int(d.get("ts", 0)),
                   kind=d.get("kind", "text"), data=d.get("data", ""),
                   size=int(d.get("size", 0)))


@dataclass
class WSTranscript:
    url: str = ""
    notes: str = ""
    messages: list[WSMessage] = field(default_factory=list)
    closed: bool = False

    def to_json(self) -> str:
        return json.dumps({
            "url": self.url, "notes": self.notes, "closed": self.closed,
            "messages": [m.to_dict() for m in self.messages],
        })

    @classmethod
    def from_json(cls, blob: str) -> "WSTranscript":
        if not blob:
            return cls()
        d = json.loads(blob)
        return cls(
            url=d.get("url", ""), notes=d.get("notes", ""),
            closed=bool(d.get("closed", False)),
            messages=[WSMessage.from_dict(m) for m in d.get("messages") or []],
        )


def send_messages(url: str, messages: list[tuple[str, str]], *,
                   headers: list[tuple[str, str]] | None = None,
                   recv_seconds: float = 2.0,
                   timeout_s: float = 15.0) -> WSTranscript:
    """Connect, send each (kind, data) message, then read for `recv_seconds`.

    ``kind`` is ``'text'`` or ``'binary'`` (binary takes hex-encoded data).
    Returns the full transcript, including any received frames.
    """
    if not WS_AVAILABLE:
        raise RuntimeError(
            "websockets not installed. 'pip install websockets' to enable "
            "the WebSocket workbench."
        )
    transcript = WSTranscript(url=url)
    extra_headers = list(headers or [])
    try:
        with _ws_connect(url, additional_headers=extra_headers,
                          open_timeout=timeout_s, close_timeout=2) as ws:
            for kind, data in messages:
                if kind == "binary":
                    payload = bytes.fromhex(data)
                    ws.send(payload)
                    transcript.messages.append(WSMessage(
                        "send", int(time.time()), "binary",
                        base64.b64encode(payload).decode(), len(payload),
                    ))
                else:
                    ws.send(data)
                    transcript.messages.append(WSMessage(
                        "send", int(time.time()), "text", data,
                        len(data.encode("utf-8")),
                    ))
            # Drain any server replies for `recv_seconds`.
            end = time.monotonic() + recv_seconds
            while time.monotonic() < end:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    frame = ws.recv(timeout=remaining)
                except TimeoutError:
                    break
                if isinstance(frame, str):
                    transcript.messages.append(WSMessage(
                        "recv", int(time.time()), "text", frame,
                        len(frame.encode("utf-8")),
                    ))
                else:
                    transcript.messages.append(WSMessage(
                        "recv", int(time.time()), "binary",
                        base64.b64encode(frame).decode(), len(frame),
                    ))
    except Exception as exc:
        transcript.messages.append(WSMessage(
            "recv", int(time.time()), "text", f"[error] {exc}", 0,
        ))
        transcript.closed = True
    else:
        transcript.closed = True
    return transcript

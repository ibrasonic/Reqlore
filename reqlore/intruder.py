"""Intruder — payload-driven request fuzzer.

Four attack types:
- sniper        : one position at a time, iterates each payload set across each position.
- battering     : every position gets the SAME payload each iteration.
- pitchfork     : positions advance in lockstep through their own payload set;
                  total iterations = min(len(set_i) for i).
- clusterbomb   : cartesian product across every position; total = product(len(set_i)).

Templates are raw HTTP request bytes with marker pairs (default ``\u00a7``) bracketing
each insertion point. The marker character is configurable to avoid clashes with
data that legitimately contains it.

Runtime is bounded by ``options.max_requests`` (defaults 1000) and per-host
concurrency (``options.concurrency``, defaults 4). Each result is written to
storage as it lands so the UI can stream rows incrementally.

All payload encoders are stdlib; no curl / no subprocess / no shell.
"""
from __future__ import annotations

import base64
import hashlib
import html
import itertools
import json
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterator
from urllib.parse import urlsplit

from .engines import Request, Response
from .engines import httpx_engine, raw_engine
from .engines import curl_cffi_engine, h3_engine
from .storage import Project


DEFAULT_MARKER = "\u00a7"   # section sign — same as Burp


# ---------- marker parsing ----------

def find_positions(template: bytes, marker: str = DEFAULT_MARKER) -> list[tuple[int, int]]:
    """Return inclusive-start, exclusive-end byte offsets between paired markers."""
    m = marker.encode("utf-8")
    out: list[tuple[int, int]] = []
    i = 0
    while True:
        a = template.find(m, i)
        if a < 0:
            break
        b = template.find(m, a + len(m))
        if b < 0:
            break
        out.append((a, b + len(m)))
        i = b + len(m)
    return out


def strip_markers(template: bytes, marker: str = DEFAULT_MARKER) -> bytes:
    return template.replace(marker.encode("utf-8"), b"")


def apply_payloads(template: bytes, positions: list[tuple[int, int]],
                    payloads: list[str], marker: str = DEFAULT_MARKER) -> bytes:
    """Replace marker spans by encoded payload strings (in order)."""
    if len(payloads) != len(positions):
        raise ValueError(
            f"payloads count ({len(payloads)}) != positions count ({len(positions)})"
        )
    pieces: list[bytes] = []
    cursor = 0
    for (a, b), p in zip(positions, payloads):
        pieces.append(template[cursor:a])
        pieces.append(p.encode("utf-8", errors="replace"))
        cursor = b
    pieces.append(template[cursor:])
    return b"".join(pieces)


# ---------- payload processors ----------

def _proc_url(s: str) -> str: return urllib.parse.quote(s, safe="")
def _proc_url2(s: str) -> str: return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")
def _proc_html(s: str) -> str: return html.escape(s, quote=True)
def _proc_b64(s: str) -> str: return base64.b64encode(s.encode()).decode()
def _proc_b64url(s: str) -> str: return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
def _proc_hex(s: str) -> str: return s.encode().hex()
def _proc_upper(s: str) -> str: return s.upper()
def _proc_lower(s: str) -> str: return s.lower()
def _proc_md5(s: str) -> str: return hashlib.md5(s.encode()).hexdigest()
def _proc_sha1(s: str) -> str: return hashlib.sha1(s.encode()).hexdigest()
def _proc_sha256(s: str) -> str: return hashlib.sha256(s.encode()).hexdigest()
def _proc_reverse(s: str) -> str: return s[::-1]


PROCESSORS: dict[str, Callable[[str], str]] = {
    "none": lambda s: s,
    "url": _proc_url, "url2": _proc_url2,
    "html": _proc_html,
    "b64": _proc_b64, "b64url": _proc_b64url,
    "hex": _proc_hex,
    "upper": _proc_upper, "lower": _proc_lower,
    "md5": _proc_md5, "sha1": _proc_sha1, "sha256": _proc_sha256,
    "reverse": _proc_reverse,
}


def apply_processors(value: str, processors: list[str]) -> str:
    out = value
    for name in processors:
        fn = PROCESSORS.get(name)
        if fn is not None:
            out = fn(out)
    return out


# ---------- payload sources ----------

def payloads_from_text(text: str) -> list[str]:
    """One per line. Blank lines preserved as empty payloads."""
    if not text:
        return []
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def payloads_numbers(start: int, end: int, step: int = 1) -> list[str]:
    if step == 0:
        return []
    if (end - start) * step < 0:
        return []
    out: list[str] = []
    n = start
    while (step > 0 and n <= end) or (step < 0 and n >= end):
        out.append(str(n))
        n += step
        if len(out) > 100_000:
            break
    return out


def payloads_brute(alphabet: str, min_len: int, max_len: int) -> Iterator[str]:
    """Generator (lazy) — clusterbomb cartesian could blow up; intruder caps it."""
    for n in range(max(1, min_len), max(1, max_len) + 1):
        for combo in itertools.product(alphabet, repeat=n):
            yield "".join(combo)


COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "letmein", "welcome",
    "admin", "administrator", "root", "toor", "iloveyou", "monkey", "dragon",
    "passw0rd", "p@ssword", "Password1", "P@ssw0rd", "changeme", "guest",
]


# ---------- attack scheduling ----------

def iterate(attack_type: str, payload_sets: list[list[str]],
             n_positions: int) -> Iterator[list[str]]:
    """Yield one payload-tuple per request, per attack type."""
    if attack_type == "sniper":
        # one payload set; per position, iterate payloads while others stay ""
        # convention: payload_sets has exactly 1 set
        if not payload_sets:
            return
        payloads = payload_sets[0]
        for pos in range(n_positions):
            for p in payloads:
                row = [""] * n_positions
                row[pos] = p
                yield row
    elif attack_type == "battering":
        if not payload_sets:
            return
        payloads = payload_sets[0]
        for p in payloads:
            yield [p] * n_positions
    elif attack_type == "pitchfork":
        if not payload_sets:
            return
        n = min(len(s) for s in payload_sets)
        for i in range(n):
            yield [s[i] for s in payload_sets]
    elif attack_type == "clusterbomb":
        if not payload_sets:
            return
        for combo in itertools.product(*payload_sets):
            yield list(combo)
    else:
        raise ValueError(f"unknown attack type: {attack_type}")


# ---------- template rendering ----------

def _parse_raw_request(raw: bytes) -> tuple[str, str, list[tuple[str, str]], bytes, str]:
    """Return method, path, headers, body, host (from Host header or ''). """
    sep = raw.find(b"\r\n\r\n")
    head, body = (raw[:sep], raw[sep + 4:]) if sep >= 0 else (raw, b"")
    text = head.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    parts = (lines[0] if lines else "").split(" ", 2)
    method = parts[0] if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: list[tuple[str, str]] = []
    host = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        headers.append((k, v))
        if k.lower() == "host":
            host = v
    return method, path, headers, body, host


def template_to_request(rendered: bytes, base_url: str,
                         http_version: str = "1.1") -> Request:
    method, path, headers, body, host = _parse_raw_request(rendered)
    p = urlsplit(base_url)
    scheme = p.scheme or "http"
    if not host:
        host = p.netloc
    url = f"{scheme}://{host}{path}" if path.startswith("/") else path
    return Request(
        method=method, url=url, headers=headers, body=body,
        http_version=http_version,
    )


# ---------- grep extraction ----------

def grep_extract(text: bytes, patterns: list[str]) -> str:
    """Return comma-joined hits across patterns. Pattern syntax: regex."""
    hits: list[str] = []
    s = text.decode("latin-1", errors="replace")
    for pat in patterns:
        if not pat:
            continue
        try:
            m = re.search(pat, s)
            if m:
                hits.append(m.group(0)[:120])
        except re.error:
            continue
    return " | ".join(hits)


# ---------- runner ----------

@dataclass
class AttackOptions:
    concurrency: int = 4
    delay_ms: int = 0
    max_requests: int = 1000
    processors: list[str] = field(default_factory=list)
    grep: list[str] = field(default_factory=list)
    timeout: float = 15.0
    follow_redirects: bool = False
    verify_tls: bool = True


@dataclass
class _Job:
    seq: int
    payloads: list[str]


class AttackRunner:
    """Threaded runner. Cancellable via cancel(); pausable via pause()/resume()."""

    def __init__(self, project: Project, attack_id: int):
        self.project = project
        self.attack_id = attack_id
        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()  # not paused
        self._thread: threading.Thread | None = None
        self._done = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.set()

    def pause(self) -> None:
        self._pause.clear()

    def resume(self) -> None:
        self._pause.set()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def wait(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    def start(self) -> None:
        if self.is_running():
            return
        self._thread = threading.Thread(
            target=self._run, name=f"intruder-{self.attack_id}", daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        try:
            attack = self.project.get_intruder(self.attack_id)
            if not attack:
                return
            self.project.set_intruder_status(self.attack_id, "running")
            opts_raw = attack["options"]
            options = AttackOptions(
                concurrency=max(1, int(opts_raw.get("concurrency", 4))),
                delay_ms=max(0, int(opts_raw.get("delay_ms", 0))),
                max_requests=max(1, int(opts_raw.get("max_requests", 1000))),
                processors=list(opts_raw.get("processors", [])),
                grep=list(opts_raw.get("grep", [])),
                timeout=float(opts_raw.get("timeout", 15.0)),
                follow_redirects=bool(opts_raw.get("follow_redirects", False)),
                verify_tls=bool(opts_raw.get("verify_tls", True)),
            )

            template = attack["template"]
            positions = [tuple(p) for p in attack["positions"]]
            payload_sets = attack["payloads"]
            engine = attack["engine"]
            base_url = attack["url"]
            atype = attack["attack_type"]

            jobs: list[_Job] = []
            for seq, combo in enumerate(iterate(atype, payload_sets, len(positions))):
                if seq >= options.max_requests:
                    break
                processed = [apply_processors(p, options.processors) for p in combo]
                jobs.append(_Job(seq=seq, payloads=processed))

            send = _send_factory(engine, options)

            def _do(job: _Job):
                self._pause.wait()
                if self._cancel.is_set():
                    return None
                rendered = apply_payloads(template, positions, job.payloads)
                req = template_to_request(rendered, base_url)
                t0 = time.monotonic()
                resp = send(req)
                dur = int((time.monotonic() - t0) * 1000)
                grep_hits = grep_extract(resp.body or b"", options.grep)
                raw_req = resp.raw_request or rendered
                raw_resp = _serialise_response(resp)
                try:
                    host = urlsplit(req.url).hostname or ""
                except Exception:
                    host = ""
                hid = self.project.add_history(
                    host=host, method=req.method, url=req.url,
                    status=resp.status,
                    duration_ms=resp.timings.total_ms or dur,
                    engine=f"intruder/{engine}",
                    raw_req=raw_req, raw_resp=raw_resp,
                    tags=f"intruder:{self.attack_id}",
                )
                self.project.add_intruder_result(
                    attack_id=self.attack_id, seq=job.seq,
                    payloads=job.payloads, status=resp.status,
                    len_resp=len(raw_resp), duration_ms=resp.timings.total_ms or dur,
                    grep_hits=grep_hits, history_id=hid,
                )
                if options.delay_ms:
                    time.sleep(options.delay_ms / 1000.0)
                return job.seq

            with ThreadPoolExecutor(max_workers=options.concurrency) as ex:
                futures = [ex.submit(_do, j) for j in jobs]
                for _ in as_completed(futures):
                    if self._cancel.is_set():
                        for f in futures:
                            f.cancel()
                        break

            self.project.set_intruder_status(
                self.attack_id, "cancelled" if self._cancel.is_set() else "done",
            )
        finally:
            self._done.set()


def _send_factory(engine: str, opts: AttackOptions):
    if engine == "raw":
        def _s(req: Request) -> Response:
            return raw_engine.send(req, verify=opts.verify_tls, timeout=opts.timeout)
        return _s
    if engine == "h3":
        def _s(req: Request) -> Response:
            return h3_engine.send(req, timeout=opts.timeout)
        return _s
    if engine.startswith("curl-cffi"):
        profile = engine.split(":", 1)[1] if ":" in engine else "chrome120"
        def _s(req: Request) -> Response:
            return curl_cffi_engine.send(
                req, profile=profile, timeout=opts.timeout,
                follow_redirects=opts.follow_redirects,
            )
        return _s
    def _s(req: Request) -> Response:
        return httpx_engine.send(
            req, verify=opts.verify_tls, timeout=opts.timeout,
            follow_redirects=opts.follow_redirects,
        )
    return _s


def _serialise_response(resp: Response) -> bytes:
    head = f"HTTP/{resp.http_version} {resp.status} {resp.reason}\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in resp.headers) + "\r\n"
    return head.encode("latin-1", errors="replace") + (resp.body or b"")


# ---------- registry of running attacks (per-process) ----------

_REGISTRY: dict[int, AttackRunner] = {}
_REG_LOCK = threading.Lock()


def get_runner(attack_id: int) -> AttackRunner | None:
    with _REG_LOCK:
        return _REGISTRY.get(attack_id)


def register(runner: AttackRunner) -> None:
    with _REG_LOCK:
        _REGISTRY[runner.attack_id] = runner


def unregister(attack_id: int) -> None:
    with _REG_LOCK:
        _REGISTRY.pop(attack_id, None)

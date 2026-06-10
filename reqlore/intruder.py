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
import binascii
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
from pathlib import Path
from typing import Callable, Iterator, Sequence
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
def _proc_b64dec(s: str) -> str:
    try:
        pad = "=" * (-len(s) % 4)
        return base64.b64decode(s + pad).decode("latin-1", errors="replace")
    except (binascii.Error, ValueError):
        return s
def _proc_hex(s: str) -> str: return s.encode().hex()
def _proc_upper(s: str) -> str: return s.upper()
def _proc_lower(s: str) -> str: return s.lower()
def _proc_md5(s: str) -> str: return hashlib.md5(s.encode()).hexdigest()
def _proc_sha1(s: str) -> str: return hashlib.sha1(s.encode()).hexdigest()
def _proc_sha256(s: str) -> str: return hashlib.sha256(s.encode()).hexdigest()
def _proc_reverse(s: str) -> str: return s[::-1]
def _proc_length(s: str) -> str: return str(len(s))
def _proc_strip(s: str) -> str: return s.strip()
def _proc_sql_quote(s: str) -> str: return s.replace("'", "''")


PROCESSORS: dict[str, Callable[[str], str]] = {
    "none": lambda s: s,
    "url": _proc_url, "url2": _proc_url2,
    "html": _proc_html,
    "b64": _proc_b64, "b64url": _proc_b64url, "b64dec": _proc_b64dec,
    "hex": _proc_hex,
    "upper": _proc_upper, "lower": _proc_lower,
    "md5": _proc_md5, "sha1": _proc_sha1, "sha256": _proc_sha256,
    "reverse": _proc_reverse,
    "length": _proc_length, "strip": _proc_strip, "sql-quote": _proc_sql_quote,
}


# Arg-accepting processors: ``name:arg`` syntax inside the processors chain.
def _proc_prefix(s: str, arg: str) -> str: return arg + s
def _proc_suffix(s: str, arg: str) -> str: return s + arg
def _proc_repeat(s: str, arg: str) -> str:
    try:
        n = int(arg)
    except ValueError:
        return s
    n = max(0, min(n, 10_000))
    return s * n


ARG_PROCESSORS: dict[str, Callable[[str, str], str]] = {
    "prefix": _proc_prefix,
    "suffix": _proc_suffix,
    "repeat": _proc_repeat,
}


def processor_names() -> list[str]:
    """All names the UI should display, including ``arg:`` forms."""
    out = [n for n in PROCESSORS if n != "none"]
    out.extend(f"{n}:<arg>" for n in ARG_PROCESSORS)
    return out


def apply_processors(value: str, processors: list[str]) -> str:
    out = value
    for spec in processors:
        if ":" in spec:
            name, arg = spec.split(":", 1)
            fn_arg = ARG_PROCESSORS.get(name)
            if fn_arg is not None:
                out = fn_arg(out, arg)
                continue
        fn = PROCESSORS.get(spec)
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

COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "demo",
    "operator", "support", "sysadmin", "webmaster", "info", "tomcat",
    "manager", "oracle", "postgres", "mysql", "ubuntu", "ec2-user",
    "azureuser", "vagrant", "service", "deploy", "git",
]

# Small reference set of LFI traversal probes. Intentionally short — operators
# layer their own wordlists on top via the file source.
LFI_PATHS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
    "../boot.ini", "../../boot.ini", "../../../boot.ini",
    "../windows/win.ini", "../../windows/win.ini",
    "/etc/passwd", "/etc/shadow", "/proc/self/environ",
    "C:\\windows\\win.ini", "C:\\boot.ini",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "<a href=javascript:alert(1)>x</a>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<svg><script>alert&#40;1&#41;</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "'", "\"", "''", "\"\"",
    "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 1=1#",
    "') OR ('1'='1", "admin'--", "admin'#", "admin'/*",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=1", "1 AND 1=2", "1' AND SLEEP(5)--",
    "' OR SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
]

SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "admin", "test", "dev", "stage",
    "staging", "api", "api-dev", "vpn", "remote", "ssh", "ns1", "ns2",
    "smtp", "pop", "imap", "blog", "shop", "store", "cdn", "static",
    "assets", "media", "img", "images", "video", "portal", "intranet",
    "internal", "secure", "auth", "sso", "files", "uploads", "git",
    "gitlab", "jenkins", "ci", "build", "monitor", "grafana", "kibana",
    "elk", "redis", "db", "mysql", "postgres",
]

WORDLISTS: dict[str, list[str]] = {
    "common_passwords": COMMON_PASSWORDS,
    "common_usernames": COMMON_USERNAMES,
    "lfi_paths": LFI_PATHS,
    "xss_payloads": XSS_PAYLOADS,
    "sqli_payloads": SQLI_PAYLOADS,
    "subdomains": SUBDOMAINS,
}


def wordlist_names() -> list[str]:
    return sorted(WORDLISTS.keys())


def load_wordlist_file(path: str, *, max_bytes: int = 5 * 1024 * 1024,
                        max_lines: int = 100_000) -> list[str]:
    """Read ``path`` as a UTF-8 text wordlist; one entry per line.

    Raises ``ValueError`` if the file is missing, too large, or yields more
    than ``max_lines`` entries. Blank lines and ``# comment`` lines are dropped.
    """
    import os
    if not path or not os.path.isfile(path):
        raise ValueError(f"Wordlist file not found: {path!r}")
    size = os.path.getsize(path)
    if size > max_bytes:
        raise ValueError(
            f"Wordlist too large ({size} bytes > {max_bytes}); split it.")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise ValueError(f"Cannot read wordlist: {exc}") from exc
    return _parse_wordlist_text(text, max_lines=max_lines)


def load_wordlist_bytes(data: bytes, *, max_bytes: int = 5 * 1024 * 1024,
                         max_lines: int = 100_000) -> list[str]:
    """Parse an in-memory wordlist (e.g. a multipart upload).

    Same caps and stripping rules as :func:`load_wordlist_file` — exists so
    the web UI can accept a real ``<input type="file">`` upload without
    having to write the bytes to disk first.
    """
    if not data:
        raise ValueError("Wordlist file is empty.")
    if len(data) > max_bytes:
        raise ValueError(
            f"Wordlist too large ({len(data)} bytes > {max_bytes}); split it.")
    text = data.decode("utf-8", errors="replace")
    return _parse_wordlist_text(text, max_lines=max_lines)


def _parse_wordlist_text(text: str, *, max_lines: int) -> list[str]:
    out: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        s = line.rstrip("\r")
        if not s or s.lstrip().startswith("#"):
            continue
        out.append(s)
        if len(out) > max_lines:
            raise ValueError(
                f"Wordlist exceeds {max_lines} lines; trim or raise the cap.")
    return out


# ---------- attack scheduling ----------

# A payload source is a zero-arg factory that returns a fresh iterator over
# the payload strings. Factories — not lists, not pre-built iterators — are
# the unit of the streaming API: cluster bomb needs to re-walk inner sources
# once per outer iteration, which only works if it can ask for a brand new
# iterator each time. ``from_list`` / ``from_path`` / ``from_bytes`` are the
# three built-in adapters; plugins can supply their own.
PayloadSource = Callable[[], Iterator[str]]


def from_list(values: Sequence[str]) -> PayloadSource:
    """Replayable factory over an in-memory sequence."""
    items = list(values)
    return lambda: iter(items)


def from_bytes(data: bytes, *, max_lines: int | None = None) -> PayloadSource:
    """Parse ``data`` once and yield each entry on every call.

    Use this when the payloads are already in RAM (small uploads, test
    fixtures). For multi-megabyte files prefer :func:`from_path` so the
    contents stream from disk and never materialise.
    """
    text = data.decode("utf-8", errors="replace")
    items = _parse_wordlist_text(
        text, max_lines=max_lines if max_lines is not None else 10**9,
    )
    return lambda: iter(items)


def from_path(path: str | Path) -> PayloadSource:
    """Stream a wordlist from disk on every call — uncapped, O(1) RAM.

    The file is opened fresh each time the factory is invoked, so cluster
    bomb's nested loops can re-walk it without holding the contents in
    memory. Blank lines and ``# comment`` lines are skipped, matching
    :func:`load_wordlist_file` semantics. Encoding errors are replaced
    rather than raised so a single bad byte never aborts an attack.
    """
    p = str(path)

    def _gen() -> Iterator[str]:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.rstrip("\r\n")
                if not line or line.lstrip().startswith("#"):
                    continue
                yield line
    return _gen


def count_wordlist_lines(path: str | Path) -> int:
    """One-pass count of non-blank, non-comment lines.

    Used at attack-create time so the progress UI can show ``N / total``
    even though the source is streamed. Cost: ~300 ms per 100 MB on a
    typical SSD; trivial next to the network cost of the attack itself.
    """
    n = 0
    with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")
            if line and not line.lstrip().startswith("#"):
                n += 1
    return n


def iterate_streaming(attack_type: str, sources: Sequence[PayloadSource],
                       n_positions: int) -> Iterator[list[str]]:
    """Yield one payload-tuple per request, streaming every source.

    The four attack types all run in constant memory regardless of source
    size: sniper / battering walk one source once, pitchfork uses ``zip``
    (lazy, stops at the shortest source naturally), and cluster bomb walks
    the sources via nested loops that re-invoke the inner factories. The
    classic ``itertools.product`` would materialise its arguments into
    tuples up front — fine for ``[[a,b],[1,2]]``, fatal for rockyou.
    """
    if not sources:
        return
    if attack_type == "sniper":
        for pos in range(n_positions):
            for p in sources[0]():
                row = [""] * n_positions
                row[pos] = p
                yield row
    elif attack_type == "battering":
        for p in sources[0]():
            yield [p] * n_positions
    elif attack_type == "pitchfork":
        iters = [s() for s in sources]
        for combo in zip(*iters):
            yield list(combo)
    elif attack_type == "clusterbomb":
        yield from _clusterbomb(list(sources), [])
    else:
        raise ValueError(f"unknown attack type: {attack_type}")


def _clusterbomb(sources: list[PayloadSource], prefix: list[str]) -> Iterator[list[str]]:
    if not sources:
        yield list(prefix)
        return
    head, rest = sources[0], sources[1:]
    for value in head():
        yield from _clusterbomb(rest, prefix + [value])


def iterate(attack_type: str, payload_sets: list[list[str]],
             n_positions: int) -> Iterator[list[str]]:
    """Legacy materialised entry: wraps each set in ``from_list`` and
    delegates to :func:`iterate_streaming`. Existing CLI / spec / test
    callers keep working unchanged; new code should call the streaming
    function directly with the factory adapters.
    """
    return iterate_streaming(
        attack_type, [from_list(s) for s in payload_sets], n_positions,
    )


def build_sources_from_storage(stored: Sequence) -> list[PayloadSource]:
    """Reconstruct payload-source factories from the attack's stored JSON.

    Storage shape per entry:
      * ``list[str]`` — inline values (text / numbers / brute / built-in /
        upload). Loaded into RAM at attack-create time.
      * ``{"kind": "path", "path": "<abs>"}`` — server-side file streamed
        from disk on every iteration. No memory cost.

    Anything else is a malformed record from a future Reqlore version;
    reject loudly so the attack errors instead of silently emitting empty
    payloads.
    """
    out: list[PayloadSource] = []
    for entry in stored:
        if isinstance(entry, list):
            out.append(from_list(entry))
        elif isinstance(entry, dict) and entry.get("kind") == "path":
            path = entry.get("path") or ""
            if not path:
                raise ValueError("Path payload source missing 'path' field.")
            out.append(from_path(path))
        else:
            raise ValueError(f"Unknown payload source entry: {entry!r}")
    return out


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
    # Payload substitution changes the body length, so any Content-Length
    # the operator pasted in from history is now stale. Two engines
    # (httpx, raw) trust user-supplied CL and would raise / send a
    # malformed frame; the other two (curl-cffi, h3) strip and re-add it.
    # Dropping it here normalises the behaviour: every engine recomputes
    # CL from the actual body bytes. Same logic for Transfer-Encoding --
    # it can conflict with CL and the framework owns body framing now,
    # not the template. Operators who deliberately want a stale CL (CL.TE
    # smuggling research) can use the smuggling tool or hand-craft via
    # match-replace on the raw engine.
    headers = [
        (k, v) for k, v in headers
        if k.lower() not in ("content-length", "transfer-encoding")
    ]
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

def grep_extract(text: bytes, patterns: list[str]) -> tuple[str, bool]:
    """Run each pattern against the response body.

    Returns ``(joined_hits, matched_any)``.

    Pattern syntax:
      - ``<regex>``                 — first match, capped at 120 chars.
      - ``=count:<regex>``          — number of matches (``findall``).
      - ``=all:<regex>``            — every match, separated by ``;``, capped at 240 chars.
    Empty / invalid patterns are skipped silently.
    """
    hits: list[str] = []
    matched = False
    s = text.decode("latin-1", errors="replace")
    for pat in patterns:
        if not pat:
            continue
        mode = "first"
        expr = pat
        if pat.startswith("=count:"):
            mode, expr = "count", pat[len("=count:"):]
        elif pat.startswith("=all:"):
            mode, expr = "all", pat[len("=all:"):]
        if not expr:
            continue
        try:
            if mode == "count":
                n = len(re.findall(expr, s))
                if n > 0:
                    matched = True
                    hits.append(f"{n}\u00d7{expr[:40]}")
            elif mode == "all":
                ms = re.findall(expr, s)
                if ms:
                    matched = True
                    joined = ";".join(str(m)[:60] for m in ms)
                    hits.append(joined[:240])
            else:
                m = re.search(expr, s)
                if m:
                    matched = True
                    hits.append(m.group(0)[:120])
        except re.error:
            continue
    return " | ".join(hits), matched


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
    retries: int = 0
    stop_on_match: bool = False
    stop_on_status: list[int] = field(default_factory=list)
    emit_findings: bool = True


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
        self.total_jobs: int = 0
        self.stop_reason: str = ""
        # Worker-thread errors (job seq -> "ExcClass: message"). Surfaced
        # via the final attack status so a transient engine failure does
        # not leave the attack stuck in 'running' forever.
        self.errors: dict[int, str] = {}

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.set()

    def pause(self) -> None:
        self._pause.clear()
        try:
            self.project.set_intruder_status(self.attack_id, "paused")
        except Exception:
            pass

    def resume(self) -> None:
        self._pause.set()
        try:
            self.project.set_intruder_status(self.attack_id, "running")
        except Exception:
            pass

    def is_paused(self) -> bool:
        return not self._pause.is_set() and not self._cancel.is_set()

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
                retries=max(0, int(opts_raw.get("retries", 0))),
                stop_on_match=bool(opts_raw.get("stop_on_match", False)),
                stop_on_status=[int(s) for s in opts_raw.get("stop_on_status", [])],
                emit_findings=bool(opts_raw.get("emit_findings", True)),
            )
            stop_codes = set(options.stop_on_status)

            template = attack["template"]
            positions = [tuple(p) for p in attack["positions"]]
            payload_sets = attack["payloads"]
            engine = attack["engine"]
            base_url = attack["url"]
            atype = attack["attack_type"]

            # Build streaming factories from storage entries so a server-
            # path source is opened fresh on each pass and never resident
            # in RAM. Inline lists round-trip through ``from_list`` for
            # uniformity with the path case.
            try:
                sources = build_sources_from_storage(payload_sets)
            except ValueError as exc:
                self.stop_reason = f"bad payload source: {exc}"
                self.project.set_intruder_status(self.attack_id, "errored")
                return

            jobs: list[_Job] = []
            for seq, combo in enumerate(
                iterate_streaming(atype, sources, len(positions))
            ):
                if seq >= options.max_requests:
                    break
                processed = [apply_processors(p, options.processors) for p in combo]
                jobs.append(_Job(seq=seq, payloads=processed))
            self.total_jobs = len(jobs)

            send = _send_factory(engine, options)

            def _send_with_retries(req: Request) -> Response:
                """Retry on send exception up to ``options.retries`` extra attempts."""
                attempts = options.retries + 1
                last_exc: Exception | None = None
                for i in range(attempts):
                    if self._cancel.is_set():
                        raise RuntimeError("cancelled")
                    try:
                        return send(req)
                    except Exception as exc:  # noqa: BLE001 — engine-agnostic
                        last_exc = exc
                        if i + 1 >= attempts:
                            break
                        if options.delay_ms:
                            time.sleep(options.delay_ms / 1000.0)
                raise last_exc if last_exc else RuntimeError("send failed")

            def _do(job: _Job):
                # The body is wrapped so engine / storage / processor
                # failures do not silently kill the worker thread (which
                # would leave the attack stuck in 'running' with no new
                # results and no error reported to the operator).
                try:
                    return _do_inner(job)
                except Exception as exc:  # noqa: BLE001 - intentional safety net
                    self.errors[job.seq] = f"{exc.__class__.__name__}: {exc}"
                    return None

            def _do_inner(job: _Job):
                self._pause.wait()
                if self._cancel.is_set():
                    return None
                rendered = apply_payloads(template, positions, job.payloads)
                req = template_to_request(rendered, base_url)
                t0 = time.monotonic()
                resp = _send_with_retries(req)
                dur = int((time.monotonic() - t0) * 1000)
                if self._cancel.is_set():
                    return None
                grep_hits, grep_matched = grep_extract(resp.body or b"", options.grep)
                raw_req = resp.raw_request or rendered
                raw_resp = _serialise_response(resp)
                body_md5 = hashlib.md5(resp.body or b"").hexdigest()
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
                    body_md5=body_md5, matched=grep_matched,
                )
                if options.emit_findings and grep_matched:
                    _emit_intruder_finding(
                        self.project, attack_id=self.attack_id, seq=job.seq,
                        host=host, url=req.url, payloads=job.payloads,
                        status=resp.status, grep_hits=grep_hits,
                        history_id=hid,
                        raw_req=raw_req, raw_resp=raw_resp,
                        elapsed_ms=resp.timings.total_ms or dur,
                    )
                if options.stop_on_match and grep_matched:
                    self.stop_reason = f"grep match on seq #{job.seq}"
                    self._cancel.set()
                elif stop_codes and resp.status in stop_codes:
                    self.stop_reason = f"status {resp.status} on seq #{job.seq}"
                    self._cancel.set()
                if options.delay_ms:
                    time.sleep(options.delay_ms / 1000.0)
                return job.seq

            with ThreadPoolExecutor(max_workers=options.concurrency) as ex:
                futures = {ex.submit(_do, j): j for j in jobs}
                for fut in as_completed(futures):
                    # Drain any exception that escaped _do's wrapper so
                    # the future doesn't carry it silently to GC.
                    try:
                        fut.result()
                    except Exception as exc:  # noqa: BLE001
                        job = futures[fut]
                        self.errors[job.seq] = (
                            f"{exc.__class__.__name__}: {exc}"
                        )
                    if self._cancel.is_set():
                        for f in futures:
                            f.cancel()
                        break

            if self._cancel.is_set():
                # Cancel set internally by stop-on-match/status becomes a
                # 'done' terminal state; operator-initiated cancel stays 'cancelled'.
                final = "done" if self.stop_reason else "cancelled"
            else:
                final = "done"
            # If every job errored out we surface that distinctly so the
            # operator notices instead of seeing an empty 'done' attack.
            if self.errors and len(self.errors) >= len(jobs) and not self.stop_reason:
                final = "errored"
                first_seq = next(iter(self.errors))
                self.stop_reason = (
                    f"all {len(jobs)} requests failed; first error "
                    f"at seq #{first_seq}: {self.errors[first_seq]}"
                )
            self.project.set_intruder_status(self.attack_id, final)
        finally:
            self._done.set()


def _emit_intruder_finding(project, *, attack_id: int, seq: int, host: str,
                             url: str, payloads: list[str], status: int,
                             grep_hits: str, history_id: int,
                             raw_req: bytes, raw_resp: bytes,
                             elapsed_ms: int) -> None:
    """Promote an Intruder grep-match into a Finding via the write bus."""
    from .findings_bus import record_finding
    payload_str = " | ".join(payloads)
    evidence = (
        f"Intruder attack #{attack_id}, request seq #{seq} matched "
        f"grep expression. Status {status}. Hits: {grep_hits}"
    )
    record_finding(
        project, source="intruder", rule_id="intruder:grep",
        severity="medium",
        title="Intruder grep match",
        description=(
            "An Intruder attack response matched an operator-specified grep "
            "expression. Grep matches typically flag injection success "
            "indicators (error strings, success markers, reflected payloads)."
        ),
        remediation=(
            "Review the matched request in the Intruder results to confirm "
            "the underlying weakness; if confirmed, fix the input handling "
            "for the targeted parameter and re-test."
        ),
        host=host, url=url, request_id=history_id,
        evidence=evidence, payload=payload_str,
        reproduction=(raw_req, raw_resp, "INTRUDER", url, int(status),
                      int(elapsed_ms)),
    )


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

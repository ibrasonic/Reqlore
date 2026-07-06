"""Out-of-Band Application Security Testing (OAST) helpers.

Two modes:

* **Local receiver** — an HTTP-only callback server running in-process on
  a high port (127.0.0.1 by default). Each generated token includes a
  short random ID; any request whose path starts with /``id``/ is logged
  as an "interaction". No DNS — out of scope for an a11y desktop tool.

* **Interactsh client** — a stateless client that pings a remote
  interactsh-style server's polling endpoint and merges interactions into
  the same store. Optional: requires the ``oast`` extra (httpx already
  on the core deps does the work). Disabled by default; opt-in per Hard
  rule 6.

Storage: interactions live in memory only — they are ephemeral by
nature. Each entry is a dict with ts (epoch ms), token, kind ("http"),
remote address, method, path, headers, body (b64 if non-text), bytes.
"""
from __future__ import annotations

import base64
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class Interaction:
    ts_ms: int
    token: str
    kind: str        # "http"
    remote: str
    method: str
    path: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""              # decoded UTF-8 if possible, else b64
    body_is_b64: bool = False
    bytes_in: int = 0


@dataclass
class OASTStatus:
    running: bool
    host: str
    port: int
    base_url: str
    tokens: list[str]


class LocalOAST:
    """Thread-safe local HTTP callback receiver."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._interactions: list[Interaction] = []
        self._tokens: set[str] = set()

    # ---- lifecycle ----
    def start(self) -> int:
        with self._lock:
            if self._server:
                return self.port
            handler = _make_handler(self)
            self._server = ThreadingHTTPServer((self.host, self.port), handler)
            self.port = self._server.server_address[1]
            self._thread = threading.Thread(
                target=self._server.serve_forever, name="reqlore-oast",
                daemon=True,
            )
            self._thread.start()
            return self.port

    def stop(self) -> None:
        with self._lock:
            if not self._server:
                return
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None

    def is_running(self) -> bool:
        with self._lock:
            return self._server is not None

    # ---- tokens ----
    def new_token(self) -> str:
        # 12 lowercase chars are enough for uniqueness here; OAST tokens
        # are not security boundaries.
        tok = secrets.token_hex(6)
        with self._lock:
            self._tokens.add(tok)
        return tok

    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def url_for(self, token: str) -> str:
        return f"{self.base_url()}/{token}/"

    def status(self) -> OASTStatus:
        with self._lock:
            return OASTStatus(
                running=self._server is not None,
                host=self.host, port=self.port,
                base_url=self.base_url(),
                tokens=sorted(self._tokens),
            )

    # ---- interactions ----
    def record(self, ix: Interaction) -> None:
        with self._lock:
            self._interactions.append(ix)
            # Bound the in-memory log so a noisy attacker can't OOM us.
            if len(self._interactions) > 5000:
                self._interactions = self._interactions[-5000:]

    def interactions(self, token: str | None = None) -> list[Interaction]:
        with self._lock:
            data = list(self._interactions)
        if token:
            data = [i for i in data if i.token == token]
        return list(reversed(data))   # newest first

    def clear(self) -> None:
        with self._lock:
            self._interactions.clear()


def _make_handler(oast: LocalOAST):
    class _H(BaseHTTPRequestHandler):
        # Silence the default stderr logging — we record everything ourselves.
        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            return

        def _record(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length) if length else b""
            try:
                body_text = body.decode("utf-8")
                b64 = False
            except UnicodeDecodeError:
                body_text = base64.b64encode(body).decode()
                b64 = True
            # Token = first path segment if known, else literal "_"
            segs = [s for s in self.path.split("/") if s]
            token = segs[0] if segs and segs[0] in oast._tokens else "_"
            ix = Interaction(
                ts_ms=int(time.time() * 1000),
                token=token, kind="http",
                remote=self.client_address[0],
                method=self.command, path=self.path,
                headers=[(k, v) for k, v in self.headers.items()],
                body=body_text, body_is_b64=b64, bytes_in=length,
            )
            oast.record(ix)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Reqlore-OAST", "1")
            self.end_headers()
            self.wfile.write(b"ok\n")

        def do_GET(self): self._record()
        def do_POST(self): self._record()
        def do_PUT(self): self._record()
        def do_DELETE(self): self._record()
        def do_PATCH(self): self._record()
        def do_HEAD(self):
            self._record()

    return _H


# ---- Interactsh client (optional, opt-in) ----

def interactsh_poll(server_url: str, correlation_id: str, secret: str,
                    *, timeout: float = 5.0) -> list[dict]:
    """Poll a remote interactsh-style server. Returns list of decoded events.

    The server is expected to return JSON ``{"data": ["<b64-encrypted>"], ...}``.
    Decryption uses RSA-OAEP-SHA256 over the per-correlation private key —
    that lives elsewhere; we return the raw envelopes so the caller can
    decode them with PyJWT/cryptography if it wants.
    """
    import httpx
    url = f"{server_url.rstrip('/')}/poll?id={correlation_id}&secret={secret}"
    try:
        r = httpx.get(url, timeout=timeout)
        if r.status_code != 200:
            return [{"_error": f"poll returned {r.status_code}"}]
        payload = r.json()
        return payload.get("data", []) or []
    except Exception as exc:  # network errors must not crash the UI
        return [{"_error": str(exc)}]


def record_oast_interactions(project, interactions: list[Interaction], *,
                              probe_url: str, probe_host: str = "",
                              request_id: int | None = None,
                              probe_kind: str = "ssrf") -> list[int]:
    """Promote OAST callback interactions into findings.

    ``probe_kind`` controls the rule_id and template — ``ssrf`` for typical
    server-side-request-forgery probes, ``xxe`` for XML out-of-band, ``log4j``
    for JNDI lookups, etc. Returns the list of created finding ids.
    """
    if not interactions:
        return []
    from .findings_bus import record_finding
    rule_map = {
        "ssrf":   ("oast:ssrf-callback",    "high",     "CWE-918"),
        "xxe":    ("oast:xxe-callback",     "high",     "CWE-611"),
        "log4j":  ("oast:jndi-callback",    "critical", "CWE-94"),
        "rce":    ("oast:rce-callback",     "critical", "CWE-78"),
        "blind":  ("oast:blind-interaction","medium",   "CWE-918"),
    }
    rule_id, severity, cwe = rule_map.get(probe_kind, rule_map["blind"])
    out: list[int] = []
    for ix in interactions:
        evidence = (
            f"OAST {ix.kind} hit from {ix.remote} at {ix.method} {ix.path} "
            f"({ix.bytes_in} bytes; token={ix.token})"
        )
        fid = record_finding(
            project, source="oast", rule_id=rule_id, severity=severity,
            title=f"Out-of-band interaction ({probe_kind.upper()})",
            description=(
                "The target made an out-of-band callback to the OAST "
                "listener after the probe was sent. OAST hits are very "
                "high-fidelity evidence that the input was processed in a "
                "context that performs network/file/JNDI lookups."
            ),
            remediation=(
                "Validate / canonicalise user-controlled URLs and file "
                "paths, disable JNDI lookups in log frameworks, and "
                "deny outbound traffic from server contexts that should "
                "not be making external calls."
            ),
            cwe=cwe, owasp="A10:2021-Server-Side Request Forgery",
            host=probe_host, url=probe_url, request_id=request_id,
            evidence=evidence,
        )
        if fid is not None:
            out.append(fid)
    return out

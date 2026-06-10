# Engines

Reqlore ships **four** request transports, exposed under one
`Request` / `Response` dataclass shape. Each is selected per-attack in
[Intruder](modules/intruder.md), per-request in [Repeater](modules/repeater.md),
or implicitly by the [Proxy](modules/proxy.md) (always `mitmproxy`)
and [Macros](modules/macros.md) / [GraphQL](modules/graphql.md) /
[WebSocket](modules/websocket.md) (always `httpx`).

| Engine                    | Use it for                                                  | Extras                       |
|---------------------------|-------------------------------------------------------------|------------------------------|
| `httpx`                   | The everyday default. HTTP/1.1 + HTTP/2, redirects, proxies. | (core dep)                   |
| `raw`                     | Byte-exact wire bytes: smuggling, header obfuscation, fuzz.  | (core dep)                   |
| `h3`                      | HTTP/3 over QUIC. Single-shot async.                         | `pip install reqlore[h3]`    |
| `curl-cffi:<profile>`     | JA3 / JA4 TLS fingerprint impersonation.                     | `pip install reqlore[impersonate]` |

Plus one **non-transport helper**:

- `curl_render(Request) → str` — produces a shell-ready `curl` command
  line from a Request, without executing it. Useful for reports and
  reproducers.

## Unified `Request` / `Response`

Defined in `reqlore/engines/__init__.py`:

```python
@dataclass
class Request:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes = b""
    http_version: str = "1.1"   # "1.0" | "1.1" | "2" | "3"
    extras: dict[str, Any] = field(default_factory=dict)

    def header(name: str) -> str | None
    def with_header(name: str, value: str) -> Request

@dataclass
class Response:
    status: int
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "1.1"
    timings: Timings = field(default_factory=Timings)   # dns/connect/tls/ttfb/total ms
    engine: str = ""
    raw_request: bytes | None = None
    error: str | None = None
```

`Response.error` is non-`None` whenever a transport refused to send
(missing extra, connection error, timeout, validation failure). Always
check it before reading `status`.

## Engine 1 — `httpx` (default)

`reqlore/engines/httpx_engine.py`.

- HTTP/1.1 by default; HTTP/2 when `req.http_version == "2"` (delegates to httpx's `http2=True`).
- Headers are normalised — case insensitive, deduplicated. `Transfer-Encoding` / `Content-Length` are normalised by httpx, which means **httpx is the wrong engine for smuggling**.
- Redirects: **off by default** (`follow_redirects=False`). Configurable per call.
- Default timeout: **30 s**.
- Decompresses `gzip` / `deflate` / `br` automatically.

When to reach for it: every "normal" request — workbench [Repeater](modules/repeater.md) traffic, [Macros](modules/macros.md), [Scanner](modules/scanner.md) probes, [GraphQL](modules/graphql.md) / [WebSocket](modules/websocket.md) workbenches.

## Engine 2 — `raw` (byte-exact)

`reqlore/engines/raw_engine.py`.

- Builds the request bytes manually and writes them over a stdlib `socket` (`ssl` for TLS). What you put in `headers` is what goes on the wire — same case, same order.
- HTTP versions: `1.0` and `1.1`.
- No automatic redirects.
- No automatic decompression (caller decodes if needed). Has a `_dechunk()` helper for chunked-transfer responses.
- TLS verification is binary (`verify=True/False`).
- `Response.raw_request` carries the exact bytes that were sent.
- Default timeout: **30 s**.

When to reach for it: [Smuggling](modules/smuggling.md), header obfuscation, Transfer-Encoding fuzz, anywhere normalisation breaks the attack.

## Engine 3 — `h3` (HTTP/3 / QUIC)

`reqlore/engines/h3_engine.py`. Optional — install with
`pip install reqlore[h3]` (pulls `aioquic >= 1.0`).

- HTTP/3 only.
- Synchronous wrapper around `asyncio.run()`. Suitable for single
  isolated requests — not a long-lived connection.
- Headers use HTTP/2 pseudo-headers (`:method`, `:scheme`,
  `:authority`, `:path`); `Host` / `Connection` / `TE` are filtered.
- No redirects.
- Default timeout: **15 s**.
- If `aioquic` isn't installed, `send()` returns `Response(status=0, error="…")` — a clear, programmatic signal rather than an import-time crash.

`H3_AVAILABLE` boolean (module-level) reflects the install state.

When to reach for it: targets that serve HTTP/3 only (or behave
differently on QUIC vs TCP), QUIC-layer fuzz.

## Engine 4 — `curl-cffi:<profile>` (TLS impersonation)

`reqlore/engines/curl_cffi_engine.py`. Optional — install with
`pip install reqlore[impersonate]` (pulls `curl-cffi >= 0.7`).

Supported profiles (full string ID is `curl-cffi:<profile>`):

| Profile        | Browser              |
|----------------|----------------------|
| `chrome120`    | Chrome 120 (default) |
| `chrome119`    | Chrome 119           |
| `chrome116`    | Chrome 116           |
| `chrome110`    | Chrome 110           |
| `safari17_0`   | Safari 17.0          |
| `safari15_5`   | Safari 15.5          |
| `firefox109`   | Firefox 109          |
| `firefox102`   | Firefox 102          |

Source of truth: `SUPPORTED_PROFILES` in `reqlore/engines/curl_cffi_engine.py`.

- Backed by libcurl + BoringSSL. JA3 / JA4 TLS fingerprint matches the
  impersonated browser.
- HTTP/1.1 and HTTP/2.
- Headers are normalised (case-insensitive dict). `Host` /
  `Content-Length` / `Connection` are filtered before send.
- Redirects: **off by default**; configurable via the caller.
- Default timeout: **15 s**.
- If `curl-cffi` isn't installed, `send()` returns `Response(status=0, error="…install reqlore[impersonate]")`.

`CFFI_AVAILABLE` boolean (module-level) reflects the install state.

When to reach for it: WAFs that fingerprint by TLS / HTTP-stack (Cloudflare, Akamai, F5, Imperva). httpx and Python's TLS stack are easy to spot; the impersonation profile blends in.

## The `curl_render` helper

`reqlore/engines/curl_render.py` is **not** a sendable engine — it's a
one-function helper:

```python
from reqlore.engines.curl_render import curl_render
print(curl_render(req))
# curl --http1.1 -X POST 'https://target.example/api' -H 'X-Foo: 1' --data-raw '...'
```

Useful in reports (paste the curl line as a reproducer) and in
accessibility paths (screen-reader-safe). Delegates to `reqlore.a11y.render_curl()`.

## How engines are selected

| Surface                                     | Engine                             | Where it's wired                                  |
|---------------------------------------------|------------------------------------|---------------------------------------------------|
| [Intruder](modules/intruder.md)             | Per-attack — operator picks        | `_send_factory(engine, opts)` in `reqlore/intruder.py` |
| [Repeater](modules/repeater.md)             | Per-request — dropdown in the form | Repeater blueprint                                |
| [Proxy](modules/proxy.md) intercept replay  | `httpx` (forward-edited) or raw byte forward (mitmproxy native) | `reqlore/proxy/mitm.py`                           |
| [Macros](modules/macros.md)                 | `httpx` (fixed)                    | `reqlore/macros.py`                               |
| [Scanner](modules/scanner.md) probes        | `httpx` (fixed)                    | `reqlore/scanner/active.py`                       |
| [GraphQL](modules/graphql.md) workbench     | `httpx` (fixed, 15 s timeout)      | `reqlore/graphql.py`                              |
| [WebSocket](modules/websocket.md) workbench | `websockets` lib (separate)        | `reqlore/websocket.py`                            |
| [Runner / Scheduler](modules/scheduler.md)  | `httpx` (fixed)                    | `reqlore/runner.py`                               |

## Capabilities matrix

| Capability                       | `httpx` | `raw` | `h3` | `curl-cffi` |
|----------------------------------|:-------:|:-----:|:----:|:-----------:|
| HTTP/1.1                         | ✔       | ✔     |      | ✔           |
| HTTP/2                           | ✔       |       |      | ✔           |
| HTTP/3                           |         |       | ✔    |             |
| TLS impersonation (JA3 / JA4)    |         |       |      | ✔           |
| Byte-exact wire control          |         | ✔     |      |             |
| Automatic gzip / br decompression| ✔       |       |      | ✔           |
| Redirect-following (optional)    | ✔       |       |      | ✔           |
| Smuggling-safe                   |         | ✔     |      |             |
| Suitable for `Transfer-Encoding` obfuscation |  | ✔ |   |             |
| Default timeout (s)              | 30      | 30    | 15   | 15          |

## Recipes

### "Why is my smuggling payload not working?"

You're sending it via `httpx`. Switch the engine to `raw` and re-send.
See [Smuggling](modules/smuggling.md) for the full story.

### "Cloudflare is blocking my Python scan"

Switch the [Intruder](modules/intruder.md) engine to
`curl-cffi:chrome120`. Make sure the `impersonate` extra is installed.

### "I need a curl one-liner for the report"

```python
from reqlore.engines.curl_render import curl_render
curl_cmd = curl_render(my_request)
```

Paste into the report.

### "Confirm an HTTP/3-only target"

Install the extra: `pip install reqlore[h3]`. Switch
[Repeater](modules/repeater.md) to `h3`. If it returns `Response(status=0, error=…)`, `aioquic` isn't installed or the target isn't QUIC-capable.

### "I want byte-exact preservation of the Cookie header order"

`raw`. `httpx` and `curl-cffi` both sort / normalise.

## Troubleshooting

| Symptom                                              | Cause                                                                  | Fix                                                                                              |
|------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `Response(status=0, error="aioquic …")`              | `[h3]` extra missing                                                   | `pip install reqlore[h3]`.                                                                       |
| `Response(status=0, error="curl_cffi …")`            | `[impersonate]` extra missing                                          | `pip install reqlore[impersonate]`.                                                              |
| `Transfer-Encoding: chunked` header dropped          | `httpx` / `curl-cffi` normalised it                                    | Use `raw`.                                                                                       |
| Got HTML instead of expected JSON, no redirect       | Default is `follow_redirects=False`                                    | Enable redirect-following on the per-call options.                                               |
| Cloudflare 403 / "challenge" page                    | TLS fingerprint mismatch                                                | Switch to `curl-cffi:chrome120` or `firefox109`.                                                 |
| `Response.raw_request` is `None`                     | Not all engines populate it                                            | Only `raw` (and partially `httpx`) populate it.                                                  |

## Test contract

- `reqlore/tests/unit/test_engines_basics.py::test_request_dataclass_header_accessors` — `Request.header()` / `with_header()`.
- `…::test_curl_render_engine_returns_string` — `curl_render()` round-trip.
- `reqlore/tests/unit/test_optional_engines.py::test_h3_availability_flag_is_boolean`, `…test_h3_send_when_missing_returns_clear_error` — h3 graceful degradation.
- `…::test_curl_cffi_availability_flag_is_boolean`, `…test_curl_cffi_send_when_missing_returns_clear_error`, `…test_curl_cffi_supported_profiles_contains_chrome120` — curl-cffi graceful degradation.

# Request smuggling — `/smuggling/`

Generate raw HTTP/1.1 payloads for the three classic desync techniques:
**CL.TE**, **TE.CL**, **TE.TE**. Comes with a timing-based detection
helper. **Always send via the raw engine** — httpx and h3 normalise
away the very headers that make smuggling work.

## Where it is

- **URL:** `/smuggling/`
- **Nav:** *Smuggling* in the top bar.
- Single page; GET shows empty form, POST returns the payload.

## Quick start

1. Open `/smuggling/`. Paste a target URL
   (`https://target.example.com/path`).
2. Pick a **technique** (CL.TE / TE.CL / TE.TE).
3. Fill in **Smuggled method** (default `GET`) and **Smuggled path**
   (default `/admin`).
4. **Generate**. Raw bytes render in `<pre>`; notes explain what to
   look for.
5. Copy bytes into [Repeater](repeater.md), switch the engine to
   **raw**, and send. Or click **Download .bin** for use elsewhere.

## Routes

| URL              | Method | What it does                                                          |
|------------------|--------|-----------------------------------------------------------------------|
| `/smuggling/`    | GET    | Render the form.                                                       |
| `/smuggling/`    | POST   | Build payload. With `?download=1`, returns `.bin` attachment; else inline. |

## Form fields

| Field             | Type   | Default        | Notes                                                  |
|-------------------|--------|----------------|--------------------------------------------------------|
| `url`             | url    | empty (req.)   | Target URL.                                            |
| `technique`       | select | `cl.te`        | `cl.te` / `te.cl` / `te.te`.                            |
| `smuggled_method` | text   | `GET`          | Method of the hidden second request.                    |
| `smuggled_path`   | text   | `/admin`       | Path of the hidden second request.                      |

## Payload builders

### CL.TE

Front-end honours `Content-Length`, back-end honours
`Transfer-Encoding: chunked`. The outer request carries both headers.
Body:

```
0
<CRLF>
<smuggled_method> <smuggled_path> HTTP/1.1
Host: <host>
Content-Length: 10

x=
```

- Front-end sees a self-contained request (length matches).
- Back-end sees an empty chunked body (`0\r\n\r\n`), then parses the
  rest as a brand-new request.

### TE.CL

Front-end honours `Transfer-Encoding`, back-end honours
`Content-Length: 4`. The chunked body encodes the smuggled request;
the back-end stops reading at 4 bytes (the chunk-length prefix), the
rest is desynced.

### TE.TE

Both honour TE — but the proxy normalises the *first* header and the
back-end uses the *second* (or vice versa). The outer request has two
`Transfer-Encoding` headers:

- `Transfer-Encoding: chunked` (canonical).
- `Transfer-encoding : x` (space-before-colon, lowercase) — obfuscated.

One side strips/ignores the obfuscated variant; the disagreement
desyncs the connection.

## Detection helper

`detect(url, technique, sender, pause_ms_threshold=1500)`:

1. **Baseline** — `Request(method="GET", url=url)` via `sender`, measure ms.
2. **Probe** — full smuggling payload via `sender`, measure ms.
3. `delta_ms = probe_ms - baseline_ms`.
4. Returns `SmugglingTest(baseline_ms, probe_ms, delta_ms, likely_vulnerable, reason)`.
5. `likely_vulnerable = delta_ms >= pause_ms_threshold` (default 1500 ms).

A back-end waiting for body bytes that never arrive is the classic
smuggling-vulnerable signal. **Heuristic only** — network jitter, slow
backends, and edge caches can all skew timing. Confirm by replaying a
real second request and looking for cross-request response bleed.

## Accessibility notes

- Every field has `<label for="…">`.
- Output: `<h2>` for the payload title; notes as `<ul>` of `<li>`; raw
  bytes in `<pre>` (preserves CRLF).
- Errors render in the global flash region.

## How it integrates

**Producers / consumers:** none — output is raw bytes for manual ship.
The detection helper is a building block; no UI uses it today (it's
intended for plugin / script integration).

## Recipes

### Generate a CL.TE PoC for a login endpoint

URL: `https://target.example/login`, technique `cl.te`, smuggled
`GET /admin`. Generate → copy bytes → [Repeater](repeater.md) → switch
engine to **raw** → **Send**. Send another request immediately
afterwards on the same back-end; if you see `/admin` content in the
*second* response, you've confirmed a queued desync.

### TE.CL with custom smuggled body

URL `https://target.example/process`, technique `te.cl`, smuggled
`POST /api/admin/reset-password`. Ship via raw engine.

### Time-based detection with the helper

```python
from reqlore.smuggling import detect
from reqlore.engines import Request, Response

def sender(req: Request) -> Response:
    # Your raw-engine wrapper. Must return Response.
    ...

result = detect("https://target.example/login", "cl.te", sender)
if result.likely_vulnerable:
    print(f"Δ {result.delta_ms} ms — likely vulnerable")
```

### TE.TE obfuscation variants

The default obfuscation is `Transfer-encoding : x` (lowercase, leading
space before colon, value `x`). Hand-edit the downloaded bytes to try:

- `Transfer-Encoding: chunked` then `Transfer-Encoding:\tx` (tab).
- Doubled-key: two `Transfer-Encoding: chunked` lines.
- Mixed-case: `Transfer-Encoding: chunked` then `transfer-encoding: identity`.

### Confirm a hit via cross-request bleed

Generate CL.TE with `smuggled_path=/random-uuid-not-real`. Ship. Then
ship a normal GET to the same path on the same backend connection. If
the response is `404` from the smuggled request instead of the second
one, the queue got desynced.

## Storage footprint

**None.** No PRG cache (unlike H2). Form values are re-rendered into
the template on POST.

## CLI

No CLI. For scripted detection, import `reqlore.smuggling.detect()`.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Smuggling never works                                    | Sent via httpx / h3 — those normalise TE/CL                            | Switch to the **raw** engine in [Repeater](repeater.md).                                         |
| Detection helper flags clean targets                      | Network jitter or slow back-end                                         | Re-run multiple times; raise `pause_ms_threshold` to 3000 ms.                                    |
| Generated payload is rejected by the front-end             | Front-end has WAF / TE/CL validation                                    | Try TE.TE obfuscation, or accept that the target is hardened.                                    |
| Cannot edit CRLF in my editor                            | Some editors auto-convert to LF                                         | Use a hex editor or `printf` to preserve `\r\n`.                                                 |
| Off-by-one in chunked body                                | Chunk-length prefix must be valid hex; CRLF delimiters are sensitive    | Inspect the bytes in the `<pre>` output; copy verbatim.                                          |

## Test contract

`reqlore/tests/unit/test_smuggling.py`:

- `test_cl_te_payload_has_both_headers` — `Content-Length` + `Transfer-Encoding: chunked`; ends with `x=`.
- `test_te_cl_payload_carries_small_cl` — TE chunked + `Content-Length: 4`.
- `test_te_te_payload_obfuscates_second_te` — second header has `Transfer-encoding : x` (space-before-colon, lowercase).
- `test_smuggled_path_and_method_propagate` — custom method/path land in the payload bytes.
- `test_payload_registry_keys` — `PAYLOAD_BUILDERS.keys() == {"cl.te", "te.cl", "te.te"}`.
- `test_detect_flags_pause` — probe sleeps 1.6 s vs instant baseline → `likely_vulnerable=True`.
- `test_detect_quiet_baseline_does_not_flag` — both fast → `likely_vulnerable=False`.
- `test_detect_unknown_technique_returns_clean_error` — unknown technique → `reason="unknown technique"`.

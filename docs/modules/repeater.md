# Repeater — `/repeater/`

The Repeater is a one-request workbench. Load a request from anywhere
(History row, Proxy intercept, curl one-liner), edit any byte, send with
any of six engines, see the response inline, then iterate. Every send is
auto-saved to [History](history.md).

## Where it is

- **URL:** `/repeater/`
- **Nav:** *Repeater* in the top bar.
- **Single-request**, not tabbed — the form persists across reloads via the
  PRG redirect pattern (`?t=<token>`), but there is exactly one request
  loaded at a time.

## Quick start

1. From [History](history.md), pick a row → **Send to Repeater**.
2. Edit any header or body byte in the textarea.
3. Pick an engine (default `httpx`) and HTTP version (default `1.1`).
4. **Send** (or **Alt+S** if you bound it in your browser). Response renders inline.
5. Repeat. Each send is now its own history row tagged `repeater/<engine>`.

## Routes

| URL              | Method | What it does                                                                                |
|------------------|--------|---------------------------------------------------------------------------------------------|
| `/repeater/`     | GET    | Display the form (optionally pre-populated from `?from_history=<hid>`, `?from_curl=<…>`, or a `?t=<token>` cache hit). |
| `/repeater/`     | POST   | Run an action — `send`, `render`, `urlencode_body`, `urldecode_body`. PRG-redirects with a token. |

## Form fields

| Field   | Type     | Default | Notes                                                                                 |
|---------|----------|---------|---------------------------------------------------------------------------------------|
| Method  | text     | `GET`   | Free-form (not validated until submit).                                                |
| URL     | url      | empty   | Required. Used to build a `Host` header if missing.                                    |
| Engine  | select   | `httpx` | `httpx`, `raw`, `h3`, `curl-cffi:chrome120`, `curl-cffi:safari17_0`, `curl-cffi:firefox109`. |
| HTTP    | select   | `1.1`   | `1.1`, `1.0`, `2` (engine permitting).                                                  |
| Headers | textarea | empty   | One per line `Name: value`; lines starting with `#` ignored.                            |
| Body    | textarea | empty   | UTF-8 text. Empty by default.                                                           |

Buttons (all submit):

| Button             | `name="action"`     | Behaviour                                                                  |
|--------------------|---------------------|----------------------------------------------------------------------------|
| **Send**           | `send`              | Run the request through the selected engine, save to history, render.       |
| **Copy as…**       | `render`            | Re-render the right-hand pane with curl / httpx / requests / fetch / raw-HTTP snippets. |
| **URL-encode body**| `urlencode_body`    | `formnovalidate` — body-only transform; no network, no URL required.        |
| **URL-decode body**| `urldecode_body`    | `formnovalidate` — inverse of the above.                                    |

## Engines

| Engine                        | Notes                                                                                                                            |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `httpx`                       | Default. HTTP/1.1 and HTTP/2, mTLS, proxy support. Strips `Content-Length` + `Transfer-Encoding` before send.                     |
| `raw`                         | Byte-exact socket transmission. Preserves header casing, order, duplicates, your `Content-Length`. Auto-adds Host / Content-Length only if missing. Decodes chunked responses. Use for smuggling, header ordering, literal `../` paths. |
| `h3`                          | HTTP/3 / QUIC. Optional — `pip install reqlore[h3]` (aioquic). If missing, returns a synthetic `status=0` with a clear message. Forces HTTPS; ignores the HTTP dropdown. |
| `curl-cffi:chrome120`         | Optional — `pip install reqlore[impersonate]`. Spoofs Chrome 120's TLS ClientHello (JA3 / JA4). Strips Host / Content-Length / Connection.    |
| `curl-cffi:safari17_0`        | Same, Safari profile.                                                                                                            |
| `curl-cffi:firefox109`        | Same, Firefox profile.                                                                                                            |

When an optional engine isn't installed, the response renders inline as
`status=0` with the install command — no 500 page.

See [`../engines.md`](../engines.md) for a full engine comparison.

## Header normalization

For all engines **except `raw`**:

- `Content-Length` is stripped — the engine recomputes it from actual body bytes.
- `Transfer-Encoding` is stripped — the engine handles framing.

For `raw`:

- Every header is sent **exactly** as typed. Casing, order, duplicates,
  even contradictory `Content-Length` values — preserved. This is the
  point of `raw`.

If you want to test a deliberate `Content-Length` mismatch (request
smuggling), pick `raw`. Otherwise let the engine recompute.

## Body shortcuts (`urlencode_body` / `urldecode_body`)

These two buttons short-circuit before any network or URL validation:

- **Form-aware.** If the body looks form-shaped (`k=v&k2=v2`), only the
  values are encoded — `&` and the outer `=` stay structural. Non-form
  input is encoded as one opaque string.
- **No URL required.** Both buttons carry `formnovalidate`, so they work
  even when the URL field is empty.
- The transformed body PRG-redirects back into the form for further edits.

## Response display

Right pane:

- Status line: `HTTP/1.1 200 OK — 5.2 kB — 412 ms (ttfb 110 ms)`.
- **Headers** — single `<pre>` block, one header per line. Not a `<dl>` —
  screen readers wouldn't enjoy term-definition mode for 30 headers.
- **Body** — separate `<pre>` block, decoded UTF-8 (errors=replace).
- **URL-decode view** — toggle button with `aria-pressed`; percent-decodes
  visible text in place. State is per-page; not persisted.
- **Copy-as** — `render` action re-shows the right pane with curl,
  httpx, requests, fetch, and raw-HTTP snippets you can copy.
- **Engine errors** — caught and rendered inline as a synthetic
  `status=0` response. No 500 page.

## Loading a request

Three ways:

1. **From history** — `/repeater/?from_history=<hid>`. The row Actions
   menu in [History](history.md) and Send-to in [Proxy](proxy.md) both
   build this URL.
2. **From curl** — `/repeater/?from_curl=<url-encoded curl command>`.
   Best-effort parser for `-X`, `-H`, `-d`, `--data`. Complex curls
   (`--compressed`, `@file`, …) may need manual cleanup.
3. **Blank** — just open `/repeater/` and type.

## Accessibility notes

- Request fieldset has `<legend>Repeater</legend>`; inputs and textareas
  carry explicit `<label for="…">`.
- Response section is `<section aria-labelledby="resp-h">` with
  `<h2 id="resp-h">`.
- "URL-decode view" toggle has `aria-pressed="false"`/`"true"`.
- Errors render in `<p role="alert">`.
- Read order: form → response status → response headers → response body
  → copy-as snippets.
- Default browser tab order is the natural form order — no `tabindex`
  hacks.

## How it integrates

**Producers** (what feeds Repeater):

- [History](history.md) — detail page + row Actions menu, both Alt+R.
- [Proxy](proxy.md) — intercept detail page (Alt+R) and "Send all queued to Repeater" bulk action.

**Consumer:** none directly — the Repeater is a sink. Copy as a curl
snippet to take a request elsewhere.

## Keyboard

| Action               | Where             | Key       |
|----------------------|-------------------|-----------|
| Open Repeater        | global top bar    | **Alt+4** |
| Send to Repeater     | History / Proxy   | **Alt+R** |

## Recipes

### Replay a captured request

History → row → Send to Repeater → Send. Done.

### URL-encode a form-body for injection testing

Paste `username=admin&password=secret' OR 1=1--`, click **URL-encode body**.
The structural `&` and `=` stay; only the values are encoded. Switch back
with **URL-decode body**.

### Test HTTP/2 support

Set HTTP to `2`, pick `httpx` or `raw`, Send.

### Force a deliberate Content-Length mismatch

Switch engine to `raw`, set `Content-Length` by hand to a wrong value,
Send. The server's reaction tells you what you wanted to know.

### Spoof a Chrome 120 TLS fingerprint

Pick `curl-cffi:chrome120` (needs `pip install reqlore[impersonate]`).
ClientHello matches JA3/JA4 of real Chrome 120.

## Storage footprint

- Every `send` writes one row to `http_history` with
  `engine = "repeater/<engine>"`.
- Form state lives in PRGCache (in-memory, cleared on app restart). The
  cache token rides in `?t=<token>` so refreshes are idempotent.
- No per-tab or per-request state in the `.rlr` database.

## Troubleshooting

| Symptom                                                       | Cause                                                                    | Fix                                                                                              |
|---------------------------------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Response shows `status=0 (h3 engine unavailable)`             | aioquic not installed                                                     | `pip install reqlore[h3]`.                                                                       |
| Response shows `status=0 (curl_cffi unavailable)`             | curl-cffi not installed                                                   | `pip install reqlore[impersonate]`.                                                              |
| Server rejects the request after you edit the body            | Stale `Content-Length` in your headers (raw engine)                       | Either remove it (raw will auto-add) or switch to httpx (it strips and recomputes).               |
| Body shows U+FFFD chars                                       | Response body is not UTF-8                                                | Copy as raw-HTTP, paste into Decoder, run `hex_encode` for byte-level inspection.                 |
| `from_curl` ignored a flag                                    | Best-effort parser doesn't cover that option                              | Paste the request body / headers manually; or use the curl one-liner from the **Copy as…** pane. |
| Raw engine sends without Host header                          | You manually included a blank Host header                                 | Remove the empty `Host:` line; raw only auto-adds Host when no Host header is present.            |

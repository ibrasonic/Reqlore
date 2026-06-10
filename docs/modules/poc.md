# PoC builder — `/poc/`

Generate self-contained, browser-runnable proof-of-concept HTML for two
common vulnerability classes: CSRF (auto-submitting form **or**
JavaScript `fetch()`) and clickjacking (overlay-on-iframe). Sourced
either from a captured [History](history.md) row or built manually for
clickjacking.

## Where it is

- **URL:** `/poc/`
- **Nav:** *PoC* in the top bar.
- Two pages: `/poc/` (CSRF, hydrate from history) and `/poc/clickjacking`.

## Quick start (CSRF)

1. From [History](history.md) row Actions → **Send to PoC builder** (Alt+B).
2. PoC builder opens with the selected request.
3. Click **Download form-style CSRF PoC** or **Download fetch-style CSRF PoC**.
4. Open the downloaded HTML in a browser already logged into the target. The PoC fires automatically (form auto-submit) or via the fetch button.

## Quick start (clickjacking)

1. Open `/poc/clickjacking`.
2. Paste a target URL (`https://victim.example/transfer`).
3. Type a lure into **Overlay**.
4. **Generate**. Download the HTML; open it in a victim browser. If the
   target's response is missing `X-Frame-Options` / `frame-ancestors`,
   the iframe loads under the lure.

## Routes

| URL                                | Method | What it does                                                                            |
|------------------------------------|--------|-----------------------------------------------------------------------------------------|
| `/poc/`                            | GET    | Render PoC index. Hydrate from `?from_history=<hid>` (request fetched from `http_history`). |
| `/poc/csrf/<hid>`                  | GET    | Generate + download the CSRF PoC. `?style=form` (default) or `?style=fetch`.             |
| `/poc/clickjacking`                | GET    | Render the clickjacking form.                                                            |
| `/poc/clickjacking`                | POST   | Generate + download the clickjacking HTML.                                              |

PoC is the destination of two Send-to slugs:

- **`/history/<hid>/send/poc`** — from [History](history.md) row Actions / detail (Alt+B).
- **`/proxy/intercept/<iid>/send/poc`** — from [Proxy](proxy.md) intercept detail. Snapshots the held flow into history first, then redirects here with `?from_history=<hid>`.

## Form fields (clickjacking)

| Field       | Type   | Default                       | Notes                                                  |
|-------------|--------|-------------------------------|--------------------------------------------------------|
| `url`       | url    | empty (required)              | Target URL to frame.                                   |
| `overlay`   | text   | `"Click here to win!"`        | Lure text rendered over the iframe (HTML-escaped).     |
| `_csrf`     | hidden | (generated)                   | CSRF token for the PoC builder itself.                 |

## How the PoC HTML is built

### CSRF form

`csrf_form_poc(request, autosubmit=True)`:

- Parses the captured body by `Content-Type`. `application/x-www-form-urlencoded` and `multipart/form-data` are supported via `_form_pairs(body, ct)` → `urllib.parse.qsl()`.
- Renders one hidden `<input>` per pair into a `<form>` whose `action` is the captured URL and whose `enctype` matches the original.
- Appends `<script>document.getElementById("p").submit();</script>` (skipped when `autosubmit=False`).

### CSRF fetch

`csrf_fetch_poc(request)`:

- Filters out: `host`, `content-length`, `cookie`, `authorization`,
  `user-agent`, `referer`, `origin`, `connection`, `accept-encoding`.
- Keeps custom headers (`X-CSRF-Token`, `X-Tenant-Id`, …).
- Renders a `fetch(url, { method, headers, credentials: "include", mode: "no-cors", body })` snippet. Body is JSON-stringified into the JS literal.
- Result + status rendered into `<pre id="o" aria-live="polite">`.

### Clickjacking

`clickjacking_poc(url, overlay)`:

- `<iframe src="…" style="…">` at 50% opacity.
- Overlay div positioned absolutely over the frame at -3° rotation.
- Overlay text HTML-escaped.
- Iframe carries `title="Framed target"` for screen-reader context.

All three return a `POC` dataclass: `title`, `filename`, `html`. The
download endpoint sets `Content-Disposition: attachment` and serves the
HTML.

## Accessibility notes

- Index page: sectioned with `<section aria-labelledby="csrf-h">` /
  `aria-labelledby="cj-h">` paired with the section heading IDs.
- Clickjacking form: `<label for="u">` and `<label for="o">` on the
  inputs.
- Fetch PoC's status `<pre>` carries `aria-live="polite"`.
- Iframe has `title="Framed target"`.

## How it integrates

**Producers:**

- [History](history.md) row Actions / detail — **Send to PoC builder** (Alt+B).
- [Proxy](proxy.md) intercept detail — same (snapshots first).

**Consumer:** none — output is a downloaded HTML file. Take it
elsewhere.

## Recipes

### CSRF for a JSON API

The form-style PoC can't express JSON bodies — use the **fetch-style**
PoC. Captured request was `POST /api/transfer` with
`Content-Type: application/json` and body `{"to":"attacker","amount":100}`.
The generated `fetch()` PoC includes `body: "{\"to\":\"attacker\",\"amount\":100}"`
and `credentials: "include"`. Host it on `attacker.example`; lure the
victim while their session cookie is valid.

### Multipart upload CSRF

If the captured body was `multipart/form-data`, `csrf_form_poc()`
detects the enctype and renders `<form enctype="multipart/form-data">`.
The browser supplies its own boundary; usually fine.

### Clickjacking proof-of-concept

URL: `https://target.example/admin/delete-account`, Overlay: `"Click to
unlock 100 free credits!"`. If the iframe loads (no X-Frame-Options /
frame-ancestors), the demo is conclusive.

### Confirm a missing `Content-Security-Policy: frame-ancestors`

Generate clickjacking PoC. If the iframe is blocked, look at the
browser console for the CSP violation — that's also a useful PoC
artifact to ship in the report.

### Strip custom headers from the fetch PoC

Custom headers (e.g. `X-CSRF-Token`) are preserved by design — they're
what makes CSRF interesting. If you want to demo without them, edit
the downloaded HTML and remove the relevant lines from the `headers:
{}` literal.

## Storage footprint

**None.** No persistent state, no PRG cache for PoC generation. The
PoC builder reads from `http_history` when hydrating from
`?from_history=<hid>` but writes nothing back.

## CLI

No CLI surface.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Form PoC dropped my custom headers                        | Form PoC can only express form fields, not headers                      | Use the **fetch-style** PoC.                                                                     |
| Fetch PoC succeeds but server rejects                     | Fetch in `no-cors` mode can't read the response — only blind fire     | That's expected; if you need the response, use [Repeater](repeater.md), not a PoC.               |
| Clickjacking iframe shows blank                           | Target sent `X-Frame-Options: DENY` or `CSP: frame-ancestors 'none'`    | Target is correctly configured — file a positive note in the report.                              |
| Multipart boundary mismatch                               | PoC uses the browser's default boundary                                 | Most servers accept any boundary; if the target is strict, hand-edit the form.                    |
| Auto-submit form fires twice                              | Browser back-button re-runs the inline `<script>`                      | Pass `autosubmit=False` (would require a patched download); easier: hand-edit the script tag.    |
| Send-to PoC missing                                       | Both `history` and `proxy intercept` always offer it; never conditional | Confirm the row exists; reload the page.                                                          |

## Test contract

- `reqlore/tests/unit/test_phase4_modules.py::test_csrf_form_poc_renders_inputs` — form PoC builds `<input>`s from a form-encoded body.
- `…::test_csrf_fetch_poc_credentials_include` — fetch PoC has `credentials: "include"` and JSON-encoded body.
- `…::test_clickjacking_poc_iframes_target` — iframe `src` set; overlay HTML-escaped.
- `reqlore/tests/unit/test_decoder_and_send_to.py::test_send_to_poc_lands_with_request` — proxy intercept Send-to → PoC.
- `…::test_history_send_to_poc_lands_with_request` — history Send-to → PoC.

# Decoder — `/decoder/`

The Decoder converts text between 24 encodings — URL, HTML, base64, hex,
gzip, JSON, JWT, hashes, ROT13, and a smart chain that unwraps nested
payloads. No persistence. Pure utility.

## Where it is

- **URL:** `/decoder/`
- **Nav:** *Decoder* in the top bar.
- Single-operation per submit; results render inline via the PRG token
  pattern.

## Quick start

1. Paste text into **Input**.
2. Pick an **Operation** (default *URL encode*).
3. **Run**. Output renders below with a character count.

Or: from [History](history.md) detail / [Proxy](proxy.md) intercept
detail, press **Alt+O** to **Send to Decoder** — the request body
arrives pre-filled.

## Routes

| URL          | Method | What it does                                                                       |
|--------------|--------|------------------------------------------------------------------------------------|
| `/decoder/`  | GET    | Display form. Optional prefill from `?text=<input>`. Optional `?t=<token>` for cached result. |
| `/decoder/`  | POST   | Run the chosen operation, cache result, PRG-redirect with token.                    |

## Operations

24 operations in the dropdown. Grouped here for sanity:

### URL / form

| Operation     | Input                | Output                                | Notes                                                                              |
|---------------|----------------------|---------------------------------------|------------------------------------------------------------------------------------|
| `url_encode`  | any text             | percent-encoded                       | `quote(safe="")` — encodes `/` too.                                                |
| `url_decode`  | percent + plus       | decoded                               | `unquote_plus()` — `+` → space (form-compatible).                                  |
| `form_encode` | `k=v&k2=v2`          | per-field encoded form body            | Preserves `&` and the outer `=`; only keys + values encoded.                       |
| `form_decode` | encoded form body    | decoded form body                     | Inverse of `form_encode`; tolerates keyless segments (e.g. bare `flag`).            |

### HTML

| Operation     | Notes                                                |
|---------------|------------------------------------------------------|
| `html_encode` | `html.escape(quote=True)` — escapes `< > & " '`.     |
| `html_decode` | `html.unescape()` — named and numeric entities.      |

### Base64 / hex

| Operation        | Notes                                                                                                          |
|------------------|----------------------------------------------------------------------------------------------------------------|
| `b64_encode`     | Standard alphabet; keeps `=` padding.                                                                           |
| `b64_decode`     | **Strict** — rejects non-alphabet characters; strips whitespace; re-pads. UTF-8 errors=replace for output.      |
| `b64url_encode`  | URL-safe (`-` `_`); **strips trailing `=`**.                                                                    |
| `b64url_decode`  | Converts `-` → `+`, `_` → `/`, re-pads; strict.                                                                |
| `hex_encode`     | `bytes.hex()` lowercase.                                                                                        |
| `hex_decode`     | Liberal — strips spaces, `:`, `-`, `_`, `0x` prefix. Rejects odd-length input.                                  |

### Compression

| Operation        | Notes                                                                                            |
|------------------|--------------------------------------------------------------------------------------------------|
| `gzip_encode`    | `gzip.compress()` → base64. Output is text.                                                       |
| `gzip_decode`    | base64-decode → `gzip.decompress()`. Rejects garbage.                                              |
| `deflate_encode` | `zlib.compress()` → base64.                                                                       |
| `deflate_decode` | base64-decode → `zlib.decompress()`.                                                              |

### Hashes

| Operation | Notes                              |
|-----------|------------------------------------|
| `md5`     | Lowercase hex digest of UTF-8 bytes.|
| `sha1`    | Same.                               |
| `sha256`  | Same.                               |
| `sha512`  | Same.                               |

### Tokens / structure

| Operation       | Notes                                                                                                          |
|-----------------|----------------------------------------------------------------------------------------------------------------|
| `jwt_decode`    | Parses 3 dot-separated parts. **No signature verification.** Output: `{"header": {...}, "payload": {...}}`.    |
| `json_pretty`   | `json.dumps(indent=2, sort_keys=False)`.                                                                       |
| `json_minify`   | `json.dumps(separators=(",",":"))`.                                                                            |
| `rot13`         | Involution — `rot13(rot13(x)) == x`. Only A–Z, a–z affected.                                                   |
| `smart_decode`  | Iteratively tries `url_decode` → `b64_decode` → `jwt_decode`. Up to 5 passes. Stops when output stabilises or goes non-printable. Each intermediate must be >85 % printable. `b64_decode` is shape-gated (4+ chars, alphabet only, divisible by 4 after re-padding) so plain text like "helloworld" is not misdecoded. |

## How it integrates

**Producers** (what feeds Decoder):

- [History](history.md) detail page — **Send to Decoder** (Alt+O). Shown
  only if the request body is non-empty.
- [Proxy](proxy.md) intercept detail page — same.

Both pass the request body as `?text=<body>` and the Decoder pre-fills.

**Consumer:** none — output is text for display / copy. Decoder doesn't
feed other tools.

## Keyboard

| Action            | Where             | Key       |
|-------------------|-------------------|-----------|
| Open Decoder      | global top bar    | **Alt+7** |
| Send to Decoder   | History / Proxy   | **Alt+O** |

## Accessibility notes

- Every input has an explicit `<label for="…">`: `d-op` for the operation
  dropdown, `d-in` for the input textarea.
- Output section uses `<section aria-labelledby="out-h">` with
  `<h2 id="out-h">Output (N chars)</h2>`.
- Errors render in `<p role="alert">`.
- Read order: form → error (if any) → output (if any).
- No client-side JS required — all operations server-side.

## Recipes

### Inject a SQLi payload safely into a form value

Input: `' OR 1=1-- `. Operation: **URL encode (form body)**. Output:
`%27%20OR%201%3D1--%20`. Paste straight into a form field value.

### Decode a form body that has both `+` and `%20`

Input: `username=jane+doe&note=hello%20world`. Operation: **URL decode
(form body, keep & =)**. `&` survives; `+` and `%20` both become space.

### Inspect a JWT without verifying

Input: the token. Operation: **JWT decode (no verify)**. Output is the
decoded header + payload as pretty JSON. Tamper detection happens
elsewhere — try [JWT workbench](jwt.md) for that.

### Unwrap a nested payload

Input: a URL-encoded → base64-encoded → URL-encoded string. Operation:
**Smart decode (chain)**. Decoder unrolls up to 5 layers or until the
output stabilises.

### Pretty-print a minified JSON response

Input: `{"a":1,"b":[2,3]}`. Operation: **JSON pretty-print**.

### Hash a candidate password

Input: `password123`. Operation: **SHA-256**. Compare hex output against
a stolen hash.

## Storage footprint

**None.** Results live in PRGCache (in-memory). Closing the tab loses
them. Nothing is written to the `.rlr` project file.

## Troubleshooting

| Symptom                                                | Cause                                                                  | Fix                                                                                              |
|--------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `b64_decode` rejects a string                          | Strict validation — `validate=True` rejects non-alphabet chars          | Strip the garbage first; or use `smart_decode` which is more forgiving (shape-gated).             |
| `+` in input vanished after `url_decode`               | `unquote_plus()` is correct for form bodies                             | If you wanted to preserve `+`, use `form_decode` instead.                                         |
| `smart_decode` left `helloworld` alone                 | Shape gate blocked `b64_decode` because input doesn't look base64-ish    | Working as designed — protects against plain-text mis-decode.                                     |
| `smart_decode` stopped after 3 passes                  | Output went non-printable (>15 % non-printable bytes) or stabilised      | Run the operations one at a time so you can inspect each layer.                                  |
| `jwt_decode` shows a payload that "shouldn't be valid" | No signature verification — that's intentional                          | Use [JWT workbench](jwt.md) for verify / forge.                                                  |
| `gzip_decode` rejects a gzip stream                    | Decoder operates on text — gzip output must be base64-encoded            | Run `gzip_encode` first if you have raw bytes (or hex-encode and decode externally).              |
| `json_pretty` errors on a single-quoted JSON-ish blob  | Not real JSON                                                            | Fix the source; or use a permissive JSON5 tool externally.                                       |
| **Send to Decoder** missing                            | Request body empty                                                       | Decoder is body-only. Use the URL Decoder operation on the URL string itself.                    |

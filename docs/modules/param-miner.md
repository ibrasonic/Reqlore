# Param miner — `/param-miner/`

Discover hidden parameters by spraying a wordlist at a URL. Detection
is sentinel-based: each probe injects a unique hex token; if the
response echoes it, the status changes, or the body length shifts by
more than a tolerance, the parameter is interesting. Built-in wordlist
of 200 names; bring your own via the **Extra** textarea.

## Where it is

- **URL:** `/param-miner/`
- **Nav:** *Param miner* in the top bar.
- Stateless / PRG-cached.

## Quick start

1. Open `/param-miner/`. Paste a target URL
   (`https://api.example.com/items`).
2. Pick **Method** (`GET`), **Location** (`query`), **Max words** (50).
3. Click **Mine**. Results table shows any parameter that altered the
   response.

## Routes

| URL              | Method   | What it does                                                          |
|------------------|----------|-----------------------------------------------------------------------|
| `/param-miner/`  | GET      | Render form. Hydrate from `?t=<token>` (PRGCache).                     |
| `/param-miner/`  | POST     | Run `mine()`, stash result, 302 to `?t=<token>`.                       |

## Form fields

| Field         | Type     | Default     | Notes                                                                    |
|---------------|----------|-------------|--------------------------------------------------------------------------|
| `url`         | url      | empty       | **Required.** `type="url"`. Placeholder shown.                            |
| `method`      | select   | `GET`       | `GET` / `POST` / `PUT` / `DELETE` / `PATCH`.                              |
| `location`    | select   | `query`     | `query` / `body` / `header`.                                              |
| `max_words`   | number   | `50`        | Cap on probes. Range `1` – `200` (size of built-in list).                 |
| `rate_delay`  | number   | `0`         | Milliseconds to sleep between probes. Range `0` – `2000`.                  |
| `extra`       | textarea | empty       | Extra wordlist (one per line). Prepended to built-ins.                    |

## Algorithm

1. **Baseline** — send the request as configured, no extra params. Record status + body length.
2. For each candidate word (in built-in list + extras, capped at `max_words`):
   - Generate sentinel: `wlpm_` + 4-byte random hex (`secrets.token_hex(4)`).
   - Inject into the chosen location:
     - **query** — `url?word=sentinel` via `urllib.parse.urlencode()`.
     - **body** — form-encoded `word=sentinel` with `Content-Type: application/x-www-form-urlencoded`.
     - **header** — custom header `X-<Word>: <sentinel>` (alphanumerics + hyphens only, others dropped).
   - Send probe; sleep `rate_delay_ms`.
3. **Compare**:
   - Sentinel reflected in body → "sentinel reflected in response body".
   - Status differs from baseline → "status differs: baseline N vs probe M".
   - Body length differs by `> 16` bytes (tolerance) → "body length differs by X bytes".
4. Any match → record finding row.

**Sequential probes** — no parallelism. `follow_redirects=False` (so
probes don't disappear into third-party sites).

## Output

Probes attempted, total elapsed ms, table of hits:

| Parameter | Evidence                                | Status (baseline → probe) | Length (baseline → probe) |
|-----------|-----------------------------------------|---------------------------|---------------------------|

## Accessibility notes

- Every field has `<label for="pm-url">` etc.
- Error message renders in `<p role="alert" class="err">`.
- Result heading `<h2>`; result table with `<caption>` and `<th scope="col">`.

## How it integrates

**Producers / consumers:** none — author-initiated. Results are
informational and not auto-recorded into the findings table.

For programmatic mining (e.g. inside an intruder pipeline), import
`reqlore.param_miner.mine()`.

## Recipes

### Vanilla query-string mine

URL: `https://example.com/items`, defaults. Click **Mine**. 50 probes
in seconds.

### Custom wordlist

Paste into **Extra**:

```
debug_mode
super_secret_token
admin_bypass
```

These are tried before / alongside the built-ins (subject to
`max_words`).

### Rate-limited scan

`rate_delay=500, max_words=10` → ten probes, half a second apart.
Useful against fragile targets.

### Header-location mine

Some apps key behaviour on custom headers (`X-Admin: true`,
`X-Debug: 1`). Set `location=header`, the miner converts each word to
`X-Word: <sentinel>`.

### POST body mine

`location=body, method=POST`. Baseline is a POST with **no body** (so
the target sees a different request shape than the probes). If your
target requires a body, this will produce false negatives — use
[Repeater](repeater.md) for a first pass.

## Storage footprint

**Transient.** PRGCache (32-entry LRU) holds the form values + result
under a 12-char token. No DB writes, no `project_state` keys.

## CLI

No CLI surface — import from `reqlore.param_miner` if you want to drive
it from a plugin or test.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| False positive: every param echoes sentinel               | Target reflects unknown input verbatim                                  | Sentinel prefix `wlpm_` is hard-coded; if the target embeds it anywhere, you'll see noise. Inspect manually. |
| All probes 401                                            | Target requires auth                                                    | Add credentials in the URL query, or use [Macros](macros.md) and copy headers into a wrapping plugin. |
| Probes follow redirects to a third-party site             | Default is `follow_redirects=False`                                     | This is the safe default; if you want to follow, patch via plugin.                               |
| Body-location mine reports lots of false positives        | Baseline has no body; probes have a body — the target may differ on shape | Use a real request with an actual body via [Repeater](repeater.md) instead.                       |
| Length diff threshold is too sensitive                    | Hard-coded 16-byte tolerance                                            | Inspect "body length differs" results manually; or modify `reqlore/param_miner.py` for your run.  |

## Test contract

`reqlore/tests/unit/test_phase7.py`:

- `test_param_miner_detects_reflected_sentinel` — fake sender echoes "debug" → flagged with "sentinel reflected".
- `test_param_miner_detects_status_difference` — fake sender returns 403 for "admin" → status-diff evidence.
- `test_param_miner_body_location_uses_form_body` — body-location POST includes the sentinel in form-encoded body.

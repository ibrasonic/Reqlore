# Search — `/search/`

Project-wide substring search across the last 5000 history rows. Scope to
URL only, request body, response body, or all three.

## Where it is

- **URL:** `/search/`
- **Nav:** *Search* in the top bar.
- Read-only — no edits, no persistence.

> **Substring, not regex.** Search is a fast, lowercase substring scan.
> For regex matching, see [Match & Replace](matchreplace.md) (in the
> proxy path) or filter [History](history.md) by URL and inspect by
> hand.

## Quick start

1. Open `/search/`. Type a query into **q** (e.g. `password=`).
2. Pick a **Where** scope (default *Any* — URL + request + response).
3. **Search**. Up to 200 rows render with the matched location flagged.
4. Click any row's `#` → opens the [History](history.md) detail.

## Routes

| URL          | Method | What it does                                                                          |
|--------------|--------|---------------------------------------------------------------------------------------|
| `/search/`   | GET    | Render form + results. Empty `q` = form only, no results.                              |

Query parameters:

| Param   | Type   | Default | Notes                                                       |
|---------|--------|---------|-------------------------------------------------------------|
| `q`     | text   | empty   | Substring (case-insensitive). Empty = no scan.              |
| `where` | select | `any`   | One of `any`, `url`, `req`, `resp`.                         |

## Form fields

| Field   | Type   | Default | Validation        | Notes                                                                 |
|---------|--------|---------|-------------------|-----------------------------------------------------------------------|
| `q`     | text   | empty   | HTML5 `required`  | Lowercase substring match (Python `str.lower()`).                     |
| `where` | select | `any`   | enum              | `any` (URL · request · response), `url`, `req` (request body), `resp` (response body). |

## Scope semantics

| Scope   | Where it looks                                                          |
|---------|-------------------------------------------------------------------------|
| `any`   | URL + decompressed request blob + decompressed response blob.            |
| `url`   | URL field only (LIKE-style substring).                                   |
| `req`   | Decompressed request bytes only (lowercased, byte-level substring).      |
| `resp`  | Decompressed response bytes only (lowercased, byte-level substring).     |

Each result row reports which scope(s) actually matched (`url`, `request`,
`response`, or a comma-joined list).

## Result columns

| Column     | Notes                                                          |
|------------|----------------------------------------------------------------|
| `#`        | History row id, links to `/history/<hid>`.                      |
| Where      | Matched scope(s).                                              |
| Method     | HTTP method.                                                    |
| URL        | Full URL.                                                       |
| Status     | HTTP status code.                                              |
| Resp len   | Response length in bytes.                                       |

Sort: implicit newest-first (history id DESC).

Cap: hard 200 rows per query. The previous 5000 history rows are
scanned; older than that is invisible to Search.

A live region above the table announces the count:
*"3 hits for `<code>password=</code>`."*

## How it integrates

**Producer:** [History](history.md) — every row indexed implicitly
(scan, not FTS).

**Consumer:** none — click-through to [History](history.md) detail; from
there, the full Send-to menu is one accesskey away.

## Accessibility notes

- `<form role="search" aria-label="Project search">`.
- Both inputs labeled via `<label for="…">`. Query input carries
  `required`.
- Result count rendered in `<p aria-live="polite">` so screen readers
  hear the count change as the query refines.
- Table has `<caption>Matches</caption>` and `<th scope="col">`
  headers.

## Recipes

### Find every request to one endpoint

q = `/api/users`, where = `url`.

### Find password leaks in response bodies

q = `password=`, where = `resp`. Catches reflected form values, log
spew, debug dumps.

### Locate a specific JWT

Copy the first 20-ish characters of the token (`eyJhbGciOiJIUzI1NiJ`),
where = `req`.

### Find requests to a host

q = `example.com`, where = `url`. The URL field contains the host, so
this works without a dedicated host filter.

### Find an error string

q = `Invalid session`, where = `resp`. Cross-references with [Scanner](scanner.md)
findings if you want to triage which endpoint surfaced it.

## Storage footprint

- **Reads only.** Every query scans the last 5000 rows of `http_history`
  in Python (decompress + lowercase). No FTS5 virtual table, no
  precomputed index.
- No `project_state` keys.

## CLI

No CLI search. For scripted access, export and grep:

```
curl 'http://127.0.0.1:8787/history/export.jsonl?host=target.com' \
  | jq -r 'select(.url | test("api/users")) | .id'
```

## Troubleshooting

| Symptom                                            | Cause                                                                  | Fix                                                                                            |
|----------------------------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| Regex characters treated as literal                 | Search is substring-only                                                | Filter [History](history.md) by URL + browse, or use [Decoder](decoder.md) + offline grep.      |
| Accents don't match (`é` vs `e`)                   | Case-fold only, no accent fold                                          | Search both forms, or normalise via NFC/NFD externally.                                         |
| Old hits missing                                    | 5000-row scan window                                                    | Filter [History](history.md) by host first to keep the relevant subset within the window.       |
| Binary response matches coincidentally              | Bytes are lowercased and substring-matched, no text-vs-binary check     | Add a `where=url` or `where=req` constraint, or open the row to confirm.                        |
| Result table empty after a known-good query         | The match is older than the 5000-row window                              | Run `reqlore import-har` or paginate the history with filters to bring relevant rows forward.   |

## Test contract

- `reqlore/tests/unit/test_storage.py::test_history_search` — URL substring via `list_history(q=…)`.
- `reqlore/tests/unit/test_storage_phase2.py::test_search_finds_url_match` — `project.search()` returns `"url"` in the matched-scope field.
- `…::test_search_finds_body_match` — body-scoped search returns `"response"` scope.
- `reqlore/tests/unit/test_web_smoke_phase2.py::test_search_index_empty` — empty form renders 200.
- `…::test_search_renders_result_link` — POST a row, search returns it with a link to `/history/<hid>`.

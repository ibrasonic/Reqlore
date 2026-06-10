# Match & Replace — `/match-replace/`

Live rewrite rules that the [Proxy](proxy.md) applies to every request
and response as it flows by. Literal or regex, scoped to a host or
applied globally, targeted at request headers / request body / response
headers / response body.

## Where it is

- **URL:** `/match-replace/`
- **Nav:** *Match & Replace* in the top bar.
- Rules execute inside the [Proxy](proxy.md) addon — **not** in
  [Repeater](repeater.md), [Intruder](intruder.md), or the
  [Scanner](scanner.md). Browse the target through the proxy to see them
  fire.

## Quick start

1. Open `/match-replace/`. Pick a *Where* (e.g. *Response headers*).
2. *Regex?* `No` for literal, `Yes` for Python regex.
3. *Host filter* optional (e.g. `^example\.com$`).
4. *Match* (required): the pattern or literal.
5. *Replace with*: the replacement (regex backreferences `\1`, `\2` allowed when regex mode is on).
6. *Comment*: human note.
7. **Add rule**. The rule is live on the next proxied request — no restart.

## Routes

| URL                              | Method | What it does                                |
|----------------------------------|--------|---------------------------------------------|
| `/match-replace/`                | GET    | List all rules + add-rule form.              |
| `/match-replace/add`             | POST   | Insert a new rule.                           |
| `/match-replace/<id>/toggle`     | POST   | Flip `enabled` 0/1 on the rule.              |
| `/match-replace/<id>/delete`     | POST   | Remove the rule.                             |

## Form fields

| Field         | Type   | Required | Default        | Notes                                                                  |
|---------------|--------|----------|----------------|------------------------------------------------------------------------|
| `where`       | select | yes      | first option   | `req_header`, `req_body`, `resp_header`, `resp_body`.                  |
| `is_regex`    | select | yes      | `0` (literal)  | `0` = `str.replace`; `1` = `re.sub`.                                   |
| `host_regex`  | text   | no       | empty          | Python regex on the request host. Empty = all hosts.                   |
| `pattern`     | text   | **yes**  | empty          | Match pattern. HTML5 `required`; server flashes "Pattern cannot be empty." otherwise. |
| `replacement` | text   | no       | empty          | Replacement. Supports `\1`, `\2`, … when `is_regex=1`.                 |
| `comment`     | text   | no       | empty          | Free-form note.                                                        |

## Rule schema (storage)

Persisted in the `match_replace` table:

| Column        | Type    | Notes                                                                              |
|---------------|---------|------------------------------------------------------------------------------------|
| `id`          | integer | Primary key, auto-increment.                                                       |
| `enabled`     | integer | `1` enabled, `0` disabled. Default `1`.                                            |
| `where_`      | text    | `req_header` / `req_body` / `resp_header` / `resp_body`.                           |
| `is_regex`    | integer | `1` regex, `0` literal.                                                            |
| `host_regex`  | text    | Default `""` (any host).                                                            |
| `pattern`     | text    | Required.                                                                          |
| `replacement` | text    | Default `""`.                                                                       |
| `comment`     | text    | Default `""`.                                                                       |
| `created_at`  | integer | Unix timestamp.                                                                     |

No index — small table, sequential scan is fine.

## Application order

1. Per HTTP transaction, the proxy addon calls `_load_mr()` → fresh list from the DB (no caching).
2. Rules are iterated in id-ascending order.
3. For each rule:
   - Skip if `enabled=0`.
   - Skip if `host_regex` is set and `re.search(host_regex, host)` doesn't match (case-insensitive).
   - Apply: `str.replace(pattern, replacement)` for literal, `re.sub(pattern, replacement, text)` for regex.
   - The next rule sees the modified text.
4. For headers, rules see a `\n`-joined block of `Name: value` lines.
   After application, the block is re-parsed; lines missing `:` are
   silently dropped.
5. For bodies, rules see the UTF-8 decoded text. Non-UTF-8 bodies are
   skipped silently (the original bytes pass through unchanged).

Live semantics: rules take effect on the **next** request after Save. No
proxy restart.

## Accessibility notes

- Add form: `<form aria-label="Add rule">` with `<fieldset><legend>New
  rule</legend>`. Every input has an explicit `<label for="…">`.
- `pattern` carries HTML5 `required`.
- Rules table has `<caption>Active rules</caption>` and
  `<th scope="col">` headers.
- Toggle / Delete buttons are individual `<form><button>` POSTs. Delete
  uses an inline confirm dialog (`onsubmit="return confirm('Delete?');"`).
- Flash messages render in the global `role="alert"` region:
  *"Rule added. It applies to proxy traffic immediately."*,
  *"Pattern cannot be empty."*, *"Rule deleted."*

## How it integrates

**Producer:** the [Proxy](proxy.md) — the same `_HistoryAddon` that
records every flow into [History](history.md) also runs M&R inline on
both request and response.

**Does not apply to:**

- [Repeater](repeater.md) requests — they don't pass through the proxy addon.
- [Intruder](intruder.md) attacks — same reason.
- [Scanner](scanner.md) active probes — same reason.
- [Macros](macros.md) chains — they replay raw, not via the proxy.

If you want a rewrite for a scripted attack, do it in the attack itself
(processor / payload editor), not via M&R.

## Recipes

### Strip every `Authorization` header on the way out

- Where: `req_header`
- Regex?: `Yes`
- Host filter: (blank)
- Pattern: `^Authorization:.*`
- Replace: empty
- Comment: "Force-anonymise outgoing requests."

### Pin CORS to `https://attacker.invalid`

- Where: `req_header`
- Regex?: `No`
- Pattern: `Origin: https://example.com`
- Replace: `Origin: https://attacker.invalid`

### Inject `<script>` into HTML responses

- Where: `resp_body`
- Regex?: `Yes`
- Pattern: `</body>`
- Replace: `<script src="/x.js"></script></body>`

### Downgrade an API error to success for client-side testing

- Where: `resp_body`
- Regex?: `No`
- Host: `^api\.example\.com$`
- Pattern: `"status":"error"`
- Replace: `"status":"ok"`

### Strip CSP to test injection payloads

- Where: `resp_header`
- Regex?: `Yes`
- Pattern: `^Content-Security-Policy:.*`
- Replace: empty

## Storage footprint

- **`match_replace`** table only (see schema above).
- No `project_state` keys.
- No in-memory cache — rules re-loaded every transaction.

## CLI

No CLI surface. Rules are authored via the web UI and applied by the
proxy automatically.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Rule doesn't fire on a request                            | Wrong `where`, or host filter doesn't match, or rule disabled           | Check the rule row's *On* and *Host* columns; remove host filter to confirm.                      |
| Regex with `[unclosed` silently does nothing              | Compile error caught and skipped                                        | Test your regex in a Python REPL first.                                                          |
| Header rule mangles other headers                         | Header block is `\n`-joined, re-parsed — any line missing `:` is dropped | Make your pattern more specific; anchor with `^` / `$` (with `re.MULTILINE` if needed).          |
| Body rule does nothing on a JSON response                 | Body wasn't valid UTF-8 (e.g. brotli/gzip-encoded)                      | Disable response compression upstream, or apply the rule before encoding (handled by the engine). |
| Rule applies via the browser but not via [Repeater](repeater.md) | Repeater bypasses the proxy addon                                | Add the rewrite into the Repeater request itself, or send via Send-to to keep both paths in sync.|
| `host_regex` accepts `example.com` but matches `unexample.com.evil` | It's `re.search`, not `re.fullmatch`                          | Anchor: `^example\.com$`.                                                                         |

## Test contract

`reqlore/tests/unit/test_matchreplace.py`:

- `test_literal_request_header_replace` — literal req_header rule rewrites a header.
- `test_regex_response_body_replace` — regex resp_body rule with `\b` word boundaries.
- `test_host_filter_skips_other_hosts` — non-matching hosts are skipped.
- `test_disabled_rule_is_skipped` — `enabled=0` rules don't fire.

`reqlore/tests/unit/test_web_smoke_phase2.py::test_matchreplace_index` —
the index page renders.

`reqlore/tests/unit/test_storage_phase2.py::test_match_replace_crud` —
`add_mr` / `list_mr` / `toggle_mr` / `delete_mr` round-trip.

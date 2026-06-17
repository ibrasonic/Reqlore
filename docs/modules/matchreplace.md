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
## Quick presets

A short list of pre-baked rule bundles for common pen-test moves
("reveal hidden form fields", "disable CSP", and so on). Each preset
is just shorthand for one or more Match & Replace rules -- applying a
preset inserts those rules into the table below, where you can review,
edit, disable, or delete them like any other rule.

**Safety**: presets require a non-empty `host_regex`. The server
flashes "Choose a host filter before applying presets." if you leave it
blank, rejects invalid regexes, and warns when the regex is not
anchored (`^...$`) so a typo like `example.com` cannot match
`evil-example.com.attacker.tld`.

### Available presets

| Preset                                | What it inserts                                                                              |
|---------------------------------------|----------------------------------------------------------------------------------------------|
| Reveal hidden form fields             | `resp_body` regex: `type=(["']?)hidden\1` -> `type=\1text\1` so `<input type="hidden">` becomes editable text. |
| Strip readonly, disabled, maxlength   | Three `resp_body` regexes that remove the `readonly`, `disabled`, and `maxlength` HTML attributes. |
| Disable Content Security Policy       | `resp_header` regex strips `Content-Security-Policy` and `Content-Security-Policy-Report-Only`. |
| Allow framing (remove X-Frame-Options)| `resp_header` regex strips `X-Frame-Options` so the page can be loaded in an iframe (clickjacking PoCs). |
| Strip HttpOnly from cookies           | `resp_header` regex removes `; HttpOnly` from `Set-Cookie` so JavaScript can read session cookies. |

### How presets are tracked

Applied presets are tagged in the rule's `comment` column with a
sentinel of the form `__preset:<slug>__ <title>`. No new schema, no
hidden state. The page reads those comments back to show an **Active
presets** table grouped by `(preset, host)`, with a *Remove* button
that deletes every rule sharing that `(slug, host_regex)` pair.

If you edit the `host_regex` of a preset-tagged rule by hand, *Remove*
will no longer find that rule -- it groups by the exact host string the
rule currently carries.

### Workflow

1. Type a host filter (anchored: `^app.example.com$`).
2. Tick one or more preset checkboxes.
3. **Apply selected presets** -- the rules appear in the rules table
   with their `__preset:...__` comment.
4. Browse the target. Rules apply on the next proxied request.
5. To revert: in *Active presets*, click **Remove** next to the
   `(preset, host)` row.
## Routes

| URL                              | Method | What it does                                                                       |
|----------------------------------|--------|------------------------------------------------------------------------------------|
| `/match-replace/`                | GET    | Quick presets + add-rule form + rules table.                                       |
| `/match-replace/add`             | POST   | Insert a new rule.                                                                  |
| `/match-replace/<id>/toggle`     | POST   | Flip `enabled` 0/1 on the rule.                                                     |
| `/match-replace/<id>/delete`     | POST   | Remove the rule.                                                                    |
| `/match-replace/preset/apply`    | POST   | Insert one or more Quick Preset bundles, scoped to a required host filter.          |
| `/match-replace/preset/remove`   | POST   | Delete every rule belonging to one `(preset, host)` pair.                           |

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

- The page is split into three landmark sections via `<section
  aria-labelledby="...">` headings: *Quick presets*, *Custom rule*,
  *Rules*.
- Quick presets form: `<form aria-label="Apply quick presets"
  aria-describedby="presets-help">`. Host scope and presets are
  grouped in their own `<fieldset><legend>` blocks. Each preset
  checkbox carries `aria-describedby` pointing at a sibling `<p
  class="hint">` so screen readers announce the description after the
  label.
- *Host filter* input is marked `required`; the visible `*` is hidden
  from assistive tech (`aria-hidden="true"`) and paired with a
  `visually-hidden` "required" span.
- Active presets table: `<caption class="visually-hidden">`, `<th
  scope="col">`, and each *Remove* button has an `aria-label` that
  names the preset and host.
- Add form: `<form aria-label="Add rule">` with `<fieldset><legend>New
  rule</legend>`. Every input has an explicit `<label for="...">`.
  `pattern` carries HTML5 `required`.
- Rules table has `<caption>Active rules</caption>` and `<th
  scope="col">` headers.
- Toggle / Delete / Remove buttons are individual `<form><button>`
  POSTs. Destructive actions use an inline confirm dialog
  (`onsubmit="return confirm(...)"`).
- Flash messages render in the global `role="alert"` region:
  *"Rule added. It applies to proxy traffic immediately."*, *"Pattern
  cannot be empty."*, *"Rule deleted."*, *"Added N preset rules for
  host filter ..."*, *"Choose a host filter before applying presets."*,
  *"Heads up: host filter is not anchored..."*.
- **No automatic context changes** when toggling preset checkboxes
  (WCAG 2.2 Level AAA 3.2.5 *Change on Request*): nothing happens until
  the operator presses *Apply selected presets*.

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
`reqlore/tests/unit/test_matchreplace_presets.py`:

- `test_preset_comment_round_trip` -- preset comment encode/decode.
- `test_parse_preset_slug_returns_empty_for_non_preset` -- user comments are not misread.
- `test_every_preset_has_required_keys` -- every shipped preset is well-formed.
- `test_active_presets_groups_by_slug_and_host` -- grouping logic.
- `test_index_renders_presets_section` -- HTML carries the preset list and `aria-describedby` links.
- `test_apply_preset_inserts_tagged_rules` -- POST insert path round-trips through the DB.
- `test_apply_preset_rejects_empty_host` -- host scope is mandatory.
- `test_apply_preset_rejects_invalid_regex` -- host regex is validated.
- `test_apply_preset_warns_when_unanchored` -- M-14 warning fires for presets too.
- `test_apply_preset_with_no_selection` -- empty selection is a soft error.
- `test_remove_preset_deletes_only_matching_rules` -- *Remove* removes only its own bundle.
- `test_remove_preset_unknown_slug` -- unknown slug rejected.
`reqlore/tests/unit/test_web_smoke_phase2.py::test_matchreplace_index` —
the index page renders.

`reqlore/tests/unit/test_storage_phase2.py::test_match_replace_crud` —
`add_mr` / `list_mr` / `toggle_mr` / `delete_mr` round-trip.

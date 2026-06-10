# Sitemap — `/sitemap/`

A flat per-endpoint inventory built from [History](history.md) — one row
per `(host, url, method)` triple, with hit count, last-seen status, and a
link back to the matching history rows. Also houses the project's
**scope rules** used by the [Scanner](scanner.md).

## Where it is

- **URL:** `/sitemap/`
- **Nav:** *Sitemap* in the top bar.
- One page: filter, endpoint table, scope rules table, add-rule form.

## Quick start

1. Browse the target through the [Proxy](proxy.md) so history fills up.
2. Open `/sitemap/`. The endpoint table shows every distinct
   `(host, url, method)` ever seen.
3. Pick a host from the filter dropdown to scope the table.
4. Add scope rules in the bottom form so [Scanner](scanner.md) knows
   what to test (include) and what to skip (exclude).

## Routes

| URL                          | Method | What it does                                                            |
|------------------------------|--------|-------------------------------------------------------------------------|
| `/sitemap/`                  | GET    | Render endpoint table + scope rules table. Optional `?host=<h>` filter.  |
| `/sitemap/scope/add`         | POST   | Insert a new scope rule.                                                 |
| `/sitemap/scope/<sid>/toggle`| POST   | Flip the rule's `enabled` flag.                                          |
| `/sitemap/scope/<sid>/delete`| POST   | Delete the rule.                                                         |

## Endpoint table

Each row is a `(host, url, method)` triple aggregated from
`http_history`:

| Column      | Source                                                       |
|-------------|--------------------------------------------------------------|
| Host        | `http_history.host`                                          |
| Method      | `http_history.method`                                        |
| URL         | `http_history.url` (linked — click jumps to [History](history.md) filtered by URL substring). |
| Hits        | `COUNT(*)` of matching rows.                                 |
| Last status | `MAX(http_history.status)` — see *Gotchas*.                  |

Filter:

| Field | Type   | Default     | Notes                                            |
|-------|--------|-------------|--------------------------------------------------|
| host  | select | (any host)  | Options populated from `g.project.hosts()`.       |

## Scope rules

Two purposes:

1. **Scanner gate.** Tells the [Scanner](scanner.md) which hosts / URLs
   it may probe (`include`) and which to skip outright (`exclude`).
2. **Audit trail.** Rules persist in the project file — re-opening the
   project preserves your scope decisions.

Rule schema:

| Column     | Type    | Notes                                                  |
|------------|---------|--------------------------------------------------------|
| `id`       | integer | Auto-increment.                                        |
| `kind`     | text    | `include` or `exclude`.                                |
| `target`   | text    | `host` (regex on hostname) or `url` (regex on full URL). |
| `pattern`  | text    | Python regex. Required.                                |
| `enabled`  | integer | `1` / `0`.                                              |

Add-rule form fields:

| Field    | Type   | Default     | Notes                                                                       |
|----------|--------|-------------|-----------------------------------------------------------------------------|
| `kind`   | select | `include`   | `include` / `exclude`.                                                       |
| `target` | select | `host`      | `host` / `url`.                                                              |
| `pattern`| text   | empty       | Python regex. Required (server flashes "Pattern required" when blank).       |

Matching is `re.search` (not full match). Empty pattern is rejected.
Order: rules iterate in `id`-ascending; first matching rule wins.
Default behaviour when no rule matches: **allow**.

The sitemap display itself ignores scope rules — every history row is
shown. Scope only affects [Scanner](scanner.md) probes.

## How it integrates

**Producer:** [History](history.md) — the entire content of the
endpoint table is `SELECT host, url, method, COUNT(*), MAX(status),
MAX(ts) FROM http_history GROUP BY host, url, method ORDER BY host, url`.

**Consumers:**

- Each URL cell links to [History](history.md) (`?q=<url>`).
- Scope rules consumed by [Scanner](scanner.md) when it builds the
  probe target list.

## Accessibility notes

- Filter form: `<form aria-label="Filter by host">`; explicit
  `<label for="sm-host">`.
- Endpoint table: `<caption>` carries the endpoint count;
  `<th scope="col">` headers; URL cell wraps anchor in
  `<td class="url"><a>`.
- Add-rule form: `<form aria-label="Add scope rule">`; every input
  labeled.
- Scope rules table: `<caption>`; `<th scope="col">`; Delete button
  uses inline confirm dialog.
- **Not a treeview.** Sitemap is a flat table — no APG treeview, no
  collapsible details. Keyboard nav is the browser default for tables
  and forms.

## Recipes

### Restrict the scanner to one host

Add rule: `kind=include`, `target=host`, `pattern=^api\.example\.com$`.
[Scanner](scanner.md) will only probe `api.example.com`.

### Block staging / dev URLs from being probed

Add rule: `kind=exclude`, `target=url`, `pattern=/(staging|dev|test)/`.

### Find every endpoint that ever returned 500

Open `/sitemap/`, scan the *Last status* column for 500. Caveat: the
column is `MAX(status)` (see *Gotchas*) — a row showing 500 means *at
least one* hit returned 500, not "currently broken".

### Bulk-disable a rule temporarily

Click the rule row's **Toggle** button. The rule stays in the DB,
`enabled` flips to `0`, [Scanner](scanner.md) ignores it.

## Storage footprint

- **`scope_rules`** — the rule rows.
- **Reads only on `http_history`** for the endpoint table.
- No `project_state` keys.

## CLI

No CLI surface for sitemap or scope today.

## Troubleshooting

| Symptom                                                | Cause                                                                  | Fix                                                                                              |
|--------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Endpoint table has thousands of rows for one URL       | Query strings aren't deduped — `?id=1` and `?id=2` are separate rows    | Filter [History](history.md) by host first; or open a focused [Search](search.md) for the path.   |
| *Last status* shows 500 for an endpoint that's now 200  | Column is `MAX(status)`, not "latest"                                   | Check [History](history.md) for the most recent row to confirm.                                  |
| Same URL appears twice with `GET` and `Get`             | Methods aren't case-normalised                                          | Unlikely from the Proxy; upper-case in your client if recurring.                                  |
| Scope rule with `[unclosed` doesn't fire                | Regex compile error caught silently at scan time                        | Test regex in a Python REPL before adding.                                                       |
| Adding an `exclude` rule didn't hide rows from sitemap  | Sitemap ignores scope rules — they apply only to the [Scanner](scanner.md) | Use the host filter to scope the visible table.                                                  |
| Empty *Host* column on some rows                       | Some history row had no Host header (raw HTTP)                          | Cosmetic; doesn't affect functionality.                                                          |

## Test contract

Storage round-trip (`reqlore/tests/unit/test_storage.py`):

- `test_project_create_and_meta` — project init.
- `test_history_add_list_get` — sitemap data source.
- `test_history_search` — URL substring helper used by the click-through link.

Scope CRUD is exercised by storage helpers (`list_scope`, `add_scope`,
`toggle_scope`, `delete_scope`); the blueprint itself currently relies
on integration coverage rather than explicit `test_sitemap_*`.

# GraphQL workbench — `/graphql/`

Introspect a GraphQL schema, browse its types, run queries / mutations
with variables. Standalone — does not consume from history; the
[Scanner](scanner.md) provides the `graphql-introspection` /
`graphql-active` passive and active checks for automated coverage.

## Where it is

- **URL:** `/graphql/`
- **Nav:** *GraphQL* in the top bar.
- Single page; PRG-cached state under `?t=<token>`.

## Quick start

1. Open `/graphql/`. Paste the endpoint URL (e.g. `https://api.example.com/graphql`).
2. Add headers if the endpoint requires auth (one per line, `Name: value`).
3. Click **Introspect schema**. The schema tree expands below.
4. Browse types and fields. Pick one, write a query against it.
5. Optional: paste a JSON object into *Variables*.
6. Click **Run query**. Response renders inline as JSON.

## Routes

| URL          | Method | What it does                                                                |
|--------------|--------|-----------------------------------------------------------------------------|
| `/graphql/`  | GET    | Render workbench. Hydrate from `?t=<token>` (PRG cache).                     |
| `/graphql/`  | POST   | Run `action=introspect` or `action=run`. Stash in PRGCache, 302 to `?t=…`.  |

## Form fields

| Field     | Type     | Default | Notes                                                                                     |
|-----------|----------|---------|-------------------------------------------------------------------------------------------|
| `url`     | url      | empty   | **Required.** Placeholder `https://api.example.com/graphql`.                              |
| `headers` | textarea | empty   | One per line `Name: value`. Parsed by `_parse_headers()` (split on first `:`, strip).      |
| `query`   | textarea | empty   | GraphQL query or mutation.                                                                 |
| `vars`    | textarea | empty   | Variables as a JSON object. Validated via `json.loads()` — invalid JSON flashes an error. |
| `action`  | button   | n/a     | `introspect` or `run`.                                                                     |

## Introspection

The query sent (verbatim from `reqlore/graphql.py`):

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { name description type { ... } defaultValue }
        type { kind name ofType { ... } }
        isDeprecated deprecationReason
      }
      inputFields { ... }
      enumValues(includeDeprecated: true) { ... }
    }
  }
}
```

The response is flattened into `SchemaType` records. Internal types
starting with `__` are filtered out. Types render with `NON_NULL` → `X!`
and `LIST` → `[X]`. Sort order: `OBJECT` types first, then by name.

## Query / mutation execution

- Sent as `POST` with JSON body `{"query": "<query>", "variables": <vars>}`.
- Auto-headers: `Content-Type: application/json`, `Accept: application/json`. User-supplied headers are appended.
- Engine: `httpx_engine.send()` with 15 s timeout.
- Errors (connection, non-JSON) fall back to latin-1 decoding for display.

## Accessibility notes

- Every form field has a `<label for="…">`.
- Schema tree renders as `<details>` blocks (progressive disclosure;
  collapsed by default).
- Field tables: `<table>` with `<caption>`, `<thead>`, `<th scope="col">`.
- Response and raw introspection render in `<h2>`-anchored sections.
- Errors render in `<p role="alert">`.

## How it integrates

**Producer:** none — workbench is author-initiated.

**Consumers:** none directly. Related modules in the codebase:

- Passive rule `passive:graphql-batching-hint` flags endpoints that
  accept batched queries (POST body is a JSON array).
- Active checks `graphql-introspection` and `graphql-active` are exposed
  via the [Scanner](scanner.md) Custom preset.
- `record_introspection_finding()` helper writes a medium-severity
  finding when introspection is open.

## Recipes

### Probe for introspection

URL only, click **Introspect schema**. If the schema renders, the
endpoint exposes introspection — usually a finding worth reporting.

### Run an authenticated query

Headers:

```
Authorization: Bearer eyJhbGciOi...
```

Query:

```graphql
query GetUser($id: ID!) { user(id: $id) { name email } }
```

Variables:

```json
{"id": "123"}
```

### Detect batching support

Leave the query blank. Open the network in your browser, POST a JSON
array (`[{"query":"{__typename}"}, {"query":"{__typename}"}]`) to the
same endpoint via [Repeater](repeater.md). If the response is an array,
batching is on — file a `passive:graphql-batching-hint` follow-up.

### Pull every type name from the schema

Introspect. Browse the `__schema.types` section; or run:

```graphql
{ __schema { types { name kind } } }
```

### Spot deprecated fields

After introspection, scroll the type tree — fields marked
**(deprecated)** carry `deprecationReason` in the table.

## Storage footprint

**None persistent.** PRGCache stores `url`, `headers_text`,
`query_text`, `vars_text`, `schema_types`, `raw_response`,
`raw_introspection` under a 12-character token (32-entry LRU,
in-memory). Lost on restart.

## CLI

No CLI. For scripted introspection, use the Intruder or write a
plugin (see [Plugins](plugins.md)).

## Troubleshooting

| Symptom                                            | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| "Variables JSON is invalid"                        | Unquoted key, trailing comma, single quotes                             | Pretty-print externally; valid JSON only.                                                        |
| "Could not parse schema"                           | Response has `{"errors": …}` or `{"data": null}`                        | Open *Raw introspection* — confirm the endpoint allows the query.                                |
| Content-Type is always `application/json`          | Hard-coded                                                              | If the server requires `application/graphql`, use [Repeater](repeater.md) and craft the request manually. |
| Internal types missing from the schema view        | Types starting with `__` are filtered                                   | Look at *Raw introspection* JSON for the full structure.                                          |
| Custom HTTP method needed                          | Workbench is POST-only                                                  | Use [Repeater](repeater.md).                                                                     |

## Test contract

- `reqlore/tests/unit/test_web_smoke_phase4.py::test_graphql_index` — page renders.
- `reqlore/tests/unit/test_passive_b1_rules.py::test_graphql_batching_hint_flags_array_post` and `_skips_*` — batching detection.
- `reqlore/tests/unit/test_active_gap_phase1b.py::test_graphql_active_*` — active check fires / skips correctly (batching, did-you-mean, hardened endpoint).
- `reqlore/tests/unit/test_producer_helpers_emission.py::test_graphql_introspection_helper` / `_disabled` — finding helper round-trip.

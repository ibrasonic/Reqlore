# Reqlore — Job runner (`reqlore run`)

`reqlore run` executes a YAML or JSON **job file** against a project: a flat
list of steps that send requests, run scans, render reports, and assert on
the results. It's the headless half of Reqlore — what you use in CI, in a
scheduled task, or to reproduce a finding.

```powershell
reqlore run --project my.rlr jobs/smoke.yaml
reqlore run --project my.rlr jobs/smoke.yaml --strict
```

YAML support requires the `pyyaml` extra (already pulled in by the default
install). JSON works with no extras.

---

## File shape

The top level is either a list of step dicts, or a `{steps: [...]}` wrapper
(useful when you also want to keep notes in the file). Each step is a dict
with a `type` field plus type-specific keys:

```yaml
- type: set
  vars:
    base: https://example.test

- type: request
  method: GET
  url: "{{base}}/healthz"

- type: assert
  expr: status == 200
```

---

## Step types

### `request` — send one HTTP request through the `httpx` engine

| Key | Type | Default | Notes |
|---|---|---|---|
| `method` | string | `GET` | Upper-cased. |
| `url` | string | required | `{{var}}` substitution applies. |
| `headers` | list of `[name, value]` pairs | `[]` | Same shape as the Repeater export. |
| `body` | string \| bytes | `""` | Strings are UTF-8 encoded. |
| `save_as` | string | — | If set, the full response object is stored in `vars[<name>]` and can be read by later steps. |
| `capture` | dict | — | Pull values out of the response into named vars. See below. |
| `save` | bool | `false` | Persist the request/response to project history (so later `scan` steps will see it). |

**`capture`** is the right way to thread data through a chain of requests.
Each entry is `varname: {source: <source>, ...}`. Supported sources:

- `header` — `{source: header, name: Set-Cookie}` reads the named response
  header (first matching value).
- `json` — `{source: json, path: data.token}` decodes the body as JSON and
  walks a dotted path; numeric segments index into lists.

### `scan` — run the passive scanner over recorded history

| Key | Type | Default | Notes |
|---|---|---|---|
| `limit` | int | `5000` | Maximum number of history rows to feed into the passive rules. |

Findings are written to the project's findings table, so a follow-up
`report` step or the `/scanner/` UI will see them.

### `active` — run the active scanner

| Key | Type | Default | Notes |
|---|---|---|---|
| `host` | string | — | Restrict to one host (e.g. `api.example.test`); omit to scan everything. |
| `limit` | int | `50` | Max history rows to use as seeds. |
| `checks` | list of strings | all built-ins | Names of active checks to enable. |
| `max_per_check` | int | `4` | Cap on probes per check per seed (rate budget). |
| `delay_ms` | int | `0` | Delay between probes — bump this on rate-limited targets. |
| `timeout_s` | float | `10.0` | Per-request timeout. |
| `follow` | bool | `false` | Follow HTTP redirects. |

### `report` — render Markdown / HTML / DOCX

| Key | Type | Default | Notes |
|---|---|---|---|
| `out` | string | required | Output path. Format is inferred from suffix unless `format` is set. |
| `format` | string | from suffix | One of `md`, `markdown`, `html`, `docx`. `docx` requires the `python-docx` extra. |

### `set` — assign vars

```yaml
- type: set
  vars:
    target: https://api.example.test
    timeout: 5
```

### `assert` — fail the job if a Python expression is false

The expression is evaluated with a **restricted** environment: only
`vars` (a dict of the current variables), `status` (last response's HTTP
status code, or `0` if no request has run), and `body_text` (last
response body decoded as UTF-8 with replacement). No builtins, no
imports, no attribute access on hidden objects.

```yaml
- type: assert
  expr: status == 200 and "ok" in body_text

- type: assert
  expr: vars["token"] != ""
```

Under `--strict`, a failing assert aborts the run. Without `--strict`,
later steps still execute and the job's overall `ok` is `false`.

### `sleep` — pause N seconds

```yaml
- type: sleep
  seconds: 2.5
```

Used mostly for OAST round-trips where you have to wait for a callback
to arrive before asserting on the result.

---

## Variable substitution

Any string value in any step (recursively, including inside lists and
dicts like `headers`) is scanned for `{{name}}` tokens. Each token is
replaced with the matching key from the current vars dict, or the empty
string if the key isn't set.

Substitution is plain string interpolation — there's no expression
language. If you want to build a value, do the work in `set` or
`capture`, not in the template.

---

## `--strict`

By default the runner records every step's result and keeps going even
when a step fails. With `--strict`, the **first** failure aborts the
run and sets `aborted = true` on the result. CI pipelines want
`--strict`; iterative debugging usually doesn't.

The process exit code is `0` if all steps succeeded and the run wasn't
aborted, otherwise non-zero.

---

## Worked examples

### Smoke-test a deployment

```yaml
- type: set
  vars:
    base: https://staging.example.test

- type: request
  method: GET
  url: "{{base}}/healthz"
- type: assert
  expr: status == 200 and "ok" in body_text

- type: request
  method: GET
  url: "{{base}}/login"
- type: assert
  expr: status == 200
```

### Authenticate, scan the authenticated surface, report

```yaml
- type: request
  method: POST
  url: https://api.example.test/login
  headers:
    - [Content-Type, application/json]
  body: '{"user":"qa","pass":"qa"}'
  capture:
    token:
      source: json
      path: token

- type: request
  method: GET
  url: https://api.example.test/account
  headers:
    - [Authorization, "Bearer {{token}}"]
  save: true

- type: scan
  limit: 1000

- type: report
  out: out/staging-passive.html
```

### OAST callback (delayed assertion)

```yaml
- type: set
  vars:
    oast: r9k7-canary.oast.live

- type: request
  method: POST
  url: https://target.example.test/notify
  headers: [[Content-Type, application/json]]
  body: '{"webhook": "https://{{oast}}/ping"}'

- type: sleep
  seconds: 8

# Run an active check that polls OAST and records a finding if it fired.
- type: active
  host: target.example.test
  checks: [ssrf_oast]
```

### Compose with CI

```yaml
# .github/workflows/nightly.yml (excerpt)
- name: Reqlore smoke
  run: |
    reqlore run --project ci.rlr jobs/smoke.yaml --strict
    reqlore report --project ci.rlr --out out/nightly.html
```

`--strict` makes the CI step fail on the first broken assertion, and
the report contains everything the scan steps recorded.

---

## See also

- [USAGE.md](USAGE.md) — interactive UI walkthroughs.
- [PLUGINS.md](PLUGINS.md) — custom passive rules and copy-as handlers
  invocable from any job via the normal `scan` step.
- [SECURITY.md](SECURITY.md) — the auth model that applies when you bind
  a UI on top of the same project the runner is writing into.

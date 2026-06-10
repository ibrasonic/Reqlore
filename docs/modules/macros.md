# Macros — `/macros/`

Macros are scripted chains of HTTP requests with variable capture and
substitution. The classic use is a login flow: step 1 logs in and
captures `Set-Cookie` + a CSRF token; step 2 uses both. The
[Scanner](scanner.md) can replay a macro every N probes to keep a
session fresh during long active scans.

## Where it is

- **URL:** `/macros/`
- **Nav:** *Macros* in the top bar.
- Per-project — macros persist in `project_state`.

## Quick start

1. Open `/macros/new`. Pick a **name**.
2. Paste a JSON definition (`new.html` ships a template under
   `<details>Show example JSON</details>`).
3. **Save**. You're redirected to `/macros/<id>`.
4. **Run**. Step results table renders with status, duration, captured
   variables.
5. Tweak the JSON, **Save** again. Re-**Run**.

## Routes

| URL                          | Method | What it does                                                            |
|------------------------------|--------|-------------------------------------------------------------------------|
| `/macros/`                   | GET    | List all saved macros.                                                   |
| `/macros/new`                | GET    | Blank form + example JSON.                                              |
| `/macros/new`                | POST   | Validate `Macro.from_json()`, save, 302 to `/macros/<id>`.               |
| `/macros/<mid>`              | GET    | Show macro definition. If `?t=<token>`, also show cached run result.    |
| `/macros/<mid>`              | POST   | Save (`action=save`) or run (`action=run`).                              |
| `/macros/<mid>/delete`       | POST   | Clear `project_state["macro:<mid>"]`.                                    |

## Form fields

| Field        | Type     | Default | Notes                                                                                |
|--------------|----------|---------|--------------------------------------------------------------------------------------|
| `name`       | text     | empty   | Macro name. Required.                                                                |
| `definition` | textarea | empty   | JSON `Macro` definition. Required; invalid JSON flashes an error.                    |
| `action`     | button   | n/a     | `save` or `run`.                                                                     |
| `_csrf`      | hidden   | (gen.)  | CSRF token.                                                                          |

## Macro schema

```json
{
  "name": "login-and-get-csrf",
  "base_headers": {"User-Agent": "Reqlore/1.0"},
  "variables": {"username": "alice"},
  "steps": [
    {
      "name": "login",
      "method": "POST",
      "url": "https://app.example/login",
      "headers": {"Content-Type": "application/x-www-form-urlencoded"},
      "body": "user={{username}}&pass=secret",
      "capture": {
        "session": {"source": "header", "name": "Set-Cookie"},
        "csrf":    {"source": "regex", "where": "body",
                    "pattern": "csrf_token=([A-Za-z0-9]+)"}
      },
      "timeout_s": 10.0,
      "follow_redirects": true
    },
    {
      "name": "verify",
      "method": "GET",
      "url": "https://app.example/account",
      "headers": {"Cookie": "{{session}}", "X-CSRF-Token": "{{csrf}}"}
    }
  ]
}
```

### Capture sources

| `source`   | Required keys                | What it does                                                                       |
|------------|------------------------------|------------------------------------------------------------------------------------|
| `header`   | `name`                       | First occurrence of the named header from the response.                             |
| `regex`    | `where`, `pattern`           | `where` is `body` or `header:<HeaderName>`. Captures `group(1)` if any, else `group(0)`. |
| `json`     | `path`                       | Dotted path (`data.token`, `users.0.id`). Missing keys → empty string.              |

Missing values become `""` — never `None`.

### Substitution

`{{varname}}` substitution applies to URL, header values, body. Regex:
`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`. String-only — no JSON
escaping. If a variable holds quotes, they paste in literally.

## Execution flow

1. Copy `macro.variables` into the run context.
2. For each step, substitute `{{var}}` placeholders, send via
   `httpx_engine` with the step's timeout and `follow_redirects`.
3. If the response carries `.error`, record the error and **break**
   (fail-stop).
4. Else, run the capture spec; update variables.
5. Record `StepResult(name, status, duration_ms, captured, error,
   request_url)`.
6. Return `MacroRun(variables, steps, elapsed_ms)`.

## Show page

After **Run**:

- Step results table: name, URL, status, duration_ms, captured
  variables, error.
- Final variables table: name + value (truncated to 200 chars).

## Accessibility notes

- `<label for="n">Name</label>`, `<label for="def">Definition (JSON)</label>` paired with inputs.
- Step / variables tables use `<caption>` and `<th scope="col">` / `<th scope="row">`.
- Definition textarea is plain (no JSON syntax highlighting — keeps it
  accessible to screen readers; pair with [Decoder](decoder.md)
  `json_pretty` for inspection).

## How it integrates

**Producer:** none — author-created.

**Consumer:**

- [Scanner](scanner.md) — `ActiveOptions.replay_macro` (in `reqlore/scanner/active.py`) is a callable that returns header overrides every N probes. Pass a macro that re-logs-in and re-captures the session cookie.

## Recipes

### Login + use captured cookie

See the quick-start JSON. Two steps; the first captures `Set-Cookie`,
the second sends `Cookie: {{session}}`.

### OAuth code-grant flow

Three steps: `/authorize` (regex-capture `code`), `/token` (JSON-path
capture `access_token`), `/api/me` (header-substitute the token).

### Pre-attack login macro for Scanner

Save the macro. In Scanner's active options, set `replay_macro=<macro id>`,
`replay_every=5`. Every 5th probe the macro runs; its captured headers
are merged into the probe.

### JSON-path capture

Response: `{"data":{"token":"abc"}}`. Capture:
`{"token": {"source":"json","path":"data.token"}}`. Variable `token` =
`"abc"`. If the JSON is `null` or the key is missing, the variable is
`""`.

### Tenant ID fanout into Intruder

Macro captures `tenant_id` from `/config`. In [Intruder](intruder.md),
reference `{{tenant_id}}` in the request template — wait, no:
Intruder doesn't substitute macro vars. Use it the other way around —
pipeline the captured value into the Intruder request manually after
running the macro.

## Storage footprint

| Key                              | Notes                                       |
|----------------------------------|---------------------------------------------|
| `project_state["macro:<id>"]`    | JSON-serialised `Macro` definition.         |
| `project_state["macro:next_id"]` | Auto-increment counter.                     |

Run results live in `_run_cache` (PRGCache, in-memory). No DB writes
for runs.

## CLI

No CLI today — macros are author/save/run via the web UI. To replay a
macro programmatically, import `reqlore.macros.run_macro()` from a
plugin (see [Plugins](plugins.md)).

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `{{var}}` came out literal in the request                 | The variable wasn't captured (missing key, no regex match)              | Confirm the previous step's response actually contained the value. Empty string substitutes silently. |
| Fail-stop on step 1 hid the rest                          | Macros are hard-fail by design                                          | Split into two macros if step 1 is allowed to fail.                                              |
| `Set-Cookie` came back with two cookies, only first kept  | `header` source returns the first occurrence                            | Use a regex source: `{"source":"regex","where":"header:Set-Cookie","pattern":"…"}`.              |
| Variable substitution mangled JSON quotes                 | Substitution is string-only, no JSON escaping                           | Pre-escape, or wrap in a JSON string: `{"name":"{{var}}"}`.                                      |
| JSON path returned empty on a list element                | Use integer indexing: `users.0.id`                                       | Confirm syntax — dotted path with integer index works.                                           |
| Step timed out                                            | `timeout_s` default is 10                                               | Bump it on the slow step.                                                                        |

## Test contract

- `reqlore/tests/unit/test_phase4_modules.py::test_macro_runs_with_variable_capture_and_substitution` — header capture + regex capture + substitution end-to-end.
- `…::test_macro_stops_on_error` — fail-stop semantics.
- `…::test_macro_json_round_trip` — `to_json()` ↔ `from_json()`.
- `…::test_macro_capture_json_path` — dotted JSON-path capture.
- `reqlore/tests/unit/test_active_b0.py::test_replay_macro_merges_new_cookie_into_followups` — scanner integration: `replay_macro` refreshes session headers every N probes.

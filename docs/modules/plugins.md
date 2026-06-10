# Plugins — `/plugins/`

Drop a `.py` file into `~/.rlr/plugins/`, click **Reload plugins**, and
your code is live: passive scanner rules, copy-as renderers (for
[History](history.md)), or even a full Flask blueprint mounted into
the app. Hot-reload via `watchdog` if installed.

> **Plugins run in-process with full Flask privileges.** There is no
> sandbox. Only load code you trust.

## Where it is

- **URL:** `/plugins/`
- **Nav:** *Plugins* in the top bar.
- Plugin directory: `~/.rlr/plugins/` (one level, non-recursive).

## Quick start

1. Drop a `.py` file into `~/.rlr/plugins/`. Minimum: a
   `PLUGIN_INFO = {"name": "my-plugin"}` dict.
2. Open `/plugins/`. Click **Reload plugins** — your plugin appears in
   the *Loaded plugins* table.
3. Add `scanner_rules()` returning passive rules → next
   [Scanner](scanner.md) run picks them up.
4. Or add `copy_as()` returning `CopyAsHandler` objects → renderers
   appear on [History](history.md) detail pages.
5. Optional: click **Enable hot reload (watchdog)** — saved file
   changes auto-trigger reload (requires `pip install watchdog`).

## Routes

| URL                          | Method | What it does                                                            |
|------------------------------|--------|-------------------------------------------------------------------------|
| `/plugins/`                  | GET    | List discovered plugins (status, version, rules count, toggle button).   |
| `/plugins/reload`            | POST   | Force re-scan of plugin directories.                                     |
| `/plugins/<name>/toggle`     | POST   | Enable / disable a single plugin.                                        |
| `/plugins/watch`             | POST   | Enable / disable watchdog hot-reload (`?on=1` / `?on=0`).                  |

**Copy-as integration** (lives in `history_bp`, not `plugins_bp`):

| URL                                       | Method | What it does                                                       |
|-------------------------------------------|--------|--------------------------------------------------------------------|
| `/history/<hid>/copy-as/<name>`           | GET    | Render the request through plugin's `copy_as()` handler. `text/plain`. |

## Plugin interface

| Symbol             | Required | Notes                                                                                    |
|--------------------|----------|------------------------------------------------------------------------------------------|
| `PLUGIN_INFO`      | **yes**  | Dict; must have `"name"`. Recommended: `version`, `description`, `author`, `homepage`, `min_reqlore`. |
| `scanner_rules()`  | optional | Returns iterable of passive rule callables.                                              |
| `copy_as()`        | optional | Returns iterable of `CopyAsHandler(name, render)` objects.                                |
| `register(app)`    | optional | Flask hook; called once with the app — register blueprints / `after_request` handlers. |

Files starting with `_` (e.g. `_helpers.py`) are skipped — convention
for private modules.

## SDK — `reqlore.plugins_sdk`

| Symbol                                                | Purpose                                                                                  |
|-------------------------------------------------------|------------------------------------------------------------------------------------------|
| `make_info(name, version, description, author, homepage, min_reqlore)` | Build a valid `PLUGIN_INFO` dict.                                                     |
| `make_passive_rule(name, severity="info")`            | Decorator. Tags a `(ctx) -> Iterable[Finding]` function with `reqlore_rule_name` and `reqlore_rule_severity`. |
| `CopyAsHandler(name: str, render: callable)`          | Dataclass for copy-as renderers. `render` takes raw request bytes, returns string.        |
| `assert_compatible(info)`                             | Validates `PLUGIN_INFO` — checks `"name"` exists, SDK major-version match. Raises `ValueError`. |

## Discovery

`PluginRegistry.discover()`:

1. Iterate every configured `dirs` entry (default: `[~/.rlr/plugins/]`).
2. `*.py` (non-recursive); skip files starting `_`.
3. `importlib.util.spec_from_file_location()` + `exec_module()`.
4. Pull `PLUGIN_INFO`, `scanner_rules`, `copy_as`, `register` from the
   module.
5. On error (import error, missing/invalid `PLUGIN_INFO`, etc.), store
   the traceback in `PluginRecord.error`; status becomes `error`.
6. Disabled state is preserved across re-discover.

`get_registry()` is a process-wide singleton (thread-safe via
`_REG_LOCK`).

## Hot reload (optional)

Requires `pip install watchdog`. Click **Enable hot reload
(watchdog)** — a `watchdog.observers.Observer` is created per plugin
dir, calling `discover()` on any `.py` change. Persisted in
`project_state["plugin_watch"]`.

## Loaded plugins table

| Column        | Source                                                          |
|---------------|-----------------------------------------------------------------|
| Name          | `PLUGIN_INFO["name"]`                                            |
| Version       | `PLUGIN_INFO["version"]` or `"?"`                               |
| Description   | `PLUGIN_INFO["description"]` or empty                            |
| Status        | `loaded` / `disabled` / `error` (with `<details>` traceback)     |
| Rules         | `len(scanner_rules() or [])`                                     |
| Action        | Toggle button (`Enable` / `Disable`)                             |

If no plugins exist, the page shows a quick-start template (PLUGIN_INFO
+ scanner_rules skeleton).

## Accessibility notes

- `<table>` with `<caption>`, `<th scope="col">`, `<th scope="row">`.
- Plugin folders inside `<fieldset><legend>Plugin directories</legend>`.
- All action buttons are `<form method="post">` with CSRF tokens.
- Error tracebacks wrapped in `<details><summary>traceback</summary>` —
  keyboard-accessible disclosure.

## How it integrates

**Producer:** plugins produce passive scanner rules and copy-as
renderers.

**Consumer:**

- [Scanner](scanner.md) — calls `registry.active_rules()` to pull in
  plugin rules for every passive scan.
- [History](history.md) — calls `registry.active_copy_as()` to render
  per-handler copy-as links on the detail page.

## Recipes

### Hello-world passive rule

```python
# ~/.rlr/plugins/xfo_check.py
from reqlore.plugins_sdk import make_info, make_passive_rule
from reqlore.scanner.findings import Finding

PLUGIN_INFO = make_info(
    name="xfo-check",
    version="0.1",
    description="Flags responses missing X-Frame-Options.",
)

@make_passive_rule("missing-xfo", severity="low")
def check_xfo(ctx):
    for k, _ in ctx.resp_headers:
        if k.lower() == "x-frame-options":
            return
    yield Finding(
        severity="low",
        title="Missing X-Frame-Options",
        host=ctx.host,
        url=ctx.url,
        description="This response allows embedding in frames.",
    )

def scanner_rules():
    return [check_xfo]
```

Drop into `~/.rlr/plugins/`, **Reload**, run [Scanner](scanner.md).

### Copy-as PHP curl

See `examples/plugins/copy_as_php.py`:

```python
from reqlore.plugins_sdk import make_info, CopyAsHandler

PLUGIN_INFO = make_info(name="copy-as-php", version="1.0",
                        description="Render as PHP curl_exec snippet.")

def _render_php(raw_req: bytes) -> str:
    # parse raw_req, build PHP code…
    return "<?php\n// curl boilerplate\n"

def copy_as():
    return [CopyAsHandler(name="PHP curl", render=_render_php)]
```

After **Reload**, the History detail page exposes a "PHP curl" link
that calls `_render_php(row.req_blob)`.

### Custom blueprint

```python
# ~/.rlr/plugins/admin_panel.py
from flask import Blueprint, render_template_string
from reqlore.plugins_sdk import make_info

PLUGIN_INFO = make_info(name="admin-panel", version="1.0",
                        description="Adds /plugin-admin.")

_bp = Blueprint("admin_plugin", __name__, url_prefix="/plugin-admin")

@_bp.route("/")
def admin():
    return render_template_string("<h1>Plugin Admin</h1>")

def register(app):
    app.register_blueprint(_bp)
```

After **Reload**, visit `/plugin-admin/`.

### Toggle a noisy plugin off

`/plugins/` → row → **Disable**. Plugin module stays in memory but its
rules / copy-as handlers are excluded from `active_*()`.

### Hot-reload during development

`pip install watchdog`, click **Enable hot reload**. Save your `.py`,
your plugin reloads. Don't ship enabled in production — file-system
events can fire during a scan.

## Storage footprint

- `project_state["plugin_watch"]` — `"0"` (off, default) or `"1"`.
- `PluginRegistry._plugins` — in-memory dict keyed by plugin name.
- `PluginRecord.enabled` — in-memory bool; preserved across re-discover.

## CLI

No CLI surface. Plugin authoring is purely "drop a `.py` file and
reload".

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Plugin shows `error` status                              | Import error or invalid `PLUGIN_INFO`                                   | Click the `<details>` to see the traceback; fix the file; **Reload**.                            |
| Plugin loaded but its rules don't fire                    | Plugin is disabled, or `scanner_rules()` returned empty                  | Toggle **Enable**; check the rules count in the table.                                            |
| Copy-as link 404s                                        | Two plugins registered the same handler name → silent overwrite          | Use plugin name as prefix (`php-curl`, `node-fetch`).                                            |
| Hot reload button does nothing                            | `watchdog` not installed                                                | `pip install watchdog`, click **Reload plugins**, then **Enable hot reload**.                    |
| SDK version mismatch silently disables                    | `assert_compatible()` rejects mismatched major versions                  | Update `min_reqlore` in your plugin or upgrade Reqlore.                                          |
| A rule crashes mid-scan                                   | Plugin code raised an exception                                          | The scanner catches it per-rule — check stderr for the traceback; fix and reload.                |

## Test contract

- `reqlore/tests/unit/test_plugins.py` — 10 tests covering discovery, error capture, underscore-skip, toggle, register hook, disabled-state preservation, rule isolation, invalid info, copy-as load.
- `reqlore/tests/unit/test_plugins_sdk.py` — 7 tests covering `make_info`, `make_passive_rule`, `assert_compatible` (positive/negative), `CopyAsHandler`, example plugins.
- `reqlore/tests/unit/test_phase6_polish.py` — 3 tests: `active_copy_as()` flattening, history copy-as route, 404 on unknown handler.

Examples in `examples/plugins/`: `copy_as_php.py`, `extra_headers.py`,
`hello_blueprint.py`.

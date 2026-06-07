# Weblore — Plugin API (planned, Phase 3)

Plugins extend Weblore at well-defined hook points. They are plain Python modules and have full access to the project — treat them like browser extensions, not like Java sandboxes.

## Installation

- **Drop-in:** any `*.py` file in `~/.weblore/plugins/` is auto-discovered.
- **Pip:** packages exposing the entry point `weblore.plugins`:

  ```toml
  [project.entry-points."weblore.plugins"]
  myplugin = "myplugin.main:register"
  ```

`register(api)` is called once at startup. Hot reload (dev mode) re-imports on file change.

## API surface

```python
def register(api: "weblore.plugins.api.PluginAPI") -> None:
    api.on_request(my_on_request)
    api.on_response(my_on_response)
    api.add_passive_check(my_check)
    api.add_active_check(my_active)
    api.add_payload_processor("rot47", rot47)
    api.add_menu_item("My Tool", "/x/mytool", my_view)
    api.add_template("mytool.html", "...jinja string...")
    api.add_decoder("base32", b32_encode, b32_decode)
```

All hook functions receive a `ctx` carrying:

- `ctx.request` / `ctx.response` — the dataclasses from `engines.common`
- `ctx.project` — `storage.Project` facade (read/write)
- `ctx.log` — namespaced logger
- `ctx.settings` — plugin-scoped config dict
- `ctx.notify(level, message)` — emits to the live region

Return values:

- `on_request` may return a modified `Request` (proxy modifies in place), `Drop()`, or `None`.
- `on_response` may return a modified `Response` or `None`.
- Passive checks return `list[Finding]`.

## Stability promise

- The `api` object's method signatures are stable across minor versions.
- The `Request`/`Response`/`Finding` dataclasses are stable; new fields will be added with defaults so existing plugins keep working.
- Internal modules (`weblore.storage.*`, `weblore.proxy.*`) are NOT a public API and may change.

## Examples (shipped with repo, Phase 3+)

- `examples/plugins/header_audit.py` — adds passive checks for missing security headers beyond the built-ins.
- `examples/plugins/jq_decode.py` — adds a jq-style JSON path decoder.
- `examples/plugins/burp_state_import.py` — imports a Burp project state file into Weblore.

# Weblore — Plugin API

> **Status:** shipped in Phase 3, expanded in Phase 5. SDK version `1.0`.

Plugins extend Weblore at well-defined entry points. They are plain Python
modules and run **in-process** with full access to the project — treat them
like browser extensions, not like Java sandboxes. The loader catches and
reports import errors so a broken plugin disables itself instead of taking
the whole app down.

---

## Installation

Drop a plugin's `.py` file into:

- **User scope:** `~/.weblore/plugins/` (Linux/macOS) or
  `%USERPROFILE%\.weblore\plugins\` (Windows).
- **Project scope:** a `plugins/` folder next to your `*.weblore` file.

The loader scans both on demand. Click **Reload plugins** in `/plugins/` (or
toggle the *Hot reload* setting in `/settings/` — requires the optional
`[plugins]` extra which installs `watchdog` for filesystem-event-driven
reloads).

Files whose name starts with `_` are ignored, so put shared helpers in
`_helpers.py` and import them from the real plugin.

---

## Required: `PLUGIN_INFO`

Every plugin module **must** expose a `PLUGIN_INFO` dict. The
[`weblore.plugins_sdk`](../weblore/plugins_sdk.py) module ships a helper:

```python
from weblore.plugins_sdk import make_info

PLUGIN_INFO = make_info(
    name="my-plugin",
    version="1.0",
    description="What it does in one sentence.",
    author="you",
    homepage="https://example.invalid/my-plugin",
    min_weblore="0.1",
)
```

`make_info` stamps `sdk_version` on the dict for you. The loader calls
`assert_compatible(PLUGIN_INFO)` and refuses to load a plugin built against
an incompatible SDK major version.

---

## Entry points

A plugin may expose any combination of these three module-level callables.
They are all optional — a plugin that only declares `PLUGIN_INFO` loads
cleanly and shows up as "loaded" on `/plugins/` with no effects.

### `scanner_rules() -> list[Callable]`

Return extra passive-scanner rules. Each rule has the signature
`(ctx: RuleContext) -> Iterable[Finding]` (re-exported from
`weblore.scanner.passive`).

The SDK provides a decorator that tags a rule with a name and severity so
it shows up nicely on the findings page:

```python
from weblore.plugins_sdk import make_passive_rule, make_info
from weblore.scanner.findings import Finding

PLUGIN_INFO = make_info(name="missing-server-timing")

@make_passive_rule("missing-server-timing", severity="info")
def rule(ctx):
    if not ctx.resp.header("server-timing"):
        yield Finding(
            severity="info",
            title="No Server-Timing header",
            host=ctx.host,
            url=ctx.url,
        )

def scanner_rules():
    return [rule]
```

### `register(app) -> None`

Receives the live `flask.Flask` instance, letting a plugin add a
[Blueprint](https://flask.palletsprojects.com/blueprints/), a
`before_request` hook, a Jinja filter, etc. The host calls this exactly
once after the registry settles.

```python
from flask import Blueprint
from weblore.plugins_sdk import make_info

PLUGIN_INFO = make_info(name="hello-blueprint",
                        description="Adds /hello-plugin/ page.")

_bp = Blueprint("hello_plugin", __name__, url_prefix="/hello-plugin")

@_bp.route("/")
def hello():
    return "<h1>Hello from a Weblore plugin</h1>"

def register(app):
    app.register_blueprint(_bp)
```

### `copy_as() -> list[CopyAsHandler]`

Add renderers to the **Copy as...** menu that appears next to a captured
request (History detail, intercept detail). Each handler takes the raw
request bytes and returns a string the user can copy.

```python
from weblore.plugins_sdk import CopyAsHandler, make_info

PLUGIN_INFO = make_info(name="copy-as-php")

def _render_php(raw_req: bytes) -> str:
    # turn raw HTTP/1.1 bytes into a tiny PHP curl snippet
    ...

def copy_as():
    return [CopyAsHandler(name="PHP curl", render=_render_php)]
```

---

## Context object (`RuleContext`)

Passive rules receive a `RuleContext` with at minimum:

- `ctx.req`, `ctx.resp` — the request/response objects.
- `ctx.host`, `ctx.url` — convenience strings for the finding.
- `ctx.resp.header(name)` — case-insensitive header lookup.

See [`weblore/scanner/passive.py`](../weblore/scanner/passive.py) for the
authoritative shape.

---

## What the loader does NOT expose (yet)

These were proposed in older drafts and are **not** part of the current API
— don't write code against them. If you need one, open an issue:

- `api.on_request(...)` / `api.on_response(...)` — proxy hooks. Use a
  match-and-replace rule, or `register()` a Flask `before_request` if a
  UI-side intercept is enough.
- `api.add_active_check(...)` — active-scanner extension. Active rules are
  currently host-internal.
- `api.add_payload_processor(...)` — Intruder payload processor. Not
  pluggable yet.
- `api.add_decoder(...)` — extra Decoder op. The op list is host-internal
  in `weblore/web/blueprints/decoder.py`.

---

## Shipped examples

The repo ships three runnable examples in
[`examples/plugins/`](../examples/plugins/):

| File | Demonstrates |
|---|---|
| [`extra_headers.py`](../examples/plugins/extra_headers.py) | A `scanner_rules()` plugin that flags missing security headers. |
| [`hello_blueprint.py`](../examples/plugins/hello_blueprint.py) | A `register(app)` plugin that adds a Flask route. |
| [`copy_as_php.py`](../examples/plugins/copy_as_php.py) | A `copy_as()` plugin that exports a request as a PHP curl snippet. |

Copy any of them into your plugins folder and they'll show up at
`/plugins/` after a reload.

---

## Stability promise

- `PLUGIN_INFO` keys and the three entry points are stable across minor
  versions.
- `Finding`, `RuleContext`, and `CopyAsHandler` may gain optional fields
  with safe defaults; existing fields will not be renamed without an SDK
  major bump.
- Anything under `weblore.storage.*`, `weblore.proxy.*`, or
  `weblore.engines.*` is **internal** — pin a specific Weblore version if
  you rely on it.

---

## Safety

Plugins run in the same process and can read/write the project file,
network, and filesystem with the same permissions as Weblore itself. Only
install plugins whose source you've read. The `/plugins/` page shows the
on-disk path of every loaded plugin so you can audit at a glance.

# Reqlore — Plugin Author's Guide

> **SDK version:** `1.0` (`reqlore.plugins_sdk.SDK_VERSION`).
> **Status:** stable. Loader, passive-rule hook, copy-as hook, Flask
> hook, and full Plugin Apps framework all shipped.

Plugins extend Reqlore at well-defined entry points. They are plain
Python modules that run **in-process** with full access to the
project — treat them like browser extensions, not like Java sandboxes.
The loader catches every error so a broken plugin disables itself
instead of taking the host down.

Two distinct extension styles live side by side:

1. **Lightweight hooks** — `scanner_rules()`, `copy_as()`,
   `register(app)`. Best for: one passive rule, a custom export
   format, a Flask blueprint that adds a route.
2. **Plugin Apps** (Phase 16) — a `PLUGIN_APP` module attribute that
   produces a complete first-class app with its own URL, settings
   form, Run / Stop buttons, live log, results table, findings
   integration, and an OAST channel. This is the path for building
   community plugins that feel native to Reqlore.

This document covers both. If you are evaluating which style to pick,
skip to [Choosing a style](#choosing-a-style).

---

## Table of contents

1. [Installation & discovery](#installation--discovery)
2. [Required: `PLUGIN_INFO`](#required-plugin_info)
3. [Choosing a style](#choosing-a-style)
4. [Lightweight hooks](#lightweight-hooks)
   - [`scanner_rules()`](#scanner_rules---listcallable)
   - [`copy_as()`](#copy_as---listcopyashandler)
   - [`register(app)`](#registerapp---none)
5. [Plugin Apps](#plugin-apps)
   - [`PLUGIN_APP` / `PLUGIN_APPS`](#plugin_app--plugin_apps)
   - [Settings fields](#settings-fields)
   - [The runner function](#the-runner-function)
   - [`PluginContext` API](#plugincontext-api)
   - [Findings](#findings)
   - [Sending HTTP](#sending-http)
   - [OAST integration](#oast-integration)
   - [Scope awareness](#scope-awareness)
   - [Send-to-plugin (`SeedRequest`)](#send-to-plugin-seedrequest)
   - [Cancellation & timeouts](#cancellation--timeouts)
6. [What the loader does NOT expose](#what-the-loader-does-not-expose)
7. [Bundled examples](#bundled-examples)
8. [Distribution & versioning](#distribution--versioning)
9. [Safety & threat model](#safety--threat-model)
10. [Testing your plugin](#testing-your-plugin)
11. [Stability promise](#stability-promise)

---

## Installation & discovery

Drop a plugin's `.py` file into either:

- **User scope:** `~/.reqlore/plugins/` (Linux/macOS) or
  `%USERPROFILE%\.reqlore\plugins\` (Windows).
- **Project scope:** a `plugins/` folder next to your `*.rlr` file.

The loader scans both directories non-recursively. Click **Reload
plugins** in `/plugins/` (or toggle the *Hot reload* setting in
`/settings/` — requires the optional `[plugins]` extra which installs
`watchdog` for filesystem-event-driven reloads).

Files whose name starts with `_` (e.g. `_helpers.py`) are skipped — use
them for shared modules a real plugin imports.

A broken plugin appears at `/plugins/` with status `error` and a
`<details>` block holding the traceback. Fix the file and click
**Reload plugins**. A failure in one plugin never affects another.

---

## Required: `PLUGIN_INFO`

Every plugin module **must** expose a module-level `PLUGIN_INFO` dict.
Use the SDK helper so the dict is shaped correctly:

```python
from reqlore.plugins_sdk import make_info

PLUGIN_INFO = make_info(
    name="my-plugin",                  # required, unique
    version="1.0",
    description="What it does in one sentence.",
    author="you",
    homepage="https://example.invalid/my-plugin",
    min_reqlore="0.1",
)
```

`make_info` stamps the host SDK version on the dict. At load time the
loader calls `assert_compatible(PLUGIN_INFO)` and refuses to load a
plugin built against an incompatible SDK major version (a `ValueError`
shows in the `/plugins/` error column).

| Key            | Required | Default       | Notes                                                          |
|----------------|----------|---------------|----------------------------------------------------------------|
| `name`         | **yes**  | —             | Must be unique across the loaded set. Display name.            |
| `version`      | no       | `"0.1"`       | Plugin's own version. Show as `v0.1.2` to operators.           |
| `description`  | no       | `""`          | One sentence; shown in the plugins list.                       |
| `author`       | no       | `""`          | Free text.                                                     |
| `homepage`     | no       | `""`          | Linked from the plugins list.                                  |
| `min_reqlore`  | no       | `"0.1"`       | Advisory minimum host version.                                 |
| `sdk_version`  | no       | host SDK      | Stamped by `make_info`. Used by `assert_compatible`.           |

---

## Choosing a style

| Style                | Pick when…                                                                                                                                       | Effort |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|--------|
| `scanner_rules()`    | You want to flag a missing header, a bad cookie attribute, a cleartext token in a body — one pure function per rule, zero UI to design.           | Tiny   |
| `copy_as()`          | You need a new "Copy as PHP", "Copy as Burp", "Copy as Nuclei template" exporter on history rows / intercept detail.                              | Tiny   |
| `register(app)`      | You want to mount a fully custom Flask blueprint (extra page, extra API endpoint, before/after-request middleware).                               | Small  |
| `PLUGIN_APP`         | You're building a tool: it takes user input, runs a workflow against a target, streams progress, and records findings. The community-scale path. | Medium |

A single plugin file can declare **any combination** of these. The
loader picks them up independently.

---

## Lightweight hooks

### `scanner_rules() -> list[Callable]`

Return extra passive-scanner rules. Each rule has the signature
`(ctx: RuleContext) -> Iterable[Finding]` (`RuleContext` is re-exported
from `reqlore.scanner.passive`).

The SDK provides a decorator that tags a rule with a name + severity so
it shows up nicely on the findings page:

```python
from reqlore.plugins_sdk import make_info, make_passive_rule
from reqlore.scanner.findings import Finding

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

**`RuleContext` essentials** (see [reqlore/scanner/passive.py](../reqlore/scanner/passive.py)
for the authoritative shape):

| Attribute / method        | What it is                                                              |
|---------------------------|-------------------------------------------------------------------------|
| `ctx.req`                 | Parsed request — `method`, `url`, `headers` (list of tuples), `body`.    |
| `ctx.resp`                | Parsed response — `status`, `headers`, `body` (bytes).                   |
| `ctx.resp.header(name)`   | Case-insensitive lookup; returns `str` or `None`.                        |
| `ctx.host`, `ctx.url`     | Convenience strings. Use these when building a `Finding`.                |
| `ctx.history_id`          | Integer ID of the originating history row (use as `request_id`).         |
| `ctx.resp_headers`        | List of `(name, value)` tuples (some helpers expect this list shape).    |
| `ctx.resp_body`           | Raw response bytes.                                                      |
| `ctx.status`              | HTTP status code (`int`).                                                |

Rules must be **side-effect free** and finish in single-digit
milliseconds. The passive worker calls every rule on every indexed
response; a slow rule slows the whole pipeline.

### `copy_as() -> list[CopyAsHandler]`

Add renderers to the **Copy as…** menu on History detail and proxy
intercept detail. Each handler takes the raw request bytes and returns
a printable string the operator can copy.

```python
from reqlore.plugins_sdk import CopyAsHandler, make_info

PLUGIN_INFO = make_info(name="copy-as-php")

def _render_php(raw_req: bytes) -> str:
    # Turn raw HTTP/1.1 bytes into a PHP curl_exec snippet.
    ...

def copy_as():
    return [CopyAsHandler(name="PHP curl", render=_render_php)]
```

The host serves the rendered text at `/history/<hid>/copy-as/<name>`
as `text/plain`.

**Tip:** namespace the handler name (`php-curl`, `node-fetch`) so two
plugins can't collide on the same menu label.

### `register(app) -> None`

Receives the live `flask.Flask` instance, letting a plugin add a
[Blueprint](https://flask.palletsprojects.com/blueprints/), a
`before_request` hook, a Jinja filter, etc. Called exactly once after
the registry settles.

```python
from flask import Blueprint
from reqlore.plugins_sdk import make_info

PLUGIN_INFO = make_info(
    name="hello-blueprint",
    description="Adds /hello-plugin/ page.",
)

_bp = Blueprint("hello_plugin", __name__, url_prefix="/hello-plugin")

@_bp.route("/")
def hello():
    return "<h1>Hello from a Reqlore plugin</h1>"

def register(app):
    app.register_blueprint(_bp)
```

If your blueprint POSTs to the host CSRF must round-trip — generate
the token in your template with `{{ csrf_token() }}` exactly like a
built-in form.

---

## Plugin Apps

A Plugin App is a standalone tool with:

* its own URL at `/plugins/app/<slug>/`,
* its own settings form (declarative fields validated by the SDK),
* a **Run** button and a **Stop** button,
* a live, streaming log,
* a live results table,
* a findings hook that writes into the project's `issues` table
  tagged `source = "plugin:<slug>"`,
* a *Send-to-plugin* entry point that prefills the form from a
  captured request,
* an OAST channel for tools that need out-of-band callbacks,
* a cooperative cancel + a per-run timeout.

The framework is the same one Reqlore's bundled
[File Upload Scanner](../reqlore/builtin_plugins/file_upload_scanner.py)
uses; you have parity with the host on day one.

### `PLUGIN_APP` / `PLUGIN_APPS`

Declare at module top level. The loader accepts either:

* `PLUGIN_APP = sdk.make_app(...)` — single app, common case;
* `PLUGIN_APPS = [sdk.make_app(...), sdk.make_app(...)]` — multiple
  apps in one module (rare; useful for "Sublister + Sublister Cleanup"
  style sibling tools).

```python
from reqlore import plugins_sdk as sdk

PLUGIN_APP = sdk.make_app(
    slug="my-tool",                # [a-z0-9_-]+, <= 64 chars
    name="My Tool",                # display name
    description="One sentence.",
    author="you",
    version="0.1",
    fields=[                       # see "Settings fields" below
        sdk.StrField("url", required=True, label="Target URL"),
        sdk.IntField("depth", default=2, min=1, max=10),
    ],
    columns=["status", "size", "note"],   # results table columns
    timeout_s=600,                 # per-run wall clock cap, seconds
    tags=["recon", "subdomain"],
    category="recon",              # used for grouping in the future
)

@PLUGIN_APP.runner
def run(ctx):
    # entry point; receives a PluginContext
    ...
```

### Settings fields

Every field validates its raw form value and returns a typed Python
value. Validation errors surface in the form with the field's label.

| Field                            | Type        | Notable kwargs                              | Validates to |
|----------------------------------|-------------|---------------------------------------------|--------------|
| `StrField(name, ...)`            | one-line    | `placeholder`, `max_len`                    | `str`        |
| `TextField(name, ...)`           | multi-line  | `rows`, `placeholder`, `max_len`            | `str`        |
| `IntField(name, ...)`            | integer     | `min`, `max`                                | `int`        |
| `BoolField(name, ...)`           | checkbox    | —                                           | `bool`       |
| `SelectField(name, choices=...)` | dropdown    | `choices: Sequence[str]` (required)         | `str`        |

Every field supports `label`, `help`, `required`, `default`.
`label` defaults to the field name title-cased; `help` is rendered as
muted help text under the input.

```python
fields=[
    sdk.StrField("url", required=True, label="Target URL",
                 placeholder="https://app.example.com"),
    sdk.SelectField("method", choices=["GET", "POST"], default="POST"),
    sdk.IntField("threads", default=8, min=1, max=64),
    sdk.BoolField("follow_redirects", default=True),
    sdk.TextField("wordlist", rows=8,
                  placeholder="one item per line"),
]
```

The validated values land on `ctx.settings` as a plain `dict`.

### The runner function

```python
@PLUGIN_APP.runner
def run(ctx: sdk.PluginContext) -> None:
    ...
```

The runner is invoked on a daemon thread the host owns. Rules:

* It takes **exactly one** argument (`ctx`). No `*args`, no `self`.
* It returns `None`. Any other return value is ignored.
* It may raise — the runner thread catches and records the traceback
  on the run as `status=error`.
* It should poll `ctx.stop_requested()` (or use `ctx.sleep()` / call
  `ctx.check_stop()`) in any inner loop so the **Stop** button is
  responsive.

### `PluginContext` API

The context is constructed fresh for each run; never reuse it across
runs.

#### Cancellation

| Method                          | What it does                                                                                       |
|---------------------------------|----------------------------------------------------------------------------------------------------|
| `ctx.stop_requested() -> bool`  | Has the operator clicked **Stop**, or has the timeout elapsed?                                      |
| `ctx.check_stop() -> None`      | Raises `sdk.CancelledError` if stop has been requested. Caught by the host runner.                  |
| `ctx.sleep(seconds) -> bool`    | Sleep, but wake early on stop. Returns `True` if the full duration elapsed, `False` if stopped.    |

Prefer `ctx.sleep(2.5)` over `time.sleep(2.5)` — the latter blocks the
runner thread for the full duration even after the operator clicks
**Stop**.

#### Log + progress + results

All three are **fire-and-forget**: a UI failure can never crash the
plugin. Call them as often as makes sense — the UI throttles its own
re-render.

```python
ctx.log("starting", "info")              # level: info|warn|error|debug
ctx.progress(done=12, total=120, message="scanning page 12/120")
ctx.add_result({"status": 200, "size": 4321, "note": "ok"})
```

`add_result` accepts any JSON-serialisable mapping. Keys matching the
app's declared `columns` populate the table; extra keys are kept (use
them to attach evidence you'll later reference from a finding).

#### Settings + scope + seed

| Attribute              | Type                  | Notes                                                                   |
|------------------------|-----------------------|-------------------------------------------------------------------------|
| `ctx.settings`         | `dict[str, Any]`      | Validated form values, keyed by field `name`.                            |
| `ctx.project`          | `Project`             | The host's project object. Use for advanced storage; prefer the helpers below. |
| `ctx.slug`             | `str`                 | Your app's slug.                                                         |
| `ctx.run_id`           | `int`                 | Unique per run; appears in the URL.                                      |
| `ctx.scope`            | `ScopeView`           | Read-only sitemap scope projection (see below).                         |
| `ctx.seed_request`     | `SeedRequest` or `None`  | Captured request the run was seeded from (Send-to-plugin), if any.    |

### Findings

```python
ctx.record_finding(
    title="Reflected XSS in q",
    severity="high",          # info|low|medium|high|critical
    host="app.example.com",
    url="https://app.example.com/search?q=...",
    evidence="<wbr-abc123>",  # short, visible substring matched
    payload="\"'<wbr-abc123>",
    description="Server reflected the payload unescaped in the …",
    remediation="Encode user input on output (HTML entity encoding).",
    cwe="CWE-79",
    owasp="A03:2021 Injection",
    references=["https://owasp.org/Top10/A03_2021-Injection/"],
    confidence="firm",        # tentative|firm|certain
    request_id=ctx.seed_request.history_id if ctx.seed_request else None,
)
```

The host writes the finding to the `issues` table with
`source="plugin:<your-slug>"` and `rule_id="plugin:<your-slug>"`.
Duplicate detection runs server-side; calling `record_finding` twice
with the same dedupe key returns the existing finding id.

### Sending HTTP

```python
resp = ctx.send(
    "POST", "https://app.example.com/login",
    headers=[("Content-Type", "application/x-www-form-urlencoded")],
    body=b"user=alice&pass=hunter2",
    engine="httpx",            # httpx (default) | raw | h3 | curl-cffi[:chrome120]
    timeout=20.0,
    follow_redirects=False,
    verify=False,
)
# resp is a reqlore.engines.Response:
#   resp.status, resp.headers, resp.body, resp.error, resp.timings
```

`ctx.send` never raises — on a transport failure it returns a
`Response` with `status=0` and `error=str(exc)`. Plugins decide
whether that's fatal or retryable.

| Engine                  | When to pick it                                                                                  |
|-------------------------|--------------------------------------------------------------------------------------------------|
| `httpx` (default)       | Anything normal. HTTP/1.1 + HTTP/2 over TLS, cookie jar, redirects.                              |
| `raw`                   | You need byte-exact control (CL.TE smuggling, malformed headers).                                |
| `h3`                    | The target speaks HTTP/3 and you need it (rare).                                                  |
| `curl-cffi:chrome120`   | You need a browser-like TLS / JA3 fingerprint to defeat anti-bot filtering.                       |

Engines that need an optional extra (`raw`, `h3`, `curl-cffi`) silently
fall back to `httpx` when the extra is not installed.

### OAST integration

For SSRF / XXE / blind-injection checks you'll want an out-of-band
callback channel. Reqlore ships a minimal listener.

```python
pair = ctx.oast_token()           # -> (token, callback_url) or None
if pair is None:
    ctx.log("OAST listener not running — skipping SSRF probe", "warn")
else:
    token, oast_url = pair
    # ... use oast_url in your payload ...
    ctx.sleep(5)                   # wait for the target to call back
    for ix in ctx.oast_interactions(token):
        ctx.record_finding(
            title="SSRF via parameter foo",
            severity="high",
            evidence=f"oast kind={ix.kind} remote={ix.remote} path={ix.path}",
            ...
        )
```

`oast_token()` returns `None` when the listener isn't running (extras
not installed, operator hasn't enabled it). Always handle that branch
— never assume OAST is available.

### Scope awareness

`ctx.scope` is a read-only `ScopeView` over the project's sitemap
scope rules. Use it to honour the operator's scope settings.

```python
if not ctx.scope.is_url_in_scope(target_url):
    ctx.log(f"skipping {target_url}: out of scope", "warn")
    return
```

| Method                            | Returns | Notes                                                                          |
|-----------------------------------|---------|--------------------------------------------------------------------------------|
| `ctx.scope.empty`                 | `bool`  | `True` when no rules exist. Convention: empty scope is permissive.             |
| `ctx.scope.is_in_scope(host)`     | `bool`  | Test by host.                                                                  |
| `ctx.scope.is_url_in_scope(url)`  | `bool`  | Test by full URL.                                                              |
| `ctx.scope.hosts()`               | `list[str]` | Host patterns from enabled "include" rules. Useful as a default target list. |
| `ctx.scope.rules`                 | `list[dict]` | Defensive copy of every rule. Inspect when you need the full picture.       |

A scope-aware plugin should usually:

1. If `ctx.scope.empty`: log a warning and proceed against the
   operator's explicit settings (they typed the URL themselves).
2. Else: filter every URL through `is_url_in_scope` before sending.

### Send-to-plugin (`SeedRequest`)

History rows, the proxy intercept detail, and the search results page
all carry a **Send to plugin…** menu. The operator picks any Plugin
App; the host opens that app's detail page with the captured request
pre-attached as `ctx.seed_request` and the form pre-filled where the
plugin opts in.

```python
@PLUGIN_APP.runner
def run(ctx):
    seed = ctx.seed_request
    if seed is not None:
        ctx.log(f"seeded from history#{seed.history_id} {seed.method} {seed.url}")
        # Convenience fields on the seed:
        seed.method        # "GET" / "POST" / ...
        seed.url           # absolute when possible
        seed.host          # Host header value
        seed.path          # request-target
        seed.headers       # list[tuple[str, str]]
        seed.body          # bytes
        seed.raw           # full request blob exactly as captured
        seed.header("authorization")   # case-insensitive lookup
```

For settings prefill from a seed, parse `seed` inside your `run`
function and call `ctx.add_result(...)` / write into your own state.
The default form-prefill mapping is **field name match**: a field
whose `name` is `url` is prefilled with `seed.url` when blank; a
field whose `name` is `method` is prefilled with `seed.method`. To
override, supply explicit values in the form before clicking **Run**.

### Cancellation & timeouts

Two things will stop a run:

1. Operator clicks **Stop** on `/plugins/app/<slug>/runs/<rid>/`.
2. The configured `timeout_s` elapses (set on `make_app`).

Both surface to your runner via `ctx.stop_requested() -> True`. The
host raises `CancelledError` inside `ctx.check_stop()` and inside
`ctx.sleep(...)` (the latter returns `False` and you should
`return` immediately). After the runner returns, the run is recorded
with `status="cancelled"` or `status="timeout"` accordingly.

The runner thread is a *daemon* thread; on host shutdown all in-flight
plugin runs are abandoned. Do not write critical state outside of
`record_finding` / `add_result`.

---

## What the loader does NOT expose

These are intentionally not part of the SDK. Don't write code against
them; open an issue if you need one.

- `api.on_request(...)` / `api.on_response(...)` — proxy interceptor
  hooks. Use a match-and-replace rule (UI-driven), a
  `register(app)` blueprint with a Flask `before_request` if the
  intercept is UI-side, or a Plugin App that consumes a `SeedRequest`.
- `api.add_active_check(...)` — adding to `BUILTIN_ACTIVE_CHECKS` from
  a plugin is intentionally not pluggable. The supported path for
  active probes is a **Plugin App** with its own runner — that scales
  better to user tools (Sublister, dirsearch, Param-Miner) without
  coupling them to the scanner's intensity / preset / coverage
  bookkeeping.
- `api.add_payload_processor(...)` — Intruder payload processor. Not
  pluggable yet.
- `api.add_decoder(...)` — Decoder op. The op list lives in
  [reqlore/web/blueprints/decoder.py](../reqlore/web/blueprints/decoder.py)
  and is host-internal.

---

## Bundled examples

The repo ships three runnable lightweight-hook examples in
[examples/plugins/](../examples/plugins/):

| File                                                              | Demonstrates                                                                 |
|-------------------------------------------------------------------|------------------------------------------------------------------------------|
| [extra_headers.py](../examples/plugins/extra_headers.py)          | A `scanner_rules()` plugin that flags missing security headers.              |
| [hello_blueprint.py](../examples/plugins/hello_blueprint.py)      | A `register(app)` plugin that adds a Flask route.                            |
| [copy_as_php.py](../examples/plugins/copy_as_php.py)              | A `copy_as()` plugin that exports a request as a PHP curl snippet.           |

For a full-fat **Plugin App** reference, read
[reqlore/builtin_plugins/file_upload_scanner.py](../reqlore/builtin_plugins/file_upload_scanner.py).
It exercises every API in this guide: a long settings form with
every field type, multipart construction, re-download oracle,
OAST callbacks, RCE-marker verification, structured findings,
progress streaming, and cooperative cancel.

---

## Distribution & versioning

There is no plugin registry. The community convention is:

* One repo per plugin. Name it `reqlore-<your-slug>`.
* `README.md` with: what it does, a screenshot of the
  `/plugins/app/<slug>/` page, an install line, the minimum
  Reqlore version, and a list of every Field the form exposes.
* Pin Reqlore's minor version in `min_reqlore` if you import
  anything outside `reqlore.plugins_sdk` / `reqlore.scanner.findings`.
* Tag releases. Reqlore is `pip`-installable, so a plugin can
  declare `reqlore>=0.2,<0.3` and stay honest about compatibility.

To ship: the operator clones (or downloads) your repo and copies the
single `.py` file (or the package's entry point) into
`~/.reqlore/plugins/`. There is no install command, no manifest, no
sandbox.

---

## Safety & threat model

Plugins run in the same process as Reqlore and inherit every
permission Reqlore itself has. There is **no sandbox**.

A plugin can:

* read / write the project file (`*.rlr`),
* read / write the filesystem (anywhere the user can),
* open arbitrary network sockets,
* mutate the Flask app in `register(app)`,
* read every captured request, response, and saved session.

Treat plugins like Chrome extensions: only install code you have
read. The `/plugins/` page shows the on-disk path of every loaded
plugin so you can audit at a glance. The
[docs/SECURITY.md](SECURITY.md) policy applies in full to plugins —
if a plugin you wrote has a vulnerability, please report it.

Defensive practices for plugin authors:

* Never `eval()` or `exec()` user-supplied input.
* When you write to the filesystem, write under `tempfile.mkdtemp()`
  or a path under `~/.reqlore/plugin-data/<slug>/`. Never write into
  `~/.reqlore/plugins/` (you'd trigger your own hot-reload loop).
* Treat every value in `ctx.seed_request` as attacker-controlled —
  the operator may have captured it from a hostile target.
* Use `ctx.send` rather than rolling your own `requests` / `httpx`
  call so the operator's upstream proxy and rate-limit settings are
  honoured.
* Surface errors through `ctx.log("...", "error")` and
  `ctx.record_finding(severity="info", title="plugin-internal: ...")`
  rather than crashing the run.

---

## Testing your plugin

`reqlore.plugins_sdk` is fully importable in a plain pytest run.

```python
# tests/test_my_plugin.py
import importlib.util
from pathlib import Path

def _load(path):
    spec = importlib.util.spec_from_file_location("p", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def test_plugin_info_is_valid():
    from reqlore.plugins_sdk import assert_compatible
    mod = _load(Path(__file__).parent.parent / "my_plugin.py")
    assert_compatible(mod.PLUGIN_INFO)

def test_settings_validate_minimal():
    mod = _load(Path(__file__).parent.parent / "my_plugin.py")
    settings = mod.PLUGIN_APP.validate_settings({"url": "https://x.test/"})
    assert settings["url"] == "https://x.test/"
```

For runner tests, build a `PluginContext` with mocked callbacks and
call `mod.PLUGIN_APP.runner_fn(ctx)` directly. See
[reqlore/tests/unit/test_phase16_plugin_apps.py](../reqlore/tests/unit/test_phase16_plugin_apps.py)
for the host-side patterns; the same shape works for plugin authors.

---

## Stability promise

The following are stable across **minor** Reqlore versions:

* `PLUGIN_INFO` keys + `make_info(...)` kwargs.
* The five entry points: `scanner_rules`, `copy_as`, `register`,
  `PLUGIN_APP`, `PLUGIN_APPS`.
* `Finding`, `RuleContext`, `CopyAsHandler` field names.
* `make_app(...)` kwargs and `PluginApp` public attributes.
* Every `Field` subclass constructor signature.
* Every `PluginContext` public method documented above.
* `SeedRequest` field names.

Fields may **gain** optional keyword arguments with safe defaults. No
existing kwarg will be renamed without an SDK major bump (the host
will refuse to load the plugin, surfacing the version mismatch
loudly in `/plugins/`).

Anything under `reqlore.storage.*`, `reqlore.proxy.*`,
`reqlore.engines.*` (other than the `Request` / `Response` types you
receive via `ctx.send`), `reqlore.web.*`, and any
`reqlore.scanner.*` module other than `findings` and `passive` is
**internal** — pin a specific Reqlore version if you rely on it.

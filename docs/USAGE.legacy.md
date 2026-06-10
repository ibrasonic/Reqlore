# Reqlore — User Guide

A complete, end-to-end walkthrough of every Reqlore module: what it does, how
to drive it from the keyboard, and how to use it against a live target.

This guide assumes Reqlore is already installed. If not, jump to
[Install](#install) first.

---

## Table of contents

1. [Install](#install)
2. [First run](#first-run)
3. [CLI reference](#cli-reference)
4. [The 28 modules](#the-28-modules)
   - [Dashboard](#dashboard-)
   - [Proxy](#proxy-proxy)
   - [History](#history-history)
   - [Repeater](#repeater-repeater)
   - [Intruder](#intruder-intruder)
   - [Param miner](#param-miner-param-miner)
   - [Scanner](#scanner-scanner)
   - [Comparer](#comparer-comparer)
   - [Decoder](#decoder-decoder)
   - [JWT workbench](#jwt-workbench-jwt)
   - [Sitemap](#sitemap-sitemap)
   - [Match & replace](#match--replace-match-replace)
   - [Search](#search-search)
   - [Reporter](#reporter-reporter)
   - [Plugins](#plugins-plugins)
   - [Audio cues](#audio-cues-cues)
   - [Settings](#settings-settings)
   - [Help](#help-help)
   - [GraphQL](#graphql-graphql)
   - [WebSocket](#websocket-ws)
   - [SAML](#saml-saml)
   - [PoC builder](#poc-builder-poc)
   - [Macros](#macros-macros)
   - [Sequencer](#sequencer-sequencer)
   - [OAST receiver](#oast-receiver-oast)
   - [HTTP/2 workbench](#http2-workbench-h2)
   - [Smuggling lab](#smuggling-lab-smuggling)
   - [Scheduler](#scheduler-schedule)
5. [Engines](#engines)
6. [Accessibility](#accessibility)
7. [Docker](#docker)
8. [Troubleshooting](#troubleshooting)

---

## Install

Requires Python 3.12 or newer (3.14 tested).

```powershell
git clone https://github.com/ibrasonic/Reqlore.git
cd Reqlore
py -m pip install -e .[dev]
```

Optional extras:

| Extra          | Purpose                                                         |
| -------------- | --------------------------------------------------------------- |
| `[dev]`        | Test + lint tools (`pytest`, `ruff`, `mypy`)                    |
| `[h3]`         | HTTP/3 + QUIC engine (`aioquic`)                                |
| `[impersonate]`| TLS-fingerprint impersonation engine (`curl-cffi`)              |
| `[report]`     | `.docx` report export (`python-docx`)                           |
| `[plugins]`    | Hot-reload plugin folder (`watchdog`)                           |
| `[yaml]`       | YAML job runner (`PyYAML`)                                      |
| `[a11y]`       | Headless axe-core CI gate (`playwright`, `axe-playwright-python`) |
| `[schedule]`   | APScheduler backend for the Scheduler module                    |

Install several at once:

```powershell
py -m pip install -e .[dev,h3,impersonate,report,yaml,schedule]
```

---

## First run

```powershell
reqlore init my.rlr
reqlore ui    --project my.rlr        # http://127.0.0.1:8787
reqlore proxy --project my.rlr        # MITM on 127.0.0.1:8080
reqlore both  --project my.rlr        # both in one process
```

A **project** is a single SQLite file (`*.rlr`). It holds the proxy history,
findings, plugins state, match-replace rules, scheduler jobs, and settings.
Move it like any file.

To trust the proxy's CA in your browser, open `http://127.0.0.1:8787/proxy/`
and click *Download CA*. Install the resulting `.crt` into the browser's
*Authorities* store.

---

## CLI reference

```text
reqlore init <project_path>
reqlore ui     --project <p> [--host H] [--port N] [--unsafe-bind] [--no-password]
reqlore proxy  --project <p> [--port N]
reqlore both   --project <p> [--host H] [--ui-port N] [--proxy-port N] [--unsafe-bind] [--no-password]
reqlore scan   --project <p> [--limit N]            # passive scanner over history (default --limit 5000)
reqlore report --project <p> --out FILE [--format md|html|docx]
reqlore run    --project <p> JOB.{yaml|yml|json} [--strict]
reqlore import-har --project <p> SESSION.har
reqlore browser  [--proxy-port N] [--url URL]
                 [--firefox-version V] [--firefox-zip FILE]
                 [--use-system] [--wait]
reqlore prefetch-firefox [--firefox-version V] [--firefox-zip FILE] [--force]
```

`--unsafe-bind` is the only way to bind a non-loopback address; it exists so
you can deliberately put Reqlore on a lab-only interface. Never expose to the
public internet.

When `--unsafe-bind` is set, Reqlore refuses to start unless you also set
`REQLORE_PASSWORD` (plaintext, argon2id-hashed in memory at startup) or
`REQLORE_PASSWORD_HASH` (pre-computed argon2id hash). Loopback clients
never need a password — if you're on the same machine you already have
filesystem access to the project. Use `--no-password` only when you front
Reqlore with your own authenticating reverse proxy (nginx with auth_basic,
Caddy `basic_auth`, `oauth2-proxy`, Cloudflare Access, etc.). See
[`docs/SECURITY.md`](SECURITY.md#ui-authentication) for the full model.

## Environment variables

All CLI flags can be overridden via environment variables. Resolution order:
CLI flag > environment variable > project setting > user config > defaults.

| Variable | Overrides | Notes |
|---|---|---|
| `REQLORE_UI_HOST` | `--host` | Default `127.0.0.1`. |
| `REQLORE_UI_PORT` | `--port` / `--ui-port` | Default `8787`. |
| `REQLORE_PROXY_HOST` | (proxy bind host) | Always `127.0.0.1`; setting otherwise is unsupported. |
| `REQLORE_PROXY_PORT` | `--port` (proxy) / `--proxy-port` | Default `8080`. |
| `REQLORE_PASSWORD` | (UI password, plaintext) | Hashed once at startup with argon2id. Required for `--unsafe-bind` unless you pass `--no-password`. |
| `REQLORE_PASSWORD_HASH` | (UI password, pre-hashed) | Use this in systemd unit files / container secrets so the plaintext never lives in env. Must be a valid argon2id hash (`$argon2id$…`). |
| `REQLORE_SESSION_MAX_AGE` | (login cookie lifetime, seconds) | Default `28800` (8 hours). Minimum 60. |
| `REQLORE_VERBOSE` | `-v` / `--verbose` | Set to `1` to enable INFO logging globally. |
| `REQLORE_NO_PIPX` | (installer) | Set to `1` to force the install script to use a venv instead of `pipx`. |
| `REQLORE_VENV` | (installer) | Custom venv path used by the install script (default `.venv`). |
| `REQLORE_NO_AUTODEPS` | (browser launcher) | Set to `1` to skip the auto-install of Linux runtime libraries Firefox depends on. |
| `REQLORE_DATA` | (Docker only) | Project data directory inside the container; default `/data`. |

**Pre-hashing a password** (recommended for shared deployments):

```powershell
py -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('your-passphrase-here'))"
```

Store the output as `REQLORE_PASSWORD_HASH` and you never have to put the
plaintext in your shell history or process listing.

---

## Pre-configured Firefox (`reqlore browser`)

`reqlore browser` launches a **dedicated Firefox profile** that is already:

- Pointed at the Reqlore MITM proxy (`127.0.0.1:8080`)
- Trusting the Reqlore CA (so HTTPS interception just works, no manual cert
  import)
- Locked down: no telemetry, no auto-update, no Firefox accounts, no Pocket,
  no password manager, no "default browser" nag
- Opened on the Reqlore UI

Your existing host Firefox install is **never touched**. The dedicated profile
lives under your user data folder (`~/.reqlore/firefox-profile/` on Linux,
`%APPDATA%\reqlore\firefox-profile\` on Windows).

### How Firefox is obtained

1. **Host install** — if `firefox` is on PATH, it's used as-is (pass
   `--use-system` to force this even when a cached copy exists).
2. **First-run download** — otherwise the official portable build from
   `archive.mozilla.org` is downloaded once (~80 MiB), SHA-256 verified
   against Mozilla's published `SHA256SUMS`, and extracted into
   `~/.reqlore/firefox/<version>/`. Subsequent launches use the cache.
3. **Air-gapped / pre-staged** — pass `--firefox-zip <path>` pointing at a
   Mozilla zip/tar.xz you downloaded ahead of time, or run
   `reqlore prefetch-firefox` once on an online box and copy the cache.

### Examples

```powershell
# Most common — just launch.
reqlore browser

# Pin a specific Firefox version.
reqlore browser --firefox-version 127.0

# Offline: use a pre-staged archive.
reqlore browser --firefox-zip C:\offline\firefox-127.0.zip

# Use the host's own Firefox (skip the managed cache).
reqlore browser --use-system

# Pre-download for offline use later (no launch).
reqlore prefetch-firefox
reqlore prefetch-firefox --firefox-version 127.0
```

### Platform support

| OS      | Supported       | Notes                                                                 |
| ------- | --------------- | --------------------------------------------------------------------- |
| Windows x64 | ✅ download or system | `firefox-<ver>.zip` from archive.mozilla.org                    |
| Linux x86_64 | ✅ download or system | `firefox-<ver>.tar.xz` from archive.mozilla.org                  |
| macOS   | system only     | Install Firefox.app manually; auto-download not implemented (.dmg).   |
| Docker  | system only     | The image is headless; run Firefox on the host instead.               |

---

## The 28 modules

Every page is reachable from the top nav. Every interactive control has a
visible label and a keyboard shortcut listed on `/help/`. Page titles follow
the pattern `Reqlore — <module>` so a screen reader's title-read command names
the current page immediately.

### Dashboard — `/`

At-a-glance counts: requests captured, findings by severity, scheduler state,
last update check (if enabled).

- **Press:** `Tab` from the address bar lands on the nav, then `Enter` to open
  any module.

### Proxy — `/proxy/`

Intercepting MITM. The held-request queue lists each pending request with
*Forward edited*, *Forward as-is*, and *Drop* buttons, plus a "Send to..."
menu so you can dispatch the held request into any other panel without
forwarding it first.

- **Read order:** breadcrumb → request summary (`<dl class="meta">`) →
  editable request `<textarea>` → action bar → "Send to..." list.
- **Action bar accesskeys** (browser-native; Alt on Chrome/Edge, Alt+Shift
  on Firefox, Ctrl+Alt on macOS):
  - **e** — Forward edited
  - **a** — Forward as-is
  - **p** — Drop request (`button.danger`)
- **Send to... targets** (each with its own accesskey, all open the target
  panel pre-populated with the held request — the request is also snapshotted
  to History so you don't lose it):
  - **r** — Repeater
  - **i** — Intruder
  - **m** — Comparer (side A)
  - **b** — PoC builder
  - **j** — JWT workbench
  - **o** — Decoder
- **Send all (queued) to Repeater** — one-shot button at the top of the
  intercept-queue listing; ships every currently-held request into Repeater
  tabs at once.
- **CA install:** *Download CA* button on `/proxy/` serves the on-disk PEM.

> The single-letter shortcuts are HTML `accesskey` attributes, which the
> browser handles **before** the screen reader's browse-mode layer — so they
> work in NVDA without the usual single-letter-quick-nav collisions.

### History — `/history/`

A paginated table of every captured request. Columns: id, method, host, path,
status, length, engine, tags, time. Each row has a *Detail* link.

The detail page (`/history/<id>/`) shows the raw request bytes, raw response
bytes, decoded body, and a *Send to* dropdown (Repeater / Intruder / Comparer
/ PoC builder / JWT workbench / Decoder). If any plugin registers `copy_as()`
handlers, they appear as links under "Copy as:".

### Repeater — `/repeater/`

Edit + replay any request. Six engines selectable per send:

- `httpx` — default, HTTP/1.1 + HTTP/2 over TLS.
- `raw` — raw socket, sends the exact bytes you typed.
- `h3` — HTTP/3 over QUIC (requires `[h3]` extra).
- `curl-cffi:chrome120` / `safari17_0` / `firefox109` — real-browser TLS
  fingerprint via curl-cffi (requires `[impersonate]` extra).

The response panel always shows status, headers, and body separately so a
screen reader can skip to whichever it wants.

### Intruder — `/intruder/`

Bulk request attack tool. Place `§marker§` in your request template, paste
a payload list, choose an attack type:

- **Sniper** — one marker, one payload at a time.
- **Battering ram** — same payload into every marker.
- **Pitchfork** — parallel lists into multiple markers.
- **Cluster bomb** — Cartesian product across all marker lists.

Same engine picker as Repeater. Results table sortable by status, length, and
time.

### Param miner — `/param-miner/`

Discover hidden query, body, or header parameters. Built-in 200-word list;
detection signals: reflected sentinel value, status code change, or body
length change beyond a configurable tolerance (default 16 bytes).

1. Paste a request URL.
2. Choose **location**: `query`, `body`, or `header`.
3. *Start mining*. The result table lists each parameter the server reacted
   to, plus the signal that triggered the find.

### Scanner — `/scanner/`

Both passive and active checks.

- **Passive** runs automatically over each new history row. Looks for missing
  security headers, cookie flag issues, reflected content, weak TLS, etc.
- **Active** is opt-in; pick a row, choose checks, hit *Run active*.
  Includes `OASTSSRFCheck` which auto-wires the running OAST receiver and
  injects its callback URL into every query/form parameter (escalates to a
  CWE-918 high-severity finding on a hit).

### Comparer — `/comparer/`

Diff two byte strings or two history rows. Three views: side-by-side, unified
diff, character-by-character. Useful for blind injection: replay with a
benign payload, replay with the malicious one, diff the responses.

### Decoder — `/decoder/`

A single textarea + an op dropdown + Run. The full op list:

| Op | What it does |
|---|---|
| `url_encode` | Percent-encode every reserved character (`quote(s, safe="")`). Use for a single value you'll drop into one URL slot. |
| `url_decode` | `unquote_plus` — decodes both `%20` and `+` to a space. |
| `form_encode` | **URL encode (form body, keep `&` and `=`).** Splits on `&` and then on the first `=`, encodes the key and value separately, rejoins. Use this when you want to decode a body, edit one value, and re-encode without `&`/`=` inside values being promoted into new param boundaries. |
| `form_decode` | **URL decode (form body, keep `&` and `=`).** Same split, `unquote_plus` on each side. |
| `html_encode` / `html_decode` | HTML entity escape / unescape (quotes included). |
| `b64_encode` / `b64_decode` | Standard base64 (strict on decode — rejects garbage rather than silently returning replacement chars). |
| `b64url_encode` / `b64url_decode` | URL-safe base64; `b64url_encode` strips padding. |
| `hex_encode` / `hex_decode` | Hex; decoder is liberal — accepts whitespace, `:` / `-` / `_` separators, and a leading `0x`. |
| `gzip_encode` / `gzip_decode` | Gzip wrapped in base64 (so you can paste it into a text field). |
| `deflate_encode` / `deflate_decode` | Raw zlib wrapped in base64. |
| `rot13` | Classic ROT-13. |
| `md5` / `sha1` / `sha256` / `sha512` | One-way hashes (hex digest). |
| `jwt_decode` | Decode a JWT without verifying — emits `{header, payload}`. |
| `json_pretty` / `json_minify` | JSON reformatters. |
| `smart_decode` | Iteratively tries url_decode → b64_decode → jwt_decode (with strict shape gates) until the output stops changing or stops looking printable. |

**Typical Intercept → Decoder → Intercept flow:** on the held request, press
**Send to...** → **Decoder** (accesskey `o`); pick `form_decode`; edit one
value in the readable output; switch the op to `form_encode`; Run; copy the
result back into the intercept textarea; *Forward edited*.

### JWT workbench — `/jwt/`

Parse / verify / re-sign JSON Web Tokens. Targeted attacks:

- `alg=none` strip + re-encode.
- HS256 secret crack (built-in 10k wordlist + custom).
- `kid` injection.
- Re-sign with arbitrary HS256 / RS256 keys.

### Sitemap — `/sitemap/`

A tree of every host & path observed. Each leaf links back to the latest
history row for that endpoint. Useful for picking targets to send to the
scanner.

### Match & replace — `/match-replace/`

Persistent rewrite rules applied by the proxy as bytes flow. Each rule has
four fields:

- **Where** — `request` (only outbound) or `response` (only inbound).
- **Part** — `headers`, `body`, or `both`.
- **Match** — either a `literal` substring or a Python `regex`. Regex uses
  the standard `re` module (no `regex` extension), and the rule body is
  the *replacement* string (`\1`, `\2` for capture groups when match is
  regex; literal text otherwise).
- **Scope** — optional host filter (`example.com`, `*.target.test`) so a
  rule only fires on the assets you actually want to rewrite.

Each rule has an *enabled* toggle so you can keep half a dozen rules
built-up over a long engagement and flip them on per task without losing
them. Rules are evaluated in order, top-down; the first match wins per
part (a `headers`-only rule never touches the body, and vice-versa).

The rule set is persisted in the project file and is exported with the
project — hand someone a `.rlr` and your match-replace rules travel with
it. The CSV-shaped table on the page is also the import surface: paste a
set of rules in and *Save* to install them in bulk.

Examples that show up often:

| Goal | Where | Part | Match | Replace |
|---|---|---|---|---|
| Force a user header on every outbound request | `request` | `headers` | `^User-Agent:.*$` (regex) | `User-Agent: Reqlore-test/1.0` |
| Add a tracing header for the dev team | `request` | `headers` | `^Host:` (regex) | `X-Reqlore-Trace: 1\r\nHost:` |
| Strip CSP so XSS PoCs render in-browser | `response` | `headers` | `^Content-Security-Policy:.*$\r\n` (regex) | `` (empty) |
| Pin a feature flag the back-end echoes | `response` | `body` | `"experimental_search":\s*false` (regex) | `"experimental_search": true` |
| Tag every API response with the test phase | `response` | `body` | `</body>` (literal) | `<!-- reqlore-phase-3 --></body>` |

If you need request-or-response-shaped logic that does more than text
rewriting (e.g. "only when the response is JSON and status is 401"), use
a plugin instead — see [`docs/PLUGINS.md`](PLUGINS.md).

### Search — `/search/`

Full-text search across request headers, request bodies, response headers,
response bodies, and findings. FTS5-backed.

### Reporter — `/reporter/`

Export a project's findings. Formats: Markdown, HTML, DOCX. Pick severities
to include, choose an export path, *Build report*.

Equivalent CLI: `reqlore report --project p.rlr --out report.docx`.

### Plugins — `/plugins/`

Lists installed plugins, their loaded state, and the routes / panels / handlers
they register. Plugins live in `~/.reqlore/plugins/` (or
`%USERPROFILE%\.reqlore\plugins\` on Windows) and follow the API in
[`PLUGINS.md`](PLUGINS.md).

### Audio cues — `/cues/`

Opt-in non-speech audio for: new request captured, new finding, scanner done,
update available. Each cue has a slider for volume and a *Test* button. Off by
default.

### Settings — `/settings/`

Theme (light / dark / high-contrast), verbosity (concise / standard / verbose),
keyboard map (remappable per action), audio cue toggles, opt-in update check.

Press *Check for updates now* (only enabled when update check is on) to
manually poll the manifest URL. The check never runs automatically.

### Help — `/help/`

Searchable keyboard-shortcut map plus a one-screen self-test that walks
through every key.

### GraphQL — `/graphql/`

Send GraphQL queries with variables. Built-in helpers for `__schema`
introspection, field-by-field fuzzing, and persisted-query forging.

### WebSocket — `/ws/`

Connect to a WS endpoint, send framed messages (text or binary), watch the
live transcript. Built-in CSWSH test: spin a tab from `/ws/cswsh` and watch
which origins the target accepts.

### SAML — `/saml/`

Parse SAML responses and assertions. Re-sign with arbitrary keys, mutate
`NameID`, strip signatures, test XSW (Signature Wrapping) variants.

### PoC builder — `/poc/`

Convert a captured request into a one-file exploit:

- Self-submitting HTML form (CSRF).
- `fetch()` snippet.
- `curl` one-liner.
- Raw HTTP bytes.

### Macros — `/macros/`

Chains of requests run in order, with response-to-request variable extraction
(regex + JSON pointer). Wire a macro into the proxy as a *pre-request hook*
to auto-refresh CSRF tokens, JWTs, etc.

### Sequencer — `/sequencer/`

Capture N samples of a token (cookie, JWT, CSRF), then estimate entropy with
FIPS 140-2 bitstream tests + character-frequency analysis. Use to grade the
unpredictability of session IDs, password reset tokens, etc.

### OAST receiver — `/oast/`

Built-in out-of-band receiver listening on a configurable port. Exposes a
public callback URL (you bring your own DNS/port-forward). Logs HTTP, DNS,
SMTP probes. Drives the `OASTSSRFCheck` active scan.

### HTTP/2 workbench — `/h2/`

Hand-craft individual HTTP/2 frames over a single connection. Useful for
request smuggling and stream-ID confusion testing.

### Smuggling lab — `/smuggling/`

Pre-built request templates for CL.TE, TE.CL, TE.TE, and H2.CL smuggling
variants. Send through any of the three forwarding engines and diff the
front-end vs back-end response.

### Scheduler — `/schedule/`

Recurring passive scans that survive restarts.

1. Click *Add job*.
2. Enter a name and an interval in seconds (minimum **30**).
3. Choose how many recent history rows to scan per run (default 1000).
4. *Save*, then *Start* the scheduler.

If `[schedule]` is installed APScheduler runs the jobs. Otherwise a tiny
thread-based loop drives them. Jobs persist to the project file under the
state key `sched:jobs`.

---

## Engines

| Engine                        | Wire protocol                         | When to use                       |
| ----------------------------- | ------------------------------------- | --------------------------------- |
| `httpx` (default)             | HTTP/1.1 + HTTP/2 over TLS            | Anything modern                   |
| `raw`                         | Raw bytes, no parsing                 | Smuggling, malformed headers      |
| `h3`                          | HTTP/3 over QUIC                      | Sites that prefer h3              |
| `curl-cffi:chrome120`         | TLS+H2 with Chrome 120 fingerprint    | TLS-fingerprint WAF bypass        |
| `curl-cffi:safari17_0`        | TLS+H2 with Safari 17 fingerprint     | Same                              |
| `curl-cffi:firefox109`        | TLS+H2 with Firefox 109 fingerprint   | Same                              |

All six show up in Repeater, Intruder, and (for forwarding) the proxy chain.

---

## Accessibility

Reqlore is built specifically for screen-reader users (NVDA, JAWS, Orca,
VoiceOver). Highlights:

- 100 % semantic HTML5. Every page validates against axe-core (run
  `pytest reqlore/tests/a11y -q` after installing the `[a11y]` extra).
- Every form control has an explicit `<label for=>`.
- Every table has captions, scoped headers, and a "Read as list" alternate
  view (per the cues on `/cues/`).
- High-contrast theme on `/settings/` toggles WCAG-AAA color pairs.
- Audio cues are opt-in, off by default, with per-cue volume.
- Keyboard map is fully remappable; the *Help* page has a self-test.
- See [`ACCESSIBILITY.md`](ACCESSIBILITY.md) for the full WCAG 2.2 AA
  conformance map.

---

## Docker

A multi-stage `Dockerfile` ships at the project root. Build & run:

```powershell
docker build -t reqlore:latest .

# Initialize a project file on the host (one-time)
docker run --rm -v ${PWD}:/data reqlore:latest init /data/my.rlr

# Run the UI (always on loopback inside the container)
docker run --rm -it `
  -v ${PWD}:/data `
  -p 127.0.0.1:8787:8787 `
  reqlore:latest ui --project /data/my.rlr --host 0.0.0.0 --port 8787 --unsafe-bind

# Run the proxy
docker run --rm -it `
  -v ${PWD}:/data `
  -p 127.0.0.1:8080:8080 `
  reqlore:latest proxy --project /data/my.rlr

# Run both in one container
docker run --rm -it `
  -v ${PWD}:/data `
  -p 127.0.0.1:8787:8787 `
  -p 127.0.0.1:8080:8080 `
  reqlore:latest both --project /data/my.rlr --host 0.0.0.0 --unsafe-bind
```

`--unsafe-bind` is required inside the container because the entrypoint binds
`0.0.0.0` so the host port-forward works. The host-side `-p` flag still pins
to loopback, so the listener is only reachable from your workstation.

A `docker-compose.yml` is provided for the "both" mode:

```powershell
docker compose up --build
```

---

## Troubleshooting

| Symptom                                     | Fix                                                                                  |
| ------------------------------------------- | ------------------------------------------------------------------------------------ |
| `ModuleNotFoundError: aioquic`              | `pip install -e .[h3]`                                                               |
| `ModuleNotFoundError: curl_cffi`            | `pip install -e .[impersonate]`                                                      |
| Scheduler "backend: thread" instead of apsched | `pip install -e .[schedule]`                                                      |
| Browser refuses proxy CA                    | Install into the browser's *Authorities* store, not the OS store.                    |
| Update check button is disabled             | Toggle *Update check* on in `/settings/` and *Save settings* first.                  |
| Port already in use                         | Pass `--port` (UI), `--proxy-port` (proxy), or stop the other process.               |
| Test suite                                  | `py -m pytest reqlore/tests/unit -q` — expect `363 passed` (Phase 9, after UI password gate).                |
| Smoke all routes                            | See `scripts/smoke-routes.ps1` (or follow the loop in `docs/ROADMAP.md` Phase 7).    |

---

## Where to go next

- A worked, end-to-end attack walkthrough against the bundled lab apps
  (vuln-bank / vuln-shop / vuln-social), narrated from a blind pentester's
  point of view, lives at [`docs/STORY-blind-pentester.txt`](STORY-blind-pentester.txt).
- Plugin authoring: [`PLUGINS.md`](PLUGINS.md).
- Internals: [`ARCHITECTURE.md`](ARCHITECTURE.md).
- Roadmap: [`ROADMAP.md`](ROADMAP.md).

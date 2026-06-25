# Scanner — `/scanner/`

The Scanner is Reqlore's vulnerability engine. Two halves:

- **Passive** — runs automatically over each new request that flows through
  the proxy, plus on demand over recent history. Cheap, no extra traffic to
  the target.
- **Active** — opt-in probes that send their own crafted requests. Pick a
  scope, pick a preset (or individual checks), hit *Run active scan*.

Findings land in one place (`/scanner/`), with severity, CWE, OWASP, the
originating request, and a reproducer.

## Where it is

- **URL:** `/scanner/`
- **Nav:** *Scanner* in the top bar.
- **Sub-pages** (tabs in the page header):
  - **Findings** — `/scanner/`
  - **Run scan** — `/scanner/run`
  - **Coverage** — `/scanner/coverage`
  - **Suppressions** — `/scanner/suppressions`

The tab nav is a `<nav aria-label="Scanner sections">` with the active link
carrying `aria-current="page"` instead of an `href`.

## Quick start — first run

1. Browse the target for a minute so Reqlore captures real requests. Passive checks already fired on each one — visit `/scanner/` and you should see early findings (missing security headers, insecure cookie flags, etc.).
2. Open **Run scan**. In the *Passive scan* block, click **Run passive scan** to back-scan up to 5000 history rows you may have captured before today.
3. In the *Active scan* block, choose a host, pick the **Standard** preset, click **Run active scan**.
4. Watch the page reload with new findings as probes complete.
5. Click any finding's title → triage it: change status to `triaged` / `false_positive` (which auto-creates a suppression) / `fixed`. Then **Export findings** to Markdown / HTML / DOCX from the [Reporter](reporter.md).

## Routes

| URL                              | Method   | What it does                                                                                |
|----------------------------------|----------|---------------------------------------------------------------------------------------------|
| `/scanner/`                      | GET      | Findings list with severity / status / host filters.                                         |
| `/scanner/run`                   | GET      | Scan launcher (passive + active forms).                                                      |
| `/scanner/run`                   | POST     | Execute passive scan over recent history.                                                    |
| `/scanner/run-active`            | POST     | Execute active scan with the chosen preset + scope.                                          |
| `/scanner/<fid>`                 | GET      | Finding detail (evidence, payload, CWE/OWASP, originating request).                          |
| `/scanner/<fid>/status`          | POST     | Update status (open / triaged / false_positive / fixed). FP triage creates a suppression.    |
| `/scanner/<fid>/delete`          | POST     | Delete a finding.                                                                            |
| `/scanner/manual`                | GET/POST | Add a finding by hand (record an issue discovered manually).                                 |
| `/scanner/suppressions`          | GET      | List suppressions (auto and manual).                                                         |
| `/scanner/suppressions/delete`   | POST     | Remove a suppression.                                                                        |
| `/scanner/coverage`              | GET      | Per-rule audit: fired / evaluated / hit-rate, broken down by host with reasons.              |

## Findings list (`/scanner/`)

Top: a **Summary** table — open findings by severity (info / low / medium /
high / critical), with a link to **Export findings →** that goes to
[Reporter](reporter.md).

Below: the findings table. Columns: `#`, **Severity** (coloured `sev sev-*`
badge), **Title** (link to detail), **Host**, **URL** (in `<code>`),
**Status**.

Filters (form `role="search"` GET):

- **Severity** — any / info / low / medium / high / critical
- **Status** — any / open / triaged / false_positive / fixed
- **Host** — populated from history hosts

Plus a single **Add manual finding** link with accesskey **m**.

## Run scan (`/scanner/run`)

### Passive scan

| Field   | Default | Range          | Notes                                                                                  |
|---------|---------|----------------|----------------------------------------------------------------------------------------|
| `limit` | `5000`  | 1 – 50 000     | Max history rows to scan in this run.                                                   |
| `full`  | off     | checkbox       | Force a full re-scan (ignore the resume marker `scanner.passive.last_scanned_id`).      |

Button: **Run passive scan** (accesskey **p**). Passive runs are
resume-aware — re-running picks up only the rows added since the last run.

### Active scan

**Scope** fieldset:

| Field      | Default      | Range          | Notes                                |
|------------|--------------|----------------|--------------------------------------|
| `host`     | *(any host)* | dropdown        | Restrict probing to one host.        |
| `limit`    | `20`         | 1 – 2000        | Max requests to probe per check.     |
| `timeout`  | `10`         | 1 – 60 sec      | Per-request timeout.                 |
| `delay`    | `0`          | 0 – 5000 ms     | Throttle between probes.             |
| `follow`   | off          | checkbox        | Follow redirects.                    |

**Preset** radiogroup (exactly one):

| Preset      | Includes                                                                                                  |
|-------------|-----------------------------------------------------------------------------------------------------------|
| `quick`     | 5 checks — `xss-reflected`, `sqli-error`, `ssti`, `jwt-alg-none`, `open-redirect`.                         |
| `standard`  | All built-ins **except** `oast-ssrf`, `http-smuggling`, `default-creds`, `race-condition`, `xss-dom`.       |
| `full`      | All built-ins **including** OAST and the dangerous ones above.                                              |
| `custom`    | Honour the individual check checkboxes below.                                                              |

**Customise checks** — collapsed `<details>` block that only renders the
checkbox grid when the **Custom** preset is selected (added in commit
`9301b2a`). Checks are grouped by family:

- **Injection** — `xss-reflected`, `xss-reflected-headers`, `sqli-error`, `ssti`, `nosqli-mongo`, `xxe-classic`, `deserialisation-reflect`, `xss-stored`, `xss-dom`.
- **File / OS** — `path-traversal-lfi`, `os-cmd-time`, `forced-browsing`.
- **Auth & Logic** — `jwt-alg-none`, `open-redirect`, `prototype-pollution`, `oauth-redirect-uri`, `default-creds`, `idor-alt-identity`, `race-condition`, `auth-enum-timing`, `csrf-token-not-validated`, `mfa-bypass`, `session-fixation`.
- **API & CORS** — `graphql-introspection`, `cors-misconfig-extended`, `web-cache-deception`, `graphql-active`.
- **SSRF / OAST** — `oast-ssrf`, `http-smuggling`.
- **TLS & DNS** — `tls-active`, `subdomain-takeover`.
- **Cloud** — `cloud-blob-misconfig`.

Button: **Run active scan** (accesskey **a**).

## Passive rules shipped

Twenty-five rules in `BUILTIN_RULES`. Each `rule_id` is namespaced `passive:*`.

| Rule ID                                | Title                                                  | Severity | CWE     |
|----------------------------------------|--------------------------------------------------------|----------|---------|
| `passive:missing_security_headers`     | Missing security response headers                       | medium   | CWE-693 |
| `passive:xframe_options`               | No clickjacking defence                                 | low      | CWE-1021|
| `passive:insecure_cookies`             | Insecure `Set-Cookie` attributes                        | medium   | CWE-614 |
| `passive:server_banner`                | Software version disclosed in response banner           | info     | CWE-200 |
| `passive:cors`                         | Dangerous CORS configuration                            | high     | CWE-942 |
| `passive:verbose_error`                | Verbose error page leaks server internals               | medium   | CWE-209 |
| `passive:directory_listing`            | Directory listing exposed                               | medium   | CWE-548 |
| `passive:sensitive_paths`              | Sensitive file or directory accessible                  | high     | CWE-538 |
| `passive:mixed_content`                | Mixed HTTP/HTTPS content reference                      | low      | CWE-319 |
| `passive:jwt_none_alg`                 | JWT with `alg=none`                                     | critical | CWE-347 |
| `passive:open_redirect_hint`           | Possible open redirect (Location echoes query param)    | medium   | CWE-601 |
| `passive:basic_auth_over_http`         | HTTP Basic Auth over plain HTTP                         | high     | CWE-319 |
| `passive:cors-null-origin`             | CORS allows the `null` origin                           | medium   | CWE-942 |
| `passive:cors-reflected-origin`        | CORS reflects request Origin with credentials           | high     | CWE-942 |
| `passive:weak-tls-hint`                | Authentication endpoint reached over plain HTTP         | medium   | CWE-319 |
| `passive:graphql-batching-hint`        | GraphQL endpoint accepts batched queries                | low      | CWE-770 |
| `passive:session-fixation`             | Possible session fixation on login                      | medium   | CWE-384 |
| `passive:autocomplete-on-password`     | Password field lacks `autocomplete` hint                | low      | CWE-549 |
| `passive:cache-control-on-private`     | `Set-Cookie` response lacks `Cache-Control: no-store`   | low      | CWE-525 |
| `passive:open-redirect-hint-headers`   | Redirect Location echoes a request header               | medium   | CWE-601 |
| `passive:weak-session-entropy`         | Set-Cookie token entropy weak (≥8 samples, cross-row)   | medium   | —       |
| `passive:pii-secrets`                  | PII or secret material in response body (AWS / GitHub / Slack / OpenAI tokens, PEM keys, CC, SSN) | high     | CWE-200 |
| `passive:cve-fingerprint`              | Known CVE / EOL component in response header (Apache, nginx, PHP, IIS, Tomcat, OpenSSL) | high     | CWE-1104|
| `passive:framework-debug-page`         | Framework debug or admin page exposed (Actuator, Werkzeug, Django, Rails, Laravel Ignition, Symfony, ELMAH, Express, phpinfo) | high     | CWE-489 |
| `passive:subdomain-takeover-hint`      | Subdomain-takeover fingerprint (GitHub Pages / Heroku / S3 / Azure / Fastly / Bitbucket / Surge / Tilda / WP Engine / Ghost / Pantheon / Shopify / Readme.io / Teamwork) | high     | CWE-1395|
| `passive:error-leak`                   | Internal infra leak in 4xx/5xx body (DB URI w/ creds, internal IP / hostname, absolute filesystem path) | medium / critical | CWE-209 |

## Active checks shipped

`BUILTIN_ACTIVE_CHECKS` — grouped here by family:

### Injection

| Check                       | What it sends                                                                              | Hit signal                                              | Severity |
|-----------------------------|--------------------------------------------------------------------------------------------|----------------------------------------------------------|----------|
| `xss-reflected`             | `"'><wbr-{marker}>` in query/form values                                                    | Marker echoed unescaped                                  | high     |
| `xss-reflected-headers`     | Same marker in `User-Agent`, `Referer`, `X-Forwarded-For`, cookies                          | Marker echoed unescaped                                  | high     |
| `xss-stored`                | Marker via state-changing POST/PUT/PATCH                                                    | Marker persists in clean GET re-fetch                    | high     |
| `xss-dom` (Playwright)      | Unique marker in query param                                                                | Marker reaches `innerHTML`, `location.href`, etc.        | high     |
| `sqli-error`                | `'` appended to param                                                                       | DB engine error signatures in response                   | high     |
| `ssti`                      | Per-engine probes (`{{7*7}}`, `{{7*'7'}}`, `{$7*7}`, …)                                     | `49`/`7777777` in response                               | critical |
| `nosqli-mongo`              | Replace string field with `{"$ne": null}` in JSON body                                     | Status flip (401→200) or body size doubles               | high     |
| `xxe-classic`               | `<!ENTITY x SYSTEM "file:///etc/hostname">`                                                 | Hostname leaked in `<r>…</r>`                            | high     |

### Auth & logic

| Check                  | What it sends                                                                  | Hit signal                                                                | Severity |
|------------------------|--------------------------------------------------------------------------------|---------------------------------------------------------------------------|----------|
| `jwt-alg-none`         | Re-sends the request's Bearer JWT with `alg=none` + empty signature             | 200 when baseline also 200                                                | critical |
| `open-redirect`        | Replaces URL-shaped param with `https://reqlore-redir.invalid/`                 | 3xx Location echoes the probe URL                                          | medium   |
| `oauth-redirect-uri`   | Swaps host on `redirect_uri`/`redirect`/`return_to`/`next`/`url`/`callback`     | 3xx to the swapped host or body containing it                              | medium   |
| `prototype-pollution`  | Appends `__proto__: {reqlore_test: marker}` to JSON body                        | Marker echoed                                                              | high     |
| `default-creds`        | HTTP Basic and HTML-form pairs (admin/admin, root/root, …)                      | Non-401 on Basic, 3xx / "logout" page on form                              | critical |
| `idor-alt-identity`    | Re-sends with alt-identity headers                                              | Both 200 and ≥ 90 % Jaccard similarity vs. baseline                        | high     |
| `race-condition`       | Baseline + 8 parallel copies of state-change                                    | ≥ 2 creates (201/202/204) in parallel vs. one baseline success             | high     |
| `auth-enum-timing`     | 7 "exists" + 7 "absent" probes interleaved against a username-shaped field      | Median + MAD timing anomaly (≥ 50 ms floor) on either side                  | medium   |
| `csrf-token-not-validated` | Re-sends state-changing 2xx with the CSRF token mangled, then with the token field omitted | Either probe still returns 2xx (token isn't actually checked)        | high     |
| `mfa-bypass`           | Re-runs the configured auth macro with every step tagged `step_type="mfa"` removed   | Verification step still returns 2xx → server hands out a full session after the password alone | high |
| `session-fixation`     | Pre-sets every captured session cookie on the macro's `step_type="login"` step to a distinctive value, replays the login | Post-login Set-Cookie echoes the attacker value OR no Set-Cookie at all (server kept the fixed value) | high |

### SSRF / OAST

| Check            | What it sends                                                              | Hit signal                                                  | Severity |
|------------------|----------------------------------------------------------------------------|-------------------------------------------------------------|----------|
| `oast-ssrf`      | Unique OAST callback URL into every query/form param                        | Inbound request to the OAST receiver within 0.6 s            | high     |
| `http-smuggling` | CL.TE / TE.CL / TE.TE timing probes via the raw-socket engine                | Latency > baseline + 1500 ms                                  | critical |

### API & CORS

| Check                       | What it sends                                                                  | Hit signal                                                                       | Severity   |
|-----------------------------|--------------------------------------------------------------------------------|----------------------------------------------------------------------------------|------------|
| `cors-misconfig-extended`   | `Origin: https://reqlore-cors.invalid`, `null`, `r{token}.example.invalid`     | Echoed + `Access-Control-Allow-Credentials: true`                                | high       |
| `graphql-introspection`     | POST `{"query":"query{__schema{types{name}}}"}`                                | Body contains `__schema` + `types`                                                | medium     |
| `graphql-active`            | Batch query and typo (`__schemaa`)                                              | Array response or "did you mean" / field echo                                     | low / med  |

### Discovery / misconfig

| Check                       | What it sends                                                                                            | Hit signal                                          | Severity |
|-----------------------------|----------------------------------------------------------------------------------------------------------|------------------------------------------------------|----------|
| `forced-browsing`           | GETs to `/.git/HEAD`, `/.env`, `/.DS_Store`, `/backup.zip`, `/swagger.json`, `/api-docs`                  | 200 + body markers (git-ref, key=value, ZIP magic …) | high/med |
| `path-traversal-lfi`        | `../../../../etc/passwd` and `..\..\win.ini` variants                                                     | `root:x:0:0:` or `[fonts]` in body                   | high     |
| `deserialisation-reflect`   | Java `rO0AB…`, .NET `AAEAAAD…`, PHP, Python pickle magic                                                 | Stack-trace signatures                               | high     |
| `web-cache-deception`       | Append `/x.css`, `/x.js`, `/x.jpg` to authed GET; re-fetch unauthenticated                                | 200 + ≥ 60 % Jaccard with the authed body            | high     |
| `cloud-blob-misconfig`      | `?list-type=2` (S3), `?restype=container&comp=list` (Azure) on S3/Azure-shaped hostnames                  | XML envelope (`ListBucketResult` / `EnumerationResults`) | high  |

### Crypto

| Check                  | What it does                                          | Hit signal                                                                 | Severity   |
|------------------------|-------------------------------------------------------|----------------------------------------------------------------------------|------------|
| `tls-active`           | Real TLS handshake to `<host>:443`                    | Expired cert, TLS < 1.2, cipher < 128 bits / on weak list, verify failure   | high/med/low |
| `subdomain-takeover`   | GET base URL, body-fingerprint match                   | "Project not found" pages (GitHub Pages, Heroku, S3, Azure, Fastly, …)      | high/med/low |

## Finding detail (`/scanner/<fid>`)

Layout:

- **Severity** badge.
- Header pairs: **CWE**, **OWASP**, **Host**, **URL**, **Status**,
  **Originating request** (link to history row when available).
- **Evidence** — `<pre class="wrap">` rendering the captured snippet.
- **Payload** — `<pre class="wrap">` rendering the attack string (active
  findings only).
- **Find in finding body** — a single server-side find widget (URL
  params `body_find` / `body_re`) sits ABOVE the Evidence / Payload
  panes and searches **both** regions in one pass. Matches are
  marked in place inside their original pane (no duplicated combined
  block) — Evidence hits as `<mark id="evidence-mN">`, Payload hits
  as `<mark id="payload-mN">` — and the combined count is announced
  via `role="status"`. The jump list links into the natural pane
  location. See
  [ACCESSIBILITY.md § Find-in-body](../ACCESSIBILITY.md#find-in-body-no-js-aaa-clean).
- **Triage** form — status dropdown + *Update status* button. Setting
  status to `false_positive` auto-creates a suppression matching the rule
  + host + URL.
- **Delete** — collapsible confirm dialog (accesskey **d**).

For active findings, a reproducer block ships with the captured probe as
raw HTTP bytes so [Reporter](reporter.md) can render a curl one-liner.

## Manual finding (`/scanner/manual`)

Use when you found something by hand and want it tracked alongside scanned
findings. Notable fields:

- **Title** (required, ≤ 180 chars), **Severity** (required).
- **rule_id_slug** — optional; if blank, derived from the title (`manual:<slug>`).
- **cwe** — matches pattern `^(CWE-\d+)?$`. **owasp** — one of the ten
  OWASP 2021 categories.
- **host** (datalist of known hosts), **url**, **request_id** (link to
  history row).
- **description**, **evidence** (drives de-duplication), **payload**,
  **remediation**, **references** (one URL per line).

Pre-fills from `?request_id=<hid>` so you can launch the form from
[History](history.md) → detail → "Create manual finding from this request".

## Suppressions (`/scanner/suppressions`)

A suppression is `(rule_id, host?, url_pattern?, reason, created_at)`.
Suppressed findings are not emitted, but the rule run is still recorded
(with `fired=0, reason="suppressed"`) so Coverage stays honest.

Suppressions are created automatically when you triage a finding as
`false_positive`. You can also delete them here.

## Coverage (`/scanner/coverage`)

Two tables drawn from `rule_runs`:

1. **Rule totals** — rule ID, fired count, evaluated count, hit-rate %.
2. **Coverage by host** — same per (rule, host). Where `fired < evaluated`,
   a `<details>` panel lists the reasons each rule was skipped or didn't
   match (`no_match`, `suppressed`, `rating_strong`, …).

Filters: `rule_id` (substring) and `host` (substring).

## CLI

```
reqlore scan --project <p> [--limit N] [--full] [--deadline SECONDS]
```

- `--limit` — default 5000.
- `--full` — ignore the resume marker.
- `--deadline` — wall-clock cap in seconds; default 300. `0` disables.

Logs rows scanned, elapsed ms, and findings by severity. If aborted on
deadline, prints the last processed row ID and suggests resuming.

## Accessibility notes

- **Tab nav** (`_section_nav.html`) — `<nav aria-label="Scanner sections">`;
  the active link has `aria-current="page"` and no `href`.
- **Filter form** — `role="search"` with `aria-label="Filter findings"`.
- **Severity badges** — colour + `aria-label="Severity: critical"`.
- **Customise-checks** — only rendered when *Custom* preset is selected;
  this avoids an enormous fieldset for keyboard / screen-reader users who
  picked a preset and never need it.
- **Manual finding form** — every input labeled, fieldsets group
  Classification / Target / Body; required fields marked `required` with
  `aria-required="true"`.
- WCAG AAA polish in commit `a5b5760` tightened section nav semantics,
  evidence/payload `<pre class="wrap">` wrapping, severity-badge contrast.

## How it integrates

**Producers** (anywhere with a "Send to Scanner" semantic):

- [History](history.md) detail → *Create manual finding from this request*.
- [Proxy](proxy.md) flows → passive checks fire automatically on every
  response.
- [Intruder](intruder.md) → grep matches with **Emit findings** ticked.
- [OAST receiver](oast.md) → the `oast-ssrf` active check uses the
  receiver to detect callbacks.

**Consumers:**

- [Reporter](reporter.md) — formats findings into Markdown / HTML / DOCX.
- [Scheduler](scheduler.md) — re-runs passive scans on a cron-like cadence.

## Storage footprint

- **`findings`** — id, rule_id, source (`scanner` / `manual`), severity,
  title, description, remediation, references, cwe, owasp, host, url,
  request_id (→ history), response_id, evidence, payload, status,
  dedupe_key (`{title}|{host}|{url}|{evidence[:200]}`), created_at, updated_at.
- **`suppressions`** — `(rule_id, host, url_pattern, reason, created_at)`.
- **`rule_runs`** — append-only audit log: rule_id, host, url, fired,
  reason, recorded_at.
- **State key `scanner.passive.last_scanned_id`** — resume marker for
  passive runs.

## Troubleshooting

| Symptom                                                | Cause                                                                | Fix                                                                                              |
|--------------------------------------------------------|----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Active scan returns 0 findings on a known-vuln target  | Preset is `quick` or `standard`                                       | Try `full`, or pick `custom` and tick the specific check.                                         |
| `oast-ssrf` never fires                                | OAST receiver not running or callback unreachable                     | Start [OAST](oast.md) first; confirm callback URL is reachable from the target.                   |
| `http-smuggling` reports false-positive `critical`     | Network jitter > 1500 ms                                              | Re-run with the same scope a second time; sustained latency is required, not single-shot.         |
| Passive run skips rows                                 | Resume marker is past those rows                                      | Tick **Full re-scan** on the form.                                                                |
| Triage drops a finding but it comes back next scan     | Suppression scope too narrow                                          | Open Suppressions, broaden the URL pattern (or set it to empty for "any URL").                    |
| Coverage shows `rating_strong`                         | Session-entropy rule fired but rating exceeded weak threshold          | This is correct — strong tokens don't produce a finding.                                          |

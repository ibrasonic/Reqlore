# Authenticated sessions

Reqlore offers five ways to carry credentials into target traffic.
Pick by what your target does at the front door.

| If the target uses…                          | Use                                                |
|----------------------------------------------|----------------------------------------------------|
| OAuth / OIDC / SAML / browser-based SSO       | [**Browser launcher**](browser-launcher.md)        |
| HTML form login + CSRF token                  | [**Macros**](modules/macros.md)                    |
| Static API key on every request               | [**Match & Replace**](modules/matchreplace.md)     |
| A copy-pasted session cookie                  | **Manual** in [Repeater](modules/repeater.md) / [Intruder](modules/intruder.md) |
| Bespoke pre-flight (e.g. HMAC signing)        | [**Plugins**](modules/plugins.md)                  |

> **There is no global "auth header" field in [Settings](modules/settings.md).** Use Match & Replace if you want a header on every outbound request.

---

## 1. Browser-driven login

Best for anything with a redirect chain (OAuth / OIDC / SAML) and
anything where the cookies are managed entirely by the browser.

### How it works

1. `reqlore browser` launches Firefox with the Reqlore CA pre-trusted
   and the proxy locked to the running [Proxy](modules/proxy.md). See
   [Browser launcher](browser-launcher.md) for the install and
   architecture details.
2. You log in normally through the GUI. Every byte — including the
   final `Set-Cookie` of the session — flows through the proxy and
   lands in [History](modules/history.md).
3. From a History row, **Send to Repeater / Intruder / Scanner** (Alt+R / Alt+I / etc.). The cookie header is part of the captured request, so subsequent tooling carries it.

### Recipe — SAML SSO into the target

```bash
reqlore browser --url https://app.target.com/login
```

Click through the IdP. Once you're logged in, find the post-login
request in [History](modules/history.md). **Send to Repeater**
(Alt+R) — the cookie is in the request template.

### Gotchas

- The browser profile persists. To reset, `rm -rf ~/.reqlore/firefox-profile/`.
- Cookies in History are inert text — if the cookie has rotated since
  capture, the replayed request will 401. Re-capture or replay through
  a Macro.

---

## 2. Macros — scripted login + capture

Best for HTTP form login with a CSRF token, multi-step authentication
flows, and keeping a session warm during long scans.

### How it works

A [Macro](modules/macros.md) is a chain of steps with variable capture
(`header` / `regex` / `json` sources) and `{{variable}}` substitution.
Step 1 logs in and captures `Set-Cookie` plus the CSRF token; step 2
re-issues them as headers.

```json
{
  "name": "login-with-csrf",
  "steps": [
    {
      "name": "login",
      "method": "POST",
      "url": "https://app.target.com/login",
      "headers": {"Content-Type": "application/x-www-form-urlencoded"},
      "body": "user=alice&pass=secret",
      "capture": {
        "session": {"source": "header", "name": "Set-Cookie"},
        "csrf":    {"source": "regex", "where": "body",
                    "pattern": "csrf_token=([A-Za-z0-9]+)"}
      }
    },
    {
      "name": "verify",
      "method": "GET",
      "url": "https://app.target.com/account",
      "headers": {"Cookie": "{{session}}", "X-CSRF-Token": "{{csrf}}"}
    }
  ]
}
```

### Replay-during-scan

The [Scanner](modules/scanner.md) active engine's `ActiveOptions` has
a `replay_macro` callable (`reqlore/scanner/active.py`). It's invoked
every `replay_every_n_probes` probes; the returned dict of headers is
merged into the next request. Wire your login macro up here to refresh
the cookie before it expires.

### Recipe — kept-alive scan

1. Author the macro above; save as `login-with-csrf`.
2. In the Scanner active options, set `replay_macro=<macro id>`,
   `replay_every_n_probes=10`.
3. Run an active scan. Every 10th probe re-logs-in, the captured
   `Cookie` is merged into subsequent probes.

### Gotchas

- Substitution is **string-only**, no JSON escaping. Wrap inside a
  JSON string: `{"name":"{{var}}"}` instead of `{{var}}` at the root.
- Macros are **fail-stop**. The first step that returns `.error`
  halts execution; everything after is recorded as not-run.
- Captured values default to `""` when missing — `{{var}}`
  substitution silently inserts empty string.

See [Macros](modules/macros.md) for the full schema.

---

## 3. Match & Replace — static header injection

Best for static API keys (`Authorization: Bearer …`,
`X-Api-Key: …`) that never rotate within a run.

### How it works

[Match & Replace](modules/matchreplace.md) rules are applied by the
proxy on every flow. The schema:

```python
MRRule {
    id: int
    enabled: bool
    where: 'req_header' | 'req_body' | 'resp_header' | 'resp_body'
    is_regex: bool
    host_regex: str   # filter by host (optional)
    pattern: str
    replacement: str
}
```

### Recipe — inject `Authorization` on every request to `api.target.com`

In [Match & Replace](modules/matchreplace.md), add:

| Field        | Value                                  |
|--------------|----------------------------------------|
| Where        | `req_header`                           |
| Host regex   | `^api\.target\.com$`                   |
| Is regex     | yes                                    |
| Pattern      | `^Host:`                               |
| Replacement  | `Authorization: Bearer eyJhbGciOi…\r\nHost:` |

(Trick: insert `Authorization:` immediately before the `Host:` line.
This guarantees the header appears even on requests that don't already
carry an `Authorization`.)

### Gotchas

- Rules apply to **all** flows passing through the proxy. Always set a
  `host_regex` so you don't leak the key to third parties.
- Rules persist in `project_state` — review them before sharing a
  `.rlr` file.

See [Match & Replace](modules/matchreplace.md) for the full rule
engine.

---

## 4. Manual cookie copy

Best for one-off testing, quick session switching, or working with
multiple sessions in parallel.

1. In [History](modules/history.md), find a request that carries the
   cookie you want.
2. Copy the `Cookie:` line from the raw request view.
3. In [Repeater](modules/repeater.md) or [Intruder](modules/intruder.md),
   paste it into the request template.

That's it — no machinery, no automation, no replay.

---

## 5. Plugins — bespoke logic

Best for HMAC signing, request signing with rotating secrets, or any
auth scheme that's too dynamic for Macros / Match & Replace.

A [Plugin](modules/plugins.md) can:

- Register a Flask `after_request` hook (limited; only affects Reqlore-served pages, not proxied traffic).
- Register an entire blueprint that does its own thing.
- Provide passive scanner rules and copy-as renderers.

For request signing on **proxied** traffic, the cleanest hook is
actually a custom mitmproxy script invoked from a plugin's
`register(app)` — but at that point you're writing application code,
not configuration.

A common middle ground: use a Macro to derive the signed header into a
variable, then have the operator paste it into Match & Replace once
per session.

See [Plugins](modules/plugins.md) for the SDK and discovery rules.

---

## Matrix summary

| Scenario                                                | Pick                            |
|---------------------------------------------------------|---------------------------------|
| OAuth / SSO with browser redirects                       | Browser                         |
| HTML form login + CSRF                                   | Macros                          |
| Static API key on every request to a host                | Match & Replace                 |
| Refresh a session cookie every N scanner probes          | Macros + `replay_macro`         |
| One-off Repeater request with a copied cookie            | Manual                          |
| Custom header injection scoped by host                   | Match & Replace with `host_regex` |
| HMAC / per-request signature derivation                  | Plugin or custom mitmproxy hook |

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Replayed Repeater request returns 401 / 403              | Captured cookie has rotated / expired                                  | Re-capture in History or use a Macro to refresh.                                                 |
| Macro's `{{session}}` substitutes empty                  | `Set-Cookie` header wasn't in the response — capture returned `""`     | Open the previous step's response in History; confirm the header is actually there.              |
| Match & Replace rule fires on third-party traffic         | No `host_regex` set                                                    | Set `host_regex` to the target host only.                                                        |
| Active scan probes drop the session after N requests      | Session rotated; no `replay_macro` configured                          | Add the login macro and set `replay_every_n_probes`.                                             |
| OAuth callback URL doesn't reach the browser              | Browser is launched standalone; the IdP can't redirect back to localhost on a different domain | Use the Browser launcher; or configure the OAuth client with a callback you can reach.            |

## Test contract

- `reqlore/tests/unit/test_phase4_modules.py::test_macro_runs_with_variable_capture_and_substitution` — Macros end-to-end.
- `reqlore/tests/unit/test_active_b0.py::test_replay_macro_merges_new_cookie_into_followups` — Scanner `replay_macro` integration.
- `reqlore/tests/unit/test_matchreplace.py` — header injection rules.
- `reqlore/tests/unit/test_phase8_browser.py` — Browser launcher behaviour.
- `reqlore/tests/unit/test_plugins.py` / `test_plugins_sdk.py` — Plugin hooks.

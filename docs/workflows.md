# Workflows

End-to-end recipes that span multiple modules. Each starts with a goal,
walks through every step, and links to the module pages for detail.

For the per-module reference, see [docs/modules/](modules/). For the
catalogue of CLI flags and module URLs, see [USAGE.md](USAGE.md).

---

## 1. Black-box bug-bounty recon

Goal: walk a target as a logged-in user, capture every endpoint, run a
passive scan, file findings.

1. `reqlore browser --url https://target.example.com/` — opens Firefox
   pre-configured to proxy through Reqlore and trust the Reqlore CA.
   See [Browser launcher](browser-launcher.md).
2. Log in normally; click around every feature.
3. Open [History](modules/history.md) — every request/response is
   recorded.
4. Open [Sitemap](modules/sitemap.md) — the tree view of unique hosts /
   paths discovered.
5. Open [Scanner](modules/scanner.md) → **Run passive scan** (Alt+P).
   The built-in rules run across the full history.
6. Triage findings in Scanner. Confirm interesting ones in
   [Repeater](modules/repeater.md) (Alt+R from any history row).
7. Export the report from [Reporter](modules/reporter.md) when done.

---

## 2. Authenticated API testing with kept-alive session

Goal: fuzz a JSON API behind a login that expires after ~5 minutes.

1. Author a [Macro](modules/macros.md) `login-and-refresh` that POSTs
   the login and captures `Set-Cookie`. See the Macros recipe.
2. From [History](modules/history.md), find a sample API call. Send
   to [Intruder](modules/intruder.md) (Alt+I).
3. In Intruder's attack form, set the engine to `httpx` (default) and
   wire up [Macro](modules/macros.md) `login-and-refresh` via the
   scanner-style `replay_macro` (see [login.md](login.md)).
4. Mark insertion points; pick a payload set; **Start** (Alt+S).
5. Every Nth probe re-runs the login macro — `Cookie` stays fresh.
6. Filter results table for `status != baseline` (Alt+A) and triage.

---

## 3. Pinpoint a request-smuggling desync

Goal: confirm CL.TE on a target front-end.

1. In [Smuggling](modules/smuggling.md), enter the URL, pick `CL.TE`,
   smuggled `GET /admin`. **Generate**.
2. Copy the bytes. Open [Repeater](modules/repeater.md), paste, switch
   engine to **`raw`** (httpx normalises TE/CL — see
   [engines.md](engines.md)).
3. **Send**. Note the timing.
4. Send a normal `GET /` to the same back-end immediately afterwards.
   If you see `/admin` content in the *second* response, desync
   confirmed.
5. Document the finding via the [Reporter](modules/reporter.md) (paste
   evidence + the raw bytes from step 1).

---

## 4. SSRF discovery via OAST callback

Goal: find a parameter that triggers an outbound request from the target.

1. In [OAST](modules/oast.md), **Start receiver**. Click **New token**
   — you get a callback URL like `http://127.0.0.1:54311/abc123def456/`.
2. In [Repeater](modules/repeater.md) (or [Intruder](modules/intruder.md)),
   set an offending parameter (e.g. `?image=`) to your callback URL.
3. **Send**.
4. Reload OAST. If an interaction row appears for your token, the
   target made the outbound — that's the SSRF.
5. For automated scanning, instead use [Scanner](modules/scanner.md)
   active checks with `oast-ssrf` enabled — it'll spray the callback
   across query/form parameters and correlate hits.

---

## 5. Test session-token randomness (Sequencer)

Goal: are these password-reset tokens guessable?

1. From [Intruder](modules/intruder.md) or shell scripting, collect
   30+ tokens.
2. Paste one-per-line into [Sequencer](modules/sequencer.md). **Analyse**.
3. Read the verdict (`weak` / `fair` / `good` / `excellent`).
4. If `weak` or `fair`, the auto-recorded finding
   (`sequencer:low-entropy`, CWE-330) shows up in
   [Scanner](modules/scanner.md). Include in [Reporter](modules/reporter.md).

---

## 6. CSRF / clickjacking PoC for a write endpoint

Goal: confirm exploitability of a state-changing POST.

1. From [History](modules/history.md), find the offending request.
2. **Send to PoC builder** (Alt+B).
3. Click **Download form-style CSRF PoC** (or fetch-style for JSON
   bodies — see [PoC](modules/poc.md)).
4. Open the downloaded HTML in a victim browser logged into the
   target. If the request fires (form auto-submit), CSRF is confirmed.
5. For clickjacking, open [PoC](modules/poc.md) → **Clickjacking
   generator**. Paste the URL + a lure. Download the HTML. If the
   iframe loads (no `X-Frame-Options` / CSP `frame-ancestors`), report.

---

## 7. JWT investigation (`alg=none`, weak HMAC, replay)

Goal: confirm a JWT vulnerability class.

1. From [History](modules/history.md), find a request carrying the
   JWT. **Send to JWT workbench** (Alt+J).
2. The [JWT](modules/jwt.md) workbench decodes header + claims.
   Inspect `alg`, `exp`, `aud`, `iss`.
3. Try `alg=none` — re-sign with empty key, paste into
   [Repeater](modules/repeater.md). If the server accepts it,
   that's a finding.
4. Brute-force HMAC if `alg=HS256` and the token looks dev-grade —
   the workbench's built-in wordlist tries common secrets.
5. Replay: re-send the token unchanged to confirm it doesn't expire.

---

## 8. Header / cookie diff between two responses

Goal: compare an authenticated vs unauthenticated response.

1. From [History](modules/history.md), pick the first response. **Send
   to Comparer side A** (Alt+M).
2. Pick the second. **Send to Comparer side B**.
3. Open [Comparer](modules/comparer.md) — character / word / line diffs
   render side-by-side, with cookie / header diffs highlighted.

---

## 9. Decode an opaque value mid-request

Goal: figure out what `?token=eyJhbGciOiJIUzI1NiJ9.…` actually contains.

1. Right-click the parameter in [Repeater](modules/repeater.md) → **Send
   to Decoder** (Alt+O).
2. [Decoder](modules/decoder.md) runs the chain (base64 → JSON
   pretty-print, etc.) and renders each layer.
3. If it's a JWT, **Send to JWT workbench** for full inspection.

---

## 10. Scheduled passive scan + report export

Goal: nightly scan of recorded history with a Markdown report.

1. [Scheduler](modules/scheduler.md) → **Start scheduler**.
2. Add a job: `name=nightly`, `interval_s=3600`, `scan_limit=5000`.
3. Leave it running. Reqlore must stay up for the job to tick (no
   external cron integration).
4. Next morning, [Reporter](modules/reporter.md) → **Export Markdown**
   (or HTML / DOCX). Findings from overnight runs are included.

---

## 11. GraphQL endpoint mapping + introspection finding

Goal: find a `/graphql` endpoint, confirm introspection is on, file a
finding.

1. Pass traffic through the proxy. If [Scanner](modules/scanner.md)
   detected a `/graphql` endpoint, the passive
   `graphql_batching_hint` rule may have already fired.
2. In [GraphQL workbench](modules/graphql.md), paste the endpoint
   URL. **Introspect schema**.
3. If the schema renders, introspection is on. The active check
   `graphql-introspection` (in [Scanner](modules/scanner.md) Custom
   preset) automates this — but the workbench is the manual confirmer.
4. Browse types; pick suspicious queries; run them with **Run query**.

---

## 12. Find a hidden parameter

Goal: discover a parameter the target accepts but doesn't document.

1. In [Param miner](modules/param-miner.md), paste the URL. Method,
   location, max_words to taste.
2. **Mine**.
3. Hits render as a table — parameters that caused a status change,
   sentinel reflection, or length delta.
4. Take the interesting ones to [Repeater](modules/repeater.md) to
   confirm impact.

---

## 13. Inspect a SAML payload from the browser

Goal: confirm a SAML Response has the usual misconfigs.

1. Open the browser DevTools network tab. Find the POST containing
   `SAMLResponse=…`. Copy the base64 value.
2. Paste into [SAML inspector](modules/saml.md). **Inspect**.
3. Read the findings list: unsigned, weak algo, no NotOnOrAfter, no
   AudienceRestriction, XML comments.
4. The high-severity ones are auto-recorded via `record_saml_findings()`.

---

## 14. WebSocket frame capture + analysis

Goal: record a server's push frames, analyse later.

1. In [WebSocket workbench](modules/websocket.md), paste the URL +
   any auth headers. `recv_seconds=30`.
2. **Connect**. Transcript captures every push frame in the 30-second
   window.
3. Look at frame sizes / cadence; copy interesting frames manually for
   replay.

---

## 15. Plugin authoring loop

Goal: ship a new passive scanner rule.

1. Drop a `.py` file into `~/.rlr/plugins/` (see [Plugins](modules/plugins.md)).
2. [Plugins](modules/plugins.md) → **Enable hot reload** (requires
   `watchdog`). Save changes; reload happens automatically.
3. Trigger the rule via [Scanner](modules/scanner.md) → **Run passive
   scan**.
4. Iterate. Add tests under `reqlore/tests/unit/` for the rule.

---

## Where to go next

- Per-module deep-dive: [docs/modules/](modules/).
- Engine matrix: [engines.md](engines.md).
- Auth approaches: [login.md](login.md).
- Keyboard shortcuts: [KEYBINDINGS.md](KEYBINDINGS.md).
- When things break: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

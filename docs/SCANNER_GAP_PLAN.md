# Scanner gap-closure plan

Audit-derived plan to close the 16 items still ❌ or 🟡 in the scanner
feature matrix as of commit `9301b2a`. Each phase ends with a clean
commit + push, then I report progress back before starting the next.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done.

---

## Phase 1 — Tier A: in-repo logic, no new deps `[x]`

8 items. Each lands as a new `ActiveCheck` (or rule wiring) in
[`reqlore/scanner/active.py`](../reqlore/scanner/active.py) and
[`reqlore/scanner/passive.py`](../reqlore/scanner/passive.py),
joins `BUILTIN_ACTIVE_CHECKS`, gets slotted into an
`ACTIVE_CHECK_GROUPS` family in
[`reqlore/web/blueprints/scanner_bp.py`](../reqlore/web/blueprints/scanner_bp.py),
and ships with at least one positive + one negative test.

- `[x]` **22 · "Explain why I'm safe"** — surface
  `record_no_finding(reason=…)` rows on `/scanner/coverage`. UI-only
  read of existing `rule_runs` data; no new DB columns.
  *Shipped:* new `Project.rule_run_reasons()` + "Why not fired" column
  on the coverage page with a `<details>` breakdown.
- `[x]` **8 · HTTP request smuggling as a check** — wrap
  `reqlore.smuggling` into `HTTPSmugglingCheck`. Probes CL.TE / TE.CL
  / TE.TE pairs against the recorded host; only fires on the
  documented timing/length disagreement (no speculative findings).
  *Shipped:* uses `raw_engine` directly (httpx would normalise the
  payloads); off by default behind
  `ActiveOptions.allow_smuggling_probes` and excluded from the
  `standard` preset.
- `[x]` **16 · Sequencer auto-feed** — call `sequencer.analyze()` on
  session-cookie samples and emit a finding when entropy drops below
  the documented threshold. Existing workbench stays unchanged.
  *Shipped:* `_scan_session_entropy` runs once after the row loop in
  `Scanner.scan_project`, aggregates Set-Cookie samples by
  `(host, name)` for cookies that look like session/auth tokens,
  needs ≥ 8 distinct samples, fires on rating == "weak". Records
  rule_runs with reasons (`only_N_samples`, `rating_<r>`) so the
  coverage page can explain why a group did not fire.
- `[x]` **11 · Forced-browsing active check** — small built-in
  wordlist (`.git/HEAD`, `.env`, `/.DS_Store`, `/backup.zip`,
  `/swagger.json`, `/api-docs`). Each entry has a body-fingerprint
  marker so SPA fallback 200s do not false-positive.
- `[x]` **18 · GraphQL beyond introspection** — batching abuse and
  field-suggestion leak. Fires only when the endpoint responded with
  JSON containing `data` / `errors`.
  *Shipped:* `GraphQLActiveCheck` posts a 3-element batched query
  (fires medium when the response is a JSON array of length ≥ 2) and
  a typo'd root-field query (fires low when the response carries a
  `Did you mean` hint).
- `[x]` **7 · Deserialisation reflection** — send Java `rO0AB…`,
  .NET `AAEAAAD…`, PHP `O:`, Python pickle magic bytes in query/form
  params; flag responses that echo a known deserialiser stack trace
  class name (`java.io.ObjectInputStream`,
  `System.Runtime.Serialization`, `unserialize()`,
  `pickle.UnpicklingError`).
- `[x]` **19 · Web cache deception** — append `/x.css` / `/x.js` /
  `/x.jpg` to authenticated-looking paths, GET without auth, compare
  the served body to the authenticated one (byte-3gram Jaccard ≥
  0.6). Only runs when the original request carried a `Cookie` or
  `Authorization` header.
- `[x]` **20 · OAuth `redirect_uri` open redirect** — for any
  recorded URL containing `redirect_uri=` (or `return_to=`,
  `next=`, `url=`, `continue=`, `callback=`), swap the host for a
  scan-unique `*.example.invalid` marker; flag a 30x whose
  `Location` echoes the swap, or a 200 whose body embeds it.

**Exit criteria for Phase 1:** all 8 boxes ticked, suite still green
(target: 809 → ≥ 850 passing), commit + push to `main`.

*Phase 1 complete (1a + 1b):* 8 / 8 items shipped. Tests:
809 → 835 passing. Phase 1a covered items 22, 11, 7, 19, 20.
Phase 1b covered the three carryovers (8 / 16 / 18).

---

## Phase 2 — Tier B: stdlib network I/O `[ ]`

3 items. Adds real socket / `ssl` / DNS work. Tests use monkey-patched
sockets so CI stays offline.

- `[ ]` **14 · Active TLS check** — `ssl.create_default_context()` +
  `wrap_socket` against `host:443`; report on expired cert, weak
  protocol (< TLS 1.2), weak cipher, hostname mismatch.
- `[ ]` **13 · Subdomain takeover** — `socket.getaddrinfo` /
  `dns.resolver` lookup; flag when CNAME resolves to a known
  dangling service fingerprint (GitHub Pages 404, Heroku no-such-app,
  S3 `NoSuchBucket`, Azure `404 Web Site not found`). Built-in
  fingerprint table only — no live HTTP fetch beyond the recorded
  host.
- `[ ]` **15 · Default-creds spray** — on detected login form (HTTP
  Basic challenge OR HTML `<input type=password>` form), try a
  short, well-known list (`admin/admin`, `admin/password`,
  `root/root`, `guest/guest`). Hard cap of 4 attempts per host per
  scan; opt-in via `ActiveOptions.allow_credential_probes`.

**Exit criteria for Phase 2:** 3 boxes ticked, tests pass without
network access, commit + push.

---

## Phase 3 — Tier C: architectural changes `[ ]`

3 items. Each changes `ActiveOptions` and/or the scan loop; sized
to a session of focused work.

- `[ ]` **2 · Stored XSS (2-step probe)** — inject a unique marker
  into each param, then re-fetch the same URL (and up to 2 sibling
  paths) without the marker; flag if the marker still appears.
  Requires the scanner to keep a per-token "injected at" map and
  re-issue a GET on the next pass.
- `[ ]` **10 · IDOR (second identity)** — extend `ActiveOptions`
  with `alt_identity: dict[str, str] | None` (e.g.
  `{"Cookie": "session=B…"}`); for every probe, also send the same
  request with `alt_identity`. If both responses are 200 and bodies
  are ≥ 90% similar, flag IDOR. Identity defaults to off.
- `[ ]` **9 · Race condition / TOCTOU** — uses `h2_tool` to send
  N parallel requests with the HTTP/2 last-byte synchronisation
  trick. Fires when the same endpoint returns at least one response
  with a state that the single-request baseline never produced
  (e.g. duplicate-resource-created status differing across runs).

**Exit criteria for Phase 3:** 3 boxes ticked, no regression in
existing tests, commit + push.

---

## Phase 4 — Tier D: heavy / optional deps `[ ]`

2 items. Both gated behind `extras_require` so the default install
stays lean.

- `[ ]` **3 · DOM XSS (Playwright)** — reuse the existing
  `reqlore/browser.py` Playwright wrapper. Renders the recorded URL,
  injects a marker into every URL/fragment/form parameter, and
  monitors the page for `eval` / `document.write` / `innerHTML=` of
  the marker. Skipped silently when Playwright is not installed.
- `[ ]` **17 · S3 / Azure Blob misconfig** — for URLs that look like
  `*.s3.amazonaws.com`, `*.s3.<region>.amazonaws.com`, or
  `*.blob.core.windows.net`, issue an unauthenticated
  `GET ?list-type=2` and flag a 200 + `<ListBucketResult>` /
  `<EnumerationResults>` body. No cloud SDK required — plain HTTP.

**Exit criteria for Phase 4:** 2 boxes ticked, tests pass with and
without optional deps, commit + push.

---

## Working agreement

- Each item is its own implementation block: class + group entry +
  tests; the diff is reviewable in isolation.
- Tests live under `reqlore/tests/unit/test_active_<item>.py` (or
  extend an existing module when it makes more sense).
- After every phase I update this file (tick the boxes, note any
  scope cuts) and report back the test delta and commit hash.
- I do not start a later phase without your okay.

Progress log:

- `[x]` Phase 1 — 1a (5 items, 809 → 824) + 1b (3 items, 824 → 835),
  all 8 Tier-A gap-list items shipped.
- `[ ]` Phase 2
- `[ ]` Phase 3
- `[ ]` Phase 4

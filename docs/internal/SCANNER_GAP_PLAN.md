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

## Phase 2 — Tier B: stdlib network I/O `[x]`

3 items. Adds real socket / `ssl` / DNS work. Tests use monkey-patched
sockets so CI stays offline.

- `[x]` **14 · Active TLS check** — `ssl.create_default_context()` +
  `wrap_socket` against `host:443`; report on expired cert, weak
  protocol (< TLS 1.2), weak cipher, hostname mismatch.
  *Shipped:* `ActiveTLSCheck` performs one handshake per
  `(host, port)` via `_tls_inspect` (test-patchable). Emits high on
  verify-failed and expired cert (CWE-295/298), medium on legacy
  protocol or weak cipher, low when expiry is within 7 days.
- `[x]` **13 · Subdomain takeover** — `socket.getaddrinfo` /
  `dns.resolver` lookup; flag when CNAME resolves to a known
  dangling service fingerprint (GitHub Pages 404, Heroku no-such-app,
  S3 `NoSuchBucket`, Azure `404 Web Site not found`). Built-in
  fingerprint table only — no live HTTP fetch beyond the recorded
  host.
  *Shipped:* `SubdomainTakeoverCheck` issues one GET per host,
  matches the response against a 10-entry fingerprint table
  (GitHub Pages, Heroku, S3, Azure, Surge, Fastly, Cargo). Fires
  high (CWE-350) on first match.
- `[x]` **15 · Default-creds spray** — on detected login form (HTTP
  Basic challenge OR HTML `<input type=password>` form), try a
  short, well-known list (`admin/admin`, `admin/password`,
  `root/root`, `guest/guest`). Hard cap of 4 attempts per host per
  scan; opt-in via `ActiveOptions.allow_credential_probes`.
  *Shipped:* `DefaultCredsSprayCheck` covers Basic-auth challenges
  and HTML password forms. Skips forms that ship a CSRF /
  authenticity token. Fires critical (CWE-521) on the first pair
  that produces a logged-in response (3xx, success markers without
  fail markers). Off by default; excluded from the standard preset.

**Exit criteria for Phase 2:** 3 boxes ticked, tests pass without
network access, commit + push.

*Phase 2 complete:* 3 / 3 items shipped. Tests: 835 → 856
passing (1 skipped, unchanged). 21 new tests in
[`test_active_gap_phase2.py`](../reqlore/tests/unit/test_active_gap_phase2.py).

---

## Phase 3 — Tier C: architectural changes `[x]`

3 items. Each changes `ActiveOptions` and/or the scan loop; sized
to a session of focused work.

- `[x]` **2 · Stored XSS (2-step probe)** — inject a unique marker
  into each param, then re-fetch the same URL (and up to 2 sibling
  paths) without the marker; flag if the marker still appears.
  Requires the scanner to keep a per-token "injected at" map and
  re-issue a GET on the next pass.
  *Shipped:* `StoredXSSCheck` only runs on POST/PUT/PATCH. For each
  query/form param it sends the recorded request with a marker
  (`\"'><wbr-stored-<hex>>`), then re-fetches the bare `base_url`
  as a clean GET. Fires high (CWE-79) when the marker echoes from
  the GET. Counts as one logical probe per (rule, location, key).
- `[x]` **10 · IDOR (second identity)** — extend `ActiveOptions`
  with `alt_identity: dict[str, str] | None` (e.g.
  `{"Cookie": "session=B…"}`); for every probe, also send the same
  request with `alt_identity`. If both responses are 200 and bodies
  are ≥ 90% similar, flag IDOR. Identity defaults to off.
  *Shipped:* `IDORAltIdentityCheck` is silent unless
  `alt_identity` is set. Reuses `_byte_3gram_jaccard` (lifted out of
  the web-cache-deception helper) with a 0.9 threshold. Evidence
  carries header names only — never the cookie value.
- `[x]` **9 · Race condition / TOCTOU** — uses `h2_tool` to send
  N parallel requests with the HTTP/2 last-byte synchronisation
  trick. Fires when the same endpoint returns at least one response
  with a state that the single-request baseline never produced
  (e.g. duplicate-resource-created status differing across runs).
  *Shipped:* `RaceConditionCheck` opt-in via
  `ActiveOptions.allow_race_probes`. POST/PUT/PATCH/DELETE only, and
  only when the baseline succeeded. Fans the request out 8× in a
  `ThreadPoolExecutor` (the HTTP/2 last-byte trick needs raw socket
  control we don't have via the standard sender; this is the
  best-effort HTTP/1.1 equivalent and documents the gap in the
  module docstring). Fires high (CWE-362) when ≥ 2 of the parallel
  sub-400 responses are creation-style statuses.

**Exit criteria for Phase 3:** 3 boxes ticked, no regression in
existing tests, commit + push.

*Phase 3 complete:* 3 / 3 items shipped. Tests: 856 → 871
passing (1 skipped unchanged). 15 new tests in
[`test_active_gap_phase3.py`](../reqlore/tests/unit/test_active_gap_phase3.py).

---

## Phase 4 — Tier D: heavy / optional deps `[x]`

2 items. Both gated so the default install stays lean.

- `[x]` **3 · DOM XSS (Playwright)** — `DOMXSSCheck` in
  [active.py](../reqlore/scanner/active.py). Gated on
  `_optdeps.PLAYWRIGHT_AVAILABLE` **and** the opt-in
  `ActiveOptions.allow_dom_xss_probes` flag (off by default because a
  headless Chromium per probe is expensive). For each GET query
  parameter, swaps the value for a unique marker, renders the URL in
  headless Chromium, then asks the page whether the marker landed in
  a DOM sink (innerHTML, location.href, inline-script body,
  `javascript:` href). Excluded from the standard preset; cleanly
  no-ops when Playwright is missing.
- `[x]` **17 · S3 / Azure Blob misconfig** — `CloudBlobMisconfigCheck`
  in [active.py](../reqlore/scanner/active.py). For hosts matching
  `*.s3.amazonaws.com`, `*.s3.<region>.amazonaws.com`,
  `*.s3-website*.amazonaws.com`, or `*.blob.core.windows.net`,
  issues one unauthenticated GET (`?list-type=2` for S3,
  `?restype=container&comp=list` for Azure) and flags a 200 + an
  XML listing envelope (`<ListBucketResult` or
  `<EnumerationResults`). One probe per host. No cloud SDK — plain
  HTTP. New "Cloud" preset group; included in the standard preset
  since it is a single safe GET.

**Exit criteria for Phase 4:** 2 boxes ticked, tests pass with and
without optional deps, commit + push. Status: shipped, 884 passing
(13 new in
[test_active_gap_phase4.py](../reqlore/tests/unit/test_active_gap_phase4.py),
including a live Playwright run against a localhost innerHTML
sink).

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
- `[x]` Phase 2 — 3 items (14, 13, 15), 835 → 856 passing.
- `[x]` Phase 3 — 3 items (2, 10, 9), 856 → 871 passing.
- `[x]` Phase 4 — 2 items (3, 17), 871 → 884 passing. Gap list
  complete.

# Reqlore — Reliability & Accessibility Test Plan

Sister doc to [SCANNER_GAP_PLAN.md](SCANNER_GAP_PLAN.md). That one
closed scanner coverage gaps; this one walks every shipped component
end-to-end to prove it is reliable, error-free, and accessible to
screen-reader users (WCAG 2.1 AAA).

Working agreement is identical to the scanner plan: one phase at a
time, each phase ends with `pytest` green, this doc updated, commit
pushed, and an okay from the operator before the next phase starts.

---

## Phase 1 — Component health matrix `[x]`

Goal: a single source of truth that proves every shipped piece of
Reqlore at least *boots* without raising and exposes its blueprint
on the expected URL prefix. Catches whole classes of regression
(stale imports after rename, missing template, blueprint not
registered, CLI subcommand wired without a handler) that no current
test catches because they only fire on the unhappy path.

- `[x]` **Module import sweep** — `pkgutil.walk_packages` over
  `reqlore.*`, `importlib.import_module` each, asserts no
  exception. Test-tree modules are filtered out so pytest's own
  collection isn't perturbed.
- `[x]` **Blueprint reachability matrix** — auto-discovers every
  GET rule from `app.url_map.iter_rules()` with no required path
  arguments, GETs each one, asserts status `∈ {200, 302, 303,
  401}`. Two intentional 404s (`auth.login` when no password is
  configured, `comparer.export_diff` with no token / history
  arguments) are explicitly skipped via a documented skip-set so
  the next intentional 404 has an obvious place to live.
  A self-check verifies the matrix actually contains the
  user-facing blueprints by URL prefix (Flask `Blueprint(name=)`
  diverges from the Python variable name, so this checks `/proxy/`,
  `/scanner/`, etc., rather than `proxy_bp.index`).
- `[x]` **CLI subcommand parse matrix** — introspects `build_parser()`,
  walks every `_SubParsersAction`, runs each subcommand with
  `--help`, asserts `SystemExit(0)`.
- `[x]` **Engine round-trip sanity** — `raw_engine._build_raw`
  produces a well-formed HTTP/1.1 request with auto-injected
  `Host` and `Content-Length`; `_parse_response` round-trips a
  minimal response; `raw_engine.send` against a dead port returns
  `Response(status=0, error=...)` (the documented contract the
  active scanner relies on); `httpx_engine.send` keeps its
  `(req, *, timeout, follow_redirects)` signature.

**Exit criteria for Phase 1:** four green matrices, test count up
by at least 4, commit + push. Status: shipped, **884 → 986
passing** (+102; the matrix parametrises so most of the delta is
additional asserts auto-generated from real introspection: 87
module imports, 11 CLI subcommands, plus 4 named tests). See
[test_reliability_phase1.py](../reqlore/tests/unit/test_reliability_phase1.py).

---

## Phase 2 — WCAG AAA structural matrix `[x]`

Goal: every rendered page passes the structural rules we list in
[ACCESSIBILITY.md](ACCESSIBILITY.md). The existing
[test_a11y.py](../reqlore/tests/unit/test_a11y.py) and
[test_wcag_aaa.py](../reqlore/tests/unit/test_wcag_aaa.py) cover
the contrast theme and helper functions; this phase covers the
HTML the user actually receives.

- `[x]` **One `<h1>` per page** — GET every GET-able route, parse
  with `html.parser`, count `<h1>`. Exactly one per page.
- `[x]` **No skipped heading levels** — walk the heading sequence,
  fail if it ever jumps by more than +1 from the running maximum.
- `[x]` **Base landmark skeleton** — `<a class="skip-link"
  href="#main">`, `<main id="main" tabindex="-1">`, polite live
  region; `aria-live="assertive"` is banned.
- `[x]` **Every form control has a real label** — every `<input>`,
  `<select>`, `<textarea>` either carries `aria-label` /
  `aria-labelledby`, is wrapped by an ancestor `<label>` (the
  implicit-label pattern, valid per WCAG 2.1 SC 1.3.1), or is
  targeted by a `<label for=>` on the same page. Hidden /
  submit / button / image / reset inputs are exempt (no visible UI
  or visible button text).
- `[x]` **No `tabindex > 0`** — natural document order only.
- `[x]` **Every `<button>` has an explicit type** — default
  `submit` inside an unrelated form is a common a11y bug; this
  catches it everywhere.
- `[x]` **`<table>` has `<caption>` + scoped headers** — every
  `<th>` on every page carries `scope=col|row|colgroup|rowgroup`;
  every `<table>` carries a `<caption>`. Pages with no tables are
  cleanly skipped.

**Exit criteria for Phase 2:** 7 boxes (we split off the assertive
live-region rule into the same test as the landmarks because they
share a parser pass), the matrix runs against every blueprint
index, commit + push. Status: shipped, **986 → 1209 passing**
(+223; the matrix parametrises across 51 GET-able routes). See
[test_reliability_phase2.py](../reqlore/tests/unit/test_reliability_phase2.py).

---

## Phase 3 — Screen-reader semantics `[ ]`

Goal: NVDA / Orca / VoiceOver users get a sensible audible
experience, not just visually-correct HTML. These are static
template checks — they assert the right ARIA exists; the manual
SR runs documented in [ACCESSIBILITY.md](ACCESSIBILITY.md) are
out of scope for automated CI.

- `[ ]` **Progress carries `aria-valuetext`** — `<progress>` on
  Intruder run page, Scanner active-scan page, and any long-running
  blueprint must expose `aria-valuetext` (a human sentence). Bare
  `value/max` makes SRs announce only "75%".
- `[ ]` **Error summaries link to fields** — every form that
  validates server-side must render errors inside `<div
  role="alert">` at the top with anchor links to the offending
  field; the field carries `aria-invalid="true"` and
  `aria-describedby`.
- `[ ]` **No `assertive` live regions** — `aria-live="assertive"`
  interrupts SR speech; we never use it. Grep ledger across
  templates.
- `[ ]` **`role="dialog"` is always `aria-modal` + labelled** —
  any `role="dialog"` must carry `aria-modal="true"` and either
  `aria-labelledby` or `aria-label`.
- `[ ]` **Accesskey letters are unique per page** — render each
  page, collect all `accesskey="x"` attributes, assert no
  collision. Already lightly covered by
  [test_intruder_accesskeys.py](../reqlore/tests/unit/test_intruder_accesskeys.py);
  this phase generalises it.
- `[ ]` **Dense tables expose a "Read as list" alternative** —
  for every `<table>` flagged `data-dense` (≥ 5 columns), assert
  a `<details>` / button companion exists.

**Exit criteria for Phase 3:** 6 boxes, commit + push.

---

## Phase 4 — Browser launch portability (incl. WSL → host) `[ ]`

Goal: `reqlore browser` reliably opens the Reqlore UI on whatever
display the user actually has, including the **WSL → Windows host**
case where the current implementation silently fails because the
Linux Firefox binary inside WSL cannot reach the Windows display
server and the user has to copy-paste the URL into a host browser
themselves.

- `[ ]` **WSL detection** — add `is_wsl()` to
  [browser.py](../reqlore/browser.py) reading `/proc/version` for
  `microsoft` / `WSL` and honouring `$WSL_DISTRO_NAME`. Pure
  function, unit-tested with monkeypatched
  `pathlib.Path.read_text`.
- `[ ]` **WSL → host hand-off** — when `is_wsl()` is true and the
  user runs `reqlore browser`, skip the Linux Firefox path and
  open the URL on the Windows host via
  `cmd.exe /c start <url>` (preferred — present on every WSL
  install) with `wslview <url>` as fallback if `wslu` is
  installed. If neither works, print a copy-pasteable URL and
  exit `0` (not `1` — the UI server is up; the operator can open
  it manually).
- `[ ]` **Loud, actionable error when Firefox cannot start** —
  the current `launch()` warmup catches process death within 2 s
  but the message format varies; pin it: every failure path must
  print the URL the operator should open and the exit code.
- `[ ]` **Tests** — `test_browser_wsl.py` covers:
  - `is_wsl()` true / false matrix (mocked `/proc/version`).
  - WSL path picks `cmd.exe /c start` first, falls back to
    `wslview`, falls back to printing the URL.
  - non-WSL path is unchanged (regression guard).
  - `cmd_browser` exits `0` and prints the URL when no opener
    works.

**Exit criteria for Phase 4:** 4 boxes, the `reqlore browser`
command no longer silently fails inside WSL, commit + push.

---

## Working agreement

- Same as [SCANNER_GAP_PLAN.md](SCANNER_GAP_PLAN.md): one phase
  per session, every box ticked or explicitly deferred, doc
  updated with the test delta and commit hash before I move on.
- I do not start a later phase without an okay.

Progress log:

- `[x]` Phase 1 — component health matrix, 884 → 986 passing.
- `[x]` Phase 2 — WCAG AAA structural matrix, 986 → 1209 passing.
- `[ ]` Phase 3
- `[ ]` Phase 4

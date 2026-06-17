# Sequencer — `/sequencer/`

Paste a pile of session IDs, CSRF tokens, password-reset tokens, or
anti-bot tokens -- get a comprehensive randomness report:
Shannon entropy + per-position analysis + Hamming distance + longest-run
for a quick verdict, plus an optional **deep statistical battery**
(character transition / FIPS-style monobit / runs / poker / longest-run
per bit / Bonferroni-corrected pairwise bit correlation / zlib
compression). If the verdict is weak or fair, a finding is recorded.

The Sequencer has **two surfaces** that share the same statistical
engine:

1. **Paste analyser** -- `/sequencer/`. Bring your own tokens
   (Intruder scrape, `curl` loop, hand-collected). One per line.
2. **Live capture** -- `/sequencer/capture/...`. Live token
   replay-and-extract. Point at a request, pick the response field
   that holds the token,
   press **Start**. Reqlore re-fires the request in a background
   thread, extracts the token from each response, and persists it. Pause
   / Resume / Cancel at will. When you have enough samples, press
   **Analyse with deep battery** to forward the captured pile through
   the same deep analysis the paste page uses.

## Where it is

- **URL:** `/sequencer/`
- **Nav:** *Sequencer* in the top bar.
- Stateless paste-and-analyse.

## Quick start

1. Collect 30+ tokens from the target (replay a request that emits
   `Set-Cookie`, scrape via [Repeater](repeater.md) or
   [Intruder](intruder.md)).
2. Open `/sequencer/`. Paste one token per line.
3. **Analyse**. Read the verdict in the rating field.
4. If weak/fair, a `sequencer:low-entropy` finding is auto-recorded —
   triage in [Scanner](scanner.md).

## Routes

| URL            | Method | What it does                                                              |
|----------------|--------|---------------------------------------------------------------------------|
| `/sequencer/`  | GET    | Render the form. If `?t=<token>` is present, show the cached result.       |
| `/sequencer/`  | POST   | Analyse, stash in PRGCache, 302 to `?t=<token>`.                          |

## Form fields

| Field          | Type     | Default  | Notes                                                                |
|----------------|----------|----------|----------------------------------------------------------------------|
| `tokens`       | textarea | empty    | **Required.** One token per line. Empty / whitespace lines dropped.   |
| `significance` | select   | `0.01`   | Alpha threshold for deep tests: `0.05`, `0.01`, `0.001`, `0.0001`.     |
| `deep`         | checkbox | unchecked on first POST, then sticky | Toggles the deep statistical battery.        |
| `_csrf`        | hidden   | (gen.)   | CSRF token for the form.                                              |

## Pipeline

1. **Collect** — split on `\n` / `\r\n`, strip each line, drop empties.
2. **Length stats** — find the most common length; record min / max delta.
3. **Overall entropy (bits/char)** — Shannon entropy across all characters: $H = -\sum p_i \log_2 p_i$.
4. **Bits/token** — `bits_per_char × most_common_length`.
5. **Per-position breakdown** — for each position `0..most_common_length-1`, count distinct characters across all tokens; compute Shannon entropy of that column. Flag as **weak position** if `< 2.0` bits. Record top-3 most-common chars at each weak position.
6. **Hamming distance (first 64 pairs)** — count differing characters between consecutive tokens (plus the absolute length delta). Report min / max / mean. If `min == 1`, append the *counter-style* hint.
7. **Longest run** — longest consecutive run of identical characters in any token. Flag if `>= 4` or `>= length / 4`.
8. **Character classes** — counts of lowercase / uppercase / digit / punctuation / other.
9. **Rating** — `>= 5.5 → excellent`, `>= 4.5 → good`, `>= 3.0 → fair`, else `weak`.

## Finding emission

Via `record_sequencer_finding()`:

- Rule id: `sequencer:low-entropy`.
- CWE: CWE-330. OWASP: A02:2021.
- Severity mapping: `weak → high`, `fair → medium`, `good → low`, `excellent → info`.

Good / excellent verdicts call `record_no_finding()` (recorded as a
skipped rule_run — coverage stays honest).

## Output sections

- **Verdict** -- a single plain-English line at the top of the Summary
  block, computed from the deep rating (or the Shannon rating when
  deep was not requested):
  - `strong` / `excellent` -> `These tokens look random.`
  - `good` -> `These tokens look mostly random.`
  - `fair` -> `These tokens are partly random.`
  - `weak` -> `These tokens are NOT random.`
  - `n/a` -> `Not enough samples to decide.`
  Marked `role="status"` so screen readers announce it; the page never
  relies on colour or on the operator interpreting `STRONG` / `WEAK`
  keywords.
- **Summary** -- quick Shannon rating, deep rating (when deep is on),
  effective bits, common length, entropy, longest run, Hamming
  min/mean/max, character classes, notes.
- **Per-position table** -- one row per character position with distinct
  count, Shannon bits, status, top-3 most common characters. Weak
  positions get a `row-warn` CSS class plus a textual `weak` status.
- **Deep statistical analysis** (only when the `deep` checkbox is on):
  - **Transition (Markov) test** -- per character position, Pearson
    chi-square independence test of `(char in token N, char in token N+1)`.
    A failure means a character at that position predicts the next token's
    character at the same position.
  - **Per-bit FIPS-style tests** -- each character position is converted
    to a `ceil(log2(alphabet))` bit slice. For each bit position across
    the sample we run:
    - **monobit** (balance of 0s and 1s -- closed-form NIST p-value via
      complementary error function),
    - **runs** (total run count -- closed-form NIST p-value, skipped
      when the monobit pre-test `|pi - 0.5| < 2/sqrt(N)` fails),
    - **poker** (chi-square over the distribution of 4-bit nibbles, df 15,
      requires at least 16 bits),
    - **longest-run** (informational: flags when the longest run of 1s is
      far above `log2(N)`).
    A bit is "effective" when monobit, runs and poker all have
    `p >= alpha`.
  - **Bit-pair correlation** -- pairwise Pearson chi-square (df 1) over
    all `bits_per_token choose 2` pairs, with **Bonferroni correction**
    so the family-wise false-positive rate stays at the chosen alpha.
    Skipped above 256 bits per token to keep runtime bounded.
  - **Per-bit compression** -- zlib(level 9) ratio per bit position
    (1.000 = incompressible; lower = structured).
  - **Deep rating** -- `strong` when at least 128 effective bits and no
    surviving correlations; `fair` when at least 64 effective bits and
    no more than 2 correlations; `weak` otherwise. Independent from the
    legacy Shannon `rating` so both numbers are visible.

## Limits (deep analysis only)

| Cap                              | Default | Rationale                                                                        |
|----------------------------------|---------|----------------------------------------------------------------------------------|
| `_DEEP_MAX_SAMPLES`              | 20,000  | FIPS-140 ceiling. Beyond this the sample is truncated with a note.                |
| `_DEEP_MAX_COMMON_LEN`           | 256     | Truncate analysis to the first 256 characters of each token.                      |
| `_DEEP_MAX_BITS_FOR_CORRELATION` | 256     | Above this, correlation skips (otherwise pair count is `O(bits^2)`).              |
| `_DEEP_MIN_SAMPLES`              | 8       | Deep analysis reports `n/a` below this; nothing is statistically meaningful.       |

## Accessibility notes

- One landmark per section: `<section aria-labelledby="input-h">`,
  `aria-labelledby="summary-h"`, `aria-labelledby="positions-h"`,
  `aria-labelledby="deep-h"`. Each heading is the `<h2>` referenced by
  the `aria-labelledby` it provides.
- The form is grouped with `<fieldset><legend>Tokens</legend>` and
  `<fieldset><legend>Analysis options</legend>`.
- The textarea is required, with an `aria-hidden="true"` asterisk
  paired with a `visually-hidden` "required" span. A `tokens-hint`
  paragraph explains sample-size expectations and is wired in via
  `aria-describedby`. `spellcheck="false"` and `autocomplete="off"`
  keep the textarea predictable for SR users.
- The significance dropdown and deep-analysis checkbox both have a
  visible hint paragraph connected via `aria-describedby`. Nothing
  changes on focus or checkbox toggle: the form is only submitted by
  pressing **Analyse** (WCAG 2.2 Level AAA, SC 3.2.5 "Change on
  Request").
- Every table has a `<caption>`. Captions that are present for SR users
  but visually redundant use `class="visually-hidden"`. All `<th>`
  cells carry `scope="col"`.
- The per-bit detail table is wrapped in `<details><summary>` so it
  collapses by default -- the keyboard order goes Summary -> Transition
  -> Per-bit summary -> Bit-pair correlation without forcing a SR to
  step through ~200 bit rows unless the operator opens them.
- Status text in tables is real text (`pass` / `FAIL (non-random)` /
  `weak` / `ok` / `yes` / `no`), never colour-only.
- `<dl>` / `<dt>` / `<dd>` for the summary metrics; the entire result
  region is keyboard-reachable in document order. Errors render in the
  global flash region (`Paste at least one token before analysing.`).

## How it integrates

**Producer:** none — author-pasted only. Combine with
[Intruder](intruder.md) (scrape mode) or shell scripting to assemble
the input.

**Consumer:** writes findings into [Scanner](scanner.md)'s `issues`
table via `record_sequencer_finding()`.

## Recipes

### Session-cookie entropy audit

Replay the login 50 times via [Repeater](repeater.md), or use a quick
shell loop:

```
for i in $(seq 50); do
  curl -is https://target/login -d 'u=a&p=b' | grep -oP 'SESSIONID=\S+'
done > tokens.txt
```

Paste into Sequencer. Aim for `>= 4.5` bits/char on a 128-bit token.

### CSRF token round-trip

Pull 30 CSRF tokens from the login page. If the verdict is `fair` or
worse, attackers can brute-force it.

### Password-reset token check

30+ tokens from `/password-reset?token=…` links. Run Sequencer. If
`longest_run >= 8` on a 24-char token, the generator is clustering
identical characters — suspicious.

### Detect counter-style IDs

If `min_hamming == 1`, IDs differ by exactly one character between
consecutive samples — almost certainly an integer counter with a
veneer.

### Regression test for a token generator

Run pre-change. Save the result. Change the generator. Run again.
Compare bits/char.

## Storage footprint

- **Findings:** writes to `issues` when the verdict is weak / fair.
- **PRGCache:** holds `tokens_text` + `result` under a 12-char token.
  No DB writes.

## CLI

No CLI surface — the Shannon math is in `reqlore/sequencer.py` if you
want to script it from a plugin.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Verdict swings between runs                              | < 20 samples — Shannon stats are sample-dependent                       | Collect 30+ and re-run.                                                                          |
| Hamming reports look weird with 1000 tokens               | Only first 64 consecutive pairs sampled                                 | Pre-trim to ~100 tokens before pasting.                                                          |
| Per-position table stops at `common_length - 1`           | Varying lengths — positions beyond `common_length` are ignored          | Filter to one length first if comparing fixed-width tokens.                                       |
| Case-insensitive duplicates inflate entropy               | The analyser is case-sensitive                                          | Normalise to one case before pasting.                                                            |
| `excellent` rating but you think it's weak                 | Thresholds are hard-coded (5.5 / 4.5 / 3.0)                              | Inspect `bits_per_char` directly; cite the threshold in your report if you disagree.              |
| Finding didn't appear                                    | Verdict was `good` / `excellent` → no-finding path                       | Working as designed. The skipped rule_run still records coverage.                                 |

## Live capture

The live-capture surface follows the classic live-token-collection
workflow: bring a request, point at the response field that holds the
token, let the tool collect.

### URLs

| Path                                | Method | Purpose                                  |
|-------------------------------------|--------|------------------------------------------|
| `/sequencer/`                       | GET    | Lists captures (when any exist).          |
| `/sequencer/capture/new`            | GET    | Empty form for a brand-new capture.       |
| `/sequencer/capture/new?from_history=<hid>` | GET | Pre-filled from a History row (used by **Send to Sequencer (live capture)**). |
| `/sequencer/capture/new`            | POST   | Persist the capture (idle status).        |
| `/sequencer/capture/<cid>`          | GET    | Detail page: status, controls, samples.   |
| `/sequencer/capture/<cid>/start`    | POST   | Spawn the runner thread.                  |
| `/sequencer/capture/<cid>/pause`    | POST   | Pause (in-flight request finishes first). |
| `/sequencer/capture/<cid>/resume`   | POST   | Resume.                                   |
| `/sequencer/capture/<cid>/cancel`   | POST   | Cancel.                                   |
| `/sequencer/capture/<cid>/delete`   | POST   | Drop capture + samples.                   |
| `/sequencer/capture/<cid>/export.txt` | GET  | One token per line, `attachment`.         |
| `/sequencer/capture/<cid>/analyse`  | POST   | Forward captured tokens to deep analyse.  |
| `/sequencer/capture/<cid>/samples.json` | GET | Tiny status JSON for polling.            |

### Workflow

1. From any **History** row, press the *Send to Sequencer (live capture)*
   button (access key **Q**). Reqlore lifts the raw request, the URL,
   and -- if the request carries a known session cookie
   (`SESSIONID`, `JSESSIONID`, `PHPSESSID`, `connect.sid`, ...) --
   defaults the extractor to `cookie = <name>`. Tweak the extractor,
   set a sample target, press **Save**.
2. On the capture detail page, press **Start** (access key **S**).
   The runner re-fires the stored template through the configured
   engine, applies the extractor to each response, and stores the
   token + HTTP status + per-request duration. Pause/Resume/Cancel
   are always available; the page reconciles automatically if the
   server restarts mid-capture.
3. When you have enough samples, press **Analyse with deep battery**
   (access key **A**). The captured tokens are piped straight into the
   paste analyser at the configured significance level.
4. **Export tokens (.txt)** drops the same pile to a file for archival
   or for sharing with another tool.

### Extractors

| `extractor_kind` | `extractor_arg` | Behaviour                                                                  |
|------------------|------------------|----------------------------------------------------------------------------|
| `cookie`         | cookie name      | Returns the value of the first `Set-Cookie: <name>=...` header. Strips `Path`, `HttpOnly`, etc. |
| `header`         | header name      | Returns the value of the first matching response header (case-insensitive).                      |
| `regex`          | Python regex     | Returns the first capture group; falls back to the whole match when there are no groups. Invalid regex returns `None`. |
| `json`           | dotted path      | Walks a JSON body; list indices are integers (`items.0.token`). Non-string values are JSON-encoded for storage.        |

Tokens longer than 4096 bytes are truncated. Bad / missing tokens count
as errors; once 10 errors arrive with zero successful tokens the
runner stops itself with a descriptive `stop_reason` (so a misconfigured
extractor doesn't loop forever).

### Form fields (capture creation)

| Field            | Type     | Default        | Notes                                                                                  |
|------------------|----------|----------------|----------------------------------------------------------------------------------------|
| `name`           | text     | `Capture`      | Display label.                                                                          |
| `url`            | url      | `http://127.0.0.1/` | Used as base URL when the raw template uses a relative path.                       |
| `engine`         | select   | `httpx`        | `httpx` (default, recomputes `Content-Length`) or `raw` (byte-exact, no rewriting).      |
| `template`       | textarea | `GET / HTTP/1.1` | Raw HTTP request as it appears on the wire. Newlines normalised to CRLF on send.       |
| `extractor_kind` | select   | `cookie`       | `cookie` / `header` / `regex` / `json`.                                                  |
| `extractor_arg`  | text     | (varies)       | Required. Cookie name, header name, regex, or JSON path.                                 |
| `max_samples`    | number   | `200`          | 8 .. 20000 (matches deep-analysis cap).                                                  |
| `delay_ms`       | number   | `0`            | Politeness throttle.                                                                     |
| `concurrency`    | number   | `1`            | Reserved; current loop is single-flight to keep ordering deterministic.                  |
| `significance`   | select   | `0.01`         | Default alpha for the post-capture deep analysis.                                        |

### Storage footprint (live capture)

Two new tables, both project-scoped:

- `sequencer_captures(id, name, url, template_blob, engine,
  extractor_kind, extractor_arg, max_samples, delay_ms, concurrency,
  significance, status, stop_reason, error_count, created_at)` --
  status is one of `idle | running | paused | done | cancelled |
  errored`.
- `sequencer_samples(id, capture_id, seq, token, status, duration_ms,
  captured_at)` -- ON DELETE CASCADE from the parent capture.

`template_blob` is zstd-compressed (same path as History blobs).

### Accessibility notes (live capture)

- Capture-list table on `/sequencer/` has a hidden `<caption>`, scoped
  column headers, and uses real text status (`idle`, `running`,
  `done`, ...) -- never colour-only.
- Capture-detail page is split into landmark sections: **Status**,
  **Controls**, **Configuration**, **Sample preview**.
- The progress indicator is a real `<progress>` element with
  `aria-valuetext` so screen readers announce *"42 of 200 samples
  (21%)"* rather than just the percentage. Phase-3 reliability tests
  enforce this on every page that exposes a `<progress>`.
- Auto-refresh is **opt-in**: the *Enable auto-refresh (3 s)* link
  toggles a `<meta http-equiv="refresh">`. WCAG 2.2.1 (Timing
  Adjustable) is satisfied because nothing refreshes until the operator
  asks for it, and the same link disables it again.
- Stale state is reconciled on render: a `running` / `paused` row with
  no in-process runner (server restart) is silently flipped to `idle`
  with a `stop_reason` set, so the controls and the announced status
  always agree.

## Test contract

`reqlore/tests/unit/test_sequencer.py`:

- `test_collect_tokens_strips_blank_lines_and_whitespace` -- input prep.
- `test_empty_input_returns_weak` -- weak verdict + "No tokens" note.
- `test_uniform_random_tokens_score_high` -- 40 random hex (16-char) -> fair/good band.
- `test_low_entropy_constant_pos_flagged` -- constant first char -> weak position 0.
- `test_counter_style_min_hamming_one` -- sequential IDs -> counter-style hint.
- `test_overall_bits_per_token_equals_per_char_times_length` -- formula sanity.
- `test_char_classes_count_all_seen_chars` -- char-class counting.

`reqlore/tests/unit/test_sequencer_deep.py` (deep battery):

- `test_gamma_p_endpoints` / `test_chi2_pvalue_uniform_is_high` /
  `test_chi2_pvalue_huge_stat_is_zero` -- math kernels.
- `test_monobit_balanced_passes` / `test_monobit_all_ones_fails_hard`.
- `test_runs_alternating_fails` -- perfect alternation rejected.
- `test_poker_uniform_passes` / `test_poker_constant_fails`.
- `test_encode_to_bits_assigns_log2_alphabet_widths` /
  `test_encode_to_bits_constant_position_is_zero_bits`.
- `test_deep_random_urlsafe_is_strong` -- CSPRNG tokens land strong.
- `test_deep_counter_tokens_are_weak` -- counter-style fails every test.
- `test_deep_detects_mirrored_bit_correlation` -- when bits at one
  position equal bits at another, correlation surfaces the exact pair.
- `test_deep_below_min_samples_returns_na` / `test_deep_empty_input_safe`.
- `test_deep_invalid_significance_falls_back` -- guards against bad input.
- `test_deep_correlation_skipped_for_oversize_tokens` -- runtime cap.
- `test_deep_does_not_break_simple_rating` -- legacy rating preserved.
- `test_per_bit_includes_compression_ratio`.
- `test_sequencer_get_renders_significance_dropdown` /
  `test_sequencer_post_runs_deep_by_default` /
  `test_sequencer_post_basic_only_skips_deep` /
  `test_sequencer_post_empty_flashes_warning` -- web surface.

`reqlore/tests/unit/test_sequencer_capture.py` (live capture, 33 tests):

- **Extractors (16 tests)** -- cookie / header / regex / json positive
  + negative paths, attribute stripping, multi-cookie selection,
  regex fallback to whole match on no-group, invalid-regex safety,
  list-index walk for JSON, `unknown kind` returns `None`, 4 KiB
  truncation, `EXTRACTOR_KINDS` constant frozen.
- **History hint (2 tests)** -- known session cookie auto-detected,
  unknown request defaults to empty arg.
- **Storage (5 tests)** -- create + list, round-trip the request
  blob, status + error-count updates, sample insertion + count +
  ordered listing, cascading delete.
- **Blueprint (5 tests)** -- `GET /capture/new` renders, missing
  extractor arg re-renders the form with the error, valid POST
  redirects to detail, 404 on missing capture, stale `running` state
  is auto-reconciled to `idle` after a simulated server restart.
- **Runner (3 tests, end-to-end against a local HTTP server)** --
  collects N unique session cookies and lands `done`; aborts with
  `errored` and a descriptive `stop_reason` when 10 responses lack
  the configured token; `cancel()` stops the loop within milliseconds
  with `cancelled` status.


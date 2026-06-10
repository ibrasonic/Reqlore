# Comparer — `/comparer/`

Side-by-side diff of any two pieces of text — typically two requests or
two responses captured by the [Proxy](proxy.md). Pairs naturally with
blind injection: replay a baseline, then replay a malicious variant, then
Comparer to see what actually changed.

## Where it is

- **URL:** `/comparer/`
- **Nav:** *Comparer* in the top bar.
- Single-page; PRG-cached form state.

## Quick start

1. From [History](history.md), pick the baseline row → row Actions → **Compare A** (Alt+M).
2. Pick the second row → **Compare B**.
3. Comparer opens with both sides pre-filled. Use the *Request / Response / Both* nav to switch what's compared.
4. Read the summary (lines added / removed / changed; bytes delta) and the side-by-side table below.
5. Optional: **Download unified diff (.diff)** for an external diff viewer or `patch -p0`.

Or paste any two blobs into the textareas and **Compare** manually.

## Routes

| URL                    | Method | What it does                                                              |
|------------------------|--------|---------------------------------------------------------------------------|
| `/comparer/`           | GET    | Render form. Prefill from `?from_a=<hid>&from_b=<hid>&view=<view>` or `?t=<token>`. |
| `/comparer/`           | POST   | Compute the diff; stash result in PRGCache; 302 to `?t=<token>`.            |
| `/comparer/export.diff`| GET    | Download a unified-diff patch (`text/x-diff`, filename includes both history IDs and the view). |

## Form fields

| Field    | Type     | Default     | Notes                                                                                  |
|----------|----------|-------------|----------------------------------------------------------------------------------------|
| Side A   | textarea | empty       | 12 rows. Loaded from history when `from_a` is set.                                      |
| Side B   | textarea | empty       | 12 rows. Loaded from history when `from_b` is set.                                      |
| view     | hidden   | `"request"` | One of `request`, `response`, `both`. Driven by the view-nav links.                     |
| from_a   | hidden   | empty       | History row id for Side A.                                                              |
| from_b   | hidden   | empty       | History row id for Side B.                                                              |

When `from_a` and/or `from_b` are set, a `<nav aria-label="What to
compare">` appears above the form with three links: **Request /
Response / Both (request + response)**. The active link carries
`aria-current="page"`.

## View modes

| Mode       | What gets diffed                                                                                  |
|------------|---------------------------------------------------------------------------------------------------|
| `request`  | Raw request bytes only (method line, headers, body).                                              |
| `response` | Raw response bytes only (status line, headers, body).                                             |
| `both`     | Request + literal separator `\n\n--- response ---\n\n` + response.                                |

## Diff algorithm

- Line-level diff via Python `difflib`.
- `diff_lines(a, b)` emits a flat list of `(tag, line_no_a, line_no_b, text)` tuples with tags `same` / `add` / `del`.
- `pair_diff_lines()` pairs consecutive `del + add` blocks into `chg` (changed) rows; unpaired ones stay pure `add` / `del`.
- The side-by-side table only renders `add` / `del` / `chg` rows — `same` lines are hidden so the table only shows what actually moved.
- Identical inputs produce an empty diff and the message *"No differences."*.

### Summaries

Two plain-English one-liners above the table:

- **Lines** — `diff_summary(a, b).sentence()`: e.g. *"3 lines only in B; 2 lines only in A; 1 line changed; 5 lines unchanged."*
- **Bytes** — `byte_diff_summary(a_bytes, b_bytes)`: e.g. *"A is 512 bytes, B is 520 bytes (delta +8)."* Or *"Identical"* when equal.

### Unified diff export

`unified_diff(a, b, label_a, label_b)` — standard `difflib.unified_diff`
output with 3 lines of context, `--- A` / `+++ B` headers, `@@` hunks,
guaranteed trailing newline. Identical inputs return empty.

Download filename:

- From-history: `history-<hid_a>-vs-<hid_b>-<view>.diff`.
- Pasted: `comparer.diff`.

## Accessibility notes

- Main form `aria-label="Compare A and B"`.
- View nav `aria-label="What to compare"`; active link `aria-current="page"`.
- Side A / Side B labels include the history id when loaded (e.g. *"A
  (history #42)"*) so screen readers can tell the panes apart.
- Summary section `<section aria-labelledby="cmp-sum">`; diff table
  section `<section aria-labelledby="cmp-diff">`.
- Diff table has `<caption>Only changed lines are shown. Each row is one
  line pair.</caption>`.
- Columns: A # / A / B # / B / Change. Numeric columns carry the
  `diff-num` class for monospace alignment.
- Empty cells render as `<span class="diff-empty">(none)</span>`.
- Row classes encode change type for high-contrast theming:
  `diff-add` / `diff-del` / `diff-chg`.
- Read order: view nav → form → submit → summary → download link →
  diff table.

## How it integrates

**Producers:**

- [History](history.md) detail + row Actions — **Send to Comparer (side A)** (Alt+M), then **Send to Comparer (side B)** on the second row.
- [Proxy](proxy.md) intercept detail — same.

**Consumers:** none — output is a downloadable `.diff` and an on-screen
table. Take the patch elsewhere if you need to apply it.

## Recipes

### Compare two pasted payloads

Paste a benign body into A, the malicious one into B. **Compare**. Read
the changed rows.

### Blind SQLi response diff

Send the baseline via [Repeater](repeater.md). Send the injection. From
[History](history.md), pick baseline → **Compare A**, pick injection →
**Compare B**, switch to **Response** view. The diff strips request
noise (headers, cookies) and shows only response deltas — perfect for
spotting a 1-row difference that indicates true-positive injection.

### Both-mode for full picture

Same setup, click **Both (request + response)**. Includes method / path
diffs and response diffs in one pass — handy when the injection lives in
a query parameter.

### Download a patch and apply elsewhere

After **Compare**, click **Download unified diff (.diff)**. Open in your
editor of choice, or `git apply`, or `patch -p0`.

## Storage footprint

**None persistent.** Form state in PRGCache (32-entry LRU, in-memory).
History rows are re-fetched on every GET when `from_a` / `from_b` are
set — no caching at the Comparer layer.

## CLI

No CLI equivalent.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Every line shows as changed                              | A uses CRLF (`\r\n`), B uses LF (`\n`); the `\r` makes every line differ | Normalise endings before pasting (Decoder → URL-decode preserves them; do it externally).         |
| Diff is huge and slow                                    | No pagination — comparing multi-MB responses renders one giant table    | Switch to **Response** only; or download the unified diff and use a streaming diff tool.          |
| View-switch lost my manual edits                          | When `from_a` / `from_b` are set, switching view re-fetches from history | Save your edits elsewhere before switching views.                                                 |
| Binary body shows as `�` chars                            | History rows decoded as UTF-8 with `errors="replace"`                   | For byte-level diff, copy each side, run `hex_encode` in [Decoder](decoder.md), then compare.    |
| "Both" mode shows `--- response ---` as content           | That string is the literal separator                                    | Working as designed — it marks the request/response boundary in the joined blob.                  |

## Test contract

`reqlore/tests/unit/test_diff_and_jwt.py` locks:

- `test_diff_summary_identical` / `test_diff_summary_add_remove_change` — counts and plain-English `.sentence()`.
- `test_diff_lines_emits_per_line_records` — tag emission.
- `test_pair_diff_lines_pairs_replace_block_into_chg` — pair-into-chg semantics.
- `test_pair_diff_lines_pure_add_and_pure_del` / `…unequal_replace_block` — asymmetric pairing.
- `test_byte_diff_summary_identical` / `…length_change` — byte summary shape.
- `test_unified_diff_emits_standard_format` / `…_identical_returns_empty` / `…_custom_labels` — patch format.

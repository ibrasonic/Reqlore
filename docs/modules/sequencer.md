# Sequencer — `/sequencer/`

Paste a pile of session IDs, CSRF tokens, password-reset tokens, or
anti-bot tokens — get a Shannon-entropy report with per-position
analysis, Hamming-distance summary, longest-run check, and a verdict
(weak / fair / good / excellent). If the verdict is weak or fair, a
finding is recorded.

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

| Field    | Type     | Default | Notes                                                                |
|----------|----------|---------|----------------------------------------------------------------------|
| `tokens` | textarea | empty   | **Required.** One token per line. Empty / whitespace lines dropped.   |
| `_csrf`  | hidden   | (gen.)  | CSRF token for the form.                                              |

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

- Rating + sample count + common length.
- Entropy (bits/char and bits/token).
- Longest run.
- Hamming min / mean / max.
- Char-class counts.
- Per-position table: position / distinct / bits / top-3 chars.
  Weak positions get a `row-warn` CSS class.

## Accessibility notes

- `<label for="tokens">Tokens (one per line)</label>` on the textarea.
- Result heading `<h2 id="result">Result — N sample(s)</h2>`.
- `<dl>` / `<dt>` / `<dd>` for the metrics; `<table>` with
  `<th scope="col">` for the per-position grid.
- Errors render in the global flash region.

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

## Test contract

`reqlore/tests/unit/test_sequencer.py`:

- `test_collect_tokens_strips_blank_lines_and_whitespace` — input prep.
- `test_empty_input_returns_weak` — weak verdict + "No tokens" note.
- `test_uniform_random_tokens_score_high` — 40 random hex (16-char) → fair/good band.
- `test_low_entropy_constant_pos_flagged` — constant first char → weak position 0.
- `test_counter_style_min_hamming_one` — sequential IDs → counter-style hint.
- `test_overall_bits_per_token_equals_per_char_times_length` — formula sanity.
- `test_char_classes_count_all_seen_chars` — char-class counting.

# Cues — `/cues/`

Five tiny synthesised audio cues — `ok`, `warn`, `error`, `intercept`,
`scan_hit` — that other modules play (when enabled in
[Settings](settings.md)) to confirm async events without needing your
eyes on the screen. Each cue is generated on the fly: 22050 Hz mono
16-bit PCM, ~5 KB per WAV, ADSR-shaped sine wave or chord.

Off by default. Toggle via [Settings](settings.md) → **Cues** checkbox.

## Where it is

- **URL:** `/cues/`
- Linked from [Settings](settings.md).
- Five WAV endpoints: `/cues/<name>.wav`.

## Quick start

1. Open [Settings](settings.md) and tick **Cues**, **Save**.
2. Open `/cues/` → table lists the five cues with description + a
   built-in `<audio controls>` player. Preview each.
3. Drive any module that emits a cue (e.g. trigger an [Intercept](proxy.md)
   pause) — your browser (or operating system) plays the WAV when the
   client-side code fetches it.

## Routes

| URL                  | Method | What it does                                       |
|----------------------|--------|----------------------------------------------------|
| `/cues/`             | GET    | Render preview table of the five cues.             |
| `/cues/<name>.wav`   | GET    | Stream a freshly synthesised WAV (`404` if unknown). |

## The five cues

| Name        | Description                                                 |
|-------------|-------------------------------------------------------------|
| `ok`        | Short major-3rd chord — operation completed.                 |
| `warn`      | Two-tone descending — non-blocking warning.                  |
| `error`     | Low minor-2nd chord — failure.                               |
| `intercept` | Short tap — an intercept arrived in the proxy queue.         |
| `scan_hit`  | Two-tone ascending — a finding hit during a passive scan.    |

Defined in the `CUES` registry in `reqlore/audio.py`.

## Synthesis

`tone(freq, ms=120, amp=0.35)`:

- Sine wave: `math.sin(2π·f·t)`.
- Linear ADSR envelope: attack = `min(20 ms, duration / 4)`, mirror release.
- Sample rate 22050 Hz, mono, 16-bit signed PCM.

`chord(freqs, ms=180)`:

- Sum of sines at the given frequencies.
- Amplitude per-component is `0.35 / len(freqs)` to stay under
  clipping.

Output via `wave.open()` + `struct.pack("<h", …)`. No external assets.

## Accessibility notes

- Native `<audio controls preload="none">` per row — OS-level play /
  pause / volume.
- Table: `<caption>` + `<th scope="col">`.
- Off by default — respects users who disable autoplay.
- Mono audio — left/right balanced by the OS, no stereo dependence.

## How it integrates

**Producer:** none — cues are author-installed only.

**Consumer:**

- [Proxy](proxy.md) intercept arrival → `intercept`.
- [Scanner](scanner.md) finding → `scan_hit`.
- General operation success → `ok`; warning → `warn`; error → `error`.

Each consumer checks `g.project.get_state("cues", "0") == "1"` before
emitting the WAV fetch.

## Recipes

### Preview a single cue without enabling

`curl http://localhost:5000/cues/ok.wav --output ok.wav`. Open in your
local audio player.

### Enable and stress-test

Tick **Cues** in Settings. Trigger an intercept; you should hear the
`intercept` tap. Trigger an error (malformed URL in [Repeater](repeater.md));
you should hear `error`.

### Disable in a hostile office

Tick *off* in Settings, **Save**. Other modules silently stop fetching
WAVs.

### Author a new cue (code)

Edit `reqlore/audio.py` and extend `CUES`:

```python
CUES["notify"] = (
    "Three-tone ascending — important event",
    lambda: chord([523.25, 659.25, 783.99], 150),
)
```

Restart. `/cues/notify.wav` is live; the preview table picks it up
automatically.

### Programmatic WAV generation

```python
from reqlore.audio import tone, chord
wav = tone(freq=440.0, ms=200, amp=0.35)  # A4, 200 ms
wav = chord([262.0, 329.63, 392.0], ms=180)  # C major triad
```

## Storage footprint

- `project_state["cues"]` — `"0"` (default) / `"1"`.

WAVs are not cached server-side — regenerated on every request
(imperceptibly fast at 22 kHz mono).

## CLI

No CLI surface.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| No sound                                                 | Cues off in Settings, or browser autoplay policy is blocking            | Tick **Cues** in Settings; click in the page once to unlock autoplay; or use the manual play button. |
| `/cues/foo.wav` → 404                                    | Cue name not in `CUES` registry                                         | Check `/cues/` for the canonical name list.                                                       |
| Chord clips / sounds harsh                               | More than 5 frequencies in a custom cue                                 | Lower the per-component `amp` (default `0.35 / N`).                                              |
| Browser keeps caching old version                        | `Cache-Control: public, max-age=3600`                                   | Bypass cache (Shift+Reload), or append `?v=<n>` in your custom client.                            |
| Mono only — no stereo separation                         | Mono by design                                                          | Out of scope; pipe through a real audio library if you need stereo.                              |

## Test contract

No dedicated `test_cues.py`. Coverage comes from the smoke tests
fetching `/cues/` and an example plugin in
`reqlore/tests/unit/test_plugins_sdk.py::test_example_extra_headers_rule_yields_finding`.

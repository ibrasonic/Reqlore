"""Audio cue generator — produces small WAV blobs from sine + envelope.

Cues are generated on demand by the cues blueprint; no external assets needed.
"""
from __future__ import annotations

import io
import math
import struct
import wave
from collections.abc import Callable

SAMPLE_RATE = 22050


def tone(freq: float = 880.0, ms: int = 120, *, amp: float = 0.35) -> bytes:
    """Return a mono 16-bit PCM WAV blob of a sine tone with linear in/out envelope."""
    n_samples = int(SAMPLE_RATE * ms / 1000)
    frames = bytearray()
    env_ms = min(20, ms // 4)
    env_samples = int(SAMPLE_RATE * env_ms / 1000) or 1
    for i in range(n_samples):
        env = 1.0
        if i < env_samples:
            env = i / env_samples
        elif i > n_samples - env_samples:
            env = max(0.0, (n_samples - i) / env_samples)
        v = amp * env * math.sin(2 * math.pi * freq * (i / SAMPLE_RATE))
        frames += struct.pack("<h", int(v * 32767))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SAMPLE_RATE)
        w.writeframes(bytes(frames))
    return buf.getvalue()


def chord(freqs: list[float], ms: int = 180) -> bytes:
    """Sum multiple tones at lower amplitude each."""
    if not freqs:
        return tone(440, ms)
    amp = 0.35 / len(freqs)
    n = int(SAMPLE_RATE * ms / 1000)
    env_samples = max(1, int(SAMPLE_RATE * 20 / 1000))
    frames = bytearray()
    for i in range(n):
        env = 1.0
        if i < env_samples:
            env = i / env_samples
        elif i > n - env_samples:
            env = max(0.0, (n - i) / env_samples)
        v = 0.0
        for f in freqs:
            v += amp * math.sin(2 * math.pi * f * (i / SAMPLE_RATE))
        frames += struct.pack("<h", int(env * v * 32767))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SAMPLE_RATE)
        w.writeframes(bytes(frames))
    return buf.getvalue()


CUES: dict[str, tuple[str, Callable[[], bytes]]] = {
    "ok":       ("Short major-3rd chord — operation completed.",
                 lambda: chord([523.25, 659.25], 140)),
    "warn":     ("Two-tone descending — needs attention.",
                 lambda: chord([523.25, 440.0], 160)),
    "error":    ("Low buzz — operation failed.",
                 lambda: tone(196.0, 220)),
    "intercept":("Single bright ping — request held.",
                 lambda: tone(1318.51, 90)),
    "scan_hit": ("Two short rising pings — scanner found something.",
                 lambda: chord([880.0, 1108.73], 180)),
}


def render(name: str) -> bytes | None:
    spec = CUES.get(name)
    return spec[1]() if spec else None

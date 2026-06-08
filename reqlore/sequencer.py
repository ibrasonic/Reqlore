"""Token-quality analyser (Burp Sequencer-style, deterministic, no plotting).

Given a list of session/CSRF/anti-bot tokens, compute:

* Shannon entropy in bits per character and bits per token (overall)
* Per-position character-class distribution (alpha / digit / mixed)
* Per-position Shannon entropy
* Character-class summary (lower, upper, digit, punct, other)
* Runs of identical characters and longest-repeat
* Pairwise Hamming distance summary (min/mean/max)

The point is to surface obvious weakness:

* "All tokens share the same length but byte 8 only ever uses 4 distinct
  characters" -> low-entropy position.
* "Min Hamming distance is 1" -> consecutive tokens differ by a single byte
  (counter-style IDs).
"""
from __future__ import annotations

import math
import string
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class PositionStats:
    index: int
    distinct: int
    entropy_bits: float
    most_common: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class SequencerResult:
    sample_count: int
    common_length: int                 # most-common token length
    length_variance: int               # max - min length
    overall_entropy_bits_per_char: float
    overall_entropy_bits_per_token: float
    char_classes: dict[str, int]       # counts across the whole pool
    positions: list[PositionStats]
    weak_positions: list[int]          # indices with entropy < 2 bits
    longest_run: int                   # longest run of identical chars
    min_hamming: int
    mean_hamming: float
    max_hamming: int
    rating: str                        # "excellent" | "good" | "fair" | "weak"
    notes: list[str] = field(default_factory=list)


def _shannon(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        p = c / total
        if p > 0:
            h -= p * math.log2(p)
    return h


def _classify(ch: str) -> str:
    if ch in string.ascii_lowercase:
        return "lower"
    if ch in string.ascii_uppercase:
        return "upper"
    if ch in string.digits:
        return "digit"
    if ch in string.punctuation:
        return "punct"
    return "other"


def _longest_run(text: str) -> int:
    if not text:
        return 0
    best = 1
    cur = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 1
    return best


def _hamming(a: str, b: str) -> int:
    n = min(len(a), len(b))
    diff = sum(1 for i in range(n) if a[i] != b[i])
    return diff + abs(len(a) - len(b))


def analyse(tokens: list[str]) -> SequencerResult:
    """Run all the sequencer checks on the supplied tokens."""
    tokens = [t for t in tokens if t]
    if not tokens:
        return SequencerResult(0, 0, 0, 0.0, 0.0, {}, [], [], 0, 0, 0.0, 0,
                                "weak", ["No tokens supplied."])

    lengths = [len(t) for t in tokens]
    length_counter = Counter(lengths)
    common_length = length_counter.most_common(1)[0][0]
    length_variance = max(lengths) - min(lengths)

    # Overall char counter for global stats.
    all_chars = Counter()
    classes = Counter()
    for t in tokens:
        for ch in t:
            all_chars[ch] += 1
            classes[_classify(ch)] += 1
    overall_bits_per_char = _shannon(all_chars)
    overall_bits_per_token = overall_bits_per_char * common_length

    # Per-position stats (limited to common_length so tokens of varied
    # lengths don't lopsidedly skew tail positions).
    positions: list[PositionStats] = []
    weak: list[int] = []
    for i in range(common_length):
        col = Counter()
        for t in tokens:
            if i < len(t):
                col[t[i]] += 1
        h = _shannon(col)
        positions.append(PositionStats(
            index=i, distinct=len(col), entropy_bits=h,
            most_common=col.most_common(3),
        ))
        if h < 2.0:
            weak.append(i)

    # Hamming distance over the first N pairs.
    pairs = min(64, len(tokens) - 1)
    if pairs > 0:
        dists = [_hamming(tokens[k], tokens[k + 1]) for k in range(pairs)]
        min_h = min(dists)
        max_h = max(dists)
        mean_h = sum(dists) / len(dists)
    else:
        min_h = max_h = 0
        mean_h = 0.0

    longest = max(_longest_run(t) for t in tokens)

    notes: list[str] = []
    if length_variance:
        notes.append(f"Token length varies by {length_variance} characters.")
    if weak:
        notes.append(f"Low-entropy positions detected: {weak}")
    if min_h == 1:
        notes.append("Consecutive tokens differ by only one character "
                      "(counter-style IDs?).")
    if longest >= max(4, common_length // 4):
        notes.append(f"Longest repeated character run: {longest}.")

    # Rating purely from entropy density (bits/char).
    if overall_bits_per_char >= 5.5:
        rating = "excellent"
    elif overall_bits_per_char >= 4.5:
        rating = "good"
    elif overall_bits_per_char >= 3.0:
        rating = "fair"
    else:
        rating = "weak"

    return SequencerResult(
        sample_count=len(tokens),
        common_length=common_length,
        length_variance=length_variance,
        overall_entropy_bits_per_char=overall_bits_per_char,
        overall_entropy_bits_per_token=overall_bits_per_token,
        char_classes=dict(classes),
        positions=positions,
        weak_positions=weak,
        longest_run=longest,
        min_hamming=min_h,
        mean_hamming=mean_h,
        max_hamming=max_h,
        rating=rating,
        notes=notes,
    )


def collect_tokens(blob: str) -> list[str]:
    """Split a textarea into individual tokens (one per line, trimmed)."""
    out: list[str] = []
    for line in blob.replace("\r", "\n").split("\n"):
        s = line.strip()
        if s:
            out.append(s)
    return out

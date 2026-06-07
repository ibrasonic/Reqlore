"""Phase 5 — Sequencer entropy analysis."""
from __future__ import annotations

import math

from weblore.sequencer import analyse, collect_tokens


def test_collect_tokens_strips_blank_lines_and_whitespace():
    out = collect_tokens("  abc\n\n  def \r\n\nxyz")
    assert out == ["abc", "def", "xyz"]


def test_empty_input_returns_weak():
    r = analyse([])
    assert r.sample_count == 0
    assert r.rating == "weak"
    assert "No tokens" in r.notes[0]


def test_uniform_random_tokens_score_high():
    import secrets
    pool = [secrets.token_hex(16) for _ in range(40)]
    r = analyse(pool)
    assert r.sample_count == 40
    assert r.common_length == 32
    # Hex alphabet has 16 symbols -> max log2(16)=4 bits/char.
    assert 3.5 <= r.overall_entropy_bits_per_char <= 4.0
    assert r.rating in ("fair", "good")


def test_low_entropy_constant_pos_flagged():
    # First char is always 'X'; rest is hex.
    import secrets
    pool = ["X" + secrets.token_hex(8) for _ in range(30)]
    r = analyse(pool)
    assert 0 in r.weak_positions       # position 0 is constant -> 0 bits
    # The note must call it out.
    assert any("Low-entropy positions" in n for n in r.notes)


def test_counter_style_min_hamming_one():
    pool = [f"abcdef-{i:06d}" for i in range(20)]
    r = analyse(pool)
    assert r.min_hamming == 1
    assert any("counter-style" in n for n in r.notes)


def test_overall_bits_per_token_equals_per_char_times_length():
    pool = ["aaaa", "aabb", "abba", "baab"]
    r = analyse(pool)
    expected = r.overall_entropy_bits_per_char * r.common_length
    assert math.isclose(r.overall_entropy_bits_per_token, expected)


def test_char_classes_count_all_seen_chars():
    pool = ["Ab1!", "Cd2@"]
    r = analyse(pool)
    assert r.char_classes["upper"] == 2
    assert r.char_classes["lower"] == 2
    assert r.char_classes["digit"] == 2
    assert r.char_classes["punct"] == 2

"""Deep statistical randomness battery for the Sequencer."""
from __future__ import annotations

import math
import random
import secrets

from reqlore.sequencer import (
    _chi2_pvalue,
    _encode_to_bits,
    _gamma_p,
    _monobit_test,
    _poker_test,
    _runs_test,
    analyse_deep,
)

# ---------------------------------------------------------------- math kernels


def test_gamma_p_endpoints():
    assert _gamma_p(1.0, 0.0) == 0.0
    # P(1, x) = 1 - e^{-x}.
    assert math.isclose(_gamma_p(1.0, 2.0), 1.0 - math.exp(-2.0), rel_tol=1e-9)


def test_chi2_pvalue_uniform_is_high():
    """A near-zero chi-square statistic must produce a p-value near 1."""
    p = _chi2_pvalue(0.01, 15)
    assert 0.9 < p <= 1.0


def test_chi2_pvalue_huge_stat_is_zero():
    """A huge chi-square must produce a near-zero p-value."""
    p = _chi2_pvalue(500.0, 15)
    assert p < 1e-20


# --------------------------------------------------------------- per-bit tests


def test_monobit_balanced_passes():
    bits = [0, 1] * 100
    t = _monobit_test(bits)
    assert t.name == "monobit"
    assert t.p_value is not None and t.p_value > 0.5


def test_monobit_all_ones_fails_hard():
    t = _monobit_test([1] * 100)
    assert t.p_value is not None and t.p_value < 1e-20


def test_runs_alternating_fails():
    """Perfect alternation produces 200 runs in 200 bits — far above the
    expected ~100 — and must register as non-random."""
    t = _runs_test([0, 1] * 100)
    assert t.p_value is not None and t.p_value < 0.01


def test_poker_uniform_passes():
    rnd = random.Random(0xC0FFEE)  # noqa: S311  # non-cryptographic — seeded PRNG for reproducible statistical-test fixtures
    bits = [rnd.randrange(2) for _ in range(4000)]
    t = _poker_test(bits)
    assert t.p_value is not None and t.p_value > 0.05


def test_poker_constant_fails():
    t = _poker_test([0] * 4000)
    assert t.p_value is not None and t.p_value < 1e-20


# --------------------------------------------------------------- bit encoding


def test_encode_to_bits_assigns_log2_alphabet_widths():
    tokens = ["a1", "b2", "c3", "d4"]  # pos0: a/b/c/d (4 = 2 bits), pos1: 1/2/3/4 (2 bits)
    bits_per_token, widths, matrix = _encode_to_bits(tokens, 2)
    assert widths == [2, 2]
    assert bits_per_token == 4
    assert len(matrix) == 4
    assert all(len(row) == 4 for row in matrix)


def test_encode_to_bits_constant_position_is_zero_bits():
    tokens = ["X1", "X2", "X3", "X4"]   # pos0 always 'X'
    bits_per_token, widths, matrix = _encode_to_bits(tokens, 2)
    assert widths[0] == 0
    assert bits_per_token == widths[1]


# ----------------------------------------------------------- end-to-end deep


def test_deep_random_urlsafe_is_strong():
    tokens = [secrets.token_urlsafe(32) for _ in range(200)]
    r = analyse_deep(tokens, significance=0.01)
    assert r.deep is not None
    assert r.deep.deep_rating == "strong"
    # Bonferroni-corrected: almost no false positives.
    assert len(r.deep.correlation_warnings) <= 3
    # Effective bits should be near the theoretical maximum.
    assert r.deep.effective_bits_at_significance >= int(0.85 * r.deep.bits_per_token)


def test_deep_counter_tokens_are_weak():
    tokens = [f"abc{i:05d}" for i in range(200)]
    r = analyse_deep(tokens, significance=0.01)
    assert r.deep is not None
    assert r.deep.deep_rating == "weak"
    # Counter style → every per-position transition fails.
    assert r.deep.transitions, "expected transition tests to run"
    failed = [t for t in r.deep.transitions if not t.passed]
    assert len(failed) == len(r.deep.transitions)
    assert r.deep.effective_bits_at_significance == 0


def test_deep_detects_mirrored_bit_correlation():
    """If a token's first hex digit always equals its last hex digit,
    the correlation test must flag the 4-bit slices."""
    rnd = random.Random(0)  # noqa: S311  # non-cryptographic — seeded PRNG for reproducible correlation-test fixture
    tokens = []
    for _ in range(300):
        body = "".join(rnd.choice("0123456789abcdef") for _ in range(16))
        tokens.append(body[0] + body[1:-1] + body[0])   # mirror last from first
    r = analyse_deep(tokens, significance=0.01)
    assert r.deep is not None
    assert r.deep.correlation_warnings, "expected at least one correlation warning"
    # First-position bits should pair with last-position bits.
    # Bits 0..3 = pos0 nibble; last 4 bits = position 15 nibble.
    a_range = set(range(0, 4))
    b_range = set(range(r.deep.bits_per_token - 4, r.deep.bits_per_token))
    found = any(c.bit_a in a_range and c.bit_b in b_range
                for c in r.deep.correlation_warnings)
    assert found, [vars(c) for c in r.deep.correlation_warnings]


def test_deep_below_min_samples_returns_na():
    r = analyse_deep(["a", "b"], significance=0.01)
    assert r.deep is not None
    assert r.deep.deep_rating == "n/a"
    assert any("at least" in n for n in r.deep.notes)


def test_deep_empty_input_safe():
    r = analyse_deep([], significance=0.01)
    assert r.sample_count == 0
    assert r.deep is not None
    assert r.deep.deep_rating == "n/a"


def test_deep_invalid_significance_falls_back():
    r = analyse_deep(["a" * 8] * 10, significance=99.0)
    assert r.deep is not None
    assert r.deep.significance == 0.01


def test_deep_correlation_skipped_for_oversize_tokens():
    """Tokens with more bits per token than the cap skip correlation."""
    # 60 positions * a 200-symbol alphabet -> 60 * 8 = 480 bits per token,
    # well above the 256-bit correlation cap. 250 samples are enough to
    # see roughly the whole alphabet at each position.
    rnd = random.Random(7)  # noqa: S311  # non-cryptographic — seeded PRNG for reproducible correlation-cap test fixture
    pool = "".join(chr(33 + i) for i in range(200))   # printable ASCII pool
    tokens = ["".join(rnd.choice(pool) for _ in range(60)) for _ in range(250)]
    r = analyse_deep(tokens, significance=0.01)
    assert r.deep is not None
    assert r.deep.bits_per_token > 256
    assert "skipped" in r.deep.correlation_skipped_reason
    assert r.deep.correlation_warnings == []


def test_deep_does_not_break_simple_rating():
    """analyse_deep must preserve the legacy 'rating' field exactly."""
    tokens = [f"abc{i:05d}" for i in range(40)]
    r = analyse_deep(tokens, significance=0.01)
    # Same simple-rating bands as analyse().
    assert r.rating in ("weak", "fair", "good", "excellent")


def test_per_bit_includes_compression_ratio():
    tokens = [secrets.token_hex(16) for _ in range(100)]
    r = analyse_deep(tokens, significance=0.01)
    assert r.deep is not None
    assert all(0.0 <= pb.compression_ratio <= 1.0 for pb in r.deep.per_bit)


# ------------------------------------------------------------ web smoke test


def _client(tmp_path):
    from reqlore.config import Settings
    from reqlore.web import create_app
    app = create_app(tmp_path / "seq.rlr", Settings(), proxy=None)
    app.config["TESTING"] = True
    return app.test_client()


def _csrf(client) -> str:
    client.get("/sequencer/")
    with client.session_transaction() as sess:
        return sess.get("csrf", "")


def test_sequencer_get_renders_significance_dropdown(tmp_path):
    client = _client(tmp_path)
    resp = client.get("/sequencer/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "significance" in body
    assert "Run deep analysis" in body
    assert 'name="deep"' in body


def test_sequencer_post_runs_deep_by_default(tmp_path):
    client = _client(tmp_path)
    csrf = _csrf(client)
    tokens = "\n".join(secrets.token_urlsafe(24) for _ in range(40))
    resp = client.post(
        "/sequencer/",
        data={"_csrf": csrf, "tokens": tokens,
              "significance": "0.01", "deep": "1"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Deep statistical analysis" in body
    assert "Effective bits at alpha" in body
    assert "Bit-pair correlation" in body


def test_sequencer_post_basic_only_skips_deep(tmp_path):
    client = _client(tmp_path)
    csrf = _csrf(client)
    tokens = "\n".join(secrets.token_urlsafe(24) for _ in range(20))
    resp = client.post(
        "/sequencer/",
        data={"_csrf": csrf, "tokens": tokens,
              "significance": "0.01"},   # no deep field
        follow_redirects=True,
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Simple summary always present.
    assert "Per-position character breakdown" in body
    # Deep section must NOT be present when deep wasn't requested.
    assert "Deep statistical analysis" not in body


def test_sequencer_post_empty_flashes_warning(tmp_path):
    client = _client(tmp_path)
    csrf = _csrf(client)
    resp = client.post(
        "/sequencer/",
        data={"_csrf": csrf, "tokens": "   \n  ",
              "significance": "0.01", "deep": "1"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Paste at least one token" in body


def test_sequencer_renders_plain_english_verdict_random(tmp_path):
    """High-entropy tokens must trigger the explicit 'look random'
    sentence, not just the STRONG / EXCELLENT word."""
    client = _client(tmp_path)
    csrf = _csrf(client)
    tokens = "\n".join(secrets.token_urlsafe(24) for _ in range(60))
    resp = client.post(
        "/sequencer/",
        data={"_csrf": csrf, "tokens": tokens,
              "significance": "0.01", "deep": "1"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Verdict:" in body
    assert "look random" in body  # plain English


def test_sequencer_renders_plain_english_verdict_not_random(tmp_path):
    """Counter-style tokens must trigger the explicit 'NOT random'
    sentence so a non-cryptographer can read the verdict."""
    client = _client(tmp_path)
    csrf = _csrf(client)
    tokens = "\n".join(f"id-{i:08d}" for i in range(60))
    resp = client.post(
        "/sequencer/",
        data={"_csrf": csrf, "tokens": tokens,
              "significance": "0.01", "deep": "1"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Verdict:" in body
    assert "NOT random" in body

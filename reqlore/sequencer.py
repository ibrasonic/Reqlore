"""Token-quality analyser (deterministic, no plotting).

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
import zlib
from collections import Counter
from dataclasses import dataclass, field
from itertools import combinations


@dataclass
class PositionStats:
    index: int
    distinct: int
    entropy_bits: float
    most_common: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class BitTest:
    """One per-bit-position statistical test result."""
    name: str
    statistic: float
    p_value: float | None              # None when test not applicable
    passed: bool | None                # None when not applicable
    note: str = ""


@dataclass
class PerBitStats:
    """Per-bit-position summary across the sample."""
    index: int
    ones: int
    zeros: int
    longest_run: int
    compression_ratio: float           # bytes_after / bytes_before, lower = less random
    tests: list[BitTest] = field(default_factory=list)
    effective_bit: bool = False        # all applicable tests passed at significance


@dataclass
class TransitionStat:
    """Per-character-position transition (Markov) test."""
    index: int
    chi_square: float
    df: int
    p_value: float
    passed: bool


@dataclass
class CorrelationWarning:
    """One bit-pair flagged for non-independence."""
    bit_a: int
    bit_b: int
    chi_square: float
    p_value: float


@dataclass
class DeepAnalysis:
    """Deep statistical analysis (FIPS-style randomness battery)."""
    significance: float                # e.g. 0.01
    bits_per_token: int                # sum of per-position bit widths
    per_position_bits: list[int]       # bit width assigned to each character position
    overall_compression_ratio: float   # zlib ratio over concatenated bit-bytes
    transitions: list[TransitionStat] = field(default_factory=list)
    per_bit: list[PerBitStats] = field(default_factory=list)
    correlation_warnings: list[CorrelationWarning] = field(default_factory=list)
    correlation_pairs_tested: int = 0
    correlation_skipped_reason: str = ""
    effective_bits_at_significance: int = 0
    deep_rating: str = "n/a"           # "strong"|"fair"|"weak"|"n/a"
    notes: list[str] = field(default_factory=list)


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
    deep: DeepAnalysis | None = None


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
    all_chars: Counter[str] = Counter()
    classes: Counter[str] = Counter()
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
        col: Counter[str] = Counter()
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


_SEVERITY_FOR_RATING = {
    "weak":      "high",
    "fair":      "medium",
    "good":      "low",
    "excellent": "info",
}


def record_sequencer_finding(project, result: SequencerResult, *,
                              host: str = "", url: str = "",
                              source_label: str = "pasted tokens"
                              ) -> int | None:
    """Promote a :class:`SequencerResult` into a single Finding. Only fires
    when the verdict is below ``good`` (weak/fair) — strong tokens record a
    skipped rule_run instead. Returns the finding id, or ``None`` when
    suppressed / no finding warranted."""
    from .findings_bus import record_finding, record_no_finding
    rule_id = "sequencer:low-entropy"
    if result.rating in ("good", "excellent"):
        record_no_finding(project, rule_id=rule_id, host=host, url=url,
                            reason=f"rating={result.rating}")
        return None
    severity = _SEVERITY_FOR_RATING.get(result.rating, "medium")
    evidence_lines = [
        f"Sample: {result.sample_count} tokens, common length "
        f"{result.common_length}.",
        f"Entropy: {result.overall_entropy_bits_per_char:.2f} bits/char, "
        f"{result.overall_entropy_bits_per_token:.1f} bits/token.",
        f"Rating: {result.rating}.",
    ]
    if result.weak_positions:
        evidence_lines.append(
            f"Low-entropy positions: {result.weak_positions}"
        )
    if result.min_hamming == 1:
        evidence_lines.append(
            "Consecutive tokens differ by only one character."
        )
    description = (
        "Session/CSRF/anti-bot tokens analysed by Reqlore's sequencer fell "
        f"into the \"{result.rating}\" band. Low-entropy tokens are guessable "
        "and can be brute-forced or predicted."
    )
    return record_finding(
        project, source="sequencer", rule_id=rule_id, severity=severity,
        title=f"Weak token entropy ({result.rating})",
        description=description,
        remediation=(
            "Generate tokens with a cryptographically-secure random source "
            "(at least 128 bits of entropy) and avoid embedding counters or "
            "timestamps in the token body."
        ),
        cwe="CWE-330", owasp="A02:2021-Cryptographic Failures",
        host=host, url=url,
        evidence=" ".join(evidence_lines),
        payload=source_label,
    )


# ---------------------------------------------------------------------------
# Deep analysis: FIPS-style statistical randomness battery.
#
# All math is pure-Python (no scipy/numpy). Implementations follow the FIPS
# 140-2 / NIST SP 800-22 style tests, with the closed-form p-value formulae
# where they exist (monobit, runs) and a small implementation of the
# regularised upper incomplete gamma for general chi-square p-values
# (poker, transition, correlation).
# ---------------------------------------------------------------------------

# Hard caps to keep wall-time bounded on hostile input.
_DEEP_MAX_SAMPLES = 20_000          # ignore beyond, like FIPS spec ceiling
_DEEP_MAX_COMMON_LEN = 256          # truncate analysis to first N chars
_DEEP_MAX_BITS_FOR_CORRELATION = 256
_DEEP_MIN_SAMPLES = 8               # below this everything reports n/a


def _gamma_p(a: float, x: float) -> float:
    """Regularised lower incomplete gamma P(a, x). Numerical-Recipes style.

    Returns a float in [0, 1]. `a` must be > 0, `x` must be >= 0.
    """
    if a <= 0 or x < 0:
        return 0.0
    if x == 0.0:
        return 0.0
    log_norm = -x + a * math.log(x) - math.lgamma(a)
    if x < a + 1.0:
        # Power-series expansion for P(a, x).
        term = 1.0 / a
        s = term
        ap = a
        for _ in range(2000):
            ap += 1.0
            term *= x / ap
            s += term
            if abs(term) < abs(s) * 1e-15:
                break
        return s * math.exp(log_norm)
    # Lentz continued fraction for Q(a, x); then P = 1 - Q.
    b = x + 1.0 - a
    c = 1e300
    d = 1.0 / b
    h = d
    for i in range(1, 2000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    q = h * math.exp(log_norm)
    return max(0.0, min(1.0, 1.0 - q))


def _chi2_pvalue(stat: float, df: int) -> float:
    """Upper-tail p-value of a chi-square with ``df`` degrees of freedom."""
    if df <= 0 or stat <= 0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - _gamma_p(df / 2.0, stat / 2.0)))


def _longest_run_bits(bits: list[int], value: int) -> int:
    best = cur = 0
    for b in bits:
        if b == value:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def _bits_to_bytes(bits: list[int]) -> bytes:
    """Pack a list of 0/1 ints into a byte string (big-endian, MSB first)."""
    if not bits:
        return b""
    pad = (-len(bits)) % 8
    padded = bits + [0] * pad
    out = bytearray(len(padded) // 8)
    for i, b in enumerate(padded):
        if b:
            out[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(out)


def _compression_ratio(bits: list[int]) -> float:
    """zlib(level=9) ratio in [0, 1]. Lower = less random.

    Constant streams compress hard, true random rounds to ~1.0 (zlib has
    framing overhead for tiny inputs, so for very small N we clamp at 1.0).
    """
    raw = _bits_to_bytes(bits)
    if not raw:
        return 1.0
    compressed = zlib.compress(raw, 9)
    return min(1.0, len(compressed) / max(1, len(raw)))


def _monobit_test(bits: list[int]) -> BitTest:
    """NIST monobit: balance of 0s and 1s.

    p = erfc(|2k - N| / sqrt(2N)) where k = number of ones.
    """
    n = len(bits)
    if n < 2:
        return BitTest("monobit", 0.0, None, None, "sample too small")
    k = sum(bits)
    s = 2 * k - n
    p = math.erfc(abs(s) / math.sqrt(2.0 * n))
    return BitTest("monobit", abs(s) / math.sqrt(float(n)), p, None)


def _runs_test(bits: list[int]) -> BitTest:
    """NIST runs test: total number of runs.

    Skipped if the monobit balance fails the pre-test |pi - 0.5| < 2/sqrt(N).
    """
    n = len(bits)
    if n < 4:
        return BitTest("runs", 0.0, None, None, "sample too small")
    pi = sum(bits) / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return BitTest("runs", 0.0, None, None,
                        "skipped: monobit pre-test failed")
    vn = 1 + sum(1 for k in range(n - 1) if bits[k] != bits[k + 1])
    expected = 2.0 * n * pi * (1.0 - pi)
    denom = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    if denom == 0:
        return BitTest("runs", 0.0, None, None, "degenerate sample")
    p = math.erfc(abs(vn - expected) / denom)
    return BitTest("runs", vn, p, None)


def _poker_test(bits: list[int]) -> BitTest:
    """FIPS 140 poker test on 4-bit nibbles. Chi-square, df=15."""
    n = len(bits)
    k = n // 4
    if k < 4:
        return BitTest("poker", 0.0, None, None,
                        "needs >=16 bits (>=16 tokens) for poker")
    counts = [0] * 16
    for i in range(k):
        nib = (bits[4*i] << 3) | (bits[4*i + 1] << 2) | \
              (bits[4*i + 2] << 1) | bits[4*i + 3]
        counts[nib] += 1
    stat = (16.0 / k) * sum(c * c for c in counts) - k
    p = _chi2_pvalue(stat, 15)
    return BitTest("poker", stat, p, None)


def _longest_run_test(bits: list[int]) -> BitTest:
    """Observed longest run of 1s vs an order-of-magnitude expectation.

    For a random stream of length N, expected longest-run-of-ones is
    around log2(N). We flag when the observed run is > log2(N) + 3.5,
    which is the >99% upper tail for moderate N.
    """
    n = len(bits)
    if n < 8:
        return BitTest("longest-run", 0.0, None, None, "sample too small")
    observed = _longest_run_bits(bits, 1)
    expected = math.log2(n) if n > 1 else 0.0
    delta = observed - expected
    # Cheap two-tailed approximation: p ~ exp(-delta) for delta > 0,
    # else 1. Not a real distribution, just a screening signal.
    p = math.exp(-max(0.0, delta))
    return BitTest("longest-run", float(observed), p, None,
                    f"expected~{expected:.1f}")


# Tests that count toward the "effective bit" verdict. The longest-run
# screening signal is informational only because its p-value is a heuristic.
_EFFECTIVE_TESTS = ("monobit", "runs", "poker")


def _per_bit_tests(bits: list[int], significance: float) -> PerBitStats:
    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    tests = [
        _monobit_test(bits),
        _runs_test(bits),
        _poker_test(bits),
        _longest_run_test(bits),
    ]
    # Stamp pass/fail; effective-bit requires the three robust tests to
    # have a p-value at or above the significance level.
    effective = True
    for t in tests:
        if t.p_value is None:
            t.passed = None
            if t.name in _EFFECTIVE_TESTS:
                effective = False
            continue
        t.passed = t.p_value >= significance
        if t.name in _EFFECTIVE_TESTS and not t.passed:
            effective = False
    return PerBitStats(
        index=-1,
        ones=ones, zeros=zeros,
        longest_run=_longest_run_bits(bits, 1),
        compression_ratio=_compression_ratio(bits),
        tests=tests,
        effective_bit=effective,
    )


def _encode_to_bits(tokens: list[str], common_length: int
                      ) -> tuple[int, list[int], list[list[int]]]:
    """Per-position bit encoding (industry-standard layout).

    For each character position (0..common_length-1):
      * gather the alphabet observed at that position,
      * assign ``ceil(log2(|alphabet|))`` bits (0 if the position is constant),
      * map each character to its sorted-index → big-endian bit slice.

    Returns ``(bits_per_token, per_position_bits, bit_matrix)`` where
    ``bit_matrix[token_index]`` is the concatenated bit list for that
    token (length == ``bits_per_token``).
    """
    if not tokens or common_length <= 0:
        return 0, [], [[] for _ in tokens]
    per_pos_alphabet: list[list[str]] = []
    per_pos_index: list[dict[str, int]] = []
    per_pos_bits: list[int] = []
    for i in range(common_length):
        seen: set[str] = set()
        for t in tokens:
            if i < len(t):
                seen.add(t[i])
        sorted_alpha = sorted(seen)
        per_pos_alphabet.append(sorted_alpha)
        per_pos_index.append({ch: idx for idx, ch in enumerate(sorted_alpha)})
        size = max(1, len(sorted_alpha))
        per_pos_bits.append(0 if size <= 1 else math.ceil(math.log2(size)))
    bits_per_token = sum(per_pos_bits)
    matrix: list[list[int]] = []
    for t in tokens:
        bits: list[int] = []
        for i in range(common_length):
            w = per_pos_bits[i]
            if w == 0:
                continue
            idx = per_pos_index[i].get(t[i] if i < len(t) else "", 0)
            for shift in range(w - 1, -1, -1):
                bits.append((idx >> shift) & 1)
        matrix.append(bits)
    return bits_per_token, per_pos_bits, matrix


def _transitions(tokens: list[str], common_length: int, significance: float
                  ) -> list[TransitionStat]:
    """Per-character-position transition (Markov) chi-square test.

    For each character position ``i``, build the contingency table of
    (char_in_token_t, char_in_token_{t+1}) over the ordered sample.
    Under the null (random), rows of this table should match the marginal
    distribution.
    """
    out: list[TransitionStat] = []
    if len(tokens) < 4:
        return out
    for i in range(common_length):
        rows: dict[str, Counter] = {}
        row_totals: Counter = Counter()
        col_totals: Counter = Counter()
        n = 0
        for j in range(len(tokens) - 1):
            t1, t2 = tokens[j], tokens[j + 1]
            if i >= len(t1) or i >= len(t2):
                continue
            a, b = t1[i], t2[i]
            rows.setdefault(a, Counter())[b] += 1
            row_totals[a] += 1
            col_totals[b] += 1
            n += 1
        if n < 8 or len(rows) < 2 or len(col_totals) < 2:
            continue
        stat = 0.0
        for a, row in rows.items():
            for b, observed in row.items():
                expected = row_totals[a] * col_totals[b] / n
                if expected > 0:
                    stat += (observed - expected) ** 2 / expected
        df = (len(rows) - 1) * (len(col_totals) - 1)
        p = _chi2_pvalue(stat, df)
        out.append(TransitionStat(index=i, chi_square=stat, df=df,
                                    p_value=p, passed=p >= significance))
    return out


def _correlation_warnings(bit_matrix: list[list[int]], bits_per_token: int,
                            significance: float
                            ) -> tuple[list[CorrelationWarning], int, str]:
    """Pairwise bit-bit independence test, chi-square df=1.

    Applies Bonferroni correction across all pair tests so the family-wise
    false-positive rate stays at ``significance``. Skipped when
    ``bits_per_token`` exceeds the cap to keep runtime bounded.
    """
    if bits_per_token > _DEEP_MAX_BITS_FOR_CORRELATION:
        return ([], 0,
                 f"skipped: {bits_per_token} bits per token exceeds cap "
                 f"({_DEEP_MAX_BITS_FOR_CORRELATION})")
    n = len(bit_matrix)
    if n < 8 or bits_per_token < 2:
        return [], 0, "skipped: not enough samples or bits"
    total_pairs = bits_per_token * (bits_per_token - 1) // 2
    # Bonferroni-corrected per-pair threshold.
    threshold = significance / max(1, total_pairs)
    columns: list[tuple[int, ...]] = []
    for b in range(bits_per_token):
        columns.append(tuple(row[b] for row in bit_matrix))
    out: list[CorrelationWarning] = []
    pairs = 0
    for a, b in combinations(range(bits_per_token), 2):
        ca, cb = columns[a], columns[b]
        c00 = c01 = c10 = c11 = 0
        for x, y in zip(ca, cb, strict=False):
            if x:
                if y:
                    c11 += 1
                else:
                    c10 += 1
            else:
                if y:
                    c01 += 1
                else:
                    c00 += 1
        row0 = c00 + c01
        row1 = c10 + c11
        col0 = c00 + c10
        col1 = c01 + c11
        pairs += 1
        if row0 == 0 or row1 == 0 or col0 == 0 or col1 == 0:
            continue
        # 2x2 chi-square (Pearson, df=1).
        stat = 0.0
        for observed, exp in (
            (c00, row0 * col0 / n),
            (c01, row0 * col1 / n),
            (c10, row1 * col0 / n),
            (c11, row1 * col1 / n),
        ):
            if exp > 0:
                stat += (observed - exp) ** 2 / exp
        p = _chi2_pvalue(stat, 1)
        if p < threshold:
            out.append(CorrelationWarning(bit_a=a, bit_b=b,
                                            chi_square=stat, p_value=p))
    return out, pairs, ""


def analyse_deep(tokens: list[str], *, significance: float = 0.01
                  ) -> SequencerResult:
    """Run the full deep statistical randomness battery.

    Wraps :func:`analyse` and additionally populates
    :attr:`SequencerResult.deep` with per-bit / transition / correlation
    statistics. ``significance`` is the alpha used for pass/fail labelling
    and the effective-bit count; typical values are 0.05, 0.01, 0.001.
    """
    if significance <= 0 or significance >= 1:
        significance = 0.01
    base = analyse(tokens)
    if base.sample_count == 0:
        base.deep = DeepAnalysis(
            significance=significance, bits_per_token=0,
            per_position_bits=[], overall_compression_ratio=1.0,
            notes=["No tokens supplied."], deep_rating="n/a",
        )
        return base
    capped = tokens
    notes: list[str] = []
    if len(tokens) > _DEEP_MAX_SAMPLES:
        capped = tokens[:_DEEP_MAX_SAMPLES]
        notes.append(f"Sample capped at {_DEEP_MAX_SAMPLES} tokens for "
                      "deep analysis.")
    common_len = min(base.common_length, _DEEP_MAX_COMMON_LEN)
    if base.common_length > _DEEP_MAX_COMMON_LEN:
        notes.append(f"Token length capped at {_DEEP_MAX_COMMON_LEN} chars "
                      "for deep analysis.")
    if base.sample_count < _DEEP_MIN_SAMPLES:
        base.deep = DeepAnalysis(
            significance=significance, bits_per_token=0,
            per_position_bits=[], overall_compression_ratio=1.0,
            notes=notes + [
                f"Need at least {_DEEP_MIN_SAMPLES} tokens for deep "
                f"analysis (got {base.sample_count})."],
            deep_rating="n/a",
        )
        return base
    if base.sample_count < 100:
        notes.append("Sample is small (<100 tokens); p-values are noisy. "
                      "Collect more for FIPS-grade confidence.")

    bits_per_token, per_pos_bits, matrix = _encode_to_bits(capped, common_len)
    transitions = _transitions(capped, common_len, significance)

    per_bit: list[PerBitStats] = []
    effective = 0
    if bits_per_token > 0:
        for b in range(bits_per_token):
            column = [row[b] for row in matrix]
            stats = _per_bit_tests(column, significance)
            stats.index = b
            per_bit.append(stats)
            if stats.effective_bit:
                effective += 1
    # Overall compression: pack each token's bits sequentially.
    flat: list[int] = [b for row in matrix for b in row]
    overall_ratio = _compression_ratio(flat)

    corr, pairs_tested, corr_skip = _correlation_warnings(
        matrix, bits_per_token, significance)

    # Deep rating: combine effective bits + correlation warnings.
    if bits_per_token == 0:
        deep_rating = "weak"
        notes.append("Every character position is constant; no entropy at all.")
    elif effective >= 128 and not corr:
        deep_rating = "strong"
    elif effective >= 64 and len(corr) <= 2:
        deep_rating = "fair"
    else:
        deep_rating = "weak"

    base.deep = DeepAnalysis(
        significance=significance,
        bits_per_token=bits_per_token,
        per_position_bits=per_pos_bits,
        overall_compression_ratio=overall_ratio,
        transitions=transitions,
        per_bit=per_bit,
        correlation_warnings=corr,
        correlation_pairs_tested=pairs_tested,
        correlation_skipped_reason=corr_skip,
        effective_bits_at_significance=effective,
        deep_rating=deep_rating,
        notes=notes,
    )
    return base

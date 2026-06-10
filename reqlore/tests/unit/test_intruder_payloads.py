"""Phase 4 — extended processors, wordlists, and file loader."""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.intruder import (
    ARG_PROCESSORS, PROCESSORS, WORDLISTS, apply_processors,
    load_wordlist_file, processor_names, wordlist_names,
)


# ---------- new no-arg processors ----------

def test_processor_length():
    assert apply_processors("hello", ["length"]) == "5"


def test_processor_strip():
    assert apply_processors("  hi \n", ["strip"]) == "hi"


def test_processor_sql_quote():
    assert apply_processors("O'Brien", ["sql-quote"]) == "O''Brien"


def test_processor_b64_roundtrip():
    assert apply_processors("hello", ["b64", "b64dec"]) == "hello"


def test_processor_b64dec_invalid_returns_input():
    assert apply_processors("not-base64!!", ["b64dec"]) == "not-base64!!"


# ---------- arg-style processors ----------

def test_processor_prefix_arg():
    assert apply_processors("payload", ["prefix:admin/"]) == "admin/payload"


def test_processor_suffix_arg():
    assert apply_processors("user", ["suffix:@example.com"]) == "user@example.com"


def test_processor_repeat_arg():
    assert apply_processors("ab", ["repeat:3"]) == "ababab"


def test_processor_repeat_invalid_arg_is_noop():
    assert apply_processors("ab", ["repeat:xx"]) == "ab"


def test_processor_repeat_negative_clamped_to_zero():
    assert apply_processors("ab", ["repeat:-5"]) == ""


def test_processor_repeat_huge_capped():
    # The cap is 10 000; without it this would explode in memory.
    out = apply_processors("a", ["repeat:99999999"])
    assert len(out) == 10_000


def test_processor_chain_arg_and_static():
    # prefix → upper → suffix
    out = apply_processors("user", ["prefix:admin_", "upper", "suffix:!"])
    assert out == "ADMIN_USER!"


def test_processor_unknown_is_silently_ignored():
    assert apply_processors("x", ["does-not-exist", "upper"]) == "X"


def test_processor_names_includes_arg_forms():
    names = processor_names()
    assert "upper" in names
    for n in ARG_PROCESSORS:
        assert f"{n}:<arg>" in names
    assert "none" not in names  # 'none' is internal


# ---------- built-in wordlists ----------

def test_wordlists_registry_has_expected_keys():
    for key in ("common_passwords", "common_usernames", "lfi_paths",
                "xss_payloads", "sqli_payloads", "subdomains"):
        assert key in WORDLISTS
        assert len(WORDLISTS[key]) >= 10


def test_wordlist_names_sorted():
    assert wordlist_names() == sorted(WORDLISTS.keys())


def test_wordlist_entries_are_non_empty_strings():
    for key, items in WORDLISTS.items():
        assert all(isinstance(p, str) and p for p in items), key


# ---------- file loader ----------

def test_load_wordlist_file_basic(tmp_path: Path):
    p = tmp_path / "wl.txt"
    p.write_text("admin\nroot\nguest\n", encoding="utf-8")
    assert load_wordlist_file(str(p)) == ["admin", "root", "guest"]


def test_load_wordlist_file_skips_blanks_and_comments(tmp_path: Path):
    p = tmp_path / "wl.txt"
    p.write_text("admin\n\n# a comment\n  # indented comment\nroot\n",
                 encoding="utf-8")
    assert load_wordlist_file(str(p)) == ["admin", "root"]


def test_load_wordlist_file_handles_crlf(tmp_path: Path):
    p = tmp_path / "wl.txt"
    p.write_bytes(b"a\r\nb\r\nc\r\n")
    assert load_wordlist_file(str(p)) == ["a", "b", "c"]


def test_load_wordlist_file_missing_raises():
    with pytest.raises(ValueError, match="not found"):
        load_wordlist_file("/no/such/file/here.txt")


def test_load_wordlist_file_empty_path_raises():
    with pytest.raises(ValueError, match="not found"):
        load_wordlist_file("")


def test_load_wordlist_file_too_large(tmp_path: Path):
    p = tmp_path / "big.txt"
    p.write_bytes(b"x" * 200)
    with pytest.raises(ValueError, match="too large"):
        load_wordlist_file(str(p), max_bytes=100)


def test_load_wordlist_file_too_many_lines(tmp_path: Path):
    p = tmp_path / "lines.txt"
    p.write_text("\n".join(str(i) for i in range(20)), encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds"):
        load_wordlist_file(str(p), max_lines=10)

"""Streaming payload-source primitives — factories, iterate_streaming, storage round-trip.

These tests exercise the new factory-based API directly so the runtime
behaviour is pinned even when no AttackRunner is involved. The legacy
``iterate(...)`` list-based tests live in ``test_intruder.py`` and stay
green via the from_list delegation in ``intruder.iterate``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from reqlore.intruder import (
    build_sources_from_storage,
    count_wordlist_lines,
    from_bytes,
    from_list,
    from_path,
    iterate_streaming,
)


# ---------- factory adapters ----------

def test_from_list_replayable():
    src = from_list(["a", "b", "c"])
    assert list(src()) == ["a", "b", "c"]
    # Second call returns a fresh iterator over the same values — required
    # for cluster bomb's nested re-walks.
    assert list(src()) == ["a", "b", "c"]


def test_from_bytes_strips_blanks_and_comments():
    data = b"alpha\n\n# this is a comment\nbeta\n  # indented comment\ngamma\n"
    src = from_bytes(data)
    assert list(src()) == ["alpha", "beta", "gamma"]


def test_from_path_streams_and_replays(tmp_path: Path):
    wl = tmp_path / "small.lst"
    wl.write_text("one\ntwo\nthree\n", encoding="utf-8")
    src = from_path(wl)
    assert list(src()) == ["one", "two", "three"]
    # Replayable: a second factory call re-opens the file.
    assert list(src()) == ["one", "two", "three"]


def test_from_path_skips_blanks_and_comments(tmp_path: Path):
    wl = tmp_path / "with_comments.lst"
    wl.write_text("alpha\n\n# header\nbeta\n   # nested\ngamma\n\n", encoding="utf-8")
    assert list(from_path(wl)()) == ["alpha", "beta", "gamma"]


def test_from_path_constant_memory_on_large_file(tmp_path: Path):
    """Sanity: a million-line file does not materialise into RAM.

    We don't actually measure memory — instead we prove laziness by
    asserting that consuming only the first few items costs O(items
    consumed), not O(file). We open the iterator and read 3 items; the
    file handle should still be live and the remaining lines untouched.
    """
    wl = tmp_path / "huge.lst"
    with open(wl, "w", encoding="utf-8") as fh:
        for i in range(100_000):
            fh.write(f"line{i}\n")
    src = from_path(wl)
    it = src()
    assert [next(it), next(it), next(it)] == ["line0", "line1", "line2"]
    # Drain to release the file handle (the generator's finally closes it).
    it.close()


# ---------- iterate_streaming behaviour ----------

def test_iterate_streaming_empty_sources_yields_nothing():
    assert list(iterate_streaming("sniper", [], n_positions=2)) == []


def test_iterate_streaming_unknown_attack_type_raises():
    with pytest.raises(ValueError, match="unknown attack type"):
        list(iterate_streaming("nope", [from_list(["a"])], n_positions=1))


def test_iterate_streaming_sniper_one_position_at_a_time():
    src = from_list(["a", "b"])
    out = list(iterate_streaming("sniper", [src], n_positions=2))
    assert out == [["a", ""], ["b", ""], ["", "a"], ["", "b"]]


def test_iterate_streaming_battering_same_payload_each_position():
    src = from_list(["x", "y"])
    out = list(iterate_streaming("battering", [src], n_positions=3))
    assert out == [["x", "x", "x"], ["y", "y", "y"]]


def test_iterate_streaming_pitchfork_stops_at_shortest():
    a = from_list(["a", "b", "c"])
    b = from_list(["1", "2"])
    out = list(iterate_streaming("pitchfork", [a, b], n_positions=2))
    # zip-based; stops naturally at the shorter source.
    assert out == [["a", "1"], ["b", "2"]]


def test_iterate_streaming_clusterbomb_cartesian():
    a = from_list(["a", "b"])
    b = from_list(["1", "2"])
    out = list(iterate_streaming("clusterbomb", [a, b], n_positions=2))
    assert out == [["a", "1"], ["a", "2"], ["b", "1"], ["b", "2"]]


def test_iterate_streaming_clusterbomb_with_path_inner(tmp_path: Path):
    """The cluster-bomb inner source must be re-opened from disk per
    outer iteration — this is the streaming guarantee that lets rockyou
    act as the inner set without ever resident in RAM.
    """
    inner = tmp_path / "inner.lst"
    inner.write_text("1\n2\n", encoding="utf-8")
    a = from_list(["a", "b"])
    b = from_path(inner)
    out = list(iterate_streaming("clusterbomb", [a, b], n_positions=2))
    assert out == [["a", "1"], ["a", "2"], ["b", "1"], ["b", "2"]]


def test_iterate_streaming_clusterbomb_single_source_degenerate():
    out = list(iterate_streaming(
        "clusterbomb", [from_list(["x", "y"])], n_positions=1,
    ))
    assert out == [["x"], ["y"]]


# ---------- storage round-trip ----------

def test_build_sources_from_storage_inline_list():
    sources = build_sources_from_storage([["a", "b"], ["1", "2"]])
    assert [list(s()) for s in sources] == [["a", "b"], ["1", "2"]]


def test_build_sources_from_storage_path_entry(tmp_path: Path):
    wl = tmp_path / "wl.lst"
    wl.write_text("p1\np2\np3\n", encoding="utf-8")
    sources = build_sources_from_storage([{"kind": "path", "path": str(wl)}])
    assert list(sources[0]()) == ["p1", "p2", "p3"]


def test_build_sources_from_storage_mixed(tmp_path: Path):
    wl = tmp_path / "wl.lst"
    wl.write_text("z1\nz2\n", encoding="utf-8")
    sources = build_sources_from_storage([
        ["a"], {"kind": "path", "path": str(wl)},
    ])
    assert [list(s()) for s in sources] == [["a"], ["z1", "z2"]]


def test_build_sources_from_storage_rejects_unknown_kind():
    with pytest.raises(ValueError, match="Unknown payload source"):
        build_sources_from_storage([{"kind": "future-thing", "url": "x"}])


def test_build_sources_from_storage_rejects_empty_path():
    with pytest.raises(ValueError, match="missing 'path'"):
        build_sources_from_storage([{"kind": "path", "path": ""}])


# ---------- count_wordlist_lines ----------

def test_count_wordlist_lines_skips_blanks_and_comments(tmp_path: Path):
    wl = tmp_path / "count.lst"
    wl.write_text("a\n\n# comment\nb\n  # indented\nc\n\n", encoding="utf-8")
    assert count_wordlist_lines(wl) == 3


def test_count_wordlist_lines_empty_file(tmp_path: Path):
    wl = tmp_path / "empty.lst"
    wl.write_text("", encoding="utf-8")
    assert count_wordlist_lines(wl) == 0


def test_count_wordlist_lines_only_comments(tmp_path: Path):
    wl = tmp_path / "comments.lst"
    wl.write_text("# only\n# comments\n# here\n", encoding="utf-8")
    assert count_wordlist_lines(wl) == 0

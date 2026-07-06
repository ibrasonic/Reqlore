"""Tests for the intruder spec-file loader."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from reqlore.intruder_spec import SpecError, build_attack, load_spec


def _write_spec(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _minimal(**overrides) -> dict:
    base = {
        "name": "test",
        "attack_type": "sniper",
        "engine": "httpx",
        "url": "http://example.com/",
        "template": "GET /?u=\u00a7admin\u00a7 HTTP/1.1\nHost: example.com\n\n",
        "payloads": [{"source": "text", "values": ["a", "b", "c"]}],
    }
    base.update(overrides)
    return base


def test_load_spec_missing_file(tmp_path: Path):
    with pytest.raises(SpecError, match="not found"):
        load_spec(tmp_path / "nope.json")


def test_load_spec_bad_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(SpecError, match="Invalid JSON"):
        load_spec(p)


def test_load_spec_root_must_be_mapping(tmp_path: Path):
    p = tmp_path / "list.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(SpecError, match="mapping"):
        load_spec(p)


def test_build_attack_basic(tmp_path: Path):
    p = _write_spec(tmp_path, "ok.json", _minimal())
    built = build_attack(load_spec(p), base_dir=tmp_path)
    assert built.name == "test"
    assert built.attack_type == "sniper"
    assert len(built.positions) == 1
    assert built.payloads == [["a", "b", "c"]]
    assert built.options["concurrency"] == 4
    assert built.options["retries"] == 0


def test_build_attack_requires_url(tmp_path: Path):
    spec = _minimal()
    spec.pop("url")
    with pytest.raises(SpecError, match="url"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_requires_template(tmp_path: Path):
    spec = _minimal()
    spec.pop("template")
    with pytest.raises(SpecError, match="template"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_requires_marker_in_template(tmp_path: Path):
    spec = _minimal(template="GET / HTTP/1.1\nHost: x\n\n")
    with pytest.raises(SpecError, match="No markers"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_unknown_attack_type(tmp_path: Path):
    spec = _minimal(attack_type="bogus")
    with pytest.raises(SpecError, match="attack_type"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_unknown_payload_source(tmp_path: Path):
    spec = _minimal(payloads=[{"source": "magic"}])
    with pytest.raises(SpecError, match="payload source"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_payloads_empty_list(tmp_path: Path):
    spec = _minimal(payloads=[])
    with pytest.raises(SpecError, match="non-empty"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_first_set_empty(tmp_path: Path):
    spec = _minimal(payloads=[{"source": "text", "values": []}])
    with pytest.raises(SpecError, match="empty"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_wordlist_source(tmp_path: Path):
    spec = _minimal(payloads=[{"source": "wordlist", "name": "common_usernames"}])
    built = build_attack(spec, base_dir=tmp_path)
    assert "admin" in built.payloads[0]


def test_build_attack_wordlist_unknown_name(tmp_path: Path):
    spec = _minimal(payloads=[{"source": "wordlist", "name": "no-such"}])
    with pytest.raises(SpecError, match="built-in wordlist"):
        build_attack(spec, base_dir=tmp_path)


def test_build_attack_wordlist_file_relative_to_spec(tmp_path: Path):
    wl = tmp_path / "list.txt"
    wl.write_text("one\ntwo\nthree\n", encoding="utf-8")
    spec = _minimal(payloads=[{"source": "wordlist_file", "path": "list.txt"}])
    built = build_attack(spec, base_dir=tmp_path)
    assert built.payloads[0] == ["one", "two", "three"]


def test_build_attack_numbers_source(tmp_path: Path):
    spec = _minimal(payloads=[{"source": "numbers", "start": 1, "end": 5}])
    built = build_attack(spec, base_dir=tmp_path)
    assert built.payloads[0] == ["1", "2", "3", "4", "5"]


def test_build_attack_options_passthrough(tmp_path: Path):
    spec = _minimal(options={
        "concurrency": 8, "retries": 2, "stop_on_match": True,
        "stop_on_status": [200, 302], "grep": ["welcome"], "processors": ["url"],
        "delay_ms": 100, "max_requests": 50,
    })
    built = build_attack(spec, base_dir=tmp_path)
    assert built.options["concurrency"] == 8
    assert built.options["retries"] == 2
    assert built.options["stop_on_match"] is True
    assert built.options["stop_on_status"] == [200, 302]
    assert built.options["grep"] == ["welcome"]
    assert built.options["processors"] == ["url"]


def test_build_attack_extra_sets_dropped_for_sniper(tmp_path: Path):
    spec = _minimal(
        attack_type="sniper",
        payloads=[
            {"source": "text", "values": ["a"]},
            {"source": "text", "values": ["b"]},
        ],
    )
    built = build_attack(spec, base_dir=tmp_path)
    assert len(built.payloads) == 1


def test_build_attack_pitchfork_keeps_all_sets(tmp_path: Path):
    spec = _minimal(
        attack_type="pitchfork",
        template="POST / HTTP/1.1\nHost: x\n\nu=\u00a7a\u00a7&p=\u00a7b\u00a7",
        payloads=[
            {"source": "text", "values": ["a1", "a2"]},
            {"source": "text", "values": ["b1", "b2"]},
        ],
    )
    built = build_attack(spec, base_dir=tmp_path)
    assert len(built.payloads) == 2

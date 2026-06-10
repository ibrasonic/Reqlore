"""Tests for Intruder CSV/JSON export endpoints."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from reqlore.config import Settings
from reqlore.web import create_app


@pytest.fixture
def app(tmp_path: Path):
    return create_app(tmp_path / "exp.rlr", Settings(), proxy=None)


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_attack(app) -> int:
    """Create an attack with three results spanning statuses, lengths, and matches."""
    proj = app.extensions["reqlore_project"]
    aid = proj.create_intruder(
        name="Login probe", attack_type="sniper", template=b"GET / HTTP/1.1\r\n\r\n",
        positions=[(8, 9)], payloads=[["a", "b", "c"]],
        options={"grep": []}, url="http://x/", engine="httpx",
    )
    proj.add_intruder_result(
        attack_id=aid, seq=1, payloads=["admin"], status=200,
        len_resp=100, duration_ms=10, grep_hits="welcome",
        history_id=None, body_md5="aaa", matched=True,
    )
    proj.add_intruder_result(
        attack_id=aid, seq=2, payloads=["root"], status=404,
        len_resp=50, duration_ms=12, grep_hits="",
        history_id=None, body_md5="bbb", matched=False,
    )
    proj.add_intruder_result(
        attack_id=aid, seq=3, payloads=["guest"], status=200,
        len_resp=100, duration_ms=11, grep_hits="welcome",
        history_id=None, body_md5="aaa", matched=True,
    )
    return aid


def test_export_csv_has_header_and_all_rows(app, client):
    aid = _seed_attack(app)
    r = client.get(f"/intruder/{aid}/export.csv")
    assert r.status_code == 200
    assert r.mimetype == "text/csv"
    assert "attachment" in r.headers["Content-Disposition"]
    assert f"intruder-{aid}-Login_probe.csv" in r.headers["Content-Disposition"]

    rows = list(csv.DictReader(io.StringIO(r.data.decode("utf-8"))))
    assert len(rows) == 3
    assert rows[0]["seq"] == "1"
    assert rows[0]["payloads"] == "admin"
    assert rows[0]["matched"] == "1"
    assert rows[1]["matched"] == "0"


def test_export_csv_respects_status_filter(app, client):
    aid = _seed_attack(app)
    r = client.get(f"/intruder/{aid}/export.csv?sc=4xx")
    rows = list(csv.DictReader(io.StringIO(r.data.decode("utf-8"))))
    assert [row["seq"] for row in rows] == ["2"]


def test_export_csv_respects_dedup(app, client):
    aid = _seed_attack(app)
    r = client.get(f"/intruder/{aid}/export.csv?dedup=1")
    rows = list(csv.DictReader(io.StringIO(r.data.decode("utf-8"))))
    # Rows 1 and 3 share body_md5='aaa'; row 3 should be hidden.
    assert [row["seq"] for row in rows] == ["1", "2"]


def test_export_json_payload_shape(app, client):
    aid = _seed_attack(app)
    r = client.get(f"/intruder/{aid}/export.json")
    assert r.status_code == 200
    assert r.mimetype == "application/json"
    assert "attachment" in r.headers["Content-Disposition"]
    payload = json.loads(r.data)
    assert payload["attack"]["id"] == aid
    assert payload["attack"]["name"] == "Login probe"
    assert payload["total"] == 3
    assert payload["exported"] == 3
    assert "filters" in payload
    assert len(payload["rows"]) == 3
    assert payload["rows"][0]["payloads"] == "admin"


def test_export_json_respects_matched_and_search(app, client):
    aid = _seed_attack(app)
    r = client.get(f"/intruder/{aid}/export.json?matched=yes&q=welcome")
    payload = json.loads(r.data)
    assert payload["exported"] == 2
    assert {row["seq"] for row in payload["rows"]} == {1, 3}


def test_export_unknown_attack_404(client):
    assert client.get("/intruder/9999/export.csv").status_code == 404
    assert client.get("/intruder/9999/export.json").status_code == 404

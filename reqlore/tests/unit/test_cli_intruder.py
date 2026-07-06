"""End-to-end tests for the `reqlore intruder` CLI subcommand."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reqlore.cli import build_parser, main
from reqlore.intruder import DEFAULT_MARKER
from reqlore.storage import Project

# ---------- parser surface ----------

def _parse(*argv: str):
    return build_parser().parse_args(list(argv))


def test_intruder_subcommand_recognised():
    ns = _parse("intruder", "list", "--project", "x.rlr")
    assert ns.subcommand == "intruder"
    assert ns.intruder_action == "list"


def test_intruder_run_args():
    ns = _parse("intruder", "run", "--project", "x.rlr", "spec.json",
                "--timeout", "30", "--dry-run")
    assert ns.intruder_action == "run"
    assert ns.spec == "spec.json"
    assert ns.timeout == 30
    assert ns.dry_run is True


def test_intruder_export_args():
    ns = _parse("intruder", "export", "--project", "x.rlr",
                "--id", "5", "--out", "out.csv", "--format", "csv")
    assert ns.intruder_action == "export"
    assert ns.id == 5
    assert ns.format == "csv"


def test_intruder_action_required():
    with pytest.raises(SystemExit):
        _parse("intruder")


# ---------- local server fixture ----------

class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        body = self.path.encode()
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a, **_k):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _spec(tmp_path: Path, port: int, **overrides) -> Path:
    data = {
        "name": "cli-test",
        "attack_type": "sniper",
        "engine": "httpx",
        "url": f"http://127.0.0.1:{port}/",
        "template": (
            f"GET /?q={DEFAULT_MARKER}X{DEFAULT_MARKER} HTTP/1.1\n"
            f"Host: 127.0.0.1:{port}\n\n"
        ),
        "payloads": [{"source": "text", "values": ["alpha", "beta", "gamma"]}],
        "options": {"concurrency": 1, "max_requests": 10, "timeout": 5},
    }
    data.update(overrides)
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# ---------- run subcommand ----------

def test_cli_intruder_run_sends_requests(tmp_path: Path, server: int, capsys):
    project = tmp_path / "p.rlr"
    spec = _spec(tmp_path, server)
    rc = main(["intruder", "run", "--project", str(project), str(spec),
               "--timeout", "30"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Created attack" in out
    assert "Done." in out
    assert "HTTP 200" in out

    p = Project(project)
    aid = p.list_intruder()[0]["id"]
    assert len(p.list_intruder_results(aid)) == 3


def test_cli_intruder_run_dry_run_does_not_send(tmp_path: Path, server: int, capsys):
    project = tmp_path / "p.rlr"
    spec = _spec(tmp_path, server)
    rc = main(["intruder", "run", "--project", str(project), str(spec), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Dry run" in out
    p = Project(project)
    aid = p.list_intruder()[0]["id"]
    assert p.list_intruder_results(aid) == []


def test_cli_intruder_run_bad_spec_returns_2(tmp_path: Path, capsys):
    spec = tmp_path / "bad.json"
    spec.write_text(json.dumps({"name": "broken"}), encoding="utf-8")
    rc = main(["intruder", "run", "--project", str(tmp_path / "p.rlr"), str(spec)])
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_cli_intruder_run_missing_spec(tmp_path: Path, capsys):
    rc = main(["intruder", "run", "--project", str(tmp_path / "p.rlr"),
               str(tmp_path / "nope.json")])
    assert rc == 2
    assert "not found" in capsys.readouterr().err


# ---------- list / show / export ----------

def test_cli_intruder_list_empty(tmp_path: Path, capsys):
    rc = main(["intruder", "list", "--project", str(tmp_path / "p.rlr")])
    assert rc == 0
    assert "No attacks" in capsys.readouterr().out


def test_cli_intruder_list_after_run(tmp_path: Path, server: int, capsys):
    project = tmp_path / "p.rlr"
    main(["intruder", "run", "--project", str(project), str(_spec(tmp_path, server)),
          "--timeout", "30"])
    capsys.readouterr()  # discard run output
    rc = main(["intruder", "list", "--project", str(project)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cli-test" in out
    assert "sniper" in out


def test_cli_intruder_show(tmp_path: Path, server: int, capsys):
    project = tmp_path / "p.rlr"
    main(["intruder", "run", "--project", str(project), str(_spec(tmp_path, server)),
          "--timeout", "30"])
    capsys.readouterr()
    aid = Project(project).list_intruder()[0]["id"]
    rc = main(["intruder", "show", "--project", str(project), "--id", str(aid)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "alpha" in out and "beta" in out


def test_cli_intruder_show_unknown_id(tmp_path: Path, capsys):
    rc = main(["intruder", "show", "--project", str(tmp_path / "p.rlr"),
               "--id", "999"])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_cli_intruder_export_csv(tmp_path: Path, server: int, capsys):
    project = tmp_path / "p.rlr"
    main(["intruder", "run", "--project", str(project), str(_spec(tmp_path, server)),
          "--timeout", "30"])
    capsys.readouterr()
    aid = Project(project).list_intruder()[0]["id"]
    out_path = tmp_path / "results.csv"
    rc = main(["intruder", "export", "--project", str(project),
               "--id", str(aid), "--out", str(out_path)])
    assert rc == 0
    text = out_path.read_text(encoding="utf-8")
    assert text.startswith(
        "seq,status,len_resp,duration_ms,matched,grep_hits,"
        "body_md5,payloads,history_id"
    )
    # Three result rows + header
    assert text.count("\n") == 4
    # CSV format inferred from .csv extension
    assert "alpha" in text


def test_cli_intruder_export_json_explicit_format(tmp_path: Path, server: int):
    project = tmp_path / "p.rlr"
    main(["intruder", "run", "--project", str(project), str(_spec(tmp_path, server)),
          "--timeout", "30"])
    aid = Project(project).list_intruder()[0]["id"]
    out_path = tmp_path / "results.txt"
    rc = main(["intruder", "export", "--project", str(project),
               "--id", str(aid), "--out", str(out_path), "--format", "json"])
    assert rc == 0
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["count"] == 3
    assert payload["attack"]["name"] == "cli-test"
    assert {row["payloads"][0] for row in payload["rows"]} == {"alpha", "beta", "gamma"}


def test_cli_intruder_export_unknown_format(tmp_path: Path):
    """argparse's choices= rejects 'xml' before our code runs → SystemExit."""
    with pytest.raises(SystemExit):
        main(["intruder", "export", "--project", str(tmp_path / "p.rlr"),
              "--id", "1", "--out", str(tmp_path / "x.bin"), "--format", "xml"])

"""CLI argument parser sanity checks.

Each subcommand should accept exactly the flags Reqlore's docs and Docker
compose file pass to it. We exercise the parser directly rather than the
command functions, so these tests stay offline and fast.
"""
from __future__ import annotations

import pytest

from reqlore.cli import build_parser


def _parse(*argv: str):
    return build_parser().parse_args(list(argv))


class TestBothSubcommand:
    def test_both_accepts_unsafe_bind(self):
        # Regression: the Docker compose file invokes
        #   reqlore both --project ... --host 0.0.0.0 ... --unsafe-bind
        # which used to crash with "unrecognized arguments: --unsafe-bind".
        ns = _parse(
            "both",
            "--project", "demo.rlr",
            "--host", "0.0.0.0",
            "--ui-port", "8787",
            "--proxy-port", "8080",
            "--unsafe-bind",
        )
        assert ns.cmd == "both"
        assert ns.unsafe_bind is True
        assert ns.host == "0.0.0.0"
        assert ns.ui_port == 8787
        assert ns.proxy_port == 8080

    def test_both_unsafe_bind_defaults_false(self):
        ns = _parse("both", "--project", "demo.rlr")
        assert ns.unsafe_bind is False


class TestUiSubcommand:
    def test_ui_accepts_unsafe_bind(self):
        ns = _parse(
            "ui",
            "--project", "demo.rlr",
            "--host", "0.0.0.0",
            "--unsafe-bind",
        )
        assert ns.unsafe_bind is True


class TestSubcommandSurface:
    @pytest.mark.parametrize("cmd", [
        "init", "ui", "proxy", "both", "scan", "report",
        "run", "import-har", "browser", "prefetch-firefox",
    ])
    def test_every_documented_subcommand_parses(self, cmd):
        # Each subcommand at least needs to be a recognised name. We use
        # --help via SystemExit(0) to avoid having to know the per-cmd
        # required args.
        with pytest.raises(SystemExit) as exc:
            _parse(cmd, "--help")
        assert exc.value.code == 0

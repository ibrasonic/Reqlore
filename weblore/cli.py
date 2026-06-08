"""Command-line entry point.

    weblore init <project.weblore>
    weblore ui   --project <project.weblore> [--host 127.0.0.1] [--port 8787]
    weblore proxy --project <project.weblore> [--port 8080] [--ui-port 8787]
    weblore both --project <project.weblore>     # UI + proxy in one process
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .config import Settings, settings_from_env
from .proxy.mitm import ProxyController
from .storage import Project


def _logger(*, verbose: bool = False) -> logging.Logger:
    """Configure root logging once. Verbose mode keeps the noisy long format
    with timestamps and logger names; the default mode is quiet and only shows
    warnings/errors (the startup banner already covers the "what is listening
    where" question)."""
    if verbose:
        level = logging.INFO
        fmt = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    else:
        level = logging.WARNING
        fmt = "%(levelname)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, force=True)
    # waitress prints its own "Serving on http://..." INFO line that duplicates
    # the banner — silence it unless the user explicitly asked for verbose.
    if not verbose:
        logging.getLogger("waitress").setLevel(logging.WARNING)
    return logging.getLogger("weblore")


def _verbose_from(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "verbose", False)) or os.environ.get("WEBLORE_VERBOSE") == "1"


def _print_banner(*, project_path: Path | str | None = None,
                  ui_url: str | None = None,
                  proxy_endpoint: str | None = None) -> None:
    """Print a clean, screen-reader-friendly startup banner."""
    title = f"Weblore {__version__}"
    bar = "=" * len(title)
    lines = [title, bar]
    if project_path is not None:
        lines.append(f"  Project:  {project_path}")
    if ui_url is not None:
        lines.append(f"  UI:       {ui_url}")
    if proxy_endpoint is not None:
        lines.append(f"  Proxy:    {proxy_endpoint}  (set this in your browser)")
    lines.append("")
    lines.append("Press Ctrl+C to stop.")
    print("\n".join(lines), flush=True)


def _resolve_project(arg: str | None) -> Path:
    if not arg:
        print("error: --project <path> required", file=sys.stderr)
        sys.exit(2)
    p = Path(arg).expanduser().resolve()
    return p


def cmd_init(args: argparse.Namespace) -> int:
    path = _resolve_project(args.project_path)
    Project(path).close()
    print(f"Initialised project at {path}")
    return 0


def cmd_ui(args: argparse.Namespace, *, proxy: ProxyController | None = None) -> int:
    verbose = _verbose_from(args)
    log = _logger(verbose=verbose)
    settings = settings_from_env(Settings(
        ui_host=args.host or Settings().ui_host,
        ui_port=args.port or Settings().ui_port,
    ))
    if settings.ui_host != "127.0.0.1" and not args.unsafe_bind:
        print("refusing to bind non-loopback without --unsafe-bind", file=sys.stderr)
        return 2

    from .web import create_app
    project_path = _resolve_project(args.project)
    app = create_app(project_path, settings, proxy=proxy)

    # When called from cmd_both the banner is already on screen with both
    # endpoints — skip the solo banner to avoid duplication.
    if proxy is None:
        _print_banner(project_path=project_path,
                      ui_url=f"http://{settings.ui_host}:{settings.ui_port}/")

    try:
        from waitress import serve
        log.debug("Serving Weblore UI on http://%s:%d/", settings.ui_host, settings.ui_port)
        serve(app, host=settings.ui_host, port=settings.ui_port, threads=8,
              ident="Weblore")
    except ImportError:
        app.run(host=settings.ui_host, port=settings.ui_port)
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    verbose = _verbose_from(args)
    log = _logger(verbose=verbose)
    project_path = _resolve_project(args.project)
    settings = settings_from_env(Settings(
        proxy_host="127.0.0.1",
        proxy_port=args.port or Settings().proxy_port,
        ui_port=args.ui_port or Settings().ui_port,
    ))
    project = Project(project_path)
    ctrl = ProxyController(project, settings.proxy_host, settings.proxy_port, settings.ca_dir,
                           ui_port=settings.ui_port)
    ctrl.start()
    _print_banner(project_path=project_path,
                  proxy_endpoint=f"{settings.proxy_host}:{settings.proxy_port}")
    log.debug("Proxy listening on %s:%d", settings.proxy_host, settings.proxy_port)
    try:
        ctrl._thread.join()  # noqa: SLF001
    except KeyboardInterrupt:
        ctrl.stop()
    return 0


def cmd_both(args: argparse.Namespace) -> int:
    verbose = _verbose_from(args)
    log = _logger(verbose=verbose)
    project_path = _resolve_project(args.project)
    settings = settings_from_env(Settings(
        ui_host=args.host or "127.0.0.1",
        ui_port=args.ui_port or 8787,
        proxy_host="127.0.0.1",
        proxy_port=args.proxy_port or 8080,
    ))
    project = Project(project_path)
    ctrl = ProxyController(project, settings.proxy_host, settings.proxy_port, settings.ca_dir,
                           ui_port=settings.ui_port)
    ctrl.start()
    _print_banner(
        project_path=project_path,
        ui_url=f"http://{settings.ui_host}:{settings.ui_port}/",
        proxy_endpoint=f"{settings.proxy_host}:{settings.proxy_port}",
    )
    log.debug("Proxy on %s:%d", settings.proxy_host, settings.proxy_port)
    return cmd_ui(argparse.Namespace(
        project=str(project_path),
        host=settings.ui_host, port=settings.ui_port,
        unsafe_bind=bool(getattr(args, "unsafe_bind", False)),
        verbose=verbose,
    ), proxy=ctrl)


def cmd_scan(args: argparse.Namespace) -> int:
    log = _logger()
    from .scanner import Scanner, BUILTIN_RULES
    from .plugins import get_registry
    project = Project(_resolve_project(args.project))
    extra = get_registry().active_rules()
    scanner = Scanner(rules=BUILTIN_RULES, extra_rules=extra)
    result = scanner.scan_project(project, limit=args.limit)
    log.info(
        "Scanned %d requests in %d ms: %d findings (critical %d, high %d, "
        "medium %d, low %d, info %d)",
        result.rows_scanned, result.elapsed_ms, result.findings_added,
        result.by_severity["critical"], result.by_severity["high"],
        result.by_severity["medium"], result.by_severity["low"],
        result.by_severity["info"],
    )
    project.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .reporter import DOCX_AVAILABLE, render_docx, render_html, render_markdown
    project = Project(_resolve_project(args.project))
    findings = project.list_findings(limit=10_000)
    meta = project.meta()
    out = Path(args.out).expanduser().resolve()
    fmt = (args.format or out.suffix.lstrip(".") or "md").lower()
    if fmt in ("md", "markdown"):
        out.write_text(render_markdown(meta, findings), encoding="utf-8")
    elif fmt == "html":
        out.write_text(render_html(meta, findings), encoding="utf-8")
    elif fmt == "docx":
        if not DOCX_AVAILABLE:
            print("error: python-docx not installed. Run 'pip install python-docx' "
                  "or pick --format md / html.", file=sys.stderr)
            return 2
        out.write_bytes(render_docx(meta, findings))
    else:
        print(f"error: unknown format '{fmt}'", file=sys.stderr)
        return 2
    print(f"Wrote {fmt} report to {out}")
    project.close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Execute a YAML/JSON job file against a project."""
    log = _logger()
    from .runner import load_job, run_job
    project = Project(_resolve_project(args.project))
    job_path = Path(args.job).expanduser().resolve()
    steps = load_job(job_path)
    result = run_job(steps, project=project, strict=args.strict)
    for sr in result.steps:
        status = "OK " if sr.ok else "FAIL"
        log.info("  [%s] step %d (%s) %s -- %dms",
                 status, sr.index, sr.type, sr.summary, sr.elapsed_ms)
        if sr.error:
            log.info("        error: %s", sr.error)
    log.info("Job %s in %d ms (%d steps).",
             "OK" if result.ok else "FAILED",
             result.elapsed_ms, len(result.steps))
    project.close()
    return 0 if result.ok else 1


def cmd_import_har(args: argparse.Namespace) -> int:
    """Import a HAR (HTTP Archive) file into the project history."""
    log = _logger()
    from .har import import_har_file
    project = Project(_resolve_project(args.project))
    har_path = Path(args.har).expanduser().resolve()
    if not har_path.exists():
        print(f"error: HAR file not found: {har_path}", file=sys.stderr)
        return 2
    result = import_har_file(project, har_path)
    log.info("HAR %s: %d entries seen, %d imported, %d skipped.",
             har_path.name, result.entries_seen, result.entries_imported,
             result.entries_skipped)
    if result.errors:
        for e in result.errors[:5]:
            log.warning("  %s", e)
        if len(result.errors) > 5:
            log.warning("  (+ %d more)", len(result.errors) - 5)
    project.close()
    return 0 if result.entries_imported > 0 else 1


def cmd_browser(args: argparse.Namespace) -> int:
    """Launch a dedicated Firefox profile wired to the Weblore proxy + CA."""
    log = _logger()
    from . import browser as fxmod
    settings = settings_from_env(Settings())
    # Make sure CA exists (creates it on first use).
    from .proxy.ca import ensure_ca
    ensure_ca(settings.ca_dir)
    ca_path = settings.ca_dir / "weblore-ca.pem"

    proxy_host = "127.0.0.1"
    proxy_port = args.proxy_port or settings.proxy_port
    ui_url = args.url or f"http://{settings.ui_host}:{settings.ui_port}/"

    archive_path = Path(args.firefox_zip).expanduser().resolve() if args.firefox_zip else None

    try:
        result = fxmod.run_browser(
            ca_path=ca_path,
            proxy_host=proxy_host, proxy_port=proxy_port,
            ui_url=ui_url,
            version=args.firefox_version,
            archive_path=archive_path,
            prefer_cache=not args.use_system,
            wait=args.wait,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log.info("Firefox launched (pid=%s)", result.pid)
    log.info("  exe      : %s", result.exe)
    log.info("  profile  : %s", result.profile)
    log.info("  policies : %s", result.policies)
    log.info("  proxy    : %s:%d", proxy_host, proxy_port)
    return 0


def cmd_prefetch_firefox(args: argparse.Namespace) -> int:
    """Pre-download Firefox into the cache for offline use later."""
    log = _logger()
    from . import browser as fxmod
    try:
        exe = fxmod.download_firefox(
            version=args.firefox_version,
            archive_path=Path(args.firefox_zip).expanduser().resolve()
                if args.firefox_zip else None,
            force=args.force,
        )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log.info("Firefox ready at %s", exe)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="weblore", description="Weblore — accessible web pentesting suite")
    p.add_argument("--version", action="version", version=f"weblore {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="Create or open a project file.")
    pi.add_argument("project_path")
    pi.set_defaults(func=cmd_init)

    pu = sub.add_parser("ui", help="Start the UI server.")
    pu.add_argument("--project", required=True)
    pu.add_argument("--host", default=None)
    pu.add_argument("--port", type=int, default=None)
    pu.add_argument("--unsafe-bind", action="store_true",
                    help="Allow binding non-loopback addresses (dangerous).")
    pu.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose logging (timestamps, logger names, INFO from dependencies).")
    pu.set_defaults(func=cmd_ui)

    pp = sub.add_parser("proxy", help="Start the MITM proxy only.")
    pp.add_argument("--project", required=True)
    pp.add_argument("--port", type=int, default=None)
    pp.add_argument("--ui-port", type=int, default=None,
                    help="Port the Weblore UI listens on; the proxy will "
                         "never hold requests to localhost:<this port> so "
                         "the operator's own UI tab can't get stuck.")
    pp.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose logging (timestamps, logger names, INFO from dependencies).")
    pp.set_defaults(func=cmd_proxy)

    pb = sub.add_parser("both", help="Start UI + proxy in the same process.")
    pb.add_argument("--project", required=True)
    pb.add_argument("--host", default=None)
    pb.add_argument("--ui-port", type=int, default=None)
    pb.add_argument("--proxy-port", type=int, default=None)
    pb.add_argument("--unsafe-bind", action="store_true",
                    help="Allow binding non-loopback addresses (dangerous).")
    pb.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose logging (timestamps, logger names, INFO from dependencies).")
    pb.set_defaults(func=cmd_both)

    psc = sub.add_parser("scan", help="Run the passive scanner on recorded history.")
    psc.add_argument("--project", required=True)
    psc.add_argument("--limit", type=int, default=5000,
                     help="How many most-recent requests to scan (default 5000).")
    psc.set_defaults(func=cmd_scan)

    pr = sub.add_parser("report", help="Export findings as md / html / docx.")
    pr.add_argument("--project", required=True)
    pr.add_argument("--out", required=True, help="Path to write the report to.")
    pr.add_argument("--format", choices=["md", "markdown", "html", "docx"],
                    default=None,
                    help="Output format (defaults to the --out file extension).")
    pr.set_defaults(func=cmd_report)

    prun = sub.add_parser("run", help="Run a YAML/JSON job file.")
    prun.add_argument("--project", required=True)
    prun.add_argument("job", help="Path to a .yaml/.yml/.json job file.")
    prun.add_argument("--strict", action="store_true",
                     help="Abort the run on the first failing step.")
    prun.set_defaults(func=cmd_run)

    pih = sub.add_parser("import-har", help="Import a HAR file into the project history.")
    pih.add_argument("--project", required=True)
    pih.add_argument("har", help="Path to a .har file.")
    pih.set_defaults(func=cmd_import_har)

    pb2 = sub.add_parser(
        "browser",
        help="Launch a dedicated Firefox preconfigured with the Weblore proxy + CA.",
    )
    pb2.add_argument("--proxy-port", type=int, default=None,
                     help="Proxy port to point Firefox at (default: settings value).")
    pb2.add_argument("--url", default=None,
                     help="Initial URL to open (default: the Weblore UI).")
    pb2.add_argument("--firefox-version", default=None,
                     help="Pin a Firefox version (default: latest from Mozilla).")
    pb2.add_argument("--firefox-zip", default=None,
                     help="Use a pre-downloaded Mozilla zip/tar.xz instead of fetching.")
    pb2.add_argument("--use-system", action="store_true",
                     help="Prefer the host Firefox install over the managed cache.")
    pb2.add_argument("--wait", action="store_true",
                     help="Block until Firefox exits (default: spawn and return).")
    pb2.set_defaults(func=cmd_browser)

    pf = sub.add_parser(
        "prefetch-firefox",
        help="Download Firefox into the cache for later offline use (no launch).",
    )
    pf.add_argument("--firefox-version", default=None)
    pf.add_argument("--firefox-zip", default=None,
                    help="Stage a pre-downloaded archive into the cache.")
    pf.add_argument("--force", action="store_true",
                    help="Re-download / re-extract even if already cached.")
    pf.set_defaults(func=cmd_prefetch_firefox)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

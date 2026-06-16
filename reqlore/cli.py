"""Command-line entry point.

    reqlore init <project.rlr>
    reqlore ui   --project <project.rlr> [--host 127.0.0.1] [--port 8787]
    reqlore proxy --project <project.rlr> [--port 8080] [--ui-port 8787]
    reqlore both --project <project.rlr>     # UI + proxy in one process
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import tarfile
import zipfile
from pathlib import Path

from . import __version__
from .config import Settings, settings_from_env
from .proxy.mitm import ProxyController
from .storage import Project


class _MitmNoiseFilter(logging.Filter):
    """Drop the per-connection TLS-trust noise mitmproxy emits whenever a
    client (Firefox, curl, Python requests, OS telemetry, ...) refuses the
    Reqlore CA. These are *expected* and not actionable: the operator either
    needs to install the CA or accept that pinned endpoints can't be MITM'd.
    The signal is one banner line at startup, not a wall of tracebacks per
    handshake. Verbose mode bypasses this filter."""

    _DROP_SUBSTRINGS = (
        "Client TLS handshake failed",
        "tlsv1 alert unknown ca",
        "tlsv13 alert unknown ca",
        "TLS Error:",
        "mitmproxy has crashed",
        "OpenSSL.SSL.Error: []",
        # Pinned-cert sites (Mozilla telemetry, etc.) can't be MITM'd — same
        # category of expected noise.
        "tlsv1 alert bad certificate",
        "tlsv1 alert certificate unknown",
        "tlsv1 alert internal error",
    )

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        msg = record.getMessage()
        for needle in self._DROP_SUBSTRINGS:
            if needle in msg:
                return False
        # Also drop the multi-line tracebacks attached to the above messages.
        if record.exc_info:
            exc = record.exc_info[1]
            if exc is not None:
                txt = repr(exc)
                if "OpenSSL.SSL.Error" in txt and "[]" in txt:
                    return False
        return True


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
        # Install the mitmproxy noise filter on every existing handler. We
        # attach to handlers (not loggers) so it catches records propagated
        # from any mitmproxy submodule.
        noise_filter = _MitmNoiseFilter()
        for handler in logging.getLogger().handlers:
            handler.addFilter(noise_filter)
    return logging.getLogger("reqlore")


def _verbose_from(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "verbose", False)) or os.environ.get("REQLORE_VERBOSE") == "1"


def _print_banner(*, project_path: Path | str | None = None,
                  ui_url: str | None = None,
                  proxy_endpoint: str | None = None) -> None:
    """Print a clean, screen-reader-friendly startup banner."""
    title = f"Reqlore {__version__}"
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


PROJECT_SUFFIXES = (".rlr", ".reqlore")


def _resolve_project(arg: str | None) -> Path:
    if not arg:
        print("error: --project <path> required", file=sys.stderr)
        sys.exit(2)
    p = Path(arg).expanduser().resolve()
    if p.suffix.lower() not in PROJECT_SUFFIXES:
        accepted = ", ".join(PROJECT_SUFFIXES)
        print(
            f"error: project file must end in {accepted} (got {p.name!r})",
            file=sys.stderr,
        )
        sys.exit(2)
    return p


def _port_in_use(host: str, port: int) -> bool:
    """Try to bind (host, port) for half a second; return True if occupied."""
    import socket
    if port <= 0:
        return False  # OS-assigned ports never collide
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False


def _abort_if_port_busy(label: str, host: str, port: int) -> int | None:
    """Return an exit code to bubble up if the port is already taken."""
    if _port_in_use(host, port):
        print(
            f"error: {label} port {host}:{port} is already in use. "
            "Is another `reqlore` instance running?",
            file=sys.stderr,
        )
        return 1
    return None


def _enforce_unsafe_bind_password(
    settings: Settings, args: argparse.Namespace,
) -> int | None:
    """Refuse to start when --unsafe-bind is requested without a password.

    Loopback binds never require a password (the operator on the same
    machine already has filesystem access). Any other bind exposes the UI
    to other hosts, so we require either REQLORE_PASSWORD or
    REQLORE_PASSWORD_HASH to be set when the operator opts in with
    --unsafe-bind. The check honours the existing
    ``require_password_on_unsafe_bind`` setting so power users can opt out
    by setting it to ``false`` in their config, but the env-var must still
    be set OR the user must pass the explicit escape hatch
    --no-password (e.g. when fronting Reqlore with their own auth proxy).
    """
    if not getattr(args, "unsafe_bind", False):
        return None
    if settings.ui_host == "127.0.0.1":
        return None
    if getattr(args, "no_password", False):
        print(
            "warning: --unsafe-bind --no-password: the UI is exposed without "
            "authentication. Front it with your own reverse proxy + auth, or "
            "you WILL be compromised.",
            file=sys.stderr,
        )
        return None
    if settings.auth_enabled:
        return None
    print(
        "error: --unsafe-bind requires a password. Set REQLORE_PASSWORD "
        "(plaintext, hashed in-memory at startup) or REQLORE_PASSWORD_HASH "
        "(pre-computed argon2id hash), or pass --no-password to acknowledge "
        "you have your own auth layer in front.",
        file=sys.stderr,
    )
    return 2


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
    if rc := _enforce_unsafe_bind_password(settings, args):
        return rc

    # Skip the port pre-check when we were chained from `cmd_both` — the proxy
    # already owns its port and we own the UI port from the same process.
    if proxy is None:
        rc = _abort_if_port_busy("UI", settings.ui_host, settings.ui_port)
        if rc is not None:
            return rc

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
        log.debug("Serving Reqlore UI on http://%s:%d/", settings.ui_host, settings.ui_port)
        serve(app, host=settings.ui_host, port=settings.ui_port, threads=8,
              ident="Reqlore")
    except ImportError:
        try:
            app.run(host=settings.ui_host, port=settings.ui_port)
        except OSError as exc:
            print(f"error: could not start UI on {settings.ui_host}:{settings.ui_port}: {exc}",
                  file=sys.stderr)
            return 1
    except OSError as exc:
        print(f"error: could not start UI on {settings.ui_host}:{settings.ui_port}: {exc}",
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
    finally:
        if proxy is not None:
            try:
                proxy.stop()
            except Exception:  # noqa: BLE001
                pass
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
    rc = _abort_if_port_busy("proxy", settings.proxy_host, settings.proxy_port)
    if rc is not None:
        return rc
    project = Project(project_path)
    ctrl = ProxyController(project, settings.proxy_host, settings.proxy_port, settings.ca_dir,
                           ui_port=settings.ui_port)
    ctrl.start()

    # Give the proxy thread a moment to actually bind. If it died (mitmproxy
    # couldn't load, bad CA dir, etc.) report it cleanly instead of dropping
    # the user into a silent join().
    import time as _time
    for _ in range(20):
        if ctrl.is_running():
            break
        _time.sleep(0.1)
    if not ctrl.is_running():
        print("error: proxy failed to start (run again with --verbose for details)",
              file=sys.stderr)
        return 1

    _print_banner(project_path=project_path,
                  proxy_endpoint=f"{settings.proxy_host}:{settings.proxy_port}")
    log.debug("Proxy listening on %s:%d", settings.proxy_host, settings.proxy_port)
    try:
        ctrl._thread.join()  # noqa: SLF001
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
    finally:
        try:
            ctrl.stop()
        except Exception:  # noqa: BLE001
            pass
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
    if settings.ui_host != "127.0.0.1" and not args.unsafe_bind:
        print("refusing to bind non-loopback without --unsafe-bind", file=sys.stderr)
        return 2
    if rc := _enforce_unsafe_bind_password(settings, args):
        return rc
    # Check both ports up front — failing after the proxy has started would
    # leak a thread and leave port 8080 held.
    rc = _abort_if_port_busy("UI", settings.ui_host, settings.ui_port)
    if rc is not None:
        return rc
    rc = _abort_if_port_busy("proxy", settings.proxy_host, settings.proxy_port)
    if rc is not None:
        return rc

    project = Project(project_path)
    ctrl = ProxyController(project, settings.proxy_host, settings.proxy_port, settings.ca_dir,
                           ui_port=settings.ui_port)
    ctrl.start()

    import time as _time
    for _ in range(20):
        if ctrl.is_running():
            break
        _time.sleep(0.1)
    if not ctrl.is_running():
        print("error: proxy failed to start (run again with --verbose for details)",
              file=sys.stderr)
        return 1

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
        no_password=bool(getattr(args, "no_password", False)),
        verbose=verbose,
    ), proxy=ctrl)


def cmd_scan(args: argparse.Namespace) -> int:
    log = _logger()
    from .scanner import Scanner, BUILTIN_RULES
    from .plugins import get_registry
    project = Project(_resolve_project(args.project))
    extra = get_registry().active_rules()
    scanner = Scanner(rules=BUILTIN_RULES, extra_rules=extra)
    # B.5 — `--full` disables the resume marker, `--deadline 0` disables
    # the wall-clock guard, any positive value is taken at face value.
    resume = not bool(getattr(args, "full", False))
    deadline_raw = float(getattr(args, "deadline", 300.0) or 0.0)
    deadline = deadline_raw if deadline_raw > 0 else None
    result = scanner.scan_project(
        project, limit=args.limit,
        deadline_seconds=deadline, resume=resume,
    )
    log.info(
        "Scanned %d requests in %d ms: %d findings (critical %d, high %d, "
        "medium %d, low %d, info %d)",
        result.rows_scanned, result.elapsed_ms, result.findings_added,
        result.by_severity["critical"], result.by_severity["high"],
        result.by_severity["medium"], result.by_severity["low"],
        result.by_severity["info"],
    )
    if result.rows_skipped_resume:
        log.info("Resume: skipped %d already-scanned rows (use --full to "
                  "force a re-scan).", result.rows_skipped_resume)
    if result.aborted_due_to_deadline:
        log.warning("Scan aborted after %.1fs deadline; partial result "
                     "written. Re-run to continue from row id %s.",
                     result.deadline_seconds, result.last_scanned_id)
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
    """Launch a dedicated Firefox profile wired to the Reqlore proxy + CA."""
    log = _logger()
    from . import browser as fxmod
    settings = settings_from_env(Settings())
    # Make sure CA exists (creates it on first use).
    from .proxy.ca import ensure_ca
    ensure_ca(settings.ca_dir)
    ca_path = settings.ca_dir / "reqlore-ca.pem"

    proxy_host = "127.0.0.1"
    proxy_port = args.proxy_port or settings.proxy_port
    ui_url = args.url or f"http://{settings.ui_host}:{settings.ui_port}/"

    # WSL hand-off: the Linux Firefox we ship cannot reach the Windows
    # display server, so silently dying inside WSL is the original bug
    # report. Detect WSL, open the URL on the Windows host browser
    # instead, and print everything the operator needs to wire host-side
    # proxy + CA trust manually. Exit 0 — the UI server is up.
    if fxmod.is_wsl():
        opener = fxmod.open_on_windows_host(ui_url)
        print(f"Reqlore UI: {ui_url}")
        print(f"Proxy:      {proxy_host}:{proxy_port}")
        print(f"CA cert:    {ca_path}")
        if opener:
            print(f"Opened on Windows host via {opener}.")
            print(
                "Note: configure your Windows browser to use the proxy "
                "above and trust the CA cert. Reqlore cannot wire those "
                "automatically from inside WSL."
            )
            return 0
        print(
            "Could not auto-open a browser on the Windows host "
            "(neither cmd.exe /c start nor wslview worked)."
        )
        print(f"Open this URL manually in your Windows browser: {ui_url}")
        return 0

    archive_path = Path(args.firefox_zip).expanduser().resolve() if args.firefox_zip else None

    project = None
    project_arg = getattr(args, "project", None)
    if project_arg:
        project_path = _resolve_project(project_arg)
        from .storage import Project
        project = Project(project_path)

    # Firefox channel to use. Defaults to Release for everyone: the
    # bundled DOM Hunter XPI is Mozilla-signed and loads on Release
    # without any signature override. Users iterating on the unsigned
    # extension source can opt into Dev Edition explicitly via
    # --channel devedition.
    channel = getattr(args, "channel", None) or "release"

    try:
        result = fxmod.run_browser(
            ca_path=ca_path,
            proxy_host=proxy_host, proxy_port=proxy_port,
            ui_url=ui_url,
            version=args.firefox_version,
            archive_path=archive_path,
            prefer_cache=not args.use_system,
            wait=args.wait,
            project=project,
            channel=channel,
        )
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        # Friendly, multi-line messages from launch()/run_browser/download.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: required file not found: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"error: permission denied: {exc}\n"
              "  Check write access to ~/.local/share/reqlore (or %APPDATA%\\reqlore).",
              file=sys.stderr)
        return 2
    except OSError as exc:
        # Covers network errors during download (urllib raises URLError <- OSError),
        # disk-full, etc.
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        print(f"error: Firefox archive is corrupt or incomplete: {exc}\n"
              "  Re-run with --firefox-version to force a fresh download.",
              file=sys.stderr)
        return 1

    log.info("Firefox launched (pid=%s)", result.pid)
    log.info("  exe      : %s", result.exe)
    log.info("  profile  : %s", result.profile)
    log.info("  policies : %s", result.policies)
    log.info("  proxy    : %s:%d", proxy_host, proxy_port)
    if project is not None:
        log.info("  extension: DOM Hunter auto-installed for project %s",
                 project.path)
        project.close()
    return 0


def cmd_intruder(args: argparse.Namespace) -> int:
    """Headless intruder: load a spec file, run it, print/export results."""
    import json as _json

    from .intruder import AttackRunner
    from .intruder_spec import SpecError, build_attack, load_spec

    action = args.intruder_action
    project = Project(Path(args.project).expanduser().resolve())

    if action == "list":
        attacks = project.list_intruder()
        if not attacks:
            print("No attacks in this project.")
            return 0
        print(f"{'id':>4}  {'status':<10}  {'type':<12}  name")
        for a in attacks:
            print(f"{a['id']:>4}  {a['status']:<10}  {a['attack_type']:<12}  {a['name']}")
        return 0

    if action == "show":
        attack = project.get_intruder(args.id)
        if not attack:
            print(f"error: attack #{args.id} not found", file=sys.stderr)
            return 1
        results = project.list_intruder_results(args.id)
        print(f"Attack #{attack['id']}: {attack['name']} ({attack['attack_type']}, "
              f"{attack['engine']}, {attack['status']})")
        print(f"URL: {attack['url']}")
        print(f"Results: {len(results)}")
        if not results:
            return 0
        print(f"{'#':>5}  {'status':>6}  {'len':>7}  {'ms':>5}  match  payloads")
        for r in results[: args.limit]:
            payloads = ", ".join(r["payloads"])[:60]
            mark = "yes" if r["matched"] else "no "
            print(f"{r['seq']:>5}  {r['status']:>6}  {r['len_resp']:>7}  "
                  f"{r['duration_ms']:>5}  {mark:<5}  {payloads}")
        if len(results) > args.limit:
            print(f"  ... ({len(results) - args.limit} more; raise --limit to see all)")
        return 0

    if action == "export":
        attack = project.get_intruder(args.id)
        if not attack:
            print(f"error: attack #{args.id} not found", file=sys.stderr)
            return 1
        results = project.list_intruder_results(args.id)
        out_path = Path(args.out).expanduser().resolve()
        fmt = args.format or out_path.suffix.lstrip(".").lower() or "json"
        if fmt == "csv":
            import csv as _csv
            with out_path.open("w", encoding="utf-8", newline="") as fh:
                w = _csv.writer(fh, lineterminator="\n")
                w.writerow(["seq", "status", "len_resp", "duration_ms",
                            "matched", "grep_hits", "body_md5",
                            "payloads", "history_id"])
                for r in results:
                    w.writerow([
                        r["seq"], r["status"], r["len_resp"], r["duration_ms"],
                        1 if r["matched"] else 0, r["grep_hits"],
                        r["body_md5"], "|".join(r["payloads"]),
                        r["history_id"] if r["history_id"] is not None else "",
                    ])
        elif fmt == "json":
            payload = {
                "attack": {
                    "id": attack["id"], "name": attack["name"],
                    "attack_type": attack["attack_type"],
                    "engine": attack["engine"], "status": attack["status"],
                    "url": attack["url"],
                },
                "count": len(results),
                "rows": results,
            }
            out_path.write_text(
                _json.dumps(payload, indent=2, default=str), encoding="utf-8")
        else:
            print(f"error: unknown export format {fmt!r} (use csv or json)",
                  file=sys.stderr)
            return 2
        print(f"Wrote {len(results)} row(s) to {out_path}")
        return 0

    # action == "run"
    log = _logger(verbose=getattr(args, "verbose", False))
    spec_path = Path(args.spec).expanduser().resolve()
    try:
        spec = load_spec(spec_path)
        built = build_attack(spec, base_dir=spec_path.parent)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    aid = project.create_intruder(
        name=built.name, attack_type=built.attack_type,
        template=built.template, positions=built.positions,
        payloads=built.payloads, options=built.options,
        url=built.url, engine=built.engine,
    )
    print(f"Created attack #{aid} '{built.name}' "
          f"({built.attack_type}, {built.engine}).")

    if args.dry_run:
        if built.attack_type == "sniper":
            est = sum(len(s) for s in built.payloads) * len(built.positions)
        elif built.attack_type == "battering":
            est = len(built.payloads[0])
        elif built.attack_type == "pitchfork":
            est = min(len(s) for s in built.payloads)
        else:  # clusterbomb
            est = 1
            for s in built.payloads:
                est *= max(1, len(s))
        cap = built.options["max_requests"]
        print(f"Dry run: {len(built.payloads)} payload set(s); "
              f"~{est} request(s) planned (capped at max_requests={cap}).")
        return 0

    runner = AttackRunner(project, aid)
    runner.start()
    timeout = args.timeout if args.timeout > 0 else None
    completed = runner.wait(timeout=timeout)
    if not completed:
        runner.cancel()
        runner.wait(timeout=10)
        print(f"warning: attack did not finish within {args.timeout}s; cancelled.",
              file=sys.stderr)

    results = project.list_intruder_results(aid)
    matched = sum(1 for r in results if r["matched"])
    by_status: dict[int, int] = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    final = project.get_intruder(aid)["status"]
    print(f"Done. status={final} sent={len(results)} matched={matched}")
    if runner.stop_reason:
        print(f"Stopped early: {runner.stop_reason}")
    if by_status:
        for code in sorted(by_status):
            print(f"  HTTP {code}: {by_status[code]}")
    log.debug("intruder finished")
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
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
        print(f"error: Firefox archive is corrupt or incomplete: {exc}",
              file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    log.info("Firefox ready at %s", exe)
    return 0


# ----------------------------------------------- A.6 finding / suppression CLI


def _print_findings_table(rows: list[dict]) -> None:
    if not rows:
        print("(no findings)")
        return
    # Compact, screen-reader-friendly columns: id, sev, status, rule, host, title.
    widths = {
        "id":     max(2, max(len(str(r.get("id", ""))) for r in rows)),
        "sev":    max(3, max(len(str(r.get("severity", ""))) for r in rows)),
        "status": max(6, max(len(str(r.get("status", ""))) for r in rows)),
        "rule":   max(7, max(len(str(r.get("rule_id", ""))) for r in rows)),
        "host":   max(4, max(len(str(r.get("host", ""))) for r in rows)),
    }
    header = (
        f"{'id'.ljust(widths['id'])}  "
        f"{'sev'.ljust(widths['sev'])}  "
        f"{'status'.ljust(widths['status'])}  "
        f"{'rule'.ljust(widths['rule'])}  "
        f"{'host'.ljust(widths['host'])}  title"
    )
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{str(r.get('id', '')).ljust(widths['id'])}  "
            f"{str(r.get('severity', '')).ljust(widths['sev'])}  "
            f"{str(r.get('status', '')).ljust(widths['status'])}  "
            f"{str(r.get('rule_id', '')).ljust(widths['rule'])}  "
            f"{str(r.get('host', '')).ljust(widths['host'])}  "
            f"{r.get('title', '')}"
        )


def _split_refs(raw: str | None) -> list[str]:
    if not raw:
        return []
    parts = [p.strip() for chunk in raw.splitlines() for p in chunk.split(",")]
    return [p for p in parts if p]


def cmd_finding_add(args: argparse.Namespace) -> int:
    """Record a manual finding via the write-bus."""
    from .findings_bus import record_finding
    from .scanner.rules import SEVERITIES

    if args.severity not in SEVERITIES:
        print(f"error: --severity must be one of {', '.join(SEVERITIES)}",
              file=sys.stderr)
        return 2
    title = (args.title or "").strip()
    if not title:
        print("error: --title is required", file=sys.stderr)
        return 2
    rule_id = (args.rule_id or "").strip()
    if not rule_id:
        slug_src = (args.slug or title).lower()
        import re as _re
        slug = _re.sub(r"[^a-z0-9]+", "-", slug_src).strip("-")[:60] or "finding"
        rule_id = f"manual:{slug}"
    project = Project(_resolve_project(args.project))
    try:
        fid = record_finding(
            project,
            source="manual",
            rule_id=rule_id,
            severity=args.severity,
            title=title,
            host=args.host or "",
            url=args.url or "",
            cwe=args.cwe or "",
            owasp=args.owasp or "",
            description=args.description or "",
            evidence=args.evidence or "",
            payload=args.payload or "",
            remediation=args.remediation or "",
            references=_split_refs(args.reference),
        )
    finally:
        project.close()
    if fid is None:
        print(f"Suppressed by an existing suppression for {rule_id}.")
        return 0
    print(f"Recorded finding #{fid} ({rule_id})")
    return 0


def cmd_finding_list(args: argparse.Namespace) -> int:
    project = Project(_resolve_project(args.project))
    try:
        rows = project.list_findings(
            severity=args.severity or None,
            status=args.status or None,
            host=args.host or None,
            source=args.source or None,
            rule_id=args.rule_id or None,
            limit=args.limit,
        )
        if args.format == "json":
            import json as _json
            print(_json.dumps(rows, indent=2, default=str))
        else:
            _print_findings_table(rows)
    finally:
        project.close()
    return 0


def cmd_finding_triage(args: argparse.Namespace) -> int:
    project = Project(_resolve_project(args.project))
    try:
        if not project.get_finding(args.id):
            print(f"error: finding #{args.id} not found", file=sys.stderr)
            return 2
        try:
            project.set_finding_status(args.id, args.status)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        msg = f"Finding #{args.id} -> {args.status}"
        if args.status == "false_positive":
            f = project.get_finding(args.id)
            if f and f.get("rule_id"):
                project.add_finding_suppression(
                    rule_id=f["rule_id"],
                    host=f.get("host") or "",
                    url_pattern=f.get("url") or "",
                    reason=args.reason or f"FP triage of finding #{args.id}",
                )
                msg += f"; suppression added for {f['rule_id']}"
            else:
                msg += " (no rule_id; no suppression created)"
        print(msg)
    finally:
        project.close()
    return 0


def cmd_finding_import(args: argparse.Namespace) -> int:
    """Bulk-import findings from a JSON file using the bus."""
    import json as _json
    from .findings_bus import record_finding
    from .scanner.rules import SEVERITIES

    path = Path(args.file).expanduser().resolve()
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    try:
        payload = _json.loads(path.read_text(encoding="utf-8"))
    except _json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2
    if isinstance(payload, dict) and "findings" in payload:
        items = payload["findings"]
    elif isinstance(payload, list):
        items = payload
    else:
        print("error: JSON must be a list of findings or an object with "
              "a 'findings' array.", file=sys.stderr)
        return 2

    project = Project(_resolve_project(args.project))
    added = suppressed = rejected = 0
    try:
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                print(f"error: row {i}: not an object", file=sys.stderr)
                rejected += 1
                continue
            title = (item.get("title") or "").strip()
            severity = item.get("severity") or ""
            if not title or severity not in SEVERITIES:
                print(f"error: row {i}: missing title or invalid severity "
                      f"({severity!r})", file=sys.stderr)
                rejected += 1
                continue
            rule_id = item.get("rule_id") or ""
            if not rule_id:
                import re as _re
                slug = _re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60]
                rule_id = f"manual:{slug or 'finding'}"
            refs = item.get("references") or []
            if isinstance(refs, str):
                refs = _split_refs(refs)
            fid = record_finding(
                project,
                source=item.get("source") or "imported",
                rule_id=rule_id,
                severity=severity,
                title=title,
                host=item.get("host") or "",
                url=item.get("url") or "",
                cwe=item.get("cwe") or "",
                owasp=item.get("owasp") or "",
                description=item.get("description") or "",
                evidence=item.get("evidence") or "",
                payload=item.get("payload") or "",
                remediation=item.get("remediation") or "",
                references=list(refs),
            )
            if fid is None:
                suppressed += 1
            else:
                added += 1
    finally:
        project.close()
    print(f"Imported {added} findings ({suppressed} suppressed, "
          f"{rejected} rejected, {len(items)} seen).")
    return 1 if rejected and not added else 0


def cmd_finding_repro(args: argparse.Namespace) -> int:
    """Print a `curl` one-liner that re-fires the probe attached to a finding."""
    from .reporter._common import curl_from_reproduction

    project = Project(_resolve_project(args.project))
    try:
        finding = project.get_finding(args.id)
        if finding is None:
            print(f"error: finding #{args.id} not found", file=sys.stderr)
            return 2
        token = finding.get("reproduction_token") or ""
        if not token:
            print(f"error: finding #{args.id} has no stored reproduction "
                  "(passive / manual / imported findings don't carry one)",
                  file=sys.stderr)
            return 2
        repro = project.get_reproduction(token)
        if repro is None:
            print(f"error: reproduction token {token} is missing from storage",
                  file=sys.stderr)
            return 2
        if args.format == "json":
            import json as _json
            out = dict(repro)
            # bytes -> str for JSON.
            out["request_blob"] = (out.get("request_blob") or b"").decode(
                "latin-1", errors="replace")
            out["response_blob"] = (out.get("response_blob") or b"").decode(
                "latin-1", errors="replace")
            print(_json.dumps(out, indent=2, default=str))
            return 0
        line = curl_from_reproduction(repro)
        if not line:
            print(f"error: reproduction for finding #{args.id} could not be "
                  "rendered as curl (no method/url recorded)", file=sys.stderr)
            return 2
        print(line)
    finally:
        project.close()
    return 0


def cmd_suppression_add(args: argparse.Namespace) -> int:
    project = Project(_resolve_project(args.project))
    try:
        try:
            project.add_finding_suppression(
                rule_id=args.rule_id,
                host=args.host or "",
                url_pattern=args.url_pattern or "",
                reason=args.reason or "",
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(
            f"Suppression added for {args.rule_id} "
            f"(host={args.host or '*'}, url={args.url_pattern or '*'})."
        )
    finally:
        project.close()
    return 0


def cmd_suppression_list(args: argparse.Namespace) -> int:
    project = Project(_resolve_project(args.project))
    try:
        rows = project.list_finding_suppressions()
        if args.format == "json":
            import json as _json
            print(_json.dumps(rows, indent=2, default=str))
            return 0
        if not rows:
            print("(no suppressions)")
            return 0
        widths = {
            "rule": max(7, max(len(r["rule_id"]) for r in rows)),
            "host": max(4, max(len(r["host"] or "*") for r in rows)),
            "url":  max(11, max(len(r["url_pattern"] or "*") for r in rows)),
        }
        header = (
            f"{'rule'.ljust(widths['rule'])}  "
            f"{'host'.ljust(widths['host'])}  "
            f"{'url_pattern'.ljust(widths['url'])}  reason"
        )
        print(header)
        print("-" * len(header))
        for r in rows:
            print(
                f"{r['rule_id'].ljust(widths['rule'])}  "
                f"{(r['host'] or '*').ljust(widths['host'])}  "
                f"{(r['url_pattern'] or '*').ljust(widths['url'])}  "
                f"{r['reason'] or ''}"
            )
    finally:
        project.close()
    return 0


def cmd_suppression_delete(args: argparse.Namespace) -> int:
    project = Project(_resolve_project(args.project))
    try:
        project.delete_finding_suppression(
            rule_id=args.rule_id,
            host=args.host or "",
            url_pattern=args.url_pattern or "",
        )
        print(
            f"Suppression removed for {args.rule_id} "
            f"(host={args.host or '*'}, url={args.url_pattern or '*'})."
        )
    finally:
        project.close()
    return 0


def cmd_finding(args: argparse.Namespace) -> int:
    """Dispatcher for `reqlore finding <action>`."""
    dispatch = {
        "add":    cmd_finding_add,
        "list":   cmd_finding_list,
        "triage": cmd_finding_triage,
        "import": cmd_finding_import,
        "repro":  cmd_finding_repro,
    }
    return dispatch[args.finding_action](args)


def cmd_suppression(args: argparse.Namespace) -> int:
    """Dispatcher for `reqlore suppression <action>`."""
    dispatch = {
        "add":    cmd_suppression_add,
        "list":   cmd_suppression_list,
        "delete": cmd_suppression_delete,
    }
    return dispatch[args.suppression_action](args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reqlore",
        description="Reqlore — accessible web pentesting suite",
        allow_abbrev=False,
    )
    p.add_argument("--version", action="version", version=f"reqlore {__version__}")
    sub = p.add_subparsers(
        dest="subcommand",
        metavar="<subcommand>",
        required=False,  # handled in main() so bare `reqlore` shows help instead of a one-liner
    )

    pi = sub.add_parser("init", help="Create or open a project file.", allow_abbrev=False)
    pi.add_argument("project_path")
    pi.set_defaults(func=cmd_init)

    pu = sub.add_parser("ui", help="Start the UI server.", allow_abbrev=False)
    pu.add_argument("--project", required=True)
    pu.add_argument("--host", default=None)
    pu.add_argument("--port", type=int, default=None)
    pu.add_argument("--unsafe-bind", action="store_true",
                    help="Allow binding non-loopback addresses (dangerous).")
    pu.add_argument("--no-password", action="store_true",
                    help="When combined with --unsafe-bind, skip the "
                         "REQLORE_PASSWORD requirement. Use this only if you "
                         "front Reqlore with your own auth proxy (nginx, "
                         "Caddy, oauth2-proxy, etc.).")
    pu.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose logging (timestamps, logger names, INFO from dependencies).")
    pu.set_defaults(func=cmd_ui)

    pp = sub.add_parser("proxy", help="Start the MITM proxy only.", allow_abbrev=False)
    pp.add_argument("--project", required=True)
    pp.add_argument("--port", type=int, default=None)
    pp.add_argument("--ui-port", type=int, default=None,
                    help="Port the Reqlore UI listens on; the proxy will "
                         "never hold requests to localhost:<this port> so "
                         "the operator's own UI tab can't get stuck.")
    pp.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose logging (timestamps, logger names, INFO from dependencies).")
    pp.set_defaults(func=cmd_proxy)

    pb = sub.add_parser("both", help="Start UI + proxy in the same process.", allow_abbrev=False)
    pb.add_argument("--project", required=True)
    pb.add_argument("--host", default=None)
    pb.add_argument("--ui-port", type=int, default=None)
    pb.add_argument("--proxy-port", type=int, default=None)
    pb.add_argument("--unsafe-bind", action="store_true",
                    help="Allow binding non-loopback addresses (dangerous).")
    pb.add_argument("--no-password", action="store_true",
                    help="When combined with --unsafe-bind, skip the "
                         "REQLORE_PASSWORD requirement. Use this only if you "
                         "front Reqlore with your own auth proxy.")
    pb.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose logging (timestamps, logger names, INFO from dependencies).")
    pb.set_defaults(func=cmd_both)

    psc = sub.add_parser("scan", help="Run the passive scanner on recorded history.", allow_abbrev=False)
    psc.add_argument("--project", required=True)
    psc.add_argument("--limit", type=int, default=5000,
                     help="How many most-recent requests to scan (default 5000).")
    psc.add_argument("--full", action="store_true",
                     help="Re-scan every row, ignoring the resume marker.")
    psc.add_argument("--deadline", type=float, default=300.0,
                     help="Wall-clock deadline in seconds (default 300; "
                          "use 0 to disable).")
    psc.set_defaults(func=cmd_scan)

    pr = sub.add_parser("report", help="Export findings as md / html / docx.", allow_abbrev=False)
    pr.add_argument("--project", required=True)
    pr.add_argument("--out", required=True, help="Path to write the report to.")
    pr.add_argument("--format", choices=["md", "markdown", "html", "docx"],
                    default=None,
                    help="Output format (defaults to the --out file extension).")
    pr.set_defaults(func=cmd_report)

    prun = sub.add_parser("run", help="Run a YAML/JSON job file.", allow_abbrev=False)
    prun.add_argument("--project", required=True)
    prun.add_argument("job", help="Path to a .yaml/.yml/.json job file.")
    prun.add_argument("--strict", action="store_true",
                     help="Abort the run on the first failing step.")
    prun.set_defaults(func=cmd_run)

    pih = sub.add_parser("import-har", help="Import a HAR file into the project history.", allow_abbrev=False)
    pih.add_argument("--project", required=True)
    pih.add_argument("har", help="Path to a .har file.")
    pih.set_defaults(func=cmd_import_har)

    pb2 = sub.add_parser(
        "browser",
        help="Launch a dedicated Firefox preconfigured with the Reqlore proxy + CA.",
        allow_abbrev=False,
    )
    pb2.add_argument("--project", default=None,
                     help="Project .rlr file. When given, the DOM Hunter "
                          "WebExtension is force-installed into the Firefox "
                          "profile, pre-configured with the project's bridge "
                          "token. Without --project, Firefox is launched "
                          "without the extension.")
    pb2.add_argument("--proxy-port", type=int, default=None,
                     help="Proxy port to point Firefox at (default: settings value).")
    pb2.add_argument("--url", default=None,
                     help="Initial URL to open (default: the Reqlore UI).")
    pb2.add_argument("--firefox-version", default=None,
                     help="Pin a Firefox version (default: latest from Mozilla).")
    pb2.add_argument("--firefox-zip", default=None,
                     help="Use a pre-downloaded Mozilla zip/tar.xz instead of fetching.")
    pb2.add_argument("--use-system", action="store_true",
                     help="Prefer the host Firefox install over the managed cache.")
    pb2.add_argument("--channel", choices=("release", "devedition"), default=None,
                     help="Firefox release channel to download. Defaults to "
                          "'release' (the bundled DOM Hunter XPI is signed "
                          "and loads on Release). Use 'devedition' only when "
                          "iterating on an unsigned local extension build.")
    pb2.add_argument("--wait", action="store_true",
                     help="Block until Firefox exits (default: spawn and return).")
    pb2.set_defaults(func=cmd_browser)

    pin = sub.add_parser(
        "intruder",
        help="Headless intruder: run an attack spec, list, show, or export results.",
        allow_abbrev=False,
    )
    pin_sub = pin.add_subparsers(
        dest="intruder_action", metavar="<action>", required=True,
    )

    pin_run = pin_sub.add_parser(
        "run", help="Run an attack from a JSON/YAML spec.", allow_abbrev=False,
    )
    pin_run.add_argument("--project", required=True)
    pin_run.add_argument("spec", help="Path to a .json/.yaml/.yml attack spec.")
    pin_run.add_argument("--timeout", type=int, default=0,
                          help="Seconds to wait before cancelling (0 = no timeout).")
    pin_run.add_argument("--dry-run", action="store_true",
                          help="Build the attack and report planned request "
                               "count without sending anything.")
    pin_run.add_argument("-v", "--verbose", action="store_true")

    pin_list = pin_sub.add_parser(
        "list", help="List attacks in a project.", allow_abbrev=False,
    )
    pin_list.add_argument("--project", required=True)

    pin_show = pin_sub.add_parser(
        "show", help="Show results for one attack.", allow_abbrev=False,
    )
    pin_show.add_argument("--project", required=True)
    pin_show.add_argument("--id", type=int, required=True)
    pin_show.add_argument("--limit", type=int, default=50,
                           help="Maximum rows to print (default 50).")

    pin_exp = pin_sub.add_parser(
        "export", help="Export results to CSV or JSON.", allow_abbrev=False,
    )
    pin_exp.add_argument("--project", required=True)
    pin_exp.add_argument("--id", type=int, required=True)
    pin_exp.add_argument("--out", required=True)
    pin_exp.add_argument("--format", choices=["csv", "json"], default=None,
                          help="Override the format inferred from --out's extension.")

    pin.set_defaults(func=cmd_intruder)

    # ----- A.6: finding management
    pfd = sub.add_parser(
        "finding",
        help="Manage findings (add manual, list, triage, bulk-import).",
        allow_abbrev=False,
    )
    pfd_sub = pfd.add_subparsers(
        dest="finding_action", metavar="<action>", required=True,
    )

    pfd_add = pfd_sub.add_parser(
        "add", help="Record a manual finding via the write-bus.",
        allow_abbrev=False,
    )
    pfd_add.add_argument("--project", required=True)
    pfd_add.add_argument("--severity", required=True,
                          choices=("info", "low", "medium", "high", "critical"))
    pfd_add.add_argument("--title", required=True)
    pfd_add.add_argument("--rule-id", default="",
                          help="Stable rule identifier. Defaults to "
                               "'manual:<slug-of-title>' or 'manual:<--slug>'.")
    pfd_add.add_argument("--slug", default="",
                          help="Slug to use when --rule-id is not given.")
    pfd_add.add_argument("--host", default="")
    pfd_add.add_argument("--url", default="")
    pfd_add.add_argument("--cwe", default="",
                          help="CWE id, e.g. CWE-79.")
    pfd_add.add_argument("--owasp", default="")
    pfd_add.add_argument("--description", default="")
    pfd_add.add_argument("--evidence", default="")
    pfd_add.add_argument("--payload", default="")
    pfd_add.add_argument("--remediation", default="")
    pfd_add.add_argument("--reference", default="",
                          help="References. Comma- or newline-separated.")

    pfd_ls = pfd_sub.add_parser(
        "list", help="List findings (filterable, tabular or JSON).",
        allow_abbrev=False,
    )
    pfd_ls.add_argument("--project", required=True)
    pfd_ls.add_argument("--severity", default="")
    pfd_ls.add_argument("--status", default="")
    pfd_ls.add_argument("--host", default="")
    pfd_ls.add_argument("--source", default="")
    pfd_ls.add_argument("--rule-id", default="")
    pfd_ls.add_argument("--limit", type=int, default=500)
    pfd_ls.add_argument("--format", choices=("table", "json"), default="table")

    pfd_tr = pfd_sub.add_parser(
        "triage",
        help="Update a finding's status. "
             "When --status=false_positive, also adds a suppression.",
        allow_abbrev=False,
    )
    pfd_tr.add_argument("--project", required=True)
    pfd_tr.add_argument("--id", type=int, required=True)
    pfd_tr.add_argument("--status", required=True,
                         choices=("open", "triaged", "false_positive", "fixed"))
    pfd_tr.add_argument("--reason", default="",
                         help="Reason recorded on the suppression "
                              "(false_positive only).")

    pfd_im = pfd_sub.add_parser(
        "import",
        help="Bulk-import findings from a JSON file via the bus.",
        allow_abbrev=False,
    )
    pfd_im.add_argument("--project", required=True)
    pfd_im.add_argument("--format", choices=("json",), default="json")
    pfd_im.add_argument("file", help="Path to a JSON file (list of findings "
                                       "or an object with a 'findings' array).")

    pfd_rp = pfd_sub.add_parser(
        "repro",
        help="Print a curl one-liner that re-fires the probe behind a finding.",
        allow_abbrev=False,
    )
    pfd_rp.add_argument("--project", required=True)
    pfd_rp.add_argument("--id", type=int, required=True)
    pfd_rp.add_argument("--format", choices=("curl", "json"), default="curl",
                          help="curl: single-line shell command (default); "
                               "json: full reproduction record with raw bytes.")

    pfd.set_defaults(func=cmd_finding)

    # ----- A.6: suppression management
    psu = sub.add_parser(
        "suppression",
        help="Manage finding suppressions (add, list, delete).",
        allow_abbrev=False,
    )
    psu_sub = psu.add_subparsers(
        dest="suppression_action", metavar="<action>", required=True,
    )

    psu_add = psu_sub.add_parser("add", help="Add a finding suppression.",
                                   allow_abbrev=False)
    psu_add.add_argument("--project", required=True)
    psu_add.add_argument("--rule-id", required=True)
    psu_add.add_argument("--host", default="",
                          help="Host glob (e.g. 'api.example.com' or "
                               "'*.example.com'). Empty = any host.")
    psu_add.add_argument("--url-pattern", default="",
                          help="Substring URL pattern. Empty = any URL.")
    psu_add.add_argument("--reason", default="")

    psu_ls = psu_sub.add_parser("list", help="List existing suppressions.",
                                  allow_abbrev=False)
    psu_ls.add_argument("--project", required=True)
    psu_ls.add_argument("--format", choices=("table", "json"), default="table")

    psu_del = psu_sub.add_parser("delete", help="Delete a suppression.",
                                   allow_abbrev=False)
    psu_del.add_argument("--project", required=True)
    psu_del.add_argument("--rule-id", required=True)
    psu_del.add_argument("--host", default="")
    psu_del.add_argument("--url-pattern", default="")

    psu.set_defaults(func=cmd_suppression)

    pf = sub.add_parser(
        "prefetch-firefox",
        help="Download Firefox into the cache for later offline use (no launch).",
        allow_abbrev=False,
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
    if getattr(args, "func", None) is None:
        # Bare `reqlore` (no subcommand). Print full help to stdout and
        # exit 0 — friendlier than argparse's default "the following
        # arguments are required" one-liner.
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        # Last-resort safety net: unexpected exceptions become a one-line
        # error instead of a traceback. Re-raise under REQLORE_VERBOSE=1
        # so developers can debug them.
        if os.environ.get("REQLORE_VERBOSE") == "1":
            raise
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

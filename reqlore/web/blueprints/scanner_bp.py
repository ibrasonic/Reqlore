"""Scanner UI: run a passive scan, browse findings, triage them."""
from __future__ import annotations

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for,
)

from ...scanner import (
    ActiveOptions, ActiveScanner, BUILTIN_ACTIVE_CHECKS, BUILTIN_RULES, Scanner,
)
from ...plugins import get_registry

bp = Blueprint("scanner", __name__)


@bp.route("/")
def index():
    sev = request.args.get("severity") or None
    status = request.args.get("status") or None
    host = request.args.get("host") or None
    findings = g.project.list_findings(severity=sev, status=status, host=host)
    summary = g.project.findings_summary()
    hosts = g.project.hosts()
    return render_template(
        "scanner/index.html",
        findings=findings, summary=summary, hosts=hosts,
        sev=sev or "", status=status or "", host=host or "",
        severities=("critical", "high", "medium", "low", "info"),
        statuses=("open", "triaged", "false_positive", "fixed"),
        active_checks=BUILTIN_ACTIVE_CHECKS,
    )


@bp.route("/run", methods=["POST"])
def run():
    try:
        limit = max(1, min(50_000, int(request.form.get("limit", "5000"))))
    except ValueError:
        limit = 5000
    extra = get_registry().active_rules()
    scanner = Scanner(rules=BUILTIN_RULES, extra_rules=extra)
    result = scanner.scan_project(g.project, limit=limit)
    flash(
        f"Passive scan complete: {result.rows_scanned} requests scanned, "
        f"{result.findings_added} findings recorded "
        f"(critical {result.by_severity['critical']}, "
        f"high {result.by_severity['high']}, "
        f"medium {result.by_severity['medium']}, "
        f"low {result.by_severity['low']}, "
        f"info {result.by_severity['info']}) "
        f"in {result.elapsed_ms} ms.",
        "ok",
    )
    return redirect(url_for(".index"))


@bp.route("/run-active", methods=["POST"])
def run_active():
    try:
        limit = max(1, min(2_000, int(request.form.get("limit", "20"))))
    except ValueError:
        limit = 20
    try:
        timeout = max(1.0, min(60.0, float(request.form.get("timeout", "10"))))
    except ValueError:
        timeout = 10.0
    try:
        delay = max(0, min(5000, int(request.form.get("delay", "0"))))
    except ValueError:
        delay = 0
    host = (request.form.get("host") or "").strip() or None
    enabled = request.form.getlist("checks") or None
    follow = request.form.get("follow") == "1"

    opts = ActiveOptions(
        max_requests_per_check=int(request.form.get("max_per_check") or 4),
        rate_delay_ms=delay, timeout_s=timeout,
        follow_redirects=follow, enabled_checks=enabled,
    )
    # Wire the running OAST receiver (if any) so oast-ssrf can callback-probe.
    oast = current_app.extensions.get("reqlore_oast")
    if oast is not None and getattr(oast, "is_running", lambda: False)():
        opts.oast = oast
    scanner = ActiveScanner()
    result = scanner.run_on_project(g.project, options=opts, host=host, limit=limit)
    flash(
        f"Active scan complete: {result.rows_scanned} requests probed, "
        f"{result.findings_added} findings recorded "
        f"(critical {result.by_severity['critical']}, "
        f"high {result.by_severity['high']}, "
        f"medium {result.by_severity['medium']}, "
        f"low {result.by_severity['low']}, "
        f"info {result.by_severity['info']}) "
        f"in {result.elapsed_ms} ms.",
        "ok" if result.findings_added == 0 else "warn",
    )
    return redirect(url_for(".index"))


@bp.route("/<int:fid>")
def show(fid: int):
    f = g.project.get_finding(fid)
    if not f:
        abort(404)
    return render_template("scanner/detail.html", f=f,
                           statuses=("open", "triaged", "false_positive", "fixed"))


@bp.route("/<int:fid>/status", methods=["POST"])
def set_status(fid: int):
    status = request.form.get("status", "open")
    try:
        g.project.set_finding_status(fid, status)
        flash(f"Finding {fid} marked '{status}'.", "ok")
    except ValueError as exc:
        flash(str(exc), "err")
    return redirect(url_for(".show", fid=fid))


@bp.route("/<int:fid>/delete", methods=["POST"])
def delete(fid: int):
    g.project.delete_finding(fid)
    flash(f"Finding {fid} deleted.", "ok")
    return redirect(url_for(".index"))

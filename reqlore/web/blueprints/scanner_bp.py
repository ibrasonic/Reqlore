"""Scanner UI: run a passive scan, browse findings, triage them."""
from __future__ import annotations

import re

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for,
)

from ...findings_bus import record_finding
from ...scanner import (
    ActiveOptions, ActiveScanner, BUILTIN_ACTIVE_CHECKS, BUILTIN_RULES, Scanner,
)
from ...scanner.rules import SEVERITIES
from ...plugins import get_registry

bp = Blueprint("scanner", __name__)


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    return _SLUG_RE.sub("-", (text or "").lower()).strip("-")[:60] or "finding"


# ----------------------------------------------- Active-scan UI metadata
#
# Five family groups + four presets. Order inside each group is just
# "what reads nicely top-to-bottom"; the scanner itself doesn't care.
# Anything not yet known (future builtin or plugin checks) lands in
# the "Other" group automatically — see _grouped_checks().

ACTIVE_CHECK_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Injection", (
        "xss-reflected", "xss-reflected-headers", "sqli-error",
        "ssti", "nosqli-mongo", "xxe-classic",
        "deserialisation-reflect",
    )),
    ("File / OS", (
        "path-traversal-lfi", "os-cmd-time",
        "forced-browsing",
    )),
    ("Auth & Logic", (
        "jwt-alg-none", "open-redirect", "prototype-pollution",
        "oauth-redirect-uri",
        "default-creds",
    )),
    ("API & CORS", (
        "graphql-introspection", "cors-misconfig-extended",
        "web-cache-deception",
        "graphql-active",
    )),
    ("SSRF / OAST", (
        "oast-ssrf",
        "http-smuggling",
    )),
    ("TLS & DNS", (
        "tls-active",
        "subdomain-takeover",
    )),
)

# A preset is a frozen set of check names. `custom` means "honour the
# per-check checkboxes the form posted"; the others override them.
ACTIVE_PRESETS: dict[str, frozenset[str] | None] = {
    "quick": frozenset({
        "xss-reflected", "sqli-error", "ssti",
        "jwt-alg-none", "open-redirect",
    }),
    # Standard = everything except OAST (which needs a running receiver).
    "standard": None,  # filled in below from BUILTIN_ACTIVE_CHECKS minus oast
    "full": None,      # filled in below from BUILTIN_ACTIVE_CHECKS
    "custom": None,    # sentinel: read posted checkboxes
}


def _all_check_names() -> frozenset[str]:
    return frozenset(c.name for c in BUILTIN_ACTIVE_CHECKS)


def _resolve_preset(preset: str, posted_checks: list[str]) -> list[str] | None:
    """Map preset → list of check names. Returns None to mean
    "use the scanner's full default set" (passed through as enabled_checks=None).
    """
    preset = (preset or "standard").lower().strip()
    if preset == "custom":
        # Only keep names that actually exist as builtins or plugins.
        return [n for n in posted_checks if n] or None
    if preset == "quick":
        return sorted(ACTIVE_PRESETS["quick"])
    if preset == "full":
        return None  # None ⇒ enable everything
    # standard (default): everything except oast
    return sorted(_all_check_names() - {"oast-ssrf", "http-smuggling",
                                          "default-creds"})


def _grouped_checks() -> list[dict]:
    """Map BUILTIN_ACTIVE_CHECKS into the family groups defined above,
    appending anything unknown to an "Other" group so future additions
    surface without a UI edit."""
    by_name = {c.name: c for c in BUILTIN_ACTIVE_CHECKS}
    seen: set[str] = set()
    out: list[dict] = []
    for label, names in ACTIVE_CHECK_GROUPS:
        members = []
        for n in names:
            if n in by_name:
                members.append(by_name[n])
                seen.add(n)
        if members:
            out.append({"label": label, "checks": members})
    leftover = [c for c in BUILTIN_ACTIVE_CHECKS if c.name not in seen]
    if leftover:
        out.append({"label": "Other", "checks": leftover})
    return out


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
        active="findings",
    )


@bp.route("/run", methods=["GET"])
def run_page():
    """Launchpad page: passive + active scan forms only."""
    return render_template(
        "scanner/run.html",
        hosts=g.project.hosts(),
        groups=_grouped_checks(),
        presets=("quick", "standard", "full", "custom"),
        default_preset="standard",
        active="run",
    )


@bp.route("/run", methods=["POST"])
def run():
    try:
        limit = max(1, min(50_000, int(request.form.get("limit", "5000"))))
    except ValueError:
        limit = 5000
    full = request.form.get("full") == "1"
    extra = get_registry().active_rules()
    scanner = Scanner(rules=BUILTIN_RULES, extra_rules=extra)
    result = scanner.scan_project(g.project, limit=limit, resume=not full)
    # B.5 — surface resume / deadline diagnostics so the operator knows when
    # the run was partial. We keep the main "ok" flash terse and put the
    # diagnostics on a separate "warning" flash so they're visually distinct.
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
    extras = []
    if result.rows_skipped_resume:
        extras.append(
            f"skipped {result.rows_skipped_resume} already-scanned rows "
            f"(tick 'Full re-scan' to force)"
        )
    if result.aborted_due_to_deadline:
        extras.append(
            f"aborted after {result.deadline_seconds:.0f}s deadline; "
            f"partial result written (last id {result.last_scanned_id})"
        )
    if extras:
        flash("Scan diagnostics: " + "; ".join(extras), "warning")
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
    enabled = _resolve_preset(
        request.form.get("preset", "standard"),
        request.form.getlist("checks"),
    )
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
    extra: list[str] = []
    if result.throttled_count:
        extra.append(f"throttled {result.throttled_count}")
    if result.skipped_out_of_scope:
        extra.append(f"out-of-scope {result.skipped_out_of_scope}")
    extra_str = (" [" + ", ".join(extra) + "]") if extra else ""
    flash(
        f"Active scan complete: {result.rows_scanned} requests probed, "
        f"{result.findings_added} findings recorded "
        f"(critical {result.by_severity['critical']}, "
        f"high {result.by_severity['high']}, "
        f"medium {result.by_severity['medium']}, "
        f"low {result.by_severity['low']}, "
        f"info {result.by_severity['info']}) "
        f"in {result.elapsed_ms} ms.{extra_str}",
        "ok" if result.findings_added == 0 else "warn",
    )
    return redirect(url_for(".index"))


@bp.route("/<int:fid>")
def show(fid: int):
    f = g.project.get_finding(fid)
    if not f:
        abort(404)
    return render_template("scanner/detail.html", f=f,
                           statuses=("open", "triaged", "false_positive", "fixed"),
                           active="findings")


@bp.route("/<int:fid>/status", methods=["POST"])
def set_status(fid: int):
    status = request.form.get("status", "open")
    try:
        g.project.set_finding_status(fid, status)
    except ValueError as exc:
        flash(str(exc), "err")
        return redirect(url_for(".show", fid=fid))
    if status == "false_positive":
        f = g.project.get_finding(fid)
        if f and f.get("rule_id"):
            g.project.add_finding_suppression(
                rule_id=f["rule_id"],
                host=f.get("host") or "",
                url_pattern=f.get("url") or "",
                reason=f"FP triage of finding #{fid}",
            )
            flash(
                f"Finding {fid} marked 'false_positive' and rule "
                f"'{f['rule_id']}' suppressed for this host/URL.",
                "ok",
            )
        else:
            flash(
                f"Finding {fid} marked 'false_positive'. "
                "No rule_id on this finding, so no suppression was created.",
                "warn",
            )
    else:
        flash(f"Finding {fid} marked '{status}'.", "ok")
    return redirect(url_for(".show", fid=fid))


@bp.route("/<int:fid>/delete", methods=["POST"])
def delete(fid: int):
    g.project.delete_finding(fid)
    flash(f"Finding {fid} deleted.", "ok")
    return redirect(url_for(".index"))


# ----------------------------------------------- A.3 manual findings UI

_OWASP_CATEGORIES = (
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery",
)


def _render_manual_form(form: dict, errors: list[str], request_id: int | None):
    return render_template(
        "scanner/manual.html",
        f=form, errors=errors,
        request_id=request_id,
        severities=SEVERITIES,
        owasp_categories=_OWASP_CATEGORIES,
        hosts=g.project.hosts(),
        active="findings",
    )


@bp.route("/manual", methods=["GET", "POST"])
def manual():
    """Operator-authored finding. Flows through the same write bus as the
    scanner so dedupe, suppression, rule_run accounting all apply."""
    pre_hid = request.args.get("request_id", type=int)
    if request.method == "GET":
        form = {
            "title": "",
            "severity": "medium",
            "rule_id_slug": "",
            "cwe": "",
            "owasp": "",
            "host": "",
            "url": "",
            "description": "",
            "evidence": "",
            "payload": "",
            "remediation": "",
            "references": "",
            "request_id": str(pre_hid) if pre_hid else "",
        }
        if pre_hid:
            row = g.project.get_history(pre_hid)
            if row:
                form["host"] = row.host or ""
                form["url"] = row.url or ""
        return _render_manual_form(form, errors=[], request_id=pre_hid)

    form = {k: (request.form.get(k) or "").strip() for k in (
        "title", "severity", "rule_id_slug", "cwe", "owasp", "host", "url",
        "description", "evidence", "payload", "remediation", "references",
        "request_id",
    )}
    errors: list[str] = []
    if not form["title"]:
        errors.append("Title is required.")
    if form["severity"] not in SEVERITIES:
        errors.append(f"Severity must be one of {', '.join(SEVERITIES)}.")
    if form["cwe"] and not re.match(r"^CWE-\d+$", form["cwe"]):
        errors.append("CWE must be empty or look like 'CWE-79'.")

    slug = _slugify(form["rule_id_slug"] or form["title"])
    rule_id = f"manual:{slug}"

    request_id: int | None = None
    if form["request_id"]:
        try:
            request_id = int(form["request_id"])
            if not g.project.get_history(request_id):
                errors.append(f"No history row with id {request_id}.")
                request_id = None
        except ValueError:
            errors.append("Originating request id must be an integer.")

    if errors:
        return _render_manual_form(form, errors=errors, request_id=request_id)

    refs = [r.strip() for r in form["references"].splitlines() if r.strip()]
    fid = record_finding(
        g.project, source="manual", rule_id=rule_id,
        severity=form["severity"], title=form["title"],
        description=form["description"], remediation=form["remediation"],
        references=refs,
        cwe=form["cwe"], owasp=form["owasp"],
        host=form["host"], url=form["url"],
        request_id=request_id,
        evidence=form["evidence"], payload=form["payload"],
    )
    if fid is None:
        flash(
            f"Finding suppressed by an existing suppression for {rule_id}.",
            "warn",
        )
        return redirect(url_for(".index"))
    flash(f"Manual finding #{fid} recorded ({rule_id}).", "ok")
    return redirect(url_for(".show", fid=fid))


# ----------------------------------------------- A.5 triage / suppressions UI


@bp.route("/suppressions", methods=["GET"])
def suppressions():
    return render_template(
        "scanner/suppressions.html",
        suppressions=g.project.list_finding_suppressions(),
        active="suppressions",
    )


@bp.route("/suppressions/delete", methods=["POST"])
def suppressions_delete():
    rule_id = (request.form.get("rule_id") or "").strip()
    host = (request.form.get("host") or "").strip()
    url_pattern = (request.form.get("url_pattern") or "").strip()
    if not rule_id:
        flash("rule_id is required to delete a suppression.", "err")
        return redirect(url_for(".suppressions"))
    g.project.delete_finding_suppression(
        rule_id=rule_id, host=host, url_pattern=url_pattern,
    )
    flash(
        f"Suppression removed for {rule_id} "
        f"(host={host or '*'}, url={url_pattern or '*'}).",
        "ok",
    )
    return redirect(url_for(".suppressions"))


# ----------------------------------------------- B.3 coverage view


@bp.route("/coverage", methods=["GET"])
def coverage():
    """Per-rule and per-(rule, host) fire/evaluate telemetry."""
    rule_filter = (request.args.get("rule_id") or "").strip()
    host_filter = (request.args.get("host") or "").strip()
    summary = g.project.rule_run_summary()
    by_host = g.project.rule_run_summary_by_host()
    reasons_raw = g.project.rule_run_reasons(
        rule_id=rule_filter, host=host_filter,
    )
    if rule_filter:
        summary = [r for r in summary if rule_filter in r["rule_id"]]
        by_host = [r for r in by_host if rule_filter in r["rule_id"]]
    if host_filter:
        by_host = [r for r in by_host if host_filter in r["host"]]
    # Pre-bucket reasons by (rule_id, host) so the template can render each
    # row's "why didn't it fire?" inline without nested loops in Jinja.
    reasons_by_pair: dict[tuple[str, str], list[dict]] = {}
    for r in reasons_raw:
        reasons_by_pair.setdefault((r["rule_id"], r["host"]), []).append(r)
    return render_template(
        "scanner/coverage.html",
        summary=summary,
        by_host=by_host,
        reasons_by_pair=reasons_by_pair,
        rule_filter=rule_filter,
        host_filter=host_filter,
        active="coverage",
    )

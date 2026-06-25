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
        "xss-stored",
        "xss-dom",
    )),
    ("File / OS", (
        "path-traversal-lfi", "os-cmd-time",
        "forced-browsing",
    )),
    ("Auth & Logic", (
        "jwt-alg-none", "open-redirect", "prototype-pollution",
        "oauth-redirect-uri",
        "default-creds",
        "idor-alt-identity",
        "race-condition",
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
    ("Cloud", (
        "cloud-blob-misconfig",
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
                                          "default-creds",
                                          "race-condition",
                                          "xss-dom"})


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
    confidence = request.args.get("confidence") or None
    waf_tagged = request.args.get("waf_tagged") == "1"
    findings = g.project.list_findings(
        severity=sev, status=status, host=host,
        confidence=confidence, waf_tagged=waf_tagged,
    )
    # Phase 4 — inline occurrence preview (first 3 URLs) for any
    # consolidated finding so the user can spot whether the
    # ``× N`` pill represents a single endpoint or a scatter.
    for f in findings:
        if (f.get("occurrence_count") or 1) > 1:
            try:
                f["occurrence_preview"] = g.project.list_finding_occurrences(
                    f["id"], limit=3,
                )
            except Exception:
                f["occurrence_preview"] = []
        else:
            f["occurrence_preview"] = []
    summary = g.project.findings_summary()
    hosts = g.project.hosts()
    # Active filter chips — the template renders these as a row of
    # text labels under the filter form so the user can see what's
    # in effect (and click each to drop it).
    active_filters: list[dict] = []
    if sev:
        active_filters.append({"name": "severity", "value": sev,
                                "label": f"Severity: {sev}"})
    if status:
        active_filters.append({"name": "status", "value": status,
                                "label": f"Status: {status}"})
    if host:
        active_filters.append({"name": "host", "value": host,
                                "label": f"Host: {host}"})
    if confidence:
        active_filters.append({"name": "confidence", "value": confidence,
                                "label": f"Confidence: {confidence}"})
    if waf_tagged:
        active_filters.append({"name": "waf_tagged", "value": "1",
                                "label": "Behind WAF"})
    return render_template(
        "scanner/index.html",
        findings=findings, summary=summary, hosts=hosts,
        sev=sev or "", status=status or "", host=host or "",
        confidence=confidence or "", waf_tagged=waf_tagged,
        active_filters=active_filters,
        severities=("critical", "high", "medium", "low", "info"),
        statuses=("open", "triaged", "false_positive", "fixed"),
        confidences=("tentative", "firm", "certain"),
        active="findings",
    )


@bp.route("/run", methods=["GET"])
def run_page():
    """Launchpad page: passive + active scan forms only."""
    # Phase 4 — surface a dry-run estimate so the operator knows
    # roughly how many requests an active scan will send before
    # they click. The estimate is intentionally conservative: it
    # uses the ``max_probes_per_check`` cap and assumes the form's
    # default row limit (20) and default check count (all 28 builtin
    # checks gated by the light+medium tiers). The active scanner's
    # actual count is bounded by these caps so the displayed figure
    # is an upper bound, never an underestimate.
    try:
        history_count = int(g.project.history_count())
    except Exception:  # noqa: BLE001 — defensive in test fakes
        history_count = 0
    from ...scanner.presets import (
        DEFAULT_PRESET as _DEFAULT_SCAN_PRESET,
        all_summaries as _scan_preset_summaries,
    )
    # Phase 10 — surface available macros so the auth fieldset can
    # render a selector. The macro store is the same plain
    # ``project_state`` table used by the macros blueprint; we walk
    # ``macro:next_id`` and load each entry's name.
    macros: list[dict] = []
    try:
        from ...macros import Macro as _Macro
        next_id = int(g.project.get_state("macro:next_id", "1") or "1")
        for i in range(1, next_id):
            blob = g.project.get_state(f"macro:{i}", "")
            if not blob:
                continue
            try:
                m = _Macro.from_json(blob)
            except Exception:  # noqa: BLE001 — corrupt entry; skip
                continue
            macros.append({"id": i, "name": m.name or f"macro #{i}"})
    except Exception:  # noqa: BLE001 — fake projects in tests
        macros = []
    return render_template(
        "scanner/run.html",
        hosts=g.project.hosts(),
        groups=_grouped_checks(),
        presets=("quick", "standard", "full", "custom"),
        default_preset="standard",
        scan_presets=_scan_preset_summaries(),
        default_scan_preset=_DEFAULT_SCAN_PRESET,
        auth_macros=macros,
        history_count=history_count,
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
    # Phase 9 — scan preset selects a baseline ActiveOptions; the
    # explicit form fields below then override its individual knobs
    # so an operator can still hand-tune from a preset starting
    # point. ``custom`` (or any unknown name) leaves the baseline at
    # the dataclass defaults.
    from ...scanner.presets import (
        DEFAULT_PRESET as _DEFAULT_SCAN_PRESET,
        PRESET_NAMES as _SCAN_PRESET_NAMES,
        apply_preset as _apply_scan_preset,
    )
    scan_preset_name = (request.form.get("scan_preset")
                         or _DEFAULT_SCAN_PRESET).strip().lower()
    if scan_preset_name not in _SCAN_PRESET_NAMES:
        scan_preset_name = _DEFAULT_SCAN_PRESET
    try:
        preset_opts = _apply_scan_preset(scan_preset_name)
    except ValueError:
        preset_opts = ActiveOptions()

    try:
        limit = max(1, min(2_000, int(request.form.get("limit", "20"))))
    except ValueError:
        limit = 20
    try:
        timeout = max(1.0, min(60.0, float(request.form.get("timeout", "10"))))
    except ValueError:
        timeout = 10.0
    raw_delay = request.form.get("delay")
    if raw_delay is None or raw_delay == "":
        delay = preset_opts.rate_delay_ms
    else:
        try:
            delay = max(0, min(5000, int(raw_delay)))
        except ValueError:
            delay = preset_opts.rate_delay_ms
    host = (request.form.get("host") or "").strip() or None
    enabled = _resolve_preset(
        request.form.get("preset", "standard"),
        request.form.getlist("checks"),
    )
    # Per-checkbox redirect-follow overrides the preset baseline.
    raw_follow = request.form.get("follow")
    follow = (raw_follow == "1") if raw_follow is not None else preset_opts.follow_redirects

    # Phase 2 — intensity tier checkboxes. Light + Medium are checked
    # by default; Intrusive is opt-in AND requires an explicit confirm
    # so an operator can't accidentally fire weaponish probes (sleep,
    # race, stored-XSS) against an out-of-scope host.
    # Phase 9 — when no tier checkboxes are posted, fall back to the
    # scan preset's baseline instead of an unconditional light+medium.
    levels: set[str] = set()
    posted_tier_field = False
    for tier_form, tier_name in (("intensity_light", "light"),
                                  ("intensity_medium", "medium"),
                                  ("intensity_intrusive", "intrusive")):
        v = request.form.get(tier_form)
        if v is not None:
            posted_tier_field = True
            if v == "1":
                levels.add(tier_name)
    if not levels:
        if posted_tier_field:
            levels = {"light", "medium"}
        else:
            levels = set(preset_opts.intensity_levels)
    if "intrusive" in levels:
        if request.form.get("confirm_intrusive") != "yes":
            flash(
                "Intrusive scans require explicit authorisation. "
                "Tick the confirmation box to run intrusive checks.",
                "warning",
            )
            return redirect(url_for(".run_page"))
        # Rate-delay floor for intrusive scans — keeps the host from
        # being hammered when sleep-based / race probes are in play.
        if delay < 100:
            delay = 100

    raw_max = request.form.get("max_per_check")
    try:
        max_per_check_val = (
            int(raw_max) if raw_max not in (None, "")
            else preset_opts.max_requests_per_check
        )
    except ValueError:
        max_per_check_val = preset_opts.max_requests_per_check

    try:
        opts = ActiveOptions(
            max_requests_per_check=max_per_check_val,
            max_probes_per_check=preset_opts.max_probes_per_check,
            max_probes_per_target=preset_opts.max_probes_per_target,
            max_insertion_points_per_row=(
                preset_opts.max_insertion_points_per_row
            ),
            rate_delay_ms=delay, timeout_s=timeout,
            follow_redirects=follow, enabled_checks=enabled,
            intensity_levels=frozenset(levels),
            wall_clock_seconds=preset_opts.wall_clock_seconds,
            allow_smuggling_probes=preset_opts.allow_smuggling_probes,
            allow_dom_xss_probes=preset_opts.allow_dom_xss_probes,
            # Phase 13 — inherit the JS analysis mode from the preset;
            # the form's "skip JS analysis" checkbox forces it off
            # below as an explicit operator override.
            js_analysis_mode=(
                "off"
                if request.form.get("skip_js_analysis") == "1"
                else preset_opts.js_analysis_mode
            ),
        )
    except ValueError as exc:
        # Defensive: unknown tier name from a forged form post.
        flash(f"Invalid intensity selection: {exc}", "warning")
        return redirect(url_for(".run_page"))
    # Wire the running OAST receiver (if any) so oast-ssrf can callback-probe.
    oast = current_app.extensions.get("reqlore_oast")
    if oast is not None and getattr(oast, "is_running", lambda: False)():
        opts.oast = oast
    # Phase 10 — wire the auth session if the form asked for it. We
    # build it here (not in ActiveOptions) so we can surface a flash
    # error if the requested macro is missing without aborting the
    # whole scan.
    if request.form.get("auth_enabled") == "1":
        from ...scanner.auth_session import (
            AuthCredentials,
            AuthSessionConfig,
            build_auth_session_from_state,
        )
        try:
            macro_id = int(request.form.get("auth_macro_id", "0"))
        except ValueError:
            macro_id = 0
        if macro_id < 1:
            flash(
                "Authenticated scan was requested but no macro id "
                "was selected; running unauthenticated.",
                "warning",
            )
        else:
            cred_user = (request.form.get("auth_username") or "").strip()
            cred_pass = request.form.get("auth_password") or ""
            creds = None
            if cred_user or cred_pass:
                creds = AuthCredentials(
                    {"username": cred_user, "password": cred_pass}
                )
            cookie_names_raw = (
                request.form.get("auth_session_cookie_names") or ""
            ).strip()
            cookie_names = tuple(
                n.strip() for n in cookie_names_raw.split(",") if n.strip()
            )
            csrf_names_raw = (
                request.form.get("auth_csrf_token_names") or ""
            ).strip()
            csrf_names = tuple(
                n.strip() for n in csrf_names_raw.split(",") if n.strip()
            )
            validity_url = (
                request.form.get("auth_validity_url") or ""
            ).strip() or None
            try:
                revalidate_every = max(0, min(10_000, int(
                    request.form.get("auth_revalidate_every") or "25"
                )))
            except ValueError:
                revalidate_every = 25
            try:
                cfg = AuthSessionConfig(
                    macro_id=macro_id,
                    credentials=creds,
                    session_cookie_names=cookie_names,
                    csrf_token_names=csrf_names,
                    validity_probe_url=validity_url,
                    revalidate_every_n_probes=revalidate_every,
                )
                opts.auth_session = build_auth_session_from_state(
                    g.project, cfg,
                )
            except (LookupError, ValueError) as exc:
                flash(
                    f"Authenticated scan disabled: {exc}",
                    "warning",
                )
    scanner = ActiveScanner()
    result = scanner.run_on_project(g.project, options=opts, host=host, limit=limit)
    extra: list[str] = []
    if result.throttled_count:
        extra.append(f"throttled {result.throttled_count}")
    if result.skipped_out_of_scope:
        extra.append(f"out-of-scope {result.skipped_out_of_scope}")
    if result.skipped_by_intensity:
        extra.append(f"skipped-by-intensity {result.skipped_by_intensity}")
    if result.aborted_due_to_deadline:
        cap = result.deadline_seconds or 0
        extra.append(
            f"aborted at {cap:.0f}s deadline "
            f"(skipped {result.rows_skipped_deadline} rows)"
        )
    if result.auth_macro_runs:
        extra.append(
            f"auth: macro x{result.auth_macro_runs}"
            + (f", recoveries {result.session_recoveries}"
                if result.session_recoveries else "")
            + (f", csrf-refetch {result.csrf_token_refetches}"
                if result.csrf_token_refetches else "")
        )
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
    from ...a11y import build_find_multi
    evidence = f.get("evidence") or ""
    payload = f.get("payload") or ""
    # One shared Find form drives highlights across both Evidence and
    # Payload panes. Each pane is marked up in place via its own anchor
    # namespace ({prefix}-mN) so the jump list links into the original
    # panes — no synthetic merged duplicate.
    find_body = build_find_multi(
        [("evidence", "evidence", evidence),
         ("payload", "payload", payload)],
        form_prefix="body",
        q=request.args.get("body_find", ""),
        regex=request.args.get("body_re") == "1",
        region_label="finding body",
        action=url_for(".show", fid=fid),
    ) if (evidence or payload) else None
    panes_by_prefix = ({p["prefix"]: p for p in find_body["panes"]}
                       if find_body else {})
    # Phase 3 — show recent occurrences alongside the canonical finding.
    try:
        occurrences = g.project.list_finding_occurrences(fid, limit=200)
    except Exception:
        occurrences = []
    # Render epoch timestamps as ISO-8601 UTC for the detail table; the
    # raw integer remains in ``ts`` as a fallback.
    import datetime as _dt
    for occ in occurrences:
        try:
            occ["ts_iso"] = _dt.datetime.fromtimestamp(
                int(occ.get("ts") or 0), tz=_dt.timezone.utc,
            ).strftime("%Y-%m-%d %H:%M:%SZ")
        except Exception:
            occ["ts_iso"] = ""
    return render_template("scanner/detail.html", f=f,
                           statuses=("open", "triaged", "false_positive", "fixed"),
                           active="findings",
                           find_body=find_body,
                           find_evidence=panes_by_prefix.get("evidence"),
                           find_payload=panes_by_prefix.get("payload"),
                           occurrences=occurrences)


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
    try:
        sugg = g.project.suppression_suggestions(threshold=5, limit=50)
    except Exception:
        sugg = []
    return render_template(
        "scanner/suppressions.html",
        suppressions=g.project.list_finding_suppressions(),
        suppression_suggestions=sugg,
        active="suppressions",
    )


@bp.route("/suppressions/add", methods=["POST"])
def suppressions_add():
    rule_id = (request.form.get("rule_id") or "").strip()
    host = (request.form.get("host") or "").strip()
    url_pattern = (request.form.get("url_pattern") or "").strip()
    reason = (request.form.get("reason") or "").strip()
    if not rule_id:
        flash("rule_id is required to add a suppression.", "err")
        return redirect(url_for(".suppressions"))
    try:
        g.project.add_finding_suppression(
            rule_id=rule_id, host=host, url_pattern=url_pattern,
            reason=reason or "manual: bulk suppression",
        )
    except ValueError as exc:
        flash(str(exc), "err")
        return redirect(url_for(".suppressions"))
    flash(
        f"Suppression added for {rule_id} "
        f"(host={host or '*'}, url={url_pattern or '*'}).",
        "ok",
    )
    return redirect(url_for(".suppressions"))


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


# --------------------------------------------- Phase 12 priority preview


@bp.route("/priority-preview", methods=["GET"])
def priority_preview():
    """Read-only preview of the audit prioritisation queue.

    Surfaces the top-N (default 20) history rows scored using the
    Phase 12 attack-surface + interest model. Operators use this to
    sanity-check the ordering before launching an active scan with
    ``prioritise=True``. The route is GET-only and never sends a
    probe; it just runs the pure-function scoring across the
    current ``list_history`` snapshot.
    """
    from ...scanner.prioritise import (
        ScoringWeights, prioritise_queue,
    )
    try:
        limit = int(request.args.get("limit", "200"))
    except ValueError:
        limit = 200
    limit = max(10, min(limit, 1000))
    try:
        top_n = int(request.args.get("top", "20"))
    except ValueError:
        top_n = 20
    top_n = max(1, min(top_n, 200))
    try:
        sw = float(request.args.get("surface_weight", "0.8"))
        iw = float(request.args.get("interest_weight", "0.2"))
    except ValueError:
        sw, iw = 0.8, 0.2
    host = (request.args.get("host") or "").strip() or None
    try:
        rows = g.project.list_history(limit=limit, host=host)
    except Exception:  # noqa: BLE001 — fake projects in tests
        rows = []
    try:
        weights = ScoringWeights(surface=sw, interest=iw)
    except ValueError as exc:
        flash(f"Invalid weights: {exc}", "err")
        weights = ScoringWeights()
    try:
        ranked = prioritise_queue(rows, weights=weights)
    except Exception:  # noqa: BLE001 — defensive: never crash on a hostile blob
        ranked = []
    preview = []
    for r, s in ranked[:top_n]:
        preview.append({
            "id": getattr(r, "id", 0),
            "method": getattr(r, "method", ""),
            "host": getattr(r, "host", ""),
            "url": getattr(r, "url", ""),
            "status": getattr(r, "status", 0),
            "score": round(s.score, 4),
            "surface_novelty": s.surface_novelty,
            "surface_total": s.surface_total,
            "interest": round(s.interest, 4),
            "method_score": s.method_score,
            "content_type_score": s.content_type_score,
            "auth_score": s.auth_score,
        })
    return render_template(
        "scanner/priority_preview.html",
        rows=preview,
        considered=len(ranked),
        limit=limit,
        top_n=top_n,
        surface_weight=weights.surface,
        interest_weight=weights.interest,
        host_filter=host or "",
        active="priority",
    )


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
    # Phase 4 — last-fire timestamps are kept as a sidecar map so the
    # shape of summary/by_host remains the legacy dict the rest of
    # the codebase asserts dict-equal against.
    try:
        last_fire = g.project.rule_last_fire_map()
    except AttributeError:
        last_fire = {}
    try:
        last_fire_by_host = g.project.rule_last_fire_map_by_host()
    except AttributeError:
        last_fire_by_host = {}
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
        last_fire=last_fire,
        last_fire_by_host=last_fire_by_host,
        rule_filter=rule_filter,
        host_filter=host_filter,
        active="coverage",
    )


# ----------------------------------------------- Phase 1 live passive scan


def _live_worker():
    """Return the app-bound LiveScanWorker, or ``None`` if no proxy is
    wired (CLI-only mode). All /scanner/live routes degrade gracefully
    when the worker is missing."""
    return current_app.extensions.get("reqlore_live_worker")


def _empty_snapshot() -> dict:
    """Default snapshot shape for when no worker is wired. Keep this
    keyed the same way as :meth:`LiveScanWorker.snapshot` so the
    template never has to guard against missing keys."""
    return {
        "alive": False,
        "queue_depth": 0,
        "backlog": 0,
        "scanned": 0,
        "findings_added": 0,
        "overflowed": 0,
        "backlog_drained": 0,
        "dropped_unrecoverable": 0,
        "skipped_out_of_scope": 0,
        "errors": 0,
        "scans_per_minute": 0.0,
        "throughput_buckets": [0, 0, 0, 0, 0, 0],
        "last_error": "",
        "last_error_ts": 0,
    }


def _backlog_count_safe() -> int:
    """Read the durable backlog count, defending against test fakes
    that haven't been migrated to expose it."""
    try:
        return int(g.project.backlog_count())
    except Exception:  # noqa: BLE001 - never let the panel poll fail
        return 0


@bp.route("/live", methods=["GET"])
def live():
    """Status panel for the live passive scanner: queue depth,
    durable-backlog depth, throughput, last 5 findings, on/off
    toggle."""
    w = _live_worker()
    snap = w.snapshot() if w is not None else _empty_snapshot()
    # Even with no worker the backlog table may still have rows from
    # a previous run; surface that so the operator can clear it.
    snap["backlog"] = _backlog_count_safe()
    enabled = g.project.get_state("live_scan:enabled", "0") == "1"
    try:
        recent = g.project.list_findings(limit=5)
    except TypeError:
        # Older storage signature without `limit` kwarg.
        recent = (g.project.list_findings() or [])[:5]
    return render_template(
        "scanner/live.html",
        snapshot=snap,
        enabled=enabled,
        recent=recent,
        active="live",
    )


@bp.route("/live.json", methods=["GET"])
def live_json():
    """Polling endpoint for the status panel. Returns the worker
    snapshot + the 5 most recent finding ids/titles so the UI can
    refresh without a full page render."""
    from flask import jsonify
    w = _live_worker()
    snap = w.snapshot() if w is not None else _empty_snapshot()
    snap["backlog"] = _backlog_count_safe()
    try:
        recent = g.project.list_findings(limit=5)
    except TypeError:
        recent = (g.project.list_findings() or [])[:5]
    snap["recent"] = [
        {
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "host": f.get("host"),
        }
        for f in (recent or [])
    ]
    snap["enabled"] = g.project.get_state("live_scan:enabled", "0") == "1"
    return jsonify(snap)


@bp.route("/live/toggle", methods=["POST"])
def live_toggle():
    """Start or stop the live worker. Submit-button form, never an
    on-change auto-submit (SC 3.2.5 Change on Request).

    The action is keyed off the posted ``action`` value — ``start`` or
    ``stop`` — so the button label is unambiguous in the rendered
    HTML, and a refresh-resubmit won't accidentally toggle the
    opposite state.
    """
    action = (request.form.get("action") or "").strip().lower()
    w = _live_worker()
    if w is None:
        flash("Live scanner is not available in this mode.", "warn")
        return redirect(url_for(".live"))
    if action == "start":
        w.start()
        g.project.set_state("live_scan:enabled", "1")
        flash("Live passive scanning started.", "ok")
    elif action == "stop":
        w.stop(timeout=1.0)
        g.project.set_state("live_scan:enabled", "0")
        flash("Live passive scanning stopped.", "ok")
    else:
        flash("Unknown action.", "err")
    return redirect(url_for(".live"))


@bp.route("/live/catchup", methods=["POST"])
def live_catchup():
    """Prioritise the durable backlog on the next idle tick.

    The worker keeps fresh proxy traffic flowing while it also
    catches up on parked rows. Pressing this button signals the
    worker to use a 10x batch on its next backlog drain so a visible
    backlog clears faster. Starting the worker first if it is not
    yet running is intentional — the user's intent is "make
    progress", so we honour it without a second click.
    """
    w = _live_worker()
    if w is None:
        flash("Live scanner is not available in this mode.", "warn")
        return redirect(url_for(".live"))
    if not w.is_alive():
        w.start()
        g.project.set_state("live_scan:enabled", "1")
    w.request_catchup()
    flash("Catching up on the live-scan backlog.", "ok")
    return redirect(url_for(".live"))


@bp.route("/live/clear-backlog", methods=["POST"])
def live_clear_backlog():
    """Drop every row currently parked in the durable backlog.

    Destructive: the cleared rows will not be re-scanned. We require
    an explicit ``confirm=yes`` form field so the action can never
    fire from a stray CSRF replay alone, and we tell the user how
    many rows were removed so they can verify the result.
    """
    if (request.form.get("confirm") or "").strip().lower() != "yes":
        flash("Backlog clear requires explicit confirmation.", "warn")
        return redirect(url_for(".live"))
    try:
        n = int(g.project.backlog_clear())
    except AttributeError:
        # Older storage fakes without backlog support.
        n = 0
    flash(f"Cleared {n} row(s) from the live-scan backlog.", "ok")
    return redirect(url_for(".live"))

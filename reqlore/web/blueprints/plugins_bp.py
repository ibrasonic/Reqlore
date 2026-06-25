"""Plugins UI: list discovered plugins, reload, toggle, optional hot-watch.

Phase 16 adds standalone *Plugin Apps*: each has its own settings
form, Run/Stop buttons, live log, results table and findings hook.
Routes under ``/plugins/app/<slug>/`` drive the per-plugin UI; a
small JSON poll endpoint feeds the live updates without WebSocket
plumbing.
"""
from __future__ import annotations

from flask import (
    Blueprint, abort, current_app, flash, g, jsonify, redirect,
    render_template, request, url_for,
)

from ...plugins import get_registry
from ...plugins_sdk import parse_seed_request

bp = Blueprint("plugins", __name__)


# ---------------------------------------------------------------- helpers

# Field names that the Send-to-plugin chooser will pre-fill from the
# parsed seed request when the plugin app declares a field with the
# same name. Keep this small and predictable so plugin authors don't
# have to memorise a long table.
_SEED_PREFILL_FIELDS = ("url", "method", "host")


def _read_seed_history_id(value: str | None) -> int | None:
    """Parse a from_history / _seed_history_id form or query value.
    Returns the integer id when it is a positive whole number and the
    history row exists in the current project; ``None`` otherwise."""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw or not raw.lstrip("-").isdigit():
        return None
    try:
        hid = int(raw)
    except (TypeError, ValueError):
        return None
    if hid <= 0:
        return None
    try:
        row = g.project.get_history(hid)
    except Exception:
        return None
    return hid if row is not None else None


def _runner():
    """Return the per-app :class:`PluginRunner` or ``None`` when the
    host process never wired one up (older tests, partial fakes)."""
    return current_app.extensions.get("reqlore_plugin_runner")


def _resolve_app(slug: str):
    """Look up a plugin app by slug. ``abort(404)`` when it is unknown,
    disabled, or the owning plugin has an import error."""
    reg = get_registry()
    app = reg.get_plugin_app(slug)
    if app is None:
        abort(404)
    return app


# ---------------------------------------------------------------- index

@bp.route("/")
def index():
    reg = get_registry()
    return render_template(
        "plugins/index.html",
        plugins=reg.list(),
        dirs=[str(d) for d in reg.dirs],
        plugin_apps=reg.active_plugin_apps(),
    )


@bp.route("/reload", methods=["POST"])
def reload_plugins():
    reg = get_registry()
    plugs = reg.discover()
    ok = sum(1 for p in plugs if not p.error)
    err = sum(1 for p in plugs if p.error)
    flash(f"Discovered {len(plugs)} plugin(s): {ok} loaded, {err} with errors.",
          "ok" if err == 0 else "warn")
    return redirect(url_for(".index"))


@bp.route("/<name>/toggle", methods=["POST"])
def toggle(name: str):
    reg = get_registry()
    if reg.get(name) is None:
        flash(f"No plugin named '{name}'.", "err")
    else:
        new_state = reg.toggle(name)
        flash(f"Plugin '{name}' {'enabled' if new_state else 'disabled'}.", "ok")
    return redirect(url_for(".index"))


@bp.route("/watch", methods=["POST"])
def watch():
    reg = get_registry()
    on = request.form.get("on") == "1"
    if on:
        started = reg.start_watch()
        if started:
            g.project.set_state("plugin_watch", "1")
            flash("Hot reload enabled — changes in the plugin folder reload automatically.", "ok")
        else:
            flash("Hot reload requires the 'watchdog' package (pip install watchdog).", "warn")
    else:
        reg.stop_watch()
        g.project.set_state("plugin_watch", "0")
        flash("Hot reload disabled.", "ok")
    return redirect(url_for(".index"))


# ============================================================ Phase 16
#
# Plugin App routes. Every state-changing endpoint is a POST so it is
# protected by the global CSRF before_request hook in web/__init__.py.


@bp.route("/app/<slug>/")
def app_detail(slug: str):
    app = _resolve_app(slug)
    runner = _runner()
    latest = g.project.latest_plugin_run(app.slug)
    # Optional Send-to-plugin seed.
    seed = None
    seed_overrides: dict[str, str] = {}
    hid = _read_seed_history_id(request.args.get("from_history"))
    if hid is not None:
        row = g.project.get_history(hid)
        if row is not None:
            parsed = parse_seed_request(hid, row.req_blob)
            seed = {
                "history_id": hid,
                "method": parsed.method,
                "url": parsed.url,
                "host": parsed.host,
                "path": parsed.path,
            }
            # Only override defaults for fields the plugin actually
            # declares; never invent settings the plugin didn't ask for.
            field_names = {f.name for f in app.fields}
            mapping = {"url": parsed.url, "method": parsed.method,
                       "host": parsed.host}
            for fname in _SEED_PREFILL_FIELDS:
                if fname in field_names and mapping[fname]:
                    seed_overrides[fname] = mapping[fname]
    return render_template(
        "plugins/app_detail.html",
        app=app,
        fields=app.field_dicts(),
        latest=latest,
        is_running=bool(runner and runner.is_running(app.slug)),
        seed=seed,
        seed_overrides=seed_overrides,
    )


@bp.route("/app/<slug>/run", methods=["POST"])
def app_run(slug: str):
    app = _resolve_app(slug)
    runner = _runner()
    if runner is None:
        flash("Plugin runner is not available in this process.", "err")
        return redirect(url_for(".app_detail", slug=app.slug))
    # Re-build the form dict; checkboxes that are unchecked omit the
    # key entirely, which BoolField interprets as False.
    settings = {k: request.form.get(k) for k in request.form.keys()
                if k not in ("_csrf", "_seed_history_id")}
    seed_hid = _read_seed_history_id(request.form.get("_seed_history_id"))
    try:
        run_id = runner.start(app, settings, seed_history_id=seed_hid)
    except ValueError as exc:
        flash(f"Invalid settings: {exc}", "err")
        return redirect(url_for(".app_detail", slug=app.slug))
    except RuntimeError as exc:
        flash(str(exc), "warn")
        return redirect(url_for(".app_detail", slug=app.slug))
    except Exception as exc:
        flash(f"Could not start plugin: {exc}", "err")
        return redirect(url_for(".app_detail", slug=app.slug))
    flash(f"Started plugin '{app.name}' (run #{run_id}).", "ok")
    return redirect(url_for(".app_run_detail", slug=app.slug, rid=run_id))


@bp.route("/app/<slug>/stop", methods=["POST"])
def app_stop(slug: str):
    app = _resolve_app(slug)
    runner = _runner()
    if runner is None:
        flash("Plugin runner is not available.", "err")
        return redirect(url_for(".app_detail", slug=app.slug))
    signalled = runner.stop(app.slug)
    if signalled:
        flash(f"Stop signal sent to '{app.name}'.", "ok")
    else:
        flash(f"No active run for '{app.name}'.", "warn")
    rid = request.form.get("rid")
    if rid and rid.isdigit():
        return redirect(url_for(".app_run_detail", slug=app.slug, rid=int(rid)))
    return redirect(url_for(".app_detail", slug=app.slug))


@bp.route("/app/<slug>/runs/")
def app_runs(slug: str):
    app = _resolve_app(slug)
    runs = g.project.list_plugin_runs(slug=app.slug, limit=200)
    return render_template(
        "plugins/app_runs.html", app=app, runs=runs,
    )


@bp.route("/app/<slug>/runs/<int:rid>/")
def app_run_detail(slug: str, rid: int):
    app = _resolve_app(slug)
    run = g.project.get_plugin_run(rid)
    if not run or run.get("slug") != app.slug:
        abort(404)
    runner = _runner()
    return render_template(
        "plugins/app_run.html",
        app=app,
        run=run,
        is_running=bool(runner and runner.is_running(app.slug)
                        and (runner._active.get(app.slug).run_id == rid
                             if runner._active.get(app.slug) else False)),
    )


@bp.route("/app/<slug>/runs/<int:rid>/poll")
def app_run_poll(slug: str, rid: int):
    """JSON snapshot for incremental polling. Optional ``?since=N``
    parameter trims log bytes and result rows below the cursor."""
    app = _resolve_app(slug)
    run = g.project.get_plugin_run(rid)
    if not run or run.get("slug") != app.slug:
        return jsonify({"error": "not found"}), 404
    try:
        since_log = int(request.args.get("log_offset") or 0)
    except (TypeError, ValueError):
        since_log = 0
    try:
        since_results = int(request.args.get("results_offset") or 0)
    except (TypeError, ValueError):
        since_results = 0
    log_text = run.get("log") or ""
    log_tail = log_text[since_log:] if 0 <= since_log <= len(log_text) else log_text
    results = run.get("results") or []
    new_results = results[since_results:] if 0 <= since_results <= len(results) else results
    runner = _runner()
    active = bool(runner and runner.is_running(app.slug)
                  and runner._active.get(app.slug)
                  and runner._active[app.slug].run_id == rid)
    return jsonify({
        "status": run.get("status", ""),
        "progress_done": run.get("progress_done", 0),
        "progress_total": run.get("progress_total", 0),
        "progress_msg": run.get("progress_msg", ""),
        "finished_at": run.get("finished_at"),
        "error": run.get("error", ""),
        "log_tail": log_tail,
        "log_offset": len(log_text),
        "new_results": new_results,
        "results_offset": len(results),
        "is_running": active,
    })


# ============================================================ Send-to-plugin
#
# A single chooser page used by every "Send to plugin app..." entry in
# History, the Proxy intercept queue, and any future surface. Picking a
# plugin app here navigates to its detail page with ``?from_history=N``
# so the operator can review/edit settings before pressing Run.


@bp.route("/send/")
def send_to_chooser():
    """List active plugin apps for the operator to pick one.

    Requires ``?from_history=<hid>``. ``404`` when the history row is
    missing so a stale bookmark doesn't silently lose the request.
    """
    hid = _read_seed_history_id(request.args.get("from_history"))
    if hid is None:
        abort(404)
    row = g.project.get_history(hid)  # _read_seed_history_id guarantees this exists
    seed = parse_seed_request(hid, row.req_blob)
    reg = get_registry()
    apps = reg.active_plugin_apps()
    return render_template(
        "plugins/send_to.html",
        apps=apps,
        seed={
            "history_id": hid,
            "method": seed.method,
            "url": seed.url,
            "host": seed.host,
        },
    )

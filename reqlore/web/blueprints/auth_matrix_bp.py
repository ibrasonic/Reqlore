"""Auth Matrix blueprint.

Routes under ``/auth-matrix/``:

* ``/``                            — landing: counters + last runs.
* ``/sessions/``                   — list saved sessions.
* ``/sessions/new``                — manual or seeded session create.
* ``/sessions/<sid>/edit``         — payload / kind / name edit.
* ``/sessions/<sid>/toggle``       — flip active flag (POST).
* ``/sessions/<sid>/delete``       — remove (POST).
* ``/runs/``                       — list runs (active + shadow).
* ``/runs/new``                    — wizard: pick history rows × sessions.
* ``/runs/<rid>/``                 — live matrix view with polling.
* ``/runs/<rid>/poll``             — JSON snapshot for polling.
* ``/runs/<rid>/stop``             — cooperative cancel (POST).
* ``/runs/<rid>/delete``           — remove run + cells (POST).
* ``/runs/<rid>/cell/<cid>/``      — per-cell diff page.
* ``/runs/<rid>/cell/<cid>/dismiss`` — flag cell as dismissed (POST).
* ``/shadow/``                     — passive worker status.
* ``/shadow/toggle``               — start / stop the shadow worker (POST).
"""
from __future__ import annotations

from typing import Any

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from ...auth_matrix import (
    SESSION_KINDS,
    AuthMatrixRunner,
    AuthShadowWorker,
    RunOptions,
    capture_session_from_history,
    decrypt_payload,
    derive_or_load_key,
    encrypt_payload,
)

bp = Blueprint("auth_matrix", __name__)


# -------- helpers ---------------------------------------------------

def _runner() -> AuthMatrixRunner | None:
    return current_app.extensions.get("reqlore_auth_matrix_runner")


def _shadow() -> AuthShadowWorker | None:
    return current_app.extensions.get("reqlore_auth_matrix_shadow")


def _read_seed_history_id(value: str | None) -> int | None:
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


def _read_int_list(values: list[str]) -> list[int]:
    out: list[int] = []
    for v in values or []:
        try:
            iv = int(v)
        except (TypeError, ValueError):
            continue
        if iv > 0 and iv not in out:
            out.append(iv)
    return out


def _hydrate_session_for_form(row: dict, key) -> dict:
    payload = ""
    try:
        payload = decrypt_payload(key, row.get("payload_blob") or b"").decode(
            "utf-8", errors="replace")
    except Exception:
        payload = ""
    return {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "payload": payload,
        "source": row.get("source") or "",
        "source_hid": row.get("source_hid"),
        "created_at": row.get("created_at") or 0,
        "last_used_at": row.get("last_used_at") or 0,
        "active": bool(row.get("active", True)),
    }


# -------- landing ---------------------------------------------------

@bp.route("/")
def index():
    sessions = g.project.auth_matrix_list_sessions()
    runs = g.project.auth_matrix_list_runs(limit=20)
    shadow = _shadow()
    return render_template(
        "auth_matrix/index.html",
        sessions=sessions,
        runs=runs,
        shadow=shadow.snapshot() if shadow is not None else None,
        runner_available=_runner() is not None,
    )


# -------- sessions --------------------------------------------------

@bp.route("/sessions/")
def sessions_list():
    sessions = g.project.auth_matrix_list_sessions()
    return render_template(
        "auth_matrix/sessions_list.html",
        sessions=sessions,
    )


@bp.route("/sessions/new", methods=["GET", "POST"])
def sessions_new():
    seed_hid = _read_seed_history_id(
        request.args.get("from_history") or request.form.get("from_history"))
    seed_headers: list[tuple[str, str]] = []
    seed_url = ""
    seed_method = ""
    if seed_hid is not None:
        row = g.project.get_history(seed_hid)
        if row is not None:
            from ...plugins_sdk import parse_seed_request
            sr = parse_seed_request(seed_hid, row.req_blob)
            seed_headers = list(sr.headers)
            seed_url = sr.url
            seed_method = sr.method

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        kind = (request.form.get("kind") or "").strip()
        payload = request.form.get("payload") or ""
        if not name:
            flash("Session name is required.", "warn")
        elif kind not in SESSION_KINDS:
            flash(f"Unknown session kind: {kind!r}.", "warn")
        else:
            try:
                key = derive_or_load_key(g.project)
                blob = encrypt_payload(key, payload.encode("utf-8"))
                sid = g.project.auth_matrix_create_session(
                    name=name, kind=kind, payload_blob=blob,
                    source=("history" if seed_hid else "manual"),
                    source_hid=seed_hid,
                )
                flash(f"Session #{sid} saved.", "ok")
                return redirect(url_for(".sessions_list"))
            except Exception as exc:
                flash(f"Could not save session: {exc}", "warn")

    suggestion: dict[str, str] = {}
    if seed_hid is not None:
        try:
            captured = capture_session_from_history(
                name="captured",
                history_id=seed_hid,
                headers=seed_headers,
            )
            suggestion = {
                "kind": captured.kind,
                "payload": captured.payload,
            }
        except Exception:
            suggestion = {}

    return render_template(
        "auth_matrix/sessions_new.html",
        kinds=SESSION_KINDS,
        seed_hid=seed_hid,
        seed_url=seed_url,
        seed_method=seed_method,
        seed_headers=seed_headers,
        suggestion=suggestion,
    )


@bp.route("/sessions/<int:sid>/edit", methods=["GET", "POST"])
def sessions_edit(sid: int):
    row = g.project.auth_matrix_get_session(sid)
    if row is None:
        abort(404)
    key = derive_or_load_key(g.project)
    form = _hydrate_session_for_form(row, key)
    if request.method == "POST":
        name = (request.form.get("name") or "").strip() or form["name"]
        kind = (request.form.get("kind") or "").strip() or form["kind"]
        payload = request.form.get("payload")
        if kind not in SESSION_KINDS:
            flash(f"Unknown session kind: {kind!r}.", "warn")
        else:
            try:
                kwargs: dict[str, Any] = {"name": name, "kind": kind}
                if payload is not None:
                    kwargs["payload_blob"] = encrypt_payload(
                        key, payload.encode("utf-8"))
                g.project.auth_matrix_update_session(sid, **kwargs)
                flash("Session updated.", "ok")
                return redirect(url_for(".sessions_list"))
            except Exception as exc:
                flash(f"Could not update session: {exc}", "warn")
    return render_template(
        "auth_matrix/sessions_edit.html",
        kinds=SESSION_KINDS,
        session=form,
    )


@bp.route("/sessions/<int:sid>/toggle", methods=["POST"])
def sessions_toggle(sid: int):
    row = g.project.auth_matrix_get_session(sid)
    if row is None:
        abort(404)
    new_state = not bool(row["active"])
    g.project.auth_matrix_update_session(sid, active=new_state)
    flash(
        f"Session '{row['name']}' is now {'active' if new_state else 'inactive'}.",
        "ok",
    )
    return redirect(url_for(".sessions_list"))


@bp.route("/sessions/<int:sid>/delete", methods=["POST"])
def sessions_delete(sid: int):
    row = g.project.auth_matrix_get_session(sid)
    if row is None:
        abort(404)
    g.project.auth_matrix_delete_session(sid)
    flash(f"Session '{row['name']}' deleted.", "ok")
    return redirect(url_for(".sessions_list"))


# -------- runs ------------------------------------------------------

@bp.route("/runs/")
def runs_list():
    runs = g.project.auth_matrix_list_runs(limit=200)
    return render_template("auth_matrix/runs_list.html", runs=runs)


@bp.route("/runs/new", methods=["GET", "POST"])
def runs_new():
    sessions = g.project.auth_matrix_list_sessions()
    seed_hid = _read_seed_history_id(
        request.args.get("from_history") or request.form.get("from_history"))
    if request.method == "POST":
        runner = _runner()
        if runner is None:
            flash("Auth Matrix runner is not available.", "warn")
            return redirect(url_for(".index"))
        history_ids_raw = (request.form.get("history_ids") or "").strip()
        history_ids: list[int] = []
        for chunk in history_ids_raw.replace(",", " ").split():
            try:
                hid = int(chunk)
            except (TypeError, ValueError):
                continue
            if hid > 0 and hid not in history_ids:
                history_ids.append(hid)
        if seed_hid is not None and seed_hid not in history_ids:
            history_ids.insert(0, seed_hid)
        compare_ids = _read_int_list(request.form.getlist("compare_session_id"))
        baseline_raw = (request.form.get("baseline_session_id") or "").strip()
        baseline_id: int | None = None
        if baseline_raw.lstrip("-").isdigit():
            iv = int(baseline_raw)
            baseline_id = iv if iv > 0 else None
        label = (request.form.get("label") or "").strip()
        try:
            sim_floor = int(request.form.get("similarity_floor") or "80")
        except (TypeError, ValueError):
            sim_floor = 80
        try:
            priv_floor = int(request.form.get("privileged_floor") or "90")
        except (TypeError, ValueError):
            priv_floor = 90
        record_findings = bool(request.form.get("record_findings"))
        verify_tls = bool(request.form.get("verify_tls"))
        follow_redirects = bool(request.form.get("follow_redirects"))
        if not history_ids:
            flash("Pick at least one history row id to replay.", "warn")
        elif not compare_ids:
            flash("Pick at least one comparison session.", "warn")
        else:
            opts = RunOptions(
                similarity_floor=sim_floor,
                privileged_floor=priv_floor,
                record_findings=record_findings,
                verify_tls=verify_tls,
                follow_redirects=follow_redirects,
            )
            try:
                rid = runner.start(
                    label=label,
                    history_ids=history_ids,
                    compare_session_ids=compare_ids,
                    baseline_session_id=baseline_id,
                    options=opts,
                )
                flash(f"Auth Matrix run #{rid} started.", "ok")
                return redirect(url_for(".runs_detail", rid=rid))
            except Exception as exc:
                flash(f"Could not start run: {exc}", "warn")
    return render_template(
        "auth_matrix/runs_new.html",
        sessions=sessions,
        seed_hid=seed_hid,
    )


@bp.route("/runs/<int:rid>/")
def runs_detail(rid: int):
    run = g.project.auth_matrix_get_run(rid)
    if run is None:
        abort(404)
    cells = g.project.auth_matrix_list_cells(rid)
    # Build matrix: rows = history ids in run.history_ids order
    # (falling back to encountered order), cols = compare session ids.
    sessions_by_id = {
        int(s["id"]): s for s in g.project.auth_matrix_list_sessions()
    }
    compare_ids: list[int] = list(run.get("compare_session_ids") or [])
    if not compare_ids:
        # Shadow run: derive compare session list from cells.
        seen: list[int] = []
        for c in cells:
            sid = int(c["session_id"])
            if sid not in seen:
                seen.append(sid)
        compare_ids = seen
    history_ids: list[int] = list(run.get("history_ids") or [])
    if not history_ids:
        seen_h: list[int] = []
        for c in cells:
            hid = int(c["history_id"])
            if hid not in seen_h:
                seen_h.append(hid)
        history_ids = seen_h
    # Index cells by (hid, sid) so the template can quickly look them up.
    cells_index: dict[tuple[int, int], dict] = {}
    for c in cells:
        cells_index[(int(c["history_id"]), int(c["session_id"]))] = c
    is_running = run["status"] in ("pending", "running")
    return render_template(
        "auth_matrix/runs_detail.html",
        run=run,
        cells=cells,
        cells_index=cells_index,
        sessions_by_id=sessions_by_id,
        compare_ids=compare_ids,
        history_ids=history_ids,
        is_running=is_running,
    )


@bp.route("/runs/<int:rid>/poll")
def runs_poll(rid: int):
    run = g.project.auth_matrix_get_run(rid)
    if run is None:
        abort(404)
    counts = g.project.auth_matrix_cell_counts(rid)
    return jsonify({
        "status": run["status"],
        "progress_done": run["progress_done"],
        "progress_total": run["progress_total"],
        "progress_msg": run["progress_msg"],
        "error": run["error"],
        "verdict_counts": counts,
        "is_running": run["status"] in ("pending", "running"),
    })


@bp.route("/runs/<int:rid>/stop", methods=["POST"])
def runs_stop(rid: int):
    runner = _runner()
    if runner is None:
        flash("Auth Matrix runner is not available.", "warn")
    elif runner.stop(rid):
        flash(f"Stop signal sent to run #{rid}.", "ok")
    else:
        flash(f"Run #{rid} was not active.", "warn")
    return redirect(url_for(".runs_detail", rid=rid))


@bp.route("/runs/<int:rid>/delete", methods=["POST"])
def runs_delete(rid: int):
    run = g.project.auth_matrix_get_run(rid)
    if run is None:
        abort(404)
    g.project.auth_matrix_delete_run(rid)
    flash(f"Run #{rid} deleted.", "ok")
    return redirect(url_for(".runs_list"))


@bp.route("/runs/<int:rid>/cell/<int:cid>/")
def cell_detail(rid: int, cid: int):
    run = g.project.auth_matrix_get_run(rid)
    cell = g.project.auth_matrix_get_cell(cid)
    if run is None or cell is None or int(cell["run_id"]) != int(rid):
        abort(404)
    sessions_by_id = {
        int(s["id"]): s for s in g.project.auth_matrix_list_sessions()
    }
    history_row = None
    try:
        history_row = g.project.get_history(int(cell["history_id"]))
    except Exception:
        history_row = None

    def _decode(b: bytes) -> str:
        if not b:
            return ""
        try:
            return bytes(b).decode("utf-8", errors="replace")
        except Exception:
            return ""

    cell_view = dict(cell)
    cell_view["request_text"] = _decode(cell.get("request_blob") or b"")
    cell_view["response_text"] = _decode(cell.get("response_blob") or b"")
    cell_view["baseline_response_text"] = _decode(
        cell.get("baseline_response_blob") or b"")
    return render_template(
        "auth_matrix/cell_detail.html",
        run=run,
        cell=cell_view,
        session=sessions_by_id.get(int(cell["session_id"])),
        history_row=history_row,
    )


@bp.route("/runs/<int:rid>/cell/<int:cid>/dismiss", methods=["POST"])
def cell_dismiss(rid: int, cid: int):
    cell = g.project.auth_matrix_get_cell(cid)
    if cell is None or int(cell["run_id"]) != int(rid):
        abort(404)
    g.project.auth_matrix_update_cell_verdict(cid, verdict="dismissed")
    flash(f"Cell #{cid} dismissed.", "ok")
    return redirect(url_for(".runs_detail", rid=rid))


# -------- shadow ----------------------------------------------------

@bp.route("/shadow/")
def shadow_status():
    shadow = _shadow()
    return render_template(
        "auth_matrix/shadow.html",
        shadow=shadow.snapshot() if shadow is not None else None,
        available=shadow is not None,
        enabled=bool(g.project.get_state("auth_matrix:shadow_enabled", "")),
    )


@bp.route("/shadow/toggle", methods=["POST"])
def shadow_toggle():
    shadow = _shadow()
    action = (request.form.get("action") or "").strip().lower()
    if shadow is None:
        flash("Auth Matrix shadow worker is not available.", "warn")
        return redirect(url_for(".shadow_status"))
    if action == "start":
        shadow.start()
        g.project.set_state("auth_matrix:shadow_enabled", "1")
        flash("Shadow Auth Matrix started.", "ok")
    elif action == "stop":
        shadow.stop(timeout=1.0)
        g.project.set_state("auth_matrix:shadow_enabled", "0")
        flash("Shadow Auth Matrix stopped.", "ok")
    return redirect(url_for(".shadow_status"))


# -------- send-to (history row entry point) --------------------------

@bp.route("/from-history/<int:hid>", methods=["GET", "POST"])
def from_history(hid: int):
    """Entry point used by the History row-actions menu. Lets the
    operator save a session, append the row to a new active run, or
    open the new-run wizard."""
    row = g.project.get_history(hid)
    if row is None:
        abort(404)
    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        if action == "save_session":
            return redirect(url_for(".sessions_new", from_history=hid))
        if action == "new_run":
            return redirect(url_for(".runs_new", from_history=hid))
    return render_template(
        "auth_matrix/from_history.html",
        hid=hid,
        url=row.url, host=row.host, method=row.method, status=row.status,
    )

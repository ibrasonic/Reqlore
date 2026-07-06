"""Session-handling macros UI."""
from __future__ import annotations

import json

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ...macros import Macro
from ...macros import run as run_macro
from .._prg import PRGCache

bp = Blueprint("macros", __name__)

_run_cache = PRGCache()


@bp.route("/")
def index():
    macros = _list(g.project)
    return render_template("macros/index.html", macros=macros)


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip() or "macro"
        body = (request.form.get("definition") or "").strip()
        if not body:
            body = _example_json(name)
        try:
            macro = Macro.from_json(body)
        except json.JSONDecodeError as exc:
            flash(f"Definition is not valid JSON: {exc}", "err")
            return render_template("macros/new.html", name=name, definition=body)
        macro.name = name
        mid = _save(g.project, macro)
        flash(f"Saved macro #{mid}.", "ok")
        return redirect(url_for(".show", mid=mid))
    return render_template("macros/new.html", name="", definition=_example_json(""))


@bp.route("/<int:mid>", methods=["GET", "POST"])
def show(mid: int):
    macro = _load(g.project, mid)
    if macro is None:
        abort(404)
    last_run = None
    if request.method == "POST":
        if request.form.get("action") == "save":
            body = (request.form.get("definition") or "").strip()
            try:
                new_macro = Macro.from_json(body)
            except json.JSONDecodeError as exc:
                flash(f"Definition is not valid JSON: {exc}", "err")
                return render_template("macros/show.html", mid=mid,
                                        macro=macro, definition=body,
                                        last_run=None, find_def=None)
            new_macro.name = macro.name
            _save(g.project, new_macro, mid=mid)
            flash("Saved.", "ok")
            return redirect(url_for(".show", mid=mid))
        if request.form.get("action") == "run":
            last_run = run_macro(macro)
            flash(f"Ran {len(last_run.steps)} step(s) in {last_run.elapsed_ms} ms.",
                  "ok" if not any(s.error for s in last_run.steps) else "warn")
            tok_new = _run_cache.put(last_run)
            return redirect(url_for(".show", mid=mid, t=tok_new))
    tok = request.args.get("t")
    if tok:
        last_run = _run_cache.get(tok)
    definition = macro.to_json()
    from ...a11y import build_find_context
    find_def = build_find_context(
        definition, prefix="def",
        q=request.args.get("def_find", ""),
        regex=request.args.get("def_re") == "1",
        region_label="definition", action=url_for(".show", mid=mid),
    )
    return render_template("macros/show.html", mid=mid, macro=macro,
                            definition=definition, last_run=last_run,
                            find_def=find_def)


@bp.route("/<int:mid>/delete", methods=["POST"])
def delete(mid: int):
    g.project.set_state(f"macro:{mid}", "")
    flash(f"Macro #{mid} cleared.", "ok")
    return redirect(url_for(".index"))


# ---- storage ----

def _save(project, macro: Macro, *, mid: int | None = None) -> int:
    if mid is None:
        mid = int(project.get_state("macro:next_id", "1") or "1")
        project.set_state("macro:next_id", str(mid + 1))
    project.set_state(f"macro:{mid}", macro.to_json())
    return mid


def _load(project, mid: int) -> Macro | None:
    blob = project.get_state(f"macro:{mid}", "")
    if not blob:
        return None
    try:
        return Macro.from_json(blob)
    except Exception:
        return None


def _list(project) -> list[dict]:
    try:
        next_id = int(project.get_state("macro:next_id", "1") or "1")
    except ValueError:
        next_id = 1
    out: list[dict] = []
    for i in range(1, next_id):
        m = _load(project, i)
        if m is None:
            continue
        out.append({"id": i, "name": m.name, "n_steps": len(m.steps)})
    out.sort(key=lambda r: r["id"], reverse=True)
    return out


def _example_json(name: str) -> str:
    return json.dumps({
        "name": name or "login-then-call",
        "base_headers": {"User-Agent": "Reqlore-Macro/1.0"},
        "variables": {},
        "steps": [
            {
                "name": "login",
                "method": "POST",
                "url": "https://example.com/login",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=alice&password=changeme",
                "capture": {
                    "session": {"source": "header", "name": "Set-Cookie"},
                    "csrf": {"source": "regex", "where": "body",
                              "pattern": "csrf_token=([A-Za-z0-9]+)"}
                }
            },
            {
                "name": "use-session",
                "method": "POST",
                "url": "https://example.com/account/update",
                "headers": {"Cookie": "{{session}}",
                             "X-CSRF": "{{csrf}}"},
                "body": "name=Alice",
                "capture": {}
            }
        ],
    }, indent=2)

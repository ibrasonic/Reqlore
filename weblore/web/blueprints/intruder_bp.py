"""Intruder UI."""
from __future__ import annotations

from flask import (
    Blueprint, abort, flash, g, redirect, render_template, request, url_for,
)

from ...intruder import (
    AttackRunner, DEFAULT_MARKER, COMMON_PASSWORDS,
    find_positions, iterate, payloads_brute, payloads_from_text, payloads_numbers,
    PROCESSORS, register,
)

bp = Blueprint("intruder", __name__)


ATTACK_TYPES = [
    ("sniper", "Sniper — one position at a time (single payload set)"),
    ("battering", "Battering Ram — same payload in every position"),
    ("pitchfork", "Pitchfork — N sets advance in lockstep"),
    ("clusterbomb", "Cluster Bomb — every combination (cartesian)"),
]


@bp.route("/")
def index():
    attacks = g.project.list_intruder()
    return render_template("intruder/index.html", attacks=attacks)


@bp.route("/new", methods=["GET", "POST"])
def new():
    form = {
        "name": "",
        "attack_type": "sniper",
        "engine": "httpx",
        "url": "http://127.0.0.1/",
        "template": (
            f"GET /?q={DEFAULT_MARKER}admin{DEFAULT_MARKER} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nUser-Agent: weblore\r\nAccept: */*\r\n\r\n"
        ),
        "marker": DEFAULT_MARKER,
        "concurrency": "4",
        "delay_ms": "0",
        "max_requests": "1000",
        "processors": "",
        "grep": "",
        "payloads_text": "admin\nroot\nguest\ntest\nuser",
        "payloads_set2": "",
        "payloads_set3": "",
        "payloads_set4": "",
        "source": "text",
        "num_start": "0",
        "num_end": "100",
        "num_step": "1",
        "brute_alphabet": "abc",
        "brute_min": "1",
        "brute_max": "3",
    }
    error = ""
    # Pre-fill the request template from a History row when arriving via
    # "Send to Intruder" from another panel (Proxy queue, History, etc.).
    if request.method == "GET":
        hid = request.args.get("from_history")
        if hid:
            try:
                row = g.project.get_history(int(hid))
            except ValueError:
                row = None
            if row:
                form["url"] = row.url
                form["template"] = row.req_blob.decode(
                    "latin-1", errors="replace").replace("\r\n", "\n")
                form["name"] = f"From history #{row.id} — {row.method} {row.url}"
    if request.method == "POST":
        for k in form:
            if k in request.form:
                form[k] = request.form[k]

        template = form["template"].replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")
        marker = form["marker"] or DEFAULT_MARKER
        positions = find_positions(template, marker)
        if not positions:
            error = (f"No markers found. Wrap insertion points with {marker} "
                     f"(e.g. {marker}payload{marker}).")
        else:
            payload_sets = _collect_payload_sets(form)
            if not payload_sets or not payload_sets[0]:
                error = "Payload set is empty."
            else:
                options = {
                    "concurrency": int(form["concurrency"] or 4),
                    "delay_ms": int(form["delay_ms"] or 0),
                    "max_requests": int(form["max_requests"] or 1000),
                    "processors": [p.strip() for p in (form["processors"] or "").split(",") if p.strip()],
                    "grep": [g for g in (form["grep"] or "").splitlines() if g.strip()],
                }
                aid = g.project.create_intruder(
                    name=form["name"] or "Attack",
                    attack_type=form["attack_type"],
                    template=template,
                    positions=positions,
                    payloads=payload_sets,
                    options=options,
                    url=form["url"],
                    engine=form["engine"],
                )
                flash(f"Created attack #{aid}.", "ok")
                return redirect(url_for("intruder.detail", aid=aid))
    return render_template(
        "intruder/new.html", form=form, attack_types=ATTACK_TYPES,
        processors=list(PROCESSORS.keys()), error=error, marker=DEFAULT_MARKER,
    )


def _collect_payload_sets(form: dict) -> list[list[str]]:
    src = form.get("source", "text")
    if src == "numbers":
        return [payloads_numbers(int(form["num_start"]), int(form["num_end"]),
                                  int(form["num_step"]))]
    if src == "brute":
        # cap brute force to avoid runaway clusterbombs in the UI
        return [list(_capped(payloads_brute(form["brute_alphabet"],
                                              int(form["brute_min"]),
                                              int(form["brute_max"])), 50_000))]
    if src == "common_pw":
        return [COMMON_PASSWORDS]
    # 'text' — up to 4 sets for pitchfork/clusterbomb
    sets: list[list[str]] = []
    for key in ("payloads_text", "payloads_set2", "payloads_set3", "payloads_set4"):
        s = (form.get(key) or "").strip()
        if s:
            sets.append(payloads_from_text(s))
    if form["attack_type"] in ("sniper", "battering"):
        return sets[:1]
    return sets


def _capped(gen, n: int) -> list[str]:
    out: list[str] = []
    for x in gen:
        out.append(x)
        if len(out) >= n:
            break
    return out


@bp.route("/<int:aid>")
def detail(aid: int):
    attack = g.project.get_intruder(aid)
    if not attack:
        abort(404)
    sort = request.args.get("sort", "seq")
    desc = request.args.get("desc") == "1"
    results = g.project.list_intruder_results(aid, sort=sort, desc=desc)
    return render_template(
        "intruder/detail.html", attack=attack, results=results,
        sort=sort, desc=desc,
    )


@bp.route("/<int:aid>/start", methods=["POST"])
def start(aid: int):
    attack = g.project.get_intruder(aid)
    if not attack:
        abort(404)
    runner = AttackRunner(g.project, aid)
    register(runner)
    runner.start()
    flash("Attack started.", "ok")
    return redirect(url_for("intruder.detail", aid=aid))


@bp.route("/<int:aid>/cancel", methods=["POST"])
def cancel(aid: int):
    from ...intruder import get_runner
    r = get_runner(aid)
    if r:
        r.cancel()
        flash("Attack cancelled.", "ok")
    else:
        flash("Attack not running.", "warn")
    return redirect(url_for("intruder.detail", aid=aid))


@bp.route("/<int:aid>/delete", methods=["POST"])
def delete(aid: int):
    g.project.delete_intruder(aid)
    flash("Attack deleted.", "ok")
    return redirect(url_for("intruder.index"))

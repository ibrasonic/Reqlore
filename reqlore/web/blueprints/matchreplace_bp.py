"""Match & Replace UI."""
from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ... import _safe_regex

bp = Blueprint("matchreplace", __name__)


WHERE_CHOICES = [
    ("req_header", "Request headers"),
    ("req_body", "Request body"),
    ("resp_header", "Response headers"),
    ("resp_body", "Response body"),
]


# ---- Quick presets -------------------------------------------------------
#
# Each preset is a small bundle of Match & Replace rules. Applying a preset
# inserts those rules tagged with a sentinel comment (``__preset:<slug>__``)
# so they can be located and removed later without touching the schema.
PRESETS = [
    {
        "slug": "reveal-hidden",
        "title": "Reveal hidden form fields",
        "description": (
            "Convert <input type=\"hidden\"> elements to type=\"text\" so "
            "you can see and edit the values in your browser."
        ),
        "rules": [
            {
                "where": "resp_body", "is_regex": True,
                "pattern": r"type=([\"']?)hidden\1",
                "replacement": r"type=\1text\1",
            },
        ],
    },
    {
        "slug": "unlock-inputs",
        "title": "Strip readonly, disabled, and maxlength",
        "description": (
            "Remove client-side input restrictions so you can submit "
            "values the form would normally block."
        ),
        "rules": [
            {
                "where": "resp_body", "is_regex": True,
                "pattern": r"\sreadonly(?:=(?:\"[^\"]*\"|'[^']*'|[^\s>]+))?",
                "replacement": "",
            },
            {
                "where": "resp_body", "is_regex": True,
                "pattern": r"\sdisabled(?:=(?:\"[^\"]*\"|'[^']*'|[^\s>]+))?",
                "replacement": "",
            },
            {
                "where": "resp_body", "is_regex": True,
                "pattern": r"\smaxlength=(?:\"[^\"]*\"|'[^']*'|[^\s>]+)",
                "replacement": "",
            },
        ],
    },
    {
        "slug": "disable-csp",
        "title": "Disable Content Security Policy",
        "description": (
            "Remove Content-Security-Policy and CSP-Report-Only response "
            "headers so you can run your own scripts and see what the "
            "policy was hiding."
        ),
        "rules": [
            {
                "where": "resp_header", "is_regex": True,
                "pattern": r"(?im)^Content-Security-Policy(?:-Report-Only)?:.*$",
                "replacement": "",
            },
        ],
    },
    {
        "slug": "disable-xfo",
        "title": "Allow framing (remove X-Frame-Options)",
        "description": (
            "Remove X-Frame-Options so you can demonstrate clickjacking "
            "by loading the page inside an iframe."
        ),
        "rules": [
            {
                "where": "resp_header", "is_regex": True,
                "pattern": r"(?im)^X-Frame-Options:.*$",
                "replacement": "",
            },
        ],
    },
    {
        "slug": "cookies-not-httponly",
        "title": "Strip HttpOnly from cookies",
        "description": (
            "Remove the HttpOnly flag from Set-Cookie response headers so "
            "browser JavaScript can read session cookies during testing."
        ),
        "rules": [
            {
                "where": "resp_header", "is_regex": True,
                "pattern": r"(?i);\s*HttpOnly",
                "replacement": "",
            },
        ],
    },
]

PRESET_MAP = {p["slug"]: p for p in PRESETS}
_PRESET_PREFIX = "__preset:"


def _preset_comment(slug: str, title: str) -> str:
    return f"{_PRESET_PREFIX}{slug}__ {title}"


def _parse_preset_slug(comment: str) -> str:
    """Return the preset slug stored in ``comment`` or '' if not a preset."""
    if not comment.startswith(_PRESET_PREFIX):
        return ""
    rest = comment[len(_PRESET_PREFIX):]
    end = rest.find("__")
    if end < 0:
        return ""
    return rest[:end]


def _active_presets(rules: list[dict]) -> list[dict]:
    """Group preset-tagged rules by ``(slug, host_regex)``."""
    counts: dict[tuple[str, str], int] = {}
    for r in rules:
        slug = _parse_preset_slug(r.get("comment", ""))
        if not slug or slug not in PRESET_MAP:
            continue
        key = (slug, r.get("host_regex", ""))
        counts[key] = counts.get(key, 0) + 1
    out = []
    for (slug, host), n in counts.items():
        out.append({
            "slug": slug,
            "host": host,
            "title": PRESET_MAP[slug]["title"],
            "count": n,
        })
    out.sort(key=lambda x: (x["host"], x["title"]))
    return out


@bp.route("/", methods=["GET"])
def index():
    rules = g.project.list_mr()
    return render_template(
        "matchreplace/index.html",
        rules=rules,
        where_choices=WHERE_CHOICES,
        presets=PRESETS,
        active_presets=_active_presets(rules),
    )


@bp.route("/preset/apply", methods=["POST"])
def preset_apply():
    host_regex = request.form.get("host_regex", "").strip()
    selected = request.form.getlist("preset")
    if not host_regex:
        flash("Choose a host filter before applying presets.", "err")
        return redirect(url_for("matchreplace.index"))
    if not _safe_regex.is_valid_pattern(host_regex):
        flash("Host filter is not a valid regular expression.", "err")
        return redirect(url_for("matchreplace.index"))
    if not (host_regex.startswith("^") or "$" in host_regex):
        flash(
            "Heads up: host filter is not anchored. Add ^ at the start "
            "and $ at the end to avoid matching attacker-controlled "
            "subdomains like evil-example.com.attacker.tld.",
            "warn",
        )
    if not selected:
        flash("No presets selected.", "err")
        return redirect(url_for("matchreplace.index"))
    added = 0
    for slug in selected:
        preset = PRESET_MAP.get(slug)
        if preset is None:
            continue
        comment = _preset_comment(slug, preset["title"])
        for rule in preset["rules"]:
            g.project.add_mr(
                where=rule["where"],
                pattern=rule["pattern"],
                replacement=rule["replacement"],
                is_regex=bool(rule["is_regex"]),
                host_regex=host_regex,
                comment=comment,
            )
            added += 1
    suffix = "" if added == 1 else "s"
    flash(
        f"Added {added} preset rule{suffix} for host filter {host_regex!r}. "
        "Review and edit them in the rules table below.",
        "ok",
    )
    return redirect(url_for("matchreplace.index"))


@bp.route("/preset/remove", methods=["POST"])
def preset_remove():
    slug = request.form.get("slug", "").strip()
    host_regex = request.form.get("host_regex", "")
    if slug not in PRESET_MAP:
        flash("Unknown preset.", "err")
        return redirect(url_for("matchreplace.index"))
    removed = 0
    for r in g.project.list_mr():
        if r.get("host_regex", "") != host_regex:
            continue
        if _parse_preset_slug(r.get("comment", "")) != slug:
            continue
        g.project.delete_mr(int(r["id"]))
        removed += 1
    suffix = "" if removed == 1 else "s"
    flash(f"Removed {removed} preset rule{suffix}.", "ok")
    return redirect(url_for("matchreplace.index"))


@bp.route("/add", methods=["POST"])
def add():
    where = request.form.get("where", "req_header")
    pattern = request.form.get("pattern", "")
    replacement = request.form.get("replacement", "")
    is_regex = request.form.get("is_regex") == "1"
    host_regex = request.form.get("host_regex", "")
    comment = request.form.get("comment", "")
    if not pattern:
        flash("Pattern cannot be empty.", "err")
        return redirect(url_for("matchreplace.index"))
    # L-12: validate user-supplied regexes at save time. Catching
    # ``regex.error`` here gives the operator immediate feedback in
    # the UI instead of a silent runtime failure inside the proxy
    # worker thread.
    if is_regex and not _safe_regex.is_valid_pattern(pattern):
        flash("Pattern is not a valid regular expression.", "err")
        return redirect(url_for("matchreplace.index"))
    if host_regex and not _safe_regex.is_valid_pattern(host_regex):
        flash("Host filter is not a valid regular expression.", "err")
        return redirect(url_for("matchreplace.index"))
    # M-14: warn (non-blocking) if the host filter is not anchored.
    # An unanchored ``example\.com`` matches ``evil-example.com.attacker``
    # too -- almost never what the operator intended.
    if host_regex and not (host_regex.startswith("^") or "$" in host_regex):
        flash(
            "Heads up: host filter is not anchored. Add ^ at the start "
            "and $ at the end to avoid matching attacker-controlled "
            "subdomains like evil-example.com.attacker.tld.",
            "warn",
        )
    g.project.add_mr(where=where, pattern=pattern, replacement=replacement,
                      is_regex=is_regex, host_regex=host_regex, comment=comment)
    flash("Rule added. It applies to proxy traffic immediately.", "ok")
    return redirect(url_for("matchreplace.index"))


@bp.route("/<int:mid>/toggle", methods=["POST"])
def toggle(mid: int):
    g.project.toggle_mr(mid)
    return redirect(url_for("matchreplace.index"))


@bp.route("/<int:mid>/delete", methods=["POST"])
def delete(mid: int):
    g.project.delete_mr(mid)
    flash("Rule deleted.", "ok")
    return redirect(url_for("matchreplace.index"))

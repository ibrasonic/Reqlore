"""WebSocket workbench: connect, send messages, view transcript."""
from __future__ import annotations

import time

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ...websocket import WS_AVAILABLE, WSTranscript, send_messages

bp = Blueprint("ws", __name__)


@bp.route("/")
def index():
    transcripts = _list(g.project)
    return render_template("ws/index.html", transcripts=transcripts,
                           ws_available=WS_AVAILABLE)


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        headers_text = request.form.get("headers", "")
        kind = request.form.get("kind", "text")
        data = request.form.get("data", "")
        recv = float(request.form.get("recv_seconds", "2"))
        if not url:
            flash("URL is required.", "err")
            return redirect(url_for(".new"))
        if not WS_AVAILABLE:
            flash("WebSocket support requires 'websockets' "
                  "(pip install websockets).", "err")
            return redirect(url_for(".index"))
        headers = _parse_headers(headers_text)
        transcript = send_messages(
            url, [(kind, data)] if data else [],
            headers=headers, recv_seconds=recv,
        )
        tid = _save(g.project, transcript)
        flash(f"Saved transcript #{tid} ({len(transcript.messages)} message(s)).",
              "ok" if transcript.closed and not _has_error(transcript) else "warn")
        return redirect(url_for(".show", tid=tid))
    return render_template("ws/new.html", ws_available=WS_AVAILABLE)


@bp.route("/<int:tid>")
def show(tid: int):
    transcript = _load(g.project, tid)
    if transcript is None:
        flash(f"No transcript #{tid}.", "err")
        return redirect(url_for(".index"))
    from ...a11y import build_find_context
    tx_text = _transcript_text(transcript)
    find_tx = build_find_context(
        tx_text, prefix="tx",
        q=request.args.get("tx_find", ""),
        regex=request.args.get("tx_re") == "1",
        region_label="transcript", action=url_for(".show", tid=tid),
    )
    return render_template("ws/show.html", tid=tid, t=transcript,
                           ws_available=WS_AVAILABLE,
                           find_tx=find_tx)


def _transcript_text(transcript: WSTranscript) -> str:
    """Flatten the message list into one searchable text block.

    Each message gets a one-line header (``[N] dir kind size``) so the
    find widget's line numbers point inside a stable, scannable layout.
    """
    parts: list[str] = []
    for i, m in enumerate(transcript.messages, start=1):
        parts.append(f"[{i}] {m.direction} {m.kind} {m.size}")
        parts.append(m.data)
        parts.append("")
    return "\n".join(parts)


@bp.route("/<int:tid>/send", methods=["POST"])
def send_more(tid: int):
    transcript = _load(g.project, tid)
    if transcript is None:
        flash(f"No transcript #{tid}.", "err")
        return redirect(url_for(".index"))
    if not WS_AVAILABLE:
        flash("WebSocket support requires 'websockets'.", "err")
        return redirect(url_for(".show", tid=tid))
    kind = request.form.get("kind", "text")
    data = request.form.get("data", "")
    headers_text = request.form.get("headers", "")
    recv = float(request.form.get("recv_seconds", "2"))
    headers = _parse_headers(headers_text)
    new_t = send_messages(transcript.url, [(kind, data)] if data else [],
                           headers=headers, recv_seconds=recv)
    transcript.messages.extend(new_t.messages)
    transcript.closed = new_t.closed
    _save(g.project, transcript, tid=tid)
    flash("Sent and refreshed transcript.", "ok")
    return redirect(url_for(".show", tid=tid))


@bp.route("/<int:tid>/delete", methods=["POST"])
def delete(tid: int):
    g.project.set_state(f"ws:{tid}", "")
    flash(f"Transcript #{tid} cleared.", "ok")
    return redirect(url_for(".index"))


# ---- storage helpers (use existing project_state KV) ----

def _save(project, transcript: WSTranscript, *, tid: int | None = None) -> int:
    if tid is None:
        tid = int(project.get_state("ws:next_id", "1") or "1")
        project.set_state("ws:next_id", str(tid + 1))
    project.set_state(f"ws:{tid}", transcript.to_json())
    return tid


def _load(project, tid: int) -> WSTranscript | None:
    blob = project.get_state(f"ws:{tid}", "")
    if not blob:
        return None
    try:
        return WSTranscript.from_json(blob)
    except Exception:
        return None


def _list(project) -> list[dict]:
    """Walk project_state keys ws:<n>. We don't have list_state, so try ids
    1..next_id - 1."""
    try:
        next_id = int(project.get_state("ws:next_id", "1") or "1")
    except ValueError:
        next_id = 1
    out: list[dict] = []
    for i in range(1, next_id):
        t = _load(project, i)
        if t is None:
            continue
        out.append({
            "id": i, "url": t.url,
            "n_msgs": len(t.messages),
            "closed": t.closed,
            "last_ts": (t.messages[-1].ts if t.messages else 0),
        })
    out.sort(key=lambda r: r["id"], reverse=True)
    return out


def _parse_headers(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out


def _has_error(t: WSTranscript) -> bool:
    return any(m.direction == "recv" and m.data.startswith("[error] ")
               for m in t.messages)

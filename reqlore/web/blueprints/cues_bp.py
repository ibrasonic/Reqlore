"""Audio cues — WAV streamer + cue index."""
from __future__ import annotations

from flask import Blueprint, Response, abort, render_template

from ...audio import CUES, render

bp = Blueprint("cues", __name__)


@bp.route("/")
def index():
    return render_template("cues/index.html",
                           cues=[(k, desc) for k, (desc, _fn) in CUES.items()])


@bp.route("/<name>.wav")
def wav(name: str):
    blob = render(name)
    if blob is None:
        abort(404)
    return Response(blob, mimetype="audio/wav",
                    headers={"Cache-Control": "public, max-age=3600"})

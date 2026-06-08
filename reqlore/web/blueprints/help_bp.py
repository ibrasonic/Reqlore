"""Help: keyboard map, a11y notes, about page."""
from __future__ import annotations

from flask import Blueprint, render_template

bp = Blueprint("help", __name__)


KEYMAP = [
    ("Alt+1",  "Dashboard"),
    ("Alt+2",  "Proxy"),
    ("Alt+3",  "History"),
    ("Alt+4",  "Repeater"),
    ("Alt+5",  "Intruder"),
    ("Alt+6",  "Scanner (passive)"),
    ("Alt+7",  "Decoder"),
    ("Alt+8",  "JWT workbench"),
    ("Alt+9",  "Settings"),
    ("Alt+0",  "Help / keyboard map"),
    ("Tab",    "Move to next focusable element"),
    ("?",      "Open this keyboard map"),
    # On the Intercept-detail page (Proxy > view a held flow):
    ("Alt+E",  "Forward edited (intercept detail)"),
    ("Alt+A",  "Forward as-is (intercept detail)"),
    ("Alt+P",  "Drop (intercept detail)"),
    ("Alt+R",  "Send to Repeater (intercept detail)"),
    ("Alt+I",  "Send to Intruder (intercept detail)"),
    ("Alt+M",  "Send to Comparer (intercept detail)"),
    ("Alt+B",  "Send to PoC builder (intercept detail)"),
    ("Alt+J",  "Send to JWT workbench (intercept detail)"),
    ("Alt+O",  "Send to Decoder (intercept detail)"),
]


@bp.route("/")
def index():
    return render_template("help/index.html", keymap=KEYMAP)

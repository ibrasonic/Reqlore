"""Example: register a Flask blueprint that adds a `/hello-plugin/` page."""
from flask import Blueprint, render_template_string

from reqlore.plugins_sdk import make_info

PLUGIN_INFO = make_info(
    name="hello-blueprint",
    version="1.0",
    description="Adds a /hello-plugin/ page so you can see plugins running.",
)

_bp = Blueprint("hello_plugin", __name__, url_prefix="/hello-plugin")


@_bp.route("/")
def hello():
    return render_template_string(
        "<h1>Hello from a Reqlore plugin</h1>"
        "<p>This page is registered by the example plugin <code>hello_blueprint.py</code>.</p>",
    )


def register(app):
    app.register_blueprint(_bp)

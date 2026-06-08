"""Flask app factory."""
from __future__ import annotations

import secrets
from pathlib import Path

from flask import Flask, current_app, g, request, session

from ..config import Settings
from ..proxy.mitm import ProxyController
from ..storage import Project


def create_app(project_path: Path, settings: Settings, *,
               proxy: ProxyController | None = None) -> Flask:
    app = Flask(
        __name__.split(".")[0] + ".web",
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["SECRET_KEY"] = secrets.token_urlsafe(32)
    app.config["PROJECT_PATH"] = str(project_path)
    app.config["REQLORE_SETTINGS"] = settings
    app.config["REQLORE_PROXY"] = proxy

    project = Project(project_path)
    app.extensions["reqlore_project"] = project

    # Tell the proxy what port the UI actually listens on, so the
    # self-bypass works regardless of how the proxy was constructed.
    if proxy:
        proxy.ui_port = settings.ui_port

    # Restore Burp-style intercept toggle + filter config across restarts.
    if proxy:
        from ..proxy.rules import InterceptConfig
        import json as _json
        raw = project.get_state("intercept_config", "")
        if raw:
            try:
                proxy.set_intercept_config(
                    InterceptConfig.from_dict(_json.loads(raw)))
            except (ValueError, TypeError):
                pass  # corrupt state row — fall back to defaults
        if project.get_state("intercept_on", "0") == "1":
            proxy.set_intercept(True)

    # CSRF token (double-submit cookie pattern, kept simple)
    @app.before_request
    def _csrf() -> None:
        token = session.get("csrf")
        if not token:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("_csrf") or request.headers.get("X-Reqlore-CSRF", "")
            if not secrets.compare_digest(sent, session.get("csrf", "")):
                from flask import abort
                abort(400, description="CSRF token mismatch")

    @app.after_request
    def _security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "media-src 'self'; "
            "connect-src 'self'; "
            "frame-src 'self'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # Force revalidation for our own assets so JS/CSS changes are
        # picked up immediately — pentest tools must never silently
        # serve stale logic from a long-lived browser cache.
        if request.endpoint == "static":
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
        return resp

    @app.context_processor
    def _ctx():
        return {
            "csrf_token": session.get("csrf", ""),
            "theme": project.get_state("theme", settings.default_theme),
            "verbosity": project.get_state("verbosity", settings.default_verbosity),
            "intercept_count": project.intercept_count(),
            "history_count": project.history_count(),
            "proxy_running": (proxy.is_running() if proxy else False),
            "proxy_endpoint": f"{settings.proxy_host}:{settings.proxy_port}",
            "intercept_on": (proxy.intercept_on() if proxy else False),
            "cues_on": project.get_state("cues", "0") == "1",
            "findings_count": project.findings_count(),
            "settings": settings,
        }

    @app.template_filter("url_unquote")
    def _url_unquote(s):
        from urllib.parse import unquote_plus
        try:
            return unquote_plus(s or "")
        except Exception:  # noqa: BLE001 - never break a template render
            return s or ""

    @app.before_request
    def _attach_project():
        g.project = project
        g.settings = settings
        g.proxy = proxy

    # Blueprints
    from .blueprints.dashboard import bp as dashboard_bp
    from .blueprints.proxy_bp import bp as proxy_bp
    from .blueprints.history import bp as history_bp
    from .blueprints.repeater import bp as repeater_bp
    from .blueprints.decoder import bp as decoder_bp
    from .blueprints.settings_bp import bp as settings_bp
    from .blueprints.help_bp import bp as help_bp
    from .blueprints.intruder_bp import bp as intruder_bp
    from .blueprints.matchreplace_bp import bp as mr_bp
    from .blueprints.comparer_bp import bp as comparer_bp
    from .blueprints.jwt_bp import bp as jwt_bp
    from .blueprints.sitemap_bp import bp as sitemap_bp
    from .blueprints.search_bp import bp as search_bp
    from .blueprints.cues_bp import bp as cues_bp
    from .blueprints.scanner_bp import bp as scanner_bp
    from .blueprints.reporter_bp import bp as reporter_bp
    from .blueprints.plugins_bp import bp as plugins_bp
    from .blueprints.graphql_bp import bp as graphql_bp
    from .blueprints.ws_bp import bp as ws_bp
    from .blueprints.saml_bp import bp as saml_bp
    from .blueprints.poc_bp import bp as poc_bp
    from .blueprints.macros_bp import bp as macros_bp
    from .blueprints.sequencer_bp import bp as sequencer_bp
    from .blueprints.oast_bp import bp as oast_bp
    from .blueprints.h2_bp import bp as h2_bp
    from .blueprints.smuggling_bp import bp as smuggling_bp
    from .blueprints.param_miner_bp import bp as param_miner_bp
    from .blueprints.schedule_bp import bp as schedule_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(proxy_bp, url_prefix="/proxy")
    app.register_blueprint(history_bp, url_prefix="/history")
    app.register_blueprint(repeater_bp, url_prefix="/repeater")
    app.register_blueprint(intruder_bp, url_prefix="/intruder")
    app.register_blueprint(mr_bp, url_prefix="/match-replace")
    app.register_blueprint(comparer_bp, url_prefix="/comparer")
    app.register_blueprint(jwt_bp, url_prefix="/jwt")
    app.register_blueprint(sitemap_bp, url_prefix="/sitemap")
    app.register_blueprint(search_bp, url_prefix="/search")
    app.register_blueprint(decoder_bp, url_prefix="/decoder")
    app.register_blueprint(cues_bp, url_prefix="/cues")
    app.register_blueprint(scanner_bp, url_prefix="/scanner")
    app.register_blueprint(reporter_bp, url_prefix="/reporter")
    app.register_blueprint(plugins_bp, url_prefix="/plugins")
    app.register_blueprint(graphql_bp, url_prefix="/graphql")
    app.register_blueprint(ws_bp, url_prefix="/ws")
    app.register_blueprint(saml_bp, url_prefix="/saml")
    app.register_blueprint(poc_bp, url_prefix="/poc")
    app.register_blueprint(macros_bp, url_prefix="/macros")
    app.register_blueprint(sequencer_bp, url_prefix="/sequencer")
    app.register_blueprint(oast_bp, url_prefix="/oast")
    app.register_blueprint(h2_bp, url_prefix="/h2")
    app.register_blueprint(smuggling_bp, url_prefix="/smuggling")
    app.register_blueprint(param_miner_bp, url_prefix="/param-miner")
    app.register_blueprint(schedule_bp, url_prefix="/schedule")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(help_bp, url_prefix="/help")

    # Let plugins register their own Flask hooks/blueprints (if any).
    from ..plugins import get_registry
    try:
        get_registry().call_register(app)
    except Exception:
        # A misbehaving plugin must never block app startup.
        pass

    @app.errorhandler(404)
    def _404(e):
        from flask import render_template
        return render_template("error.html", code=404, msg="Page not found."), 404

    @app.errorhandler(400)
    def _400(e):
        from flask import render_template
        return render_template("error.html", code=400,
                               msg=getattr(e, "description", "Bad request.")), 400

    return app


def get_project() -> Project:
    return current_app.extensions["reqlore_project"]

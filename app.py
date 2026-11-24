"""TSH Hardware Monitor - Flask application entry point.

Run (development):   python app.py
Run (production):    waitress-serve --listen=0.0.0.0:5000 app:app
"""
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from types import SimpleNamespace

from flask import Flask, g, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

import accounts
import auth
import database
import monitoring
import switches
import switch_monitor
import users
import views
from config import Config, production_config_errors
from device_monitor import start_background_monitor


# --------------------------------------------------------------- template helpers
def fmt_uptime(hours):
    """782 -> '32d 14h'."""
    if hours is None:
        return "-"
    return f"{hours // 24}d {hours % 24:02d}h"


# ----------------------------------------------------------------------- logging
def setup_logging(app):
    """Write important events and errors to instance/app.log (rotates at 1 MB)."""
    log_file = Path(app.config["DATABASE"]).parent / "app.log"
    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


# ------------------------------------------------------------------ app factory
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # reject request bodies over 1 MB
    config_errors = production_config_errors(app.config)
    if config_errors:
        raise RuntimeError("Invalid production configuration: " + " ".join(config_errors))

    database.init_db(app)
    setup_logging(app)
    auth.setup_admin(app)
    auth.bootstrap_admin(app)

    if not os.environ.get("SECRET_KEY"):
        msg = "SECRET_KEY is not set in .env - everyone is signed out each time the app restarts."
        app.logger.warning(msg)
        print(f"  WARNING: {msg}")

    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(switches.bp)
    app.register_blueprint(users.bp)
    app.before_request(auth.enforce_idle_timeout)
    app.before_request(auth.load_user)
    app.before_request(auth.protect_csrf)
    app.jinja_env.filters["uptime"] = fmt_uptime

    # ------------------------------------------------------- values for templates
    @app.context_processor
    def inject_globals():
        open_alerts = 0
        soc = None
        me = g.get("user")
        if session.get("user") and not (me and me["must_change_password"]):  # nothing to poll while a new password is required
            try:
                open_alerts = database.query(
                    "SELECT COUNT(*) AS c FROM alerts WHERE status != 'resolved'", one=True
                )["c"]
                soc = monitoring.soc_summary()  # numbers for the SOC bar shown on every page
            except Exception:  # never break a page just because the badge failed
                app.logger.exception("Could not count open alerts")
        refresh_setting = database.query(
            "SELECT value FROM app_settings WHERE key = 'refresh_seconds'", one=True
        )
        return {
            "soc": soc,
            "csrf_token": auth.csrf_token,
            "now": datetime.now().strftime("%I:%M:%S %p"),
            "open_alert_count": open_alerts,
            "demo_mode": app.config["DEMO_MODE"],
            "simulation_mode": app.config["DEMO_MODE"],
            "workspace_name": app.config["WORKSPACE_NAME"],
            "initials": accounts.initials(me) if me else app.config["ADMIN_INITIALS"],
            "current_user": me,
            "is_admin": bool(me) and me["role"] == "admin",
            "role_label": accounts.ROLES.get(me["role"], "") if me else "",
            "refresh_seconds": int(refresh_setting["value"]) if refresh_setting else app.config["REFRESH_SECONDS"],
            "notify_seconds": app.config["NOTIFY_SECONDS"],
            "host_metrics_refresh_seconds": app.config["HOST_METRICS_REFRESH_SECONDS"],
            "cfg": app.config,
        }

    # ------------------------------------------------------------ security headers
    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
        )
        if app.config["SESSION_COOKIE_SECURE"]:  # site is served over HTTPS
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Pages hold live data: never cache. CSS/JS: always re-check, so edits show up at once.
        resp.headers["Cache-Control"] = "no-cache" if request.endpoint == "static" else "no-store"
        return resp

    # --------------------------------------------------------------- health check
    @app.route("/healthz")
    def healthz():
        """Open endpoint for uptime checks. Reveals nothing except ok / error."""
        try:
            database.query("SELECT 1", one=True)
            return jsonify(status="ok")
        except Exception:
            app.logger.exception("Health check failed")
            return jsonify(status="error"), 503

    # ---------------------------------------------------------------- error pages
    def render_error(code, name, description):
        err = SimpleNamespace(code=code, name=name, description=description)
        return render_template("error.html", err=err, active=""), code

    @app.errorhandler(HTTPException)
    def http_error(e):
        return render_error(e.code, e.name, e.description)

    @app.errorhandler(Exception)
    def server_error(e):
        if app.debug:
            raise e  # show the full debugger while developing
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        return render_error(500, "Server error", "Something went wrong. The error was written to instance/app.log.")

    start_background_monitor(app)
    switch_monitor.start_background_monitor(app)
    app.logger.info("TSH Hardware Monitor started (demo_mode=%s)", app.config["DEMO_MODE"])
    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  TSH Hardware Monitor is running at http://{host}:{port}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from flask import Flask, g

import auth
import database
import users
import views


class RefreshSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        project_root = Path(__file__).resolve().parents[1]
        self.app = Flask(
            __name__,
            template_folder=str(project_root / "templates"),
            static_folder=str(project_root / "static"),
        )
        self.app.config.update(
            SECRET_KEY="test-secret",
            DATABASE=str(Path(self.temp_dir.name) / "monitor.db"),
            ADMIN_USERNAME="admin",
            ADMIN_PASSWORD="Test-admin-password-2026!",
            DEMO_MODE=False,
            REFRESH_SECONDS=10,
            REFRESH_INTERVAL_OPTIONS=((1800, "30 minutes"), (3600, "1 hour")),
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
            SESSION_COOKIE_SECURE=False,
            MAX_LOGIN_ATTEMPTS=5,
            LOCKOUT_MINUTES=5,
            CPU_WARN=80,
            MEMORY_WARN=85,
            DISK_WARN=85,
        )
        self.app.register_blueprint(auth.bp)
        self.app.register_blueprint(views.bp)
        self.app.register_blueprint(users.bp)

        @self.app.before_request
        def security_hooks():
            response = auth.enforce_idle_timeout()
            if response is not None:
                return response
            response = auth.load_user()
            if response is not None:
                return response
            return auth.protect_csrf()

        @self.app.context_processor
        def template_globals():
            return {
                "csrf_token": auth.csrf_token,
                "now": "test",
                "open_alert_count": 0,
                "soc": None,
                "simulation_mode": False,
                "demo_mode": False,
                "workspace_name": "Test workspace",
                "initials": "TS",
                "current_user": g.get("user"),
                "is_admin": auth.is_admin(),
                "role_label": "Admin",
                "notify_seconds": 5,
                "refresh_seconds": 1800,
                "cfg": self.app.config,
            }

        self.app.jinja_env.filters["uptime"] = (
            lambda hours: "-" if hours is None else f"{hours // 24}d {hours % 24:02d}h"
        )
        auth.setup_admin(self.app)
        database.init_db(self.app)
        auth.bootstrap_admin(self.app)
        self.client = self.app.test_client()
        with self.app.app_context():
            admin = database.query("SELECT id, password_changed_at FROM users WHERE username = 'admin'", one=True)
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "admin"
            browser_session["uid"] = admin["id"]
            browser_session["pv"] = admin["password_changed_at"] or ""
            browser_session["role"] = "admin"
            browser_session["_csrf"] = "refresh-test-csrf"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_admin_can_persist_only_supported_refresh_intervals(self):
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="1800" selected', response.data)

        response = self.client.post(
            "/settings",
            data={"_csrf": "refresh-test-csrf", "refresh_seconds": "3600"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="3600" selected', response.data)
        with self.app.app_context():
            setting = database.query(
                "SELECT value FROM app_settings WHERE key = 'refresh_seconds'", one=True
            )
            audit_entry = database.query(
                "SELECT action FROM audit_logs WHERE action = 'refresh_interval_updated'",
                one=True,
            )
        self.assertEqual(setting["value"], "3600")
        self.assertIsNotNone(audit_entry)

        response = self.client.post(
            "/settings",
            data={"_csrf": "refresh-test-csrf", "refresh_seconds": "10"},
        )
        self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            setting = database.query(
                "SELECT value FROM app_settings WHERE key = 'refresh_seconds'", one=True
            )
        self.assertEqual(setting["value"], "3600")

    def test_refresh_setting_post_requires_csrf(self):
        response = self.client.post("/settings", data={"refresh_seconds": "1800"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

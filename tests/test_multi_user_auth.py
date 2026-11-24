import re
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, g
from werkzeug.security import check_password_hash

import accounts
import auth
import database
import monitoring
import users
import views


class MultiUserAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        project_root = Path(__file__).resolve().parents[1]
        self.app = Flask(
            __name__,
            template_folder=str(project_root / "templates"),
            static_folder=str(project_root / "static"),
        )
        self.app.config.update(
            SECRET_KEY="multi-user-test-secret",
            DATABASE=str(Path(self.temp_dir.name) / "monitor.db"),
            ADMIN_USERNAME="admin",
            ADMIN_PASSWORD="Test-admin-password-2026!",
            DEMO_MODE=False,
            REFRESH_SECONDS=1800,
            REFRESH_INTERVAL_OPTIONS=((1800, "30 minutes"), (3600, "1 hour")),
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
            SESSION_COOKIE_SECURE=False,
            MAX_LOGIN_ATTEMPTS=5,
            LOCKOUT_MINUTES=5,
            CPU_WARN=80,
            MEMORY_WARN=85,
            DISK_WARN=85,
            WORKSPACE_NAME="Test workspace",
            ADMIN_INITIALS="TS",
            NOTIFY_SECONDS=5,
        )
        auth.setup_admin(self.app)
        database.init_db(self.app)
        auth.bootstrap_admin(self.app)
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
            current = g.get("user")
            return {
                "csrf_token": auth.csrf_token,
                "now": "test",
                "open_alert_count": 0,
                "soc": None,
                "demo_mode": False,
                "simulation_mode": False,
                "workspace_name": "Test workspace",
                "initials": accounts.initials(current) if current else "TS",
                "current_user": current,
                "is_admin": auth.is_admin(),
                "role_label": accounts.ROLES.get(current["role"], "") if current else "",
                "notify_seconds": 5,
                "refresh_seconds": 1800,
                "cfg": self.app.config,
            }

        self.app.jinja_env.filters["uptime"] = (
            lambda hours: "-" if hours is None else f"{hours // 24}d {hours % 24:02d}h"
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _login(self, client, username, password):
        client.get("/login")
        with client.session_transaction() as browser_session:
            token = browser_session["_csrf"]
        response = client.post(
            "/login", data={"_csrf": token, "username": username, "password": password}
        )
        self.assertEqual(response.status_code, 302)
        return response

    def _csrf(self, client):
        with client.session_transaction() as browser_session:
            return browser_session["_csrf"]

    def test_supervisor_forced_password_change_and_role_boundaries(self):
        self._login(self.client, "admin", "Test-admin-password-2026!")
        token = self._csrf(self.client)
        response = self.client.post(
            "/users/new",
            data={
                "_csrf": token,
                "username": "supervisor1",
                "full_name": "Test Supervisor",
                "role": "supervisor",
                "password": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        passwords = re.findall(r"<code>(.*?)</code>", response.data.decode())
        self.assertEqual(len(passwords), 2)
        temporary_password = passwords[1]

        with self.app.app_context():
            supervisor = accounts.find_user("supervisor1")
            self.assertEqual(supervisor["role"], "supervisor")
            self.assertEqual(supervisor["is_active"], 1)
            self.assertEqual(supervisor["must_change_password"], 1)
            self.assertTrue(check_password_hash(supervisor["password_hash"], temporary_password))

        supervisor_client = self.app.test_client()
        response = self._login(supervisor_client, "supervisor1", temporary_password)
        self.assertEqual(response.headers["Location"], "/account/password")
        self.assertEqual(supervisor_client.get("/account/password").status_code, 200)
        token = self._csrf(supervisor_client)
        response = supervisor_client.post(
            "/account/password",
            data={
                "_csrf": token,
                "current": temporary_password,
                "new": "New-strong-password-2026!",
                "confirm": "New-strong-password-2026!",
            },
        )
        self.assertEqual(response.status_code, 302)
        with supervisor_client.session_transaction() as browser_session:
            self.assertEqual(browser_session["role"], "supervisor")
        with self.app.app_context():
            supervisor = accounts.find_user("supervisor1")
            self.assertEqual(supervisor["must_change_password"], 0)
            audit_rows = database.query(
                "SELECT detail FROM audit_logs WHERE action = 'password_changed'"
            )
            self.assertNotIn("New-strong-password-2026!", " ".join(row["detail"] for row in audit_rows))

        token = self._csrf(supervisor_client)
        self.assertEqual(supervisor_client.get("/users").status_code, 403)
        self.assertEqual(
            supervisor_client.post("/devices/new", data={"_csrf": token}).status_code, 403
        )
        self.assertEqual(
            supervisor_client.post(
                "/settings", data={"_csrf": token, "refresh_seconds": "3600"}
            ).status_code,
            403,
        )

        with self.app.app_context():
            alert_id = database.execute(
                "INSERT INTO alerts (title, severity, device_name, message, created_at) "
                "VALUES ('Test alert', 'warning', 'test-device', 'test', ?)",
                (database.now_iso(),),
            )
        response = supervisor_client.post(
            f"/alerts/{alert_id}/acknowledge", data={"_csrf": token, "back": "/alerts"}
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            alert = database.query("SELECT status FROM alerts WHERE id = ?", (alert_id,), one=True)
            self.assertEqual(alert["status"], "acknowledged")

    def test_admin_cannot_disable_self_or_remove_last_admin_role(self):
        self._login(self.client, "admin", "Test-admin-password-2026!")
        self.assertEqual(self.client.get("/users").status_code, 200)
        with self.app.app_context():
            admin = accounts.find_user("admin")
        token = self._csrf(self.client)

        response = self.client.post(
            f"/users/{admin['id']}/toggle", data={"_csrf": token}
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.post(
            f"/users/{admin['id']}/profile",
            data={"_csrf": token, "full_name": "System administrator", "role": "supervisor"},
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            admin = accounts.find_user("admin")
            self.assertEqual(admin["is_active"], 1)
            self.assertEqual(admin["role"], "admin")
            self.assertEqual(accounts.active_admin_count(), 1)

    def test_admin_can_change_roles_status_and_reset_passwords(self):
        self._login(self.client, "admin", "Test-admin-password-2026!")
        token = self._csrf(self.client)
        response = self.client.post(
            "/users/new",
            data={
                "_csrf": token,
                "username": "operator2",
                "full_name": "Second Operator",
                "role": "supervisor",
                "password": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            operator = accounts.find_user("operator2")
        user_id = operator["id"]

        response = self.client.post(
            f"/users/{user_id}/profile",
            data={"_csrf": token, "full_name": "Second Operator", "role": "admin"},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertEqual(accounts.find_user("operator2")["role"], "admin")
            self.assertEqual(accounts.active_admin_count(), 2)

        response = self.client.post(
            f"/users/{user_id}/profile",
            data={"_csrf": token, "full_name": "Second Operator", "role": "supervisor"},
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.post(f"/users/{user_id}/toggle", data={"_csrf": token})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertEqual(accounts.find_user("operator2")["is_active"], 0)
        response = self.client.post(f"/users/{user_id}/toggle", data={"_csrf": token})
        self.assertEqual(response.status_code, 302)

        response = self.client.post(f"/users/{user_id}/reset", data={"_csrf": token})
        self.assertEqual(response.status_code, 200)
        passwords = re.findall(r"<code>(.*?)</code>", response.data.decode())
        self.assertEqual(len(passwords), 2)
        with self.app.app_context():
            operator = accounts.find_user("operator2")
            self.assertEqual(operator["must_change_password"], 1)
            self.assertTrue(check_password_hash(operator["password_hash"], passwords[1]))
            self.assertNotIn(
                passwords[1],
                " ".join(
                    row["detail"]
                    for row in database.query(
                        "SELECT detail FROM audit_logs WHERE action = 'user_password_reset'"
                    )
                ),
            )

    def test_role_changes_refresh_and_disabled_accounts_lose_sessions(self):
        password = "Supervisor-password-2026!"
        with self.app.app_context():
            supervisor = accounts.create_user(
                "opsuser", "Operations User", "supervisor", password, "admin", must_change=False
            )
        client = self.app.test_client()
        self._login(client, "opsuser", password)
        with client.session_transaction() as browser_session:
            self.assertEqual(browser_session["role"], "supervisor")

        with self.app.app_context():
            database.execute("UPDATE users SET role = 'admin' WHERE id = ?", (supervisor["id"],))
        self.assertEqual(client.get("/users").status_code, 200)
        with client.session_transaction() as browser_session:
            self.assertEqual(browser_session["role"], "admin")

        with self.app.app_context():
            database.execute("UPDATE users SET is_active = 0 WHERE id = ?", (supervisor["id"],))
        self.assertEqual(client.get("/users").status_code, 302)
        with client.session_transaction() as browser_session:
            self.assertNotIn("user", browser_session)

    def test_maintenance_suppresses_alerts_but_retains_polling_and_handover(self):
        self._login(self.client, "admin", "Test-admin-password-2026!")
        with self.app.app_context():
            device = database.query(
                "SELECT * FROM devices WHERE name = 'TSHSER001'", one=True
            )
        self.assertIsNotNone(device)
        starts = datetime.now() - timedelta(minutes=5)
        ends = datetime.now() + timedelta(hours=1)
        response = self.client.post(
            "/maintenance",
            data={
                "_csrf": self._csrf(self.client),
                "device_id": device["id"],
                "reason": "Planned host maintenance",
                "starts_at": starts.strftime("%Y-%m-%dT%H:%M"),
                "ends_at": ends.strftime("%Y-%m-%dT%H:%M"),
            },
        )
        self.assertEqual(response.status_code, 302)
        overlap_response = self.client.post(
            "/maintenance",
            data={
                "_csrf": self._csrf(self.client),
                "device_id": device["id"],
                "reason": "Overlapping work",
                "starts_at": starts.strftime("%Y-%m-%dT%H:%M"),
                "ends_at": ends.strftime("%Y-%m-%dT%H:%M"),
            },
        )
        self.assertEqual(overlap_response.status_code, 400)

        with self.app.app_context():
            current = database.query(
                "SELECT * FROM devices WHERE id = ?", (device["id"],), one=True
            )
            monitoring.apply_host_telemetry(
                current, {"cpu": 90}, reported_status="down"
            )
            updated = database.query(
                "SELECT cpu, status, last_checked FROM devices WHERE id = ?",
                (device["id"],), one=True,
            )
            suppressed = database.query(
                "SELECT COUNT(*) AS count FROM alerts WHERE device_name = ? "
                "AND title IN ('High CPU utilization', 'Device unavailable')",
                (device["name"],), one=True,
            )
            maintenance_row = database.query(
                "SELECT id FROM maintenance_windows WHERE device_id = ? AND is_active = 1",
                (device["id"],), one=True,
            )
            display_rows = views._decorate_device_rows([
                database.query(
                    "SELECT * FROM devices WHERE id = ?", (device["id"],), one=True
                )
            ])
        self.assertEqual(updated["cpu"], 90)
        self.assertEqual(updated["status"], "down")
        self.assertIsNotNone(updated["last_checked"])
        self.assertEqual(suppressed["count"], 0)
        self.assertEqual(display_rows[0]["status"], "maintenance")

        status_response = self.client.get("/api/v1/device-status")
        self.assertEqual(status_response.status_code, 200)
        status_row = next(
            item for item in status_response.get_json()["devices"]
            if item["id"] == device["id"]
        )
        self.assertEqual(status_row["status"], "maintenance")
        handover_response = self.client.get("/handover?hours=8")
        self.assertEqual(handover_response.status_code, 200)
        self.assertIn(b"Planned host maintenance", handover_response.data)

        response = self.client.post(
            f"/maintenance/{maintenance_row['id']}/cancel",
            data={"_csrf": self._csrf(self.client)},
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            current = database.query(
                "SELECT * FROM devices WHERE id = ?", (device["id"],), one=True
            )
            monitoring.apply_host_telemetry(
                current, {"cpu": 90}, reported_status="down"
            )
            alert = database.query(
                "SELECT severity FROM alerts WHERE device_name = ? "
                "AND title = 'Device unavailable'",
                (device["name"],), one=True,
            )
            audit_actions = database.query(
                "SELECT action FROM audit_logs WHERE action LIKE 'maintenance_%' "
                "ORDER BY id"
            )
        self.assertIsNotNone(alert)
        self.assertEqual(
            [row["action"] for row in audit_actions],
            ["maintenance_scheduled", "maintenance_cancelled"],
        )

    def test_supervisor_can_view_maintenance_and_handover_but_cannot_manage_windows(self):
        self._login(self.client, "admin", "Test-admin-password-2026!")
        with self.app.app_context():
            accounts.create_user(
                "shiftlead", "Shift Lead", "supervisor",
                "Supervisor-test-password-2026!", "admin", must_change=False,
            )
        supervisor_client = self.app.test_client()
        self._login(
            supervisor_client, "shiftlead", "Supervisor-test-password-2026!"
        )
        self.assertEqual(supervisor_client.get("/maintenance").status_code, 200)
        self.assertEqual(supervisor_client.get("/handover?hours=12").status_code, 200)
        self.assertEqual(supervisor_client.get("/handover?hours=1").status_code, 400)
        response = supervisor_client.post(
            "/maintenance",
            data={
                "_csrf": self._csrf(supervisor_client),
                "device_id": "1",
                "reason": "Not permitted",
                "starts_at": datetime.now().strftime("%Y-%m-%dT%H:%M"),
                "ends_at": (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            },
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()

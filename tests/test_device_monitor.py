import sqlite3
import socket
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask

import auth
import database
import device_monitor
import monitoring
import switches
import views


class DeviceMonitorTests(unittest.TestCase):
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
            DEMO_MODE=False,
            TELEMETRY_TOKEN="test-telemetry-token-that-is-long-enough",
            TELEMETRY_STALE_SECONDS=180,
            HOST_METRICS_REFRESH_SECONDS=15,
            DEVICE_CHECK_INTERVAL_SECONDS=30,
            DEVICE_CHECK_TIMEOUT_SECONDS=1,
            DEVICE_CHECK_FAILURE_LIMIT=2,
            DEVICE_CHECK_WORKERS=2,
            DEVICE_CHECK_TCP_PORTS=(),
            REFRESH_SECONDS=1800,
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
            SESSION_COOKIE_SECURE=False,
            MAX_LOGIN_ATTEMPTS=5,
            LOCKOUT_MINUTES=5,
        )
        self.app.register_blueprint(auth.bp)
        self.app.register_blueprint(views.bp)
        self.app.register_blueprint(switches.bp)

        @self.app.before_request
        def security_hooks():
            response = auth.enforce_idle_timeout()
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
                "notify_seconds": 5,
                "simulation_mode": False,
                "workspace_name": "Test workspace",
                "initials": "TS",
                "refresh_seconds": 1800,
                "cfg": self.app.config,
            }

        self.app.jinja_env.filters["uptime"] = (
            lambda hours: "-" if hours is None else f"{hours // 24}d {hours % 24:02d}h"
        )
        database.init_db(self.app)
        with self.app.app_context():
            database.execute(
                "INSERT INTO devices (name, role, ip, type) VALUES (?, ?, ?, ?)",
                ("CHECK-DEVICE", "test target", "192.0.2.90", "server"),
            )
            self.device = database.query(
                "SELECT * FROM devices WHERE name = ?", ("CHECK-DEVICE",), one=True
            )
        self.client = self.app.test_client()
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "admin"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_device_status_debounces_down_and_resolves_after_recovery(self):
        with self.app.app_context():
            database.execute(
                "UPDATE devices SET status = 'healthy' WHERE id = ?",
                (self.device["id"],),
            )
        with patch.object(device_monitor, "check_device", return_value=False):
            self.assertTrue(device_monitor.poll_once(self.app, [self.device["id"]]))
            with self.app.app_context():
                row = database.query(
                    "SELECT status, check_failures, last_checked FROM devices WHERE id = ?",
                    (self.device["id"],), one=True,
                )
                alert_count = database.query(
                    "SELECT COUNT(*) AS c FROM alerts WHERE fingerprint = ?",
                    (f"device_down:{self.device['id']}",), one=True,
                )["c"]
            self.assertEqual((row["status"], row["check_failures"]), ("warning", 1))
            self.assertIsNotNone(row["last_checked"])
            self.assertEqual(alert_count, 0)

            device_monitor.poll_once(self.app, [self.device["id"]])
        with self.app.app_context():
            row = database.query(
                "SELECT status, check_failures FROM devices WHERE id = ?",
                (self.device["id"],), one=True,
            )
            alert = database.query(
                "SELECT severity, status FROM alerts WHERE fingerprint = ?",
                (f"device_down:{self.device['id']}",), one=True,
            )
        self.assertEqual((row["status"], row["check_failures"]), ("down", 2))
        self.assertEqual((alert["severity"], alert["status"]), ("threat", "open"))

        with patch.object(device_monitor, "check_device", return_value=True):
            device_monitor.poll_once(self.app, [self.device["id"]])
        with self.app.app_context():
            row = database.query(
                "SELECT status, check_failures FROM devices WHERE id = ?",
                (self.device["id"],), one=True,
            )
            alert = database.query(
                "SELECT status FROM alerts WHERE fingerprint = ?",
                (f"device_down:{self.device['id']}",), one=True,
            )
        self.assertEqual((row["status"], row["check_failures"]), ("healthy", 0))
        self.assertEqual(alert["status"], "resolved")

    def test_devices_without_ip_are_not_probed_or_alerted(self):
        with self.app.app_context():
            device_id = database.execute(
                "INSERT INTO devices (name, role, ip, type) VALUES (?, ?, NULL, ?)",
                ("NO-IP-DEVICE", "not configured", "server"),
            )
        with patch.object(device_monitor, "check_device") as check:
            device_monitor.poll_once(self.app, [device_id])
        check.assert_not_called()
        with self.app.app_context():
            device = database.query(
                "SELECT status, last_checked FROM devices WHERE id = ?", (device_id,), one=True
            )
            alerts = database.query(
                "SELECT COUNT(*) AS c FROM alerts WHERE device_name = ?",
                ("NO-IP-DEVICE",), one=True,
            )["c"]
        self.assertEqual((device["status"], device["last_checked"]), ("unknown", None))
        self.assertEqual(alerts, 0)

    def test_configured_tcp_probe_succeeds_when_ping_does_not(self):
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with patch.object(
                device_monitor.subprocess, "run", return_value=SimpleNamespace(returncode=1)
            ):
                self.assertTrue(device_monitor.check_device("127.0.0.1", (port,), 1))
        finally:
            listener.close()

    def test_switch_status_uses_switch_monitor_without_duplicate_device_alerts(self):
        with self.app.app_context():
            switch = monitoring.all_switches()[0]
            switch_id, device_id = switch["id"], switch["device_id"]
            with patch.object(device_monitor, "check_device") as check:
                device_monitor.poll_once(self.app, [device_id])
            check.assert_not_called()

            monitoring.apply_switch_poll(switch, reachable=False)
            monitoring.apply_switch_poll(
                monitoring.get_switch(switch_id), reachable=False
            )
            device = database.query(
                "SELECT status, last_checked FROM devices WHERE id = ?", (device_id,), one=True
            )
            offline_alert = database.query(
                "SELECT category, status FROM alerts WHERE fingerprint = ?",
                (f"switch_offline:{switch['name']}",), one=True,
            )
            duplicate = database.query(
                "SELECT COUNT(*) AS c FROM alerts WHERE fingerprint = ?",
                (f"device_down:{device_id}",), one=True,
            )["c"]
        self.assertEqual(device["status"], "down")
        self.assertIsNotNone(device["last_checked"])
        self.assertEqual((offline_alert["category"], offline_alert["status"]), ("switch", "open"))
        self.assertEqual(duplicate, 0)

        with self.app.app_context():
            monitoring.apply_switch_poll(
                monitoring.get_switch(switch_id), reachable=True, snmp_ok=False
            )
            device = database.query(
                "SELECT status FROM devices WHERE id = ?", (device_id,), one=True
            )
            offline_alert = database.query(
                "SELECT status FROM alerts WHERE fingerprint = ?",
                (f"switch_offline:{switch['name']}",), one=True,
            )
            snmp_alert = database.query(
                "SELECT status FROM alerts WHERE fingerprint = ?",
                (f"snmp_down:{switch['name']}",), one=True,
            )
        self.assertEqual(device["status"], "warning")
        self.assertEqual(offline_alert["status"], "resolved")
        self.assertEqual(snmp_alert["status"], "open")

        with self.app.app_context():
            monitoring.apply_switch_poll(
                monitoring.get_switch(switch_id), reachable=True, snmp_ok=True
            )
            device = database.query(
                "SELECT status FROM devices WHERE id = ?", (device_id,), one=True
            )
            snmp_alert = database.query(
                "SELECT status FROM alerts WHERE fingerprint = ?",
                (f"snmp_down:{switch['name']}",), one=True,
            )
        self.assertEqual(device["status"], "healthy")
        self.assertEqual(snmp_alert["status"], "resolved")

    def test_switch_maintenance_suppresses_offline_alert_and_marks_badge(self):
        with self.app.app_context():
            switch = monitoring.all_switches()[0]
            starts = database.now_iso()
            ends = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
            database.execute(
                "INSERT INTO maintenance_windows "
                "(device_id, reason, starts_at, ends_at, created_by) "
                "VALUES (?, ?, ?, ?, ?)",
                (switch["device_id"], "Planned switch work", starts, ends, "admin"),
            )
            monitoring.apply_switch_poll(switch, reachable=False)
            monitoring.apply_switch_poll(
                monitoring.get_switch(switch["id"]), reachable=False
            )
            alert = database.query(
                "SELECT id FROM alerts WHERE fingerprint = ?",
                (f"switch_offline:{switch['name']}",), one=True,
            )
            device = database.query(
                "SELECT last_checked, status FROM devices WHERE id = ?",
                (switch["device_id"],), one=True,
            )
            display = switches._build(switch["id"])[0]
        self.assertIsNone(alert)
        self.assertIsNotNone(device["last_checked"])
        self.assertEqual(device["status"], "down")
        self.assertEqual(display["health"], "maintenance")

        with self.app.app_context():
            database.execute("UPDATE maintenance_windows SET is_active = 0")
            monitoring.apply_switch_poll(
                monitoring.get_switch(switch["id"]), reachable=False
            )
            alert = database.query(
                "SELECT id FROM alerts WHERE fingerprint = ?",
                (f"switch_offline:{switch['name']}",), one=True,
            )
        self.assertIsNotNone(alert)

    def test_status_page_feed_is_authenticated_and_does_not_probe_in_get(self):
        with patch.object(device_monitor, "check_device") as check:
            response = self.client.get("/network")
            servers = self.client.get("/servers")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"data-device-status-url=\"/api/v1/device-status\"", response.data)
        self.assertIn(b"No IP", response.data)
        self.assertEqual(servers.status_code, 200)
        self.assertIn(b"data-device-status-url=\"/api/v1/device-status\"", servers.data)
        check.assert_not_called()

        feed = self.client.get("/api/v1/device-status?auto=1")
        self.assertEqual(feed.status_code, 200)
        device = next(
            item for item in feed.json["devices"] if item["id"] == self.device["id"]
        )
        self.assertEqual((device["status"], device["last_check_label"]),
                         ("unknown", "Waiting for first check"))

        anonymous = self.app.test_client().get("/api/v1/device-status?auto=1")
        self.assertEqual(anonymous.status_code, 302)

    def test_existing_devices_table_gets_last_check_columns_additively(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, "
                "type TEXT NOT NULL DEFAULT 'vm')"
            )
            connection.execute(
                "INSERT INTO devices (name, type) VALUES ('LEGACY-DEVICE', 'server')"
            )
            connection.commit()
        finally:
            connection.close()

        legacy_app = Flask(__name__)
        legacy_app.config.update(
            DATABASE=str(legacy_path),
            DEMO_MODE=False,
            REFRESH_SECONDS=1800,
        )
        database.init_db(legacy_app)
        with legacy_app.app_context():
            columns = {
                row["name"] for row in database.query("PRAGMA table_info(devices)")
            }
            row = database.query(
                "SELECT name, status, last_checked, check_failures FROM devices "
                "WHERE name = 'LEGACY-DEVICE'",
                one=True,
            )
        self.assertTrue({"last_checked", "check_failures"} <= columns)
        self.assertEqual(
            (row["name"], row["status"], row["last_checked"], row["check_failures"]),
            ("LEGACY-DEVICE", "unknown", None, 0),
        )


if __name__ == "__main__":
    unittest.main()

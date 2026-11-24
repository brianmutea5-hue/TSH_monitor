import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from flask import Flask

import auth
import database
import views


class LiveHostTelemetryTests(unittest.TestCase):
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
            REFRESH_SECONDS=1800,
            CPU_WARN=80,
            CPU_THREAT=95,
            MEMORY_WARN=85,
            MEMORY_THREAT=98,
            DISK_WARN=85,
            DISK_THREAT=98,
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
            SESSION_COOKIE_SECURE=False,
            MAX_LOGIN_ATTEMPTS=5,
            LOCKOUT_MINUTES=5,
        )
        self.app.register_blueprint(auth.bp)
        self.app.register_blueprint(views.bp)

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
        self.client = self.app.test_client()
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "admin"

    def tearDown(self):
        self.temp_dir.cleanup()

    def ingest(self, payload, token=None):
        return self.client.post(
            "/api/v1/telemetry",
            json=payload,
            headers={
                "Authorization": "Bearer " + (
                    token or self.app.config["TELEMETRY_TOKEN"]
                )
            },
        )

    def test_real_metrics_update_host_cards_and_threshold_alerts(self):
        rejected = self.ingest(
            {"device": "TSHSER001", "metrics": {"cpu": 96}},
            token="invalid-token",
        )
        self.assertEqual(rejected.status_code, 401)

        accepted = self.ingest({
            "device": "TSHSER001",
            "metrics": {"cpu": 96, "memory": 50, "disk": 42, "uptime_hours": 100},
        })
        self.assertEqual(accepted.status_code, 200)
        with self.app.app_context():
            device = database.query(
                "SELECT cpu, memory, disk, status FROM devices WHERE name = ?",
                ("TSHSER001",), one=True,
            )
            alert = database.query(
                "SELECT severity, status FROM alerts "
                "WHERE device_name = ? AND title = ?",
                ("TSHSER001", "High CPU utilization"), one=True,
            )
            cards = views._host_cards()
        self.assertEqual(
            (device["cpu"], device["memory"], device["disk"], device["status"]),
            (96.0, 50.0, 42.0, "threat"),
        )
        self.assertEqual((alert["severity"], alert["status"]), ("threat", "open"))
        host = next(card for card in cards if card["name"] == "TSHSER001")
        self.assertEqual((host["cpu"], host["memory"], host["disk"], host["state"]),
                         (96.0, 50.0, 42.0, "threat"))

        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"96%", page.data)
        self.assertIn(b"50%", page.data)
        self.assertIn(b"42%", page.data)
        self.assertIn(b'data-host-metrics-url="/api/v1/host-metrics"', page.data)

        recovered = self.ingest({
            "device": "TSHSER001",
            "metrics": {"cpu": 20, "memory": 50, "disk": 42, "uptime_hours": 101},
        })
        self.assertEqual(recovered.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT status FROM alerts WHERE device_name = ? AND title = ?",
                ("TSHSER001", "High CPU utilization"), one=True,
            )
        self.assertEqual(alert["status"], "resolved")

    def test_invalid_or_stale_metrics_are_not_presented_as_live(self):
        invalid = self.ingest({
            "device": "TSHSER001",
            "metrics": {"cpu": 101},
        })
        self.assertEqual(invalid.status_code, 400)
        oversized = self.ingest({
            "device": "TSHSER001",
            "metrics": {"cpu": 10 ** 400},
        })
        self.assertEqual(oversized.status_code, 400)

        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Unknown", page.data)

        accepted = self.ingest({
            "device": "TSHSER001",
            "metrics": {"cpu": 40, "memory": 60, "disk": 50},
        })
        self.assertEqual(accepted.status_code, 200)
        with self.app.app_context():
            database.execute(
                "UPDATE device_telemetry SET last_seen = '2000-01-01 00:00:00' "
                "WHERE device_id = (SELECT id FROM devices WHERE name = ?)",
                ("TSHSER001",),
            )
            database.execute(
                "UPDATE devices SET last_checked = '2000-01-01 00:00:00' "
                "WHERE name = ?",
                ("TSHSER001",),
            )
            cards = views._host_cards()
            with patch.object(views, "query", wraps=views.query) as query_spy:
                views._host_cards()
                self.assertEqual(query_spy.call_count, 1)
            with patch.object(views, "query", wraps=views.query) as query_spy:
                views._summary(cards)
                self.assertEqual(query_spy.call_count, 1)
        host = next(card for card in cards if card["name"] == "TSHSER001")
        self.assertEqual((host["state"], host["cpu"], host["memory"], host["disk"]),
                         ("unknown", None, None, None))

        feed = self.client.get("/api/v1/host-metrics?auto=1")
        self.assertEqual(feed.status_code, 200)
        stale = next(host for host in feed.json["hosts"] if host["name"] == "TSHSER001")
        self.assertEqual((stale["state"], stale["cpu"]), ("unknown", None))

    def test_status_only_telemetry_updates_state_without_refreshing_metrics(self):
        metrics = self.ingest({
            "device": "TSHSER001",
            "metrics": {"cpu": 40, "memory": 60, "disk": 50},
        })
        self.assertEqual(metrics.status_code, 200)
        with self.app.app_context():
            previous_seen = database.query(
                "SELECT last_seen FROM device_telemetry "
                "WHERE device_id = (SELECT id FROM devices WHERE name = ?)",
                ("TSHSER001",), one=True,
            )["last_seen"]

        rejected = self.ingest({"device": "TSHSER001", "status": "not-a-status"})
        self.assertEqual(rejected.status_code, 400)
        status_only = self.ingest({"device": "TSHSER001", "status": "warning"})
        self.assertEqual(status_only.status_code, 200)
        with self.app.app_context():
            device = database.query(
                "SELECT status, last_checked, cpu FROM devices WHERE name = ?",
                ("TSHSER001",), one=True,
            )
            seen = database.query(
                "SELECT last_seen FROM device_telemetry "
                "WHERE device_id = (SELECT id FROM devices WHERE name = ?)",
                ("TSHSER001",), one=True,
            )["last_seen"]
            status_audit = database.query(
                "SELECT COUNT(*) AS c FROM audit_logs "
                "WHERE action = 'device_status_changed' AND detail LIKE '%warning'",
                one=True,
            )["c"]
        self.assertEqual((device["status"], device["cpu"]), ("warning", 40.0))
        self.assertIsNotNone(device["last_checked"])
        self.assertEqual(seen, previous_seen)
        self.assertEqual(status_audit, 1)

    def test_existing_telemetry_table_gets_status_column_additively(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE device_telemetry ("
                "device_id INTEGER PRIMARY KEY, last_seen TEXT NOT NULL)"
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
                row["name"] for row in database.query("PRAGMA table_info(device_telemetry)")
            }
            cards = views._host_cards()
        self.assertIn("status", columns)
        self.assertTrue(cards)
        self.assertTrue(all(card["state"] == "unknown" for card in cards))


if __name__ == "__main__":
    unittest.main()

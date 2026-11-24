import sqlite3
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from flask import Flask, session
from werkzeug.security import generate_password_hash

import auth
import database
import switches
import users
import views
from config import production_config_errors
from switch_monitor import UsmUserData, _auth_data, snmp_configured


class MonitoringUpgradeTests(unittest.TestCase):
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
            TESTING=True,
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=5),
            SESSION_COOKIE_SECURE=True,
            TELEMETRY_TOKEN="test-telemetry-token-that-is-long-enough",
            TELEMETRY_TOKEN_CONFIGURED=True,
            TELEMETRY_STALE_SECONDS=180,
            CPU_WARN=80,
            CPU_THREAT=95,
            MEMORY_WARN=85,
            MEMORY_THREAT=98,
            DISK_WARN=85,
            DISK_THREAT=98,
            AP_CLIENTS_WARN=50,
            AP_CLIENTS_THREAT=80,
            AP_CHANNEL_WARN=70,
            AP_CHANNEL_THREAT=90,
            AP_RSSI_WARN=-75,
            AP_RSSI_THREAT=-85,
            GUEST_DNS_LATENCY_WARN_MS=250,
            GUEST_DNS_LATENCY_THREAT_MS=1000,
            GUEST_DHCP_LATENCY_WARN_MS=500,
            GUEST_DHCP_LATENCY_THREAT_MS=2000,
            SWITCH_MONITOR_ENABLED=False,
            SWITCH_SNMP_VERSION="2c",
            SWITCH_SNMP_COMMUNITY="",
        )
        self.app.register_blueprint(auth.bp)
        self.app.register_blueprint(switches.bp)
        self.app.register_blueprint(users.bp)
        self.app.register_blueprint(views.bp)

        @self.app.before_request
        def security_hooks():
            response = auth.enforce_idle_timeout()
            if response is not None:
                return response
            return auth.protect_csrf()

        @self.app.get("/test-protected")
        def test_protected():
            return "ok"

        @self.app.get("/test-cookie")
        def test_cookie():
            session["cookie_test"] = True
            return "ok"

        @self.app.post("/test-post")
        def test_post():
            return "ok"

        self.app.jinja_env.filters["uptime"] = (
            lambda hours: "-" if hours is None else f"{hours // 24}d {hours % 24:02d}h"
        )

        @self.app.context_processor
        def template_globals():
            return {
                "csrf_token": auth.csrf_token,
                "now": "test",
                "open_alert_count": 0,
                "simulation_mode": self.app.config["DEMO_MODE"],
                "workspace_name": "Test workspace",
                "initials": "TS",
                "refresh_seconds": 10,
                "cfg": self.app.config,
            }

        database.init_db(self.app)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def ingest(self, payload, token=None):
        return self.client.post(
            "/api/v1/telemetry",
            json=payload,
            headers={"Authorization": f"Bearer {token or self.app.config['TELEMETRY_TOKEN']}"},
        )

    def add_device(self, name, device_type, **fields):
        values = {"name": name, "role": "", "ip": None, "type": device_type}
        values.update(fields)
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        with self.app.app_context():
            database.execute(
                f"INSERT INTO devices ({columns}) VALUES ({placeholders})",
                tuple(values.values()),
            )

    def test_idle_timeout_ignores_auto_activity_but_still_expires(self):
        old_activity = time.time() - 30
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "operator"
            browser_session["last_active"] = old_activity

        response = self.client.get("/test-protected?auto=1")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as browser_session:
            self.assertEqual(browser_session["last_active"], old_activity)

        expired_activity = time.time() - 600
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "operator"
            browser_session["last_active"] = expired_activity
        response = self.client.get("/test-protected?auto=1")
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("user", browser_session)

    def test_secure_cookie_and_csrf_protection(self):
        response = self.client.get("/test-cookie")
        self.assertIn("Secure", response.headers["Set-Cookie"])
        self.assertEqual(self.client.post("/test-post").status_code, 400)

        with self.client.session_transaction() as browser_session:
            browser_session["_csrf"] = "expected-token"
        response = self.client.post("/test-post", data={"_csrf": "expected-token"})
        self.assertEqual(response.status_code, 200)

    def test_demo_word_is_absent_from_rendered_pages(self):
        self.app.config["DEMO_MODE"] = True
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "operator"
            browser_session["_csrf"] = "test-token"

        for path in ("/", "/network", "/alerts", "/threats", "/settings"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(b"demo", response.data.lower())

    def test_production_configuration_rejects_missing_or_weak_credentials(self):
        missing = {
            "DEMO_MODE": False,
            "SECRET_KEY_CONFIGURED": False,
            "SECRET_KEY": "",
            "ADMIN_USERNAME_CONFIGURED": False,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "",
            "ADMIN_PASSWORD_HASH": "",
        }
        self.assertEqual(len(production_config_errors(missing)), 3)

        valid = {
            **missing,
            "SECRET_KEY_CONFIGURED": True,
            "SECRET_KEY": "Strong-Secret-Key-2026-" * 3,
            "ADMIN_USERNAME_CONFIGURED": True,
            "ADMIN_USERNAME": "soc-admin",
            "ADMIN_PASSWORD": "A-strong-password-2026",
            "SESSION_COOKIE_SECURE": True,
        }
        self.assertEqual(production_config_errors(valid), [])
        self.assertTrue(production_config_errors({**valid, "SESSION_COOKIE_SECURE": False}))
        valid_hash = {
            **valid,
            "ADMIN_PASSWORD": "",
            "ADMIN_PASSWORD_HASH": generate_password_hash("Configured-admin-password-2026"),
        }
        self.assertEqual(production_config_errors(valid_hash), [])
        malformed_hash = {**valid_hash, "ADMIN_PASSWORD_HASH": "pbkdf2:not-a-valid-hash"}
        self.assertTrue(production_config_errors(malformed_hash))

    def test_telemetry_bearer_auth_and_host_alert_recovery(self):
        self.add_device("test-server", "server")
        unauthorized = self.ingest(
            {"device": "test-server", "metrics": {"cpu": 96}},
            token="incorrect-token",
        )
        self.assertEqual(unauthorized.status_code, 401)

        accepted = self.ingest({"device": "test-server", "metrics": {"cpu": 96}})
        self.assertEqual(accepted.status_code, 200)
        with self.app.app_context():
            device = database.query(
                "SELECT status, cpu FROM devices WHERE name = ?",
                ("test-server",), one=True,
            )
            alert = database.query(
                "SELECT severity, status FROM alerts "
                "WHERE device_name = ? AND title = ?",
                ("test-server", "High CPU utilization"), one=True,
            )
        self.assertEqual((device["status"], device["cpu"]), ("threat", 96.0))
        self.assertEqual((alert["severity"], alert["status"]), ("threat", "open"))

        recovered = self.ingest({"device": "test-server", "metrics": {"cpu": 20}})
        self.assertEqual(recovered.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT status FROM alerts WHERE device_name = ? AND title = ?",
                ("test-server", "High CPU utilization"), one=True,
            )
        self.assertEqual(alert["status"], "resolved")

    def test_access_point_kpi_creates_and_resolves_threshold_alert(self):
        self.add_device("test-ap", "access_point")
        response = self.ingest({
            "device": "test-ap",
            "metrics": {
                "connected_clients": 24,
                "channel_utilization": 20,
                "avg_rssi": -60,
                "dns_latency_ms": 1500,
                "dhcp_latency_ms": 100,
            },
        })
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT severity, status FROM alerts "
                "WHERE device_name = ? AND title = ?",
                ("test-ap", "High guest DNS latency"), one=True,
            )
        self.assertEqual((alert["severity"], alert["status"]), ("threat", "open"))

        response = self.ingest({
            "device": "test-ap",
            "metrics": {
                "connected_clients": 24,
                "channel_utilization": 20,
                "avg_rssi": -60,
                "dns_latency_ms": 80,
                "dhcp_latency_ms": 100,
            },
        })
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT status FROM alerts WHERE device_name = ? AND title = ?",
                ("test-ap", "High guest DNS latency"), one=True,
            )
        self.assertEqual(alert["status"], "resolved")

    def test_stale_host_data_is_unknown_and_queries_are_aggregated(self):
        self.add_device("stale-host", "host", status="healthy", cpu=20)
        with self.app.app_context():
            cards = views._host_cards()
            stale_host = next(card for card in cards if card["name"] == "stale-host")
            self.assertEqual(stale_host["state"], "unknown")

            with patch.object(views, "query", wraps=views.query) as query_spy:
                views._host_cards()
                self.assertEqual(query_spy.call_count, 1)
            with patch.object(views, "query", wraps=views.query) as query_spy:
                views._summary(cards)
                self.assertEqual(query_spy.call_count, 1)

    def test_stale_host_metrics_are_not_used_for_new_threshold_decisions(self):
        self.add_device("stale-metric-host", "host", cpu=99)
        response = self.ingest({
            "device": "stale-metric-host",
            "metrics": {"temp": 42},
        })
        self.assertEqual(response.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT id FROM alerts WHERE device_name = ? AND title = ?",
                ("stale-metric-host", "High CPU utilization"), one=True,
            )
        self.assertIsNone(alert)

    def test_database_uses_wal_and_additive_telemetry_tables(self):
        with self.app.app_context():
            mode = database.query("PRAGMA journal_mode", one=True)[0]
            tables = {
                row["name"] for row in database.query(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertEqual(mode.lower(), "wal")
        self.assertTrue({"device_telemetry", "access_point_metrics", "monitor_status"} <= tables)

    def test_workbook_inventory_is_seeded_idempotently(self):
        with self.app.app_context():
            ap_counts = database.query(
                "SELECT COUNT(*) AS total, COUNT(DISTINCT ip) AS unique_ips "
                "FROM devices WHERE type = 'access_point'",
                one=True,
            )
            wan = database.query(
                "SELECT role, status FROM devices WHERE name = 'WAN 1'",
                one=True,
            )
            switch = database.query(
                "SELECT model FROM devices WHERE name = 'CORE-SWITCH'",
                one=True,
            )
        self.assertEqual((ap_counts["total"], ap_counts["unique_ips"]), (100, 100))
        self.assertEqual((wan["role"], wan["status"]), ("Safaricom", "unknown"))
        self.assertEqual(switch["model"], "ICX 7250-24p")

        database.init_db(self.app)
        with self.app.app_context():
            count = database.query(
                "SELECT COUNT(*) AS c FROM devices WHERE type = 'access_point'",
                one=True,
            )["c"]
        self.assertEqual(count, 100)

    def test_existing_database_gets_model_column_additively(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE devices ("
                "id INTEGER PRIMARY KEY, name TEXT UNIQUE, role TEXT DEFAULT '', "
                "ip TEXT, type TEXT DEFAULT 'vm', parent_id INTEGER, "
                "status TEXT DEFAULT 'unknown', cpu INTEGER, memory INTEGER, disk INTEGER, "
                "temp INTEGER, uptime_hours INTEGER)"
            )
            connection.execute(
                "INSERT INTO devices (name, role, type) VALUES ('legacy-device', 'kept', 'device')"
            )
            connection.commit()
        finally:
            connection.close()

        legacy_app = Flask(__name__)
        legacy_app.config["DATABASE"] = str(legacy_path)
        database.init_db(legacy_app)
        with legacy_app.app_context():
            device = database.query(
                "SELECT role, model FROM devices WHERE name = 'legacy-device'",
                one=True,
            )
        self.assertEqual((device["role"], device["model"]), ("kept", ""))

    def test_existing_access_point_metrics_gets_kpi_columns_additively(self):
        legacy_path = Path(self.temp_dir.name) / "legacy-ap.db"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE access_point_metrics ("
                "device_id INTEGER PRIMARY KEY, last_seen TEXT NOT NULL)"
            )
            connection.commit()
        finally:
            connection.close()

        legacy_app = Flask(__name__)
        legacy_app.config.update(DATABASE=str(legacy_path), DEMO_MODE=False)
        database.init_db(legacy_app)
        with legacy_app.app_context():
            columns = {
                row["name"] for row in database.query("PRAGMA table_info(access_point_metrics)")
            }
            views._decorate_device_rows(
                database.query("SELECT * FROM devices ORDER BY id")
            )
        self.assertTrue({
            "device_id", "last_seen", "status", "connected_clients",
            "channel_utilization", "avg_rssi", "dns_latency_ms", "dhcp_latency_ms",
        } <= columns)

    def test_wan_telemetry_alerts_recover_and_stale_links_are_unknown(self):
        self.add_device("WAN test link", "wan_link", role="Test ISP")
        unauthorized = self.ingest(
            {"device": "WAN test link", "status": "down"},
            token="incorrect-token",
        )
        self.assertEqual(unauthorized.status_code, 401)

        invalid = self.ingest({
            "device": "WAN test link",
            "status": "down",
            "metrics": {"cpu": 99},
        })
        self.assertEqual(invalid.status_code, 400)

        down = self.ingest({"device": "WAN test link", "status": "down"})
        self.assertEqual(down.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT severity, status FROM alerts "
                "WHERE device_name = ? AND title = ?",
                ("WAN test link", "WAN link unavailable"),
                one=True,
            )
        self.assertEqual((alert["severity"], alert["status"]), ("threat", "open"))

        recovered = self.ingest({"device": "WAN test link", "status": "healthy"})
        self.assertEqual(recovered.status_code, 200)
        with self.app.app_context():
            alert = database.query(
                "SELECT status FROM alerts WHERE device_name = ? AND title = ?",
                ("WAN test link", "WAN link unavailable"),
                one=True,
            )
        self.assertEqual(alert["status"], "resolved")

        with self.app.app_context():
            database.execute(
                "UPDATE device_telemetry SET last_seen = '2000-01-01 00:00:00' "
                "WHERE device_id = (SELECT id FROM devices WHERE name = ?)",
                ("WAN test link",),
            )
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "operator"
        response = self.client.get("/network")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"WAN test link", response.data)
        self.assertIn(b"Unknown", response.data)

    def test_vendor_contacts_are_available_on_alerts_page(self):
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "operator"
        response = self.client.get("/alerts")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Vendor escalation contacts", response.data)
        self.assertIn(b"Businesssupport@ke.airtel.com", response.data)

    def test_network_get_does_not_poll_and_csrf_protected_post_does(self):
        self.app.config["SWITCH_SNMP_COMMUNITY"] = "test-community"
        with self.client.session_transaction() as browser_session:
            browser_session["user"] = "operator"
            browser_session["_csrf"] = "network-csrf"

        with patch.object(views, "refresh_switch_ports", return_value={}) as poll:
            response = self.client.get("/network")
            self.assertEqual(response.status_code, 200)
            poll.assert_not_called()

            response = self.client.post(
                "/network", data={"_csrf": "network-csrf"}
            )
            self.assertEqual(response.status_code, 302)
            poll.assert_called_once_with()

    def test_snmpv3_profile_is_validated_without_revealing_keys(self):
        profile = {
            "SWITCH_SNMP_VERSION": "3",
            "SWITCH_SNMP_V3_USERNAME": "monitor",
            "SWITCH_SNMP_V3_SECURITY_LEVEL": "authPriv",
            "SWITCH_SNMP_V3_AUTH_KEY": "auth-key-for-tests",
            "SWITCH_SNMP_V3_AUTH_PROTOCOL": "SHA256",
            "SWITCH_SNMP_V3_PRIV_KEY": "priv-key-for-tests",
            "SWITCH_SNMP_V3_PRIV_PROTOCOL": "AES128",
        }
        self.assertTrue(snmp_configured(profile))
        self.assertIsInstance(_auth_data(profile), UsmUserData)
        self.assertFalse(snmp_configured({
            "SWITCH_SNMP_VERSION": "3",
            "SWITCH_SNMP_V3_USERNAME": "monitor",
            "SWITCH_SNMP_V3_SECURITY_LEVEL": "authPriv",
        }))


if __name__ == "__main__":
    unittest.main()

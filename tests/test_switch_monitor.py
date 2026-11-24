import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import switch_monitor


class ReadSwitchTests(unittest.TestCase):
    def test_read_switch_preserves_recorded_interface_labels_and_status(self):
        recorded_columns = {
            switch_monitor.IF_DESCR_OID: {
                1: "uplink description",
                7: "camera interface",
            },
            switch_monitor.IF_NAME_OID: {
                1: "uplink-A",
                7: "camera-B",
            },
            switch_monitor.IF_OPER_STATUS_OID: {
                1: "1",
                7: "2",
            },
        }

        async def walk_column(engine, community, target, column_oid):
            self.assertIsNotNone(engine)
            self.assertIsInstance(community, switch_monitor.CommunityData)
            self.assertIsNotNone(target)
            return recorded_columns[column_oid]

        engine = SimpleNamespace(close_dispatcher=Mock())
        with (
            patch.object(switch_monitor, "SnmpEngine", return_value=engine),
            patch.object(
                switch_monitor.UdpTransportTarget,
                "create",
                new=AsyncMock(return_value=object()),
            ),
            patch.object(
                switch_monitor,
                "_get_sys_uptime",
                new=AsyncMock(return_value="987654"),
            ),
            patch.object(switch_monitor, "_walk_column", side_effect=walk_column),
        ):
            result = switch_monitor.read_switch("192.0.2.10", "test-community")

        self.assertEqual(result["sysUpTime"], "987654")
        self.assertEqual(result["interfaces"], [
            {
                "ifIndex": 1,
                "ifName": "uplink-A",
                "ifDescr": "uplink description",
                "ifOperStatus": "1",
            },
            {
                "ifIndex": 7,
                "ifName": "camera-B",
                "ifDescr": "camera interface",
                "ifOperStatus": "2",
            },
        ])
        engine.close_dispatcher.assert_called_once_with()

    def test_read_switch_exposes_ruckus_ports_for_background_monitoring(self):
        recorded_columns = {
            switch_monitor.IF_DESCR_OID: {1: "ethernet 1/1/1"},
            switch_monitor.IF_NAME_OID: {1: "1/1/1"},
            switch_monitor.IF_OPER_STATUS_OID: {1: "1"},
            switch_monitor.IF_ADMIN_STATUS_OID: {1: "1"},
            switch_monitor.IF_ALIAS_OID: {1: "Guest Wi-Fi uplink"},
        }

        async def walk_column(engine, community, target, column_oid):
            return recorded_columns[column_oid]

        engine = SimpleNamespace(close_dispatcher=Mock())
        with (
            patch.object(switch_monitor, "SnmpEngine", return_value=engine),
            patch.object(
                switch_monitor.UdpTransportTarget,
                "create",
                new=AsyncMock(return_value=object()),
            ),
            patch.object(
                switch_monitor,
                "_get_sys_uptime",
                new=AsyncMock(return_value="Timeticks: (98765) 0:16:27.65"),
            ),
            patch.object(switch_monitor, "_walk_column", side_effect=walk_column),
        ):
            result = switch_monitor.read_switch(
                "192.0.2.10", "test-community", include_ports=True
            )

        self.assertEqual(result["uptime"], 987)
        self.assertEqual(result["ports"], {
            "1/1/1": {
                "oper": "up",
                "admin": "up",
                "alias": "Guest Wi-Fi uplink",
            }
        })


if __name__ == "__main__":
    unittest.main()

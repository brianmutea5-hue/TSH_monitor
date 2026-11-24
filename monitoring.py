"""Switch monitoring rules, shared by the web app, the collector and the demo buttons.

Everything that decides "is this a problem?" lives here, so a port that goes down
raises exactly the same alert whether it was found by SNMP, by a syslog message,
or by the "Simulate" button in demo mode.
"""
import re
from datetime import datetime, timedelta

from flask import current_app

import seed_data
from database import (
    DEVICE_STATUSES, audit, execute, get_status, is_in_maintenance,
    now_iso, query, set_status,
)

THREATS = {
    key: {"key": key, "title": title, "severity": sev, "how": how, "meaning": meaning, "action": action}
    for key, title, sev, how, meaning, action in seed_data.SWITCH_THREATS
}
KIND_ORDER = "CASE s.kind WHEN 'core' THEN 0 WHEN 'floor' THEN 1 ELSE 2 END"
SWITCH_SELECT = (
    "SELECT s.*, d.name AS name, d.ip AS ip FROM switches s JOIN devices d ON d.id = s.device_id"
)


def _cfg(name, default):
    return current_app.config.get(name, default)


# ----------------------------------------------------------------------- alerts
def raise_alert(title, severity, device_name, message, recommendation, category="switch",
                switch_id=None, port_label="", fingerprint=None, maintenance_down=False):
    """Create an alert unless the same one is still open. Returns (alert_id, created)."""
    device = query(
        "SELECT id FROM devices WHERE name = ? COLLATE NOCASE",
        (device_name,),
        one=True,
    )
    if device and is_in_maintenance(device["id"]) and (
        severity == "warning" or maintenance_down
    ):
        return None, False
    stamp = now_iso()
    if fingerprint:
        row = query("SELECT id FROM alerts WHERE fingerprint = ? AND status != 'resolved'", (fingerprint,), one=True)
        if row:
            execute("UPDATE alerts SET occurrences = occurrences + 1, last_seen = ? WHERE id = ?", (stamp, row["id"]))
            return row["id"], False
    alert_id = execute(
        "INSERT INTO alerts (title, severity, device_name, message, recommendation, status, created_at,"
        " category, switch_id, port_label, fingerprint, occurrences, last_seen)"
        " VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, 1, ?)",
        (title, severity, device_name, message, recommendation, stamp, category, switch_id, port_label or "", fingerprint, stamp),
    )
    audit("alert_raised", f"{title} on {device_name}" + (f" port {port_label}" if port_label else ""), actor="monitor")
    current_app.logger.warning("ALERT %s: %s on %s %s", severity, title, device_name, port_label or "")
    return alert_id, True


def resolve_alerts(fingerprint_prefix, note):
    """Close every open alert whose fingerprint starts with the given text."""
    rows = query(
        "SELECT id, title, device_name FROM alerts WHERE fingerprint IS NOT NULL AND status != 'resolved'"
        " AND substr(fingerprint, 1, length(?)) = ?", (fingerprint_prefix, fingerprint_prefix),
    )
    for row in rows:
        execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (row["id"],))
        audit("alert_resolved", f"{row['title']} on {row['device_name']} - {note}", actor="monitor")
    return len(rows)


# -------------------------------------------------------------- host telemetry
HOST_METRIC_RULES = {
    "cpu": ("CPU_WARN", "CPU_THREAT", "High CPU utilization"),
    "memory": ("MEMORY_WARN", "MEMORY_THREAT", "High memory utilization"),
    "disk": ("DISK_WARN", "DISK_THREAT", "High disk utilization"),
}
ACCESS_POINT_METRIC_RULES = {
    "connected_clients": (
        "AP_CLIENTS_WARN", "AP_CLIENTS_THREAT", "High AP client count",
    ),
    "channel_utilization": (
        "AP_CHANNEL_WARN", "AP_CHANNEL_THREAT", "High AP channel utilization",
    ),
    "dns_latency_ms": (
        "GUEST_DNS_LATENCY_WARN_MS", "GUEST_DNS_LATENCY_THREAT_MS",
        "High guest DNS latency",
    ),
    "dhcp_latency_ms": (
        "GUEST_DHCP_LATENCY_WARN_MS", "GUEST_DHCP_LATENCY_THREAT_MS",
        "High guest DHCP latency",
    ),
}


def apply_device_status(device, status, last_checked=None, check_failures=None):
    """Persist a validated device state and audit/alert only on state transitions."""
    if status not in DEVICE_STATUSES:
        raise ValueError(f"Unsupported device status: {status}")
    previous = device["status"]
    stamp = last_checked or now_iso()
    if check_failures is None:
        execute(
            "UPDATE devices SET status = ?, last_checked = ? WHERE id = ?",
            (status, stamp, device["id"]),
        )
    else:
        execute(
            "UPDATE devices SET status = ?, last_checked = ?, check_failures = ? WHERE id = ?",
            (status, stamp, check_failures, device["id"]),
        )

    fingerprint = f"device_down:{device['id']}"
    if previous != status:
        audit(
            "device_status_changed",
            f"{device['name']}: {previous} -> {status}",
            actor="monitor",
        )
    if status == "down" and not is_in_maintenance(device["id"]):
        existing = query(
            "SELECT 1 FROM alerts WHERE fingerprint = ? AND status != 'resolved' LIMIT 1",
            (fingerprint,),
            one=True,
        )
        if not existing:
            raise_alert(
                "Device unavailable", "threat", device["name"],
                f"{device['name']} did not respond to its configured reachability checks.",
                "Check the device power, network link, and configured check ports.",
                category="device", fingerprint=fingerprint, maintenance_down=True,
            )
    elif previous == "down" and status != "down":
        resolve_alerts(fingerprint, "device responded to a reachability check")


def apply_host_telemetry(device, metrics=None, reported_status=None):
    """Store one host-agent snapshot, raise threshold alerts and resolve recovered metrics."""
    name = device["name"]
    if reported_status is not None and reported_status not in DEVICE_STATUSES:
        raise ValueError(f"Unsupported device status: {reported_status}")
    active_states = []
    primary_metric_received = False

    if metrics is not None:
        for metric, (warn_key, threat_key, title) in HOST_METRIC_RULES.items():
            if metric not in metrics:
                continue
            primary_metric_received = True
            value = metrics[metric]
            fingerprint = f"host_metric:{name}:{metric}"
            if value >= _cfg(threat_key, 98):
                severity = "threat"
            elif value >= _cfg(warn_key, 85):
                severity = "warning"
            else:
                severity = None

            if severity:
                active_states.append(severity)
                raise_alert(
                    title, severity, name,
                    f"{metric.capitalize()} utilization is {value:g}%.",
                    "Check current resource usage and the processes using it.",
                    category="host", fingerprint=fingerprint,
                )
            else:
                resolve_alerts(fingerprint, f"{metric} returned below its warning threshold")

    if reported_status == "down":
        status = "down"
    elif "threat" in active_states or reported_status == "threat":
        status = "threat"
    elif "warning" in active_states or reported_status == "warning":
        status = "warning"
    elif primary_metric_received or reported_status == "healthy":
        status = "healthy"
    else:
        status = reported_status or "unknown"

    stamp = now_iso()
    if metrics is not None:
        snapshot = {
            key: metrics.get(key)
            for key in ("cpu", "memory", "disk", "temp", "uptime_hours")
        }
        execute(
            "UPDATE devices SET cpu = ?, memory = ?, disk = ?, temp = ?, uptime_hours = ? WHERE id = ?",
            (
                snapshot["cpu"], snapshot["memory"], snapshot["disk"], snapshot["temp"],
                snapshot["uptime_hours"], device["id"],
            ),
        )
        execute(
            "INSERT INTO device_telemetry (device_id, last_seen, status) VALUES (?, ?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen, status = excluded.status",
            (device["id"], stamp, status),
        )

    apply_device_status(device, status, stamp, check_failures=0)
    return status


def apply_access_point_telemetry(device, metrics=None, reported_status=None):
    """Persist AP/guest Wi-Fi KPIs and raise or resolve threshold alerts."""
    name = device["name"]
    if reported_status is not None and reported_status not in DEVICE_STATUSES:
        raise ValueError(f"Unsupported device status: {reported_status}")
    if metrics is not None:
        for metric, (warn_key, threat_key, title) in ACCESS_POINT_METRIC_RULES.items():
            if metric not in metrics:
                continue
            value = metrics[metric]
            fingerprint = f"ap_metric:{name}:{metric}"
            if value >= _cfg(threat_key, 1000000):
                severity = "threat"
            elif value >= _cfg(warn_key, 1000000):
                severity = "warning"
            else:
                severity = None
            if severity:
                raise_alert(
                    title, severity, name,
                    f"{metric.replace('_', ' ').capitalize()} is {value:g}.",
                    "Check access point load and guest Wi-Fi service health.",
                    category="access_point", fingerprint=fingerprint,
                )
            else:
                resolve_alerts(fingerprint, f"{metric} returned below its warning threshold")

        if "avg_rssi" in metrics:
            value = metrics["avg_rssi"]
            fingerprint = f"ap_metric:{name}:avg_rssi"
            if value <= _cfg("AP_RSSI_THREAT", -85):
                severity = "threat"
            elif value <= _cfg("AP_RSSI_WARN", -75):
                severity = "warning"
            else:
                severity = None
            if severity:
                raise_alert(
                    "Low AP signal strength", severity, name,
                    f"Average guest Wi-Fi RSSI is {value:g} dBm.",
                    "Check AP placement, radio interference, and client signal coverage.",
                    category="access_point", fingerprint=fingerprint,
                )
            else:
                resolve_alerts(fingerprint, "signal strength returned above its warning threshold")

    active = query(
        "SELECT severity FROM alerts WHERE device_name = ? AND category = 'access_point' "
        "AND status != 'resolved'",
        (name,),
    )
    if reported_status == "down":
        status = "down"
    elif any(row["severity"] == "threat" for row in active) or reported_status == "threat":
        status = "threat"
    elif any(row["severity"] == "warning" for row in active) or reported_status == "warning":
        status = "warning"
    elif metrics is not None or reported_status == "healthy":
        status = "healthy"
    else:
        status = reported_status or "unknown"

    stamp = now_iso()
    fields = {
        "connected_clients": None,
        "channel_utilization": None,
        "avg_rssi": None,
        "dns_latency_ms": None,
        "dhcp_latency_ms": None,
    }
    if metrics is not None:
        fields.update(metrics)
    execute(
        "INSERT INTO access_point_metrics "
        "(device_id, last_seen, status, connected_clients, channel_utilization, avg_rssi, "
        "dns_latency_ms, dhcp_latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen, "
        "status = excluded.status, "
        "connected_clients = COALESCE(excluded.connected_clients, access_point_metrics.connected_clients), "
        "channel_utilization = COALESCE(excluded.channel_utilization, access_point_metrics.channel_utilization), "
        "avg_rssi = COALESCE(excluded.avg_rssi, access_point_metrics.avg_rssi), "
        "dns_latency_ms = COALESCE(excluded.dns_latency_ms, access_point_metrics.dns_latency_ms), "
        "dhcp_latency_ms = COALESCE(excluded.dhcp_latency_ms, access_point_metrics.dhcp_latency_ms)",
        (
            device["id"], stamp, status, fields["connected_clients"],
            fields["channel_utilization"], fields["avg_rssi"],
            fields["dns_latency_ms"], fields["dhcp_latency_ms"],
        ),
    )
    apply_device_status(device, status, stamp, check_failures=0)
    return status


def apply_wan_telemetry(device, reported_status):
    """Persist WAN link health and alert on a reported outage."""
    if reported_status not in DEVICE_STATUSES:
        raise ValueError(f"Unsupported device status: {reported_status}")
    stamp = now_iso()
    fingerprint = f"wan_link_down:{device['id']}"
    if reported_status == "down":
        raise_alert(
            "WAN link unavailable", "threat", device["name"],
            f"{device['name']} reported that its external link is unavailable.",
            "Check the ISP handoff, router interface, and upstream provider status.",
            category="wan", fingerprint=fingerprint, maintenance_down=True,
        )
    elif reported_status == "healthy":
        resolve_alerts(fingerprint, "WAN link recovered")
    execute(
        "INSERT INTO device_telemetry (device_id, last_seen, status) VALUES (?, ?, ?) "
        "ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen, status = excluded.status",
        (device["id"], stamp, reported_status),
    )
    apply_device_status(device, reported_status, stamp, check_failures=0)
    return reported_status


# ---------------------------------------------------------------------- lookups
def get_switch(switch_id):
    return query(SWITCH_SELECT + " WHERE s.id = ?", (switch_id,), one=True)


def find_switch(ref):
    """Find a switch by device name or IP address (used by syslog and the ingest API)."""
    ref = (ref or "").strip()
    return query(SWITCH_SELECT + " WHERE lower(d.name) = lower(?) OR d.ip = ?", (ref, ref), one=True)


def all_switches():
    return query(SWITCH_SELECT + f" ORDER BY s.floor_order, {KIND_ORDER}, d.name")


def get_port(switch_id, label):
    return query("SELECT * FROM switch_ports WHERE switch_id = ? AND label = ?", (switch_id, label), one=True)


def record_event(switch_id, port_label, event, detail=""):
    execute(
        "INSERT INTO switch_events (ts, switch_id, port_label, event, detail) VALUES (?, ?, ?, ?, ?)",
        (now_iso(), switch_id, port_label or "", event, detail),
    )


# ------------------------------------------------------------------------ ports
def _flapping(sw, port):
    since = (datetime.now() - timedelta(minutes=_cfg("FLAP_WINDOW_MINUTES", 10))).strftime("%Y-%m-%d %H:%M:%S")
    count = query(
        "SELECT COUNT(*) AS c FROM switch_events WHERE switch_id = ? AND port_label = ? AND event = 'port_down' AND ts >= ?",
        (sw["id"], port["label"], since), one=True,
    )["c"]
    return count >= _cfg("FLAP_LIMIT", 3), count


def apply_port(sw, port, oper, admin="up", alias=None, simulated=False):
    """Store a port reading and raise or clear alerts. `sw` and `port` are database rows."""
    stamp = now_iso()
    tag = "SIMULATED: " if simulated else ""
    label, name = port["label"], sw["name"]
    where = f"{name} ({sw['location']})"
    prev, prev_admin = port["oper_status"], port["admin_status"]
    expected = port["expected_up"]
    fp = f"port_down:{name}:{label}"

    if oper == "up" and admin == "up":
        expected = 1  # a port seen working is expected to stay working
    fields = {"oper_status": oper, "admin_status": admin, "expected_up": expected, "reported": 1}
    if alias is not None:
        fields["alias"] = alias
    if oper != prev:
        fields["changed_at"] = stamp
    sets = ", ".join(f"{k} = ?" for k in fields)
    execute(f"UPDATE switch_ports SET {sets} WHERE id = ?", (*fields.values(), port["id"]))

    if admin == "down":  # switched off on purpose: not a fault
        if prev_admin != "down":
            record_event(sw["id"], label, "port_disabled", "Switched off in the switch settings")
        resolve_alerts(fp, "port was switched off on purpose")
        return
    if oper == prev:
        if oper == "down" and expected and not is_in_maintenance(sw["device_id"]):
            existing = query(
                "SELECT 1 FROM alerts WHERE fingerprint = ? AND status != 'resolved' LIMIT 1",
                (fp,),
                one=True,
            )
            if not existing:
                threat = THREATS["uplink_down" if port["kind"] == "uplink" else "port_down"]
                raise_alert(
                    threat["title"], threat["severity"], name,
                    f"Port {label} on {where} remains down.",
                    threat["action"], "switch", sw["id"], label, fp,
                    maintenance_down=True,
                )
        return

    port_name = f" ({port['alias']})" if port["alias"] else ""
    if oper == "down":
        if prev == "up":
            record_event(sw["id"], label, "port_down", "SIMULATED" if simulated else "")
            flapping, count = _flapping(sw, port)
            if flapping:
                t = THREATS["port_flapping"]
                severity = "threat" if port["kind"] == "uplink" else t["severity"]
                raise_alert(t["title"], severity, name,
                            f"{tag}Port {label}{port_name} on {where} went down {count} times in "
                            f"{_cfg('FLAP_WINDOW_MINUTES', 10)} minutes.", t["action"], "switch",
                            sw["id"], label, f"port_flapping:{name}:{label}",
                            maintenance_down=True)
        if expected and prev != "down":
            t = THREATS["uplink_down" if port["kind"] == "uplink" else "port_down"]
            extra = " Devices behind this uplink may have lost the network." if port["kind"] == "uplink" else ""
            raise_alert(t["title"], t["severity"], name,
                        f"{tag}Port {label}{port_name} on {where} lost its link.{extra}", t["action"],
                        "switch", sw["id"], label, fp, maintenance_down=True)
    elif oper == "up" and prev == "down":
        record_event(sw["id"], label, "port_up", "SIMULATED" if simulated else "")
        resolve_alerts(fp, "link restored")


def _kind_from_label(label):
    parts = label.split("/")
    return "uplink" if len(parts) == 3 and parts[1] != "1" else "access"


def _sync_switch_device_status(sw, status, stamp, check_failures):
    device = query("SELECT id, name, status FROM devices WHERE id = ?", (sw["device_id"],), one=True)
    if device is None:
        return
    next_status = status or device["status"]
    execute(
        "UPDATE devices SET status = ?, last_checked = ?, check_failures = ? WHERE id = ?",
        (next_status, stamp, check_failures, device["id"]),
    )
    if device["status"] != next_status:
        audit(
            "device_status_changed",
            f"{device['name']}: {device['status']} -> {next_status}",
            actor="monitor",
        )
        if device["status"] == "down":
            resolve_alerts(
                f"device_down:{device['id']}",
                "switch responded to a reachability check",
            )


def _sync_switch_alert_state(sw, stamp, check_failures):
    active = query(
        "SELECT severity FROM alerts WHERE device_name = ? AND status != 'resolved'",
        (sw["name"],),
    )
    if any(row["severity"] == "threat" for row in active):
        device_status = "threat"
    elif any(row["severity"] == "warning" for row in active):
        device_status = "warning"
    else:
        device_status = "healthy"
    _sync_switch_device_status(sw, device_status, stamp, check_failures)


# ---------------------------------------------------------------------- switches
def apply_switch_poll(sw, reachable, snmp_ok=True, uptime=None, ports=None, simulated=False):
    """Store one polling result for a switch.

    reachable : answered ping (or SNMP)
    snmp_ok   : SNMP answered, so `uptime` and `ports` are real
    ports     : {label: {"oper": "up|down", "admin": "up|down", "alias": str}}
    """
    stamp = now_iso()
    tag = "SIMULATED: " if simulated else ""
    name = sw["name"]
    where = f"{name} ({sw['location']})"

    if not reachable:
        miss = sw["miss_count"] + 1
        execute("UPDATE switches SET miss_count = ?, last_poll = ? WHERE id = ?", (miss, stamp, sw["id"]))
        if miss >= _cfg("MISS_LIMIT", 2):
            if sw["state"] != "offline":
                execute("UPDATE switches SET state = 'offline' WHERE id = ?", (sw["id"],))
                record_event(sw["id"], "", "switch_offline", "SIMULATED" if simulated else "")
            t = THREATS["switch_offline"]
            fingerprint = f"switch_offline:{name}"
            existing = query(
                "SELECT 1 FROM alerts WHERE fingerprint = ? AND status != 'resolved' LIMIT 1",
                (fingerprint,),
                one=True,
            )
            if not existing:
                raise_alert(t["title"], t["severity"], name,
                            f"{tag}{where} is not answering. Everything connected to it may be offline.",
                            t["action"], "switch", sw["id"], "", fingerprint,
                            maintenance_down=True)
        _sync_switch_device_status(
            sw, "down" if miss >= _cfg("MISS_LIMIT", 2) else None, stamp, miss
        )
        return

    execute("UPDATE switches SET miss_count = 0, state = 'online', last_seen = ?, last_poll = ?, snmp_ok = ? WHERE id = ?",
            (stamp, stamp, 1 if snmp_ok else 0, sw["id"]))
    if sw["state"] == "offline":
        record_event(sw["id"], "", "switch_online", "")
        resolve_alerts(f"switch_offline:{name}", "switch is answering again")

    fp_snmp = f"snmp_down:{name}"
    if not snmp_ok:
        t = THREATS["snmp_down"]
        raise_alert(t["title"], t["severity"], name,
                    f"{tag}{where} answers ping but not SNMP, so port status cannot be read.",
                    t["action"], "switch", sw["id"], "", fp_snmp)
        _sync_switch_alert_state(sw, stamp, 0)
        return
    resolve_alerts(fp_snmp, "SNMP is answering again")

    if uptime is not None:
        if sw["uptime_seconds"] is not None and uptime + 120 < sw["uptime_seconds"]:
            record_event(sw["id"], "", "switch_reboot", f"uptime fell from {sw['uptime_seconds']}s to {uptime}s")
            t = THREATS["switch_reboot"]
            raise_alert(t["title"], t["severity"], name, f"{tag}{where} restarted.", t["action"],
                        "switch", sw["id"], "", f"switch_reboot:{name}:{stamp}")
        execute("UPDATE switches SET uptime_seconds = ? WHERE id = ?", (uptime, sw["id"]))

    if ports:
        existing = {p["label"]: p for p in query("SELECT * FROM switch_ports WHERE switch_id = ?", (sw["id"],))}
        for label in ports:
            if label not in existing:  # a port the switch has that we did not know about
                execute("INSERT INTO switch_ports (switch_id, label, kind, expected_up) VALUES (?, ?, ?, ?)",
                        (sw["id"], label, _kind_from_label(label), 0))  # watched once seen working
        if not sw["discovered"]:  # first real reading: drop the estimated ports the switch does not have
            for label, p in existing.items():
                if label not in ports and not p["reported"]:
                    execute("DELETE FROM switch_ports WHERE id = ?", (p["id"],))
            execute("UPDATE switches SET discovered = 1 WHERE id = ?", (sw["id"],))
        fresh = {p["label"]: p for p in query("SELECT * FROM switch_ports WHERE switch_id = ?", (sw["id"],))}
        for label, reading in ports.items():
            apply_port(sw, fresh[label], reading["oper"], reading.get("admin", "up"), reading.get("alias"))
    _sync_switch_alert_state(sw, stamp, 0)


# -------------------------------------------------------------- security events
def raise_security_event(sw, key, port="", detail="", simulated=False):
    """Alert for an attack or risk on a switch (from syslog, the ingest API or the demo buttons)."""
    t = THREATS[key]
    tag = "SIMULATED: " if simulated else ""
    where = f"{sw['name']} ({sw['location']})" + (f", port {port}" if port else "")
    text = f"{tag}{t['meaning']} Seen on {where}." + (f" Detail: {detail[:200]}" if detail else "")
    record_event(sw["id"], port, key, ("SIMULATED " if simulated else "") + detail[:200])
    return raise_alert(t["title"], t["severity"], sw["name"], text, t["action"], "switch-security",
                       sw["id"], port, f"{key}:{sw['name']}:{port}")


# ----------------------------------------------------------------------- syslog
SYSLOG_RULES = [  # starter patterns: tune them against the real messages your ICX switches send
    (re.compile(r"port.?security|secure.?mac.{0,30}violat|mac.{0,20}violation", re.I), "port_security"),
    (re.compile(r"dhcp.{0,30}(snoop|rogue|untrusted|spoof)", re.I), "rogue_dhcp"),
    (re.compile(r"arp.{0,30}(inspect|spoof|invalid|violation)|\bdai\b", re.I), "arp_spoof"),
    (re.compile(r"bpdu.?guard|loop.?detect|topology.?change|root.?guard|stp.{0,20}(change|loop)", re.I), "stp_loop"),
    (re.compile(r"mac.{0,20}(flood|table.?full|learn.{0,10}limit)", re.I), "mac_flood"),
    (re.compile(r"(login|authentication|auth).{0,40}(fail|invalid|denied|incorrect)|invalid (user|password)", re.I), "auth_fail"),
    (re.compile(r"(config|startup).{0,30}(change|modif|saved)|write mem", re.I), "config_change"),
]
_PORT = r"(\d{1,2}/\d{1,2}/\d{1,3})"
LINK_DOWN = re.compile(r"(?:ethernet|interface|port)\D{0,20}" + _PORT + r".{0,40}\bdown\b", re.I)
LINK_UP = re.compile(r"(?:ethernet|interface|port)\D{0,20}" + _PORT + r".{0,40}\bup\b", re.I)
PORT_IN_TEXT = re.compile(r"\b" + _PORT + r"\b")


def handle_syslog(source_ip, text):
    """Turn one syslog line from a switch into a port update or an alert. Returns a short description or None."""
    sw = find_switch(source_ip)
    if sw is None:
        return None
    for regex, state in ((LINK_DOWN, "down"), (LINK_UP, "up")):
        m = regex.search(text)
        if m:
            port = get_port(sw["id"], m.group(1))
            if port is None:
                return None
            apply_port(sw, port, state, port["admin_status"])
            return f"{sw['name']} port {m.group(1)} {state}"
    for regex, key in SYSLOG_RULES:
        if regex.search(text):
            m = PORT_IN_TEXT.search(text)
            raise_security_event(sw, key, m.group(1) if m else "", text)
            return f"{sw['name']} {key}"
    return None


# ------------------------------------------------------------------- the screen
def collector_state():
    """('demo' | 'ok' | 'stale' | 'never', seconds since the last check)."""
    if current_app.config["DEMO_MODE"]:
        return "demo", 0
    row = get_status("collector")
    if row is None:
        return "never", None
    age = (datetime.now() - datetime.strptime(row["updated_at"], "%Y-%m-%d %H:%M:%S")).total_seconds()
    limit = max(60, 3 * _cfg("SWITCH_POLL_SECONDS", 30))
    return ("ok" if age <= limit else "stale"), int(age)


def port_counts():
    """Ports that should be working but are down (the number the SOC cares about)."""
    return query(
        "SELECT COUNT(*) AS c FROM switch_ports p JOIN switches s ON s.id = p.switch_id "
        "WHERE p.expected_up = 1 AND p.oper_status = 'down' AND p.admin_status = 'up' AND s.state != 'offline'",
        one=True)["c"]


def soc_summary():
    """Numbers for the red/amber bar shown on every page."""
    threats = query("SELECT COUNT(*) AS c FROM alerts WHERE severity = 'threat' AND status = 'open'", one=True)["c"]
    warnings = query("SELECT COUNT(*) AS c FROM alerts WHERE severity = 'warning' AND status = 'open'", one=True)["c"]
    offline = query("SELECT COUNT(*) AS c FROM switches WHERE state = 'offline'", one=True)["c"]
    state, age = collector_state()
    return {
        "threats": threats, "warnings": warnings, "switches_offline": offline,
        "ports_down": port_counts(), "collector": state, "collector_age": age,
        "max_alert_id": query("SELECT COALESCE(MAX(id), 0) AS m FROM alerts", one=True)["m"],
    }


# ------------------------------------------------------------------ demo buttons
ATTACKS = ("mac_flood", "rogue_dhcp", "arp_spoof", "port_security", "stp_loop", "auth_fail", "config_change")


def _default_port(sw, only_up=True):
    sql = "SELECT * FROM switch_ports WHERE switch_id = ? AND kind = 'access'"
    if only_up:
        sql += " AND oper_status = 'up'"
    return query(sql + " ORDER BY id LIMIT 1", (sw["id"],), one=True)


def simulate(sw, action, port_label=""):
    """Demo mode only: act out a fault so the SOC can see the screen react. Returns a message."""
    port = get_port(sw["id"], port_label) if port_label else None
    if action == "port_down":
        port = port or _default_port(sw)
        if port is None:
            return "This switch has no working port to drop."
        execute("UPDATE switch_ports SET oper_status = 'up', admin_status = 'up', expected_up = 1 WHERE id = ?", (port["id"],))
        apply_port(sw, get_port(sw["id"], port["label"]), "down", "up", simulated=True)
        return f"Port {port['label']} dropped."
    if action == "port_up":
        port = port or query("SELECT * FROM switch_ports WHERE switch_id = ? AND oper_status = 'down' AND expected_up = 1 ORDER BY id LIMIT 1", (sw["id"],), one=True)
        if port is None:
            return "No downed port to restore."
        apply_port(sw, port, "up", "up", simulated=True)
        return f"Port {port['label']} restored."
    if action == "switch_offline":
        for _ in range(_cfg("MISS_LIMIT", 2)):
            apply_switch_poll(get_switch(sw["id"]), reachable=False, simulated=True)
        return f"{sw['name']} is now unreachable."
    if action == "switch_online":
        apply_switch_poll(get_switch(sw["id"]), reachable=True, snmp_ok=True, uptime=sw["uptime_seconds"], simulated=True)
        return f"{sw['name']} is answering again."
    if action in ATTACKS:
        port = port or _default_port(sw)
        label = port["label"] if (port and action not in ("auth_fail", "config_change")) else ""
        raise_security_event(sw, action, label, simulated=True)
        return f"{THREATS[action]['title']} raised."
    if action == "clear":
        count = 0
        for row in query("SELECT id, fingerprint FROM alerts WHERE switch_id = ? AND status != 'resolved' AND message LIKE 'SIMULATED:%'", (sw["id"],)):
            execute("UPDATE alerts SET status = 'resolved' WHERE id = ?", (row["id"],))
            count += 1
        execute("UPDATE switch_ports SET oper_status = 'up' WHERE switch_id = ? AND expected_up = 1 AND admin_status = 'up'", (sw["id"],))
        execute("UPDATE switches SET state = 'online', miss_count = 0 WHERE id = ?", (sw["id"],))
        audit("simulation_cleared", f"{sw['name']}: {count} simulated alerts closed")
        return f"Cleared {count} simulated alert(s)."
    return "Unknown action."


# ----------------------------------------------------------- leaving demo mode
def reset_switch_data():
    """Forget demo readings so the first live poll starts clean (ports back to 'unknown')."""
    execute("DELETE FROM alerts WHERE category IN ('switch', 'switch-security')")
    execute("DELETE FROM switch_events")
    execute("UPDATE switch_ports SET oper_status = 'unknown', admin_status = 'up', reported = 0, changed_at = NULL, "
            "expected_up = 0, alias = ''")
    execute("UPDATE switches SET state = 'unknown', snmp_ok = 0, miss_count = 0, uptime_seconds = NULL, "
            "last_seen = NULL, last_poll = NULL, discovered = 0")
    execute("DELETE FROM monitor_status WHERE key = 'demo_seeded'")
    audit("switch_data_reset", "Demo switch readings cleared", actor="monitor")


def purge_old(days=30):
    execute("DELETE FROM switch_events WHERE ts < datetime('now', 'localtime', ?)", (f"-{days} days",))

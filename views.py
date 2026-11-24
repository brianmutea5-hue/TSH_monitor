"""Dashboard pages: overview, servers, network, threats, alerts, logs, settings,
plus the device manager (add / edit / remove)."""
import hmac
import ipaddress
import math
from datetime import datetime, timedelta

from flask import (Blueprint, abort, current_app, flash, g, jsonify, redirect,
                   render_template, request, url_for)

import monitoring
import switch_monitor
from auth import csrf_exempt, is_admin, login_required, role_required, safe_path
from database import (
    DEVICE_STATUSES, active_maintenance_device_ids, active_maintenance_windows,
    audit, execute, now_iso, query,
)

bp = Blueprint("views", __name__)

DEVICE_TYPES = [
    ("host", "Physical host"),
    ("vm", "Virtual machine"),
    ("server", "Server"),
    ("storage", "Storage / NAS"),
    ("switch", "Switch"),
    ("access_point", "Wireless access point"),
    ("wan_link", "WAN link"),
]
ALERT_STATUSES = ("open", "acknowledged", "resolved")
ALERT_ORDER = "CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END, id DESC"
LOG_LIMIT = 200


# --------------------------------------------------------------------- helpers
def _host_cards():
    """Physical hosts, showing simulation samples or fresh agent readings."""
    cards = []
    hosts = query(
        "SELECT d.*, t.last_seen AS telemetry_last_seen, t.status AS telemetry_status, "
        "(SELECT COUNT(*) FROM devices child WHERE child.parent_id = d.id) AS vm_count, "
        "(SELECT COUNT(*) FROM alerts a WHERE a.device_name = d.name "
        "AND a.severity = 'threat' AND a.status != 'resolved') AS active_threats "
        "FROM devices d LEFT JOIN device_telemetry t ON t.device_id = d.id "
        "WHERE d.type = 'host' ORDER BY d.id"
    )
    stale_after = current_app.config.get("TELEMETRY_STALE_SECONDS", 180)
    check_stale_after = _device_status_stale_after()
    simulation_mode = current_app.config.get("DEMO_MODE", False)
    maintenance_ids = active_maintenance_device_ids(
        [host["id"] for host in hosts]
    )
    for host in hosts:
        card = dict(host)
        seen = host["telemetry_last_seen"]
        fresh = _fresh_telemetry(seen)
        checked_fresh = _fresh_device_check(host["last_checked"], check_stale_after)
        card["telemetry_live"] = fresh
        if fresh:
            card["last_checked"] = seen
        card["last_check_label"] = _device_check_label(card)
        if fresh:
            state = host["telemetry_status"]
            if host["status"] == "down":
                state = "down"
            elif host["active_threats"] or state == "threat":
                state = "threat"
            elif state == "warning" or host["status"] == "warning":
                state = "warning"
            elif state not in DEVICE_STATUSES:
                state = "unknown"
        elif simulation_mode and not seen:
            state = "threat" if host["active_threats"] else "healthy"
        else:
            for metric in ("cpu", "memory", "disk", "temp", "uptime_hours"):
                card[metric] = None
            if checked_fresh and host["status"] in DEVICE_STATUSES:
                state = host["status"]
            else:
                state = "unknown"
        card["maintenance"] = host["id"] in maintenance_ids
        card["state"] = "maintenance" if card["maintenance"] else state
        card["telemetry_fresh"] = fresh
        cards.append(card)
    return cards


def _summary(cards):
    """Numbers for the four tiles and the top banner on the overview page."""
    totals = query(
        "SELECT COALESCE(SUM(CASE WHEN severity = 'threat' AND status != 'resolved' "
        "THEN 1 ELSE 0 END), 0) AS threats, "
        "COALESCE(SUM(CASE WHEN status != 'resolved' THEN 1 ELSE 0 END), 0) AS open_alerts "
        "FROM alerts",
        one=True,
    )
    down = sum(1 for c in cards if c["state"] == "down")
    online = sum(1 for c in cards if c["state"] in ("healthy", "warning", "threat", "maintenance"))
    return {
        "online": online,
        "down": down,
        "threats": totals["threats"],
        "open_alerts": totals["open_alerts"],
        "issues": totals["open_alerts"] + down,
    }


def _fresh_telemetry(last_seen):
    if not last_seen:
        return False
    try:
        age = (datetime.now() - datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")).total_seconds()
    except ValueError:
        return False
    return age <= current_app.config.get("TELEMETRY_STALE_SECONDS", 180)


def _fresh_device_check(last_checked, stale_after=None):
    if not last_checked:
        return False
    try:
        age = (datetime.now() - datetime.strptime(last_checked, "%Y-%m-%d %H:%M:%S")).total_seconds()
    except ValueError:
        return False
    if stale_after is None:
        stale_after = _device_status_stale_after()
    return age <= stale_after


def _device_status_stale_after():
    return max(
        30,
        current_app.config.get("DEVICE_CHECK_INTERVAL_SECONDS", 30) * 3,
        current_app.config.get("TELEMETRY_STALE_SECONDS", 180),
    )


def refresh_switch_ports():
    """Queue a switch refresh; never wait for SNMP from the request thread."""
    return switch_monitor.schedule_refresh(current_app._get_current_object())


def _device_check_label(device):
    ip = device.get("ip")
    if not ip:
        if device.get("telemetry_live") and device.get("last_checked"):
            return f"Last telemetry {device['last_checked']}"
        return "No IP · not checked"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid IP · not checked"
    if device.get("last_checked"):
        return f"Last checked {device['last_checked']}"
    return "Waiting for first check"


def _decorate_device_rows(rows):
    check_stale_after = _device_status_stale_after()
    ids = tuple(row["id"] for row in rows)
    if ids:
        placeholders = ",".join("?" for _ in ids)
        telemetry = {
            row["device_id"]: row
            for row in query(
                f"SELECT device_id, last_seen, status FROM device_telemetry "
                f"WHERE device_id IN ({placeholders})",
                ids,
            )
        }
        ap_metrics = {
            row["device_id"]: row
            for row in query(
                f"SELECT device_id, last_seen, status FROM access_point_metrics "
                f"WHERE device_id IN ({placeholders})",
                ids,
            )
        }
        maintenance_ids = active_maintenance_device_ids(ids)
    else:
        telemetry = {}
        ap_metrics = {}
        maintenance_ids = set()
    result = []
    for row in rows:
        device = dict(row)
        live = telemetry.get(device["id"])
        ap_live = ap_metrics.get(device["id"])
        device["telemetry_live"] = False
        if live and _fresh_telemetry(live["last_seen"]):
            device["status"] = live["status"]
            device["last_checked"] = live["last_seen"]
            device["telemetry_live"] = True
        elif ap_live and _fresh_telemetry(ap_live["last_seen"]):
            device["status"] = ap_live["status"]
            device["last_checked"] = ap_live["last_seen"]
            device["telemetry_live"] = True
        if not device["telemetry_live"]:
            if (
                not device.get("ip")
                or not _valid_device_ip(device.get("ip"))
                or not _fresh_device_check(device.get("last_checked"), check_stale_after)
            ):
                device["status"] = "unknown"
            elif device.get("status") not in DEVICE_STATUSES:
                device["status"] = "unknown"
        device["maintenance"] = device["id"] in maintenance_ids
        if device["maintenance"]:
            device["status"] = "maintenance"
        device["last_check_label"] = _device_check_label(device)
        result.append(device)
    return result


def _valid_device_ip(ip):
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def _validate_host_metrics(raw_metrics):
    allowed = {
        "cpu": (0, 100),
        "memory": (0, 100),
        "disk": (0, 100),
        "temp": (-100, 200),
        "uptime_hours": (0, 2_000_000),
    }
    if not isinstance(raw_metrics, dict) or not raw_metrics:
        return None, "Send at least one host metric."
    if set(raw_metrics) - set(allowed):
        return None, "One or more metric names are not supported."
    metrics = {}
    for name, value in raw_metrics.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, f"{name} must be a finite number."
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            return None, f"{name} must be a finite number."
        minimum, maximum = allowed[name]
        if not minimum <= value <= maximum:
            return None, f"{name} must be between {minimum} and {maximum}."
        metrics[name] = value
    return metrics, None


def _validate_access_point_metrics(raw_metrics):
    allowed = {
        "connected_clients": (0, 10000),
        "channel_utilization": (0, 100),
        "avg_rssi": (-120, 0),
        "dns_latency_ms": (0, 120000),
        "dhcp_latency_ms": (0, 120000),
    }
    if not isinstance(raw_metrics, dict) or not raw_metrics:
        return None, "Send at least one access-point metric."
    if set(raw_metrics) - set(allowed):
        return None, "One or more access-point metric names are not supported."
    metrics = {}
    for name, value in raw_metrics.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, f"{name} must be a finite number."
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            return None, f"{name} must be a finite number."
        minimum, maximum = allowed[name]
        if not minimum <= value <= maximum:
            return None, f"{name} must be between {minimum} and {maximum}."
        metrics[name] = value
    return metrics, None


def _alerts(severity=None):
    """Alerts for the Alerts / Threats pages, filtered by ?status=."""
    status = request.args.get("status", "all")
    if status not in ALERT_STATUSES:
        status = "all"
    sql, args = "SELECT * FROM alerts WHERE 1 = 1", []
    if severity:
        sql += " AND severity = ?"
        args.append(severity)
    if status != "all":
        sql += " AND status = ?"
        args.append(status)
    return query(f"{sql} ORDER BY {ALERT_ORDER}", args), status


def _validate_device(form, device=None):
    """Check the add / edit form. Returns (list of error messages, clean values)."""
    device_id = device["id"] if device else None
    name = form.get("name", "").strip()
    role = form.get("role", "").strip()
    ip = form.get("ip", "").strip()
    dtype = form.get("type", "vm")
    parent = form.get("parent_id", "").strip()
    errors = []

    if not name or len(name) > 100:
        errors.append("Name is required (max 100 characters).")
    if len(role) > 150:
        errors.append("Role is too long (max 150 characters).")
    if dtype not in dict(DEVICE_TYPES):
        errors.append("Choose a valid device type.")

    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            errors.append("IP address is not valid (example: 192.168.8.101).")
        else:
            clash = query("SELECT id, name FROM devices WHERE ip = ?", (ip,), one=True)
            if clash and clash["id"] != device_id:
                errors.append(f"IP address {ip} is already used by {clash['name']}.")

    parent_id = None
    if parent and dtype == "vm":
        row = query("SELECT id FROM devices WHERE id = ? AND type = 'host'", (parent,), one=True)
        if row is None:
            errors.append("Choose a valid parent host.")
        else:
            parent_id = row["id"]

    dup = query("SELECT id FROM devices WHERE lower(name) = lower(?)", (name,), one=True)
    if dup and dup["id"] != device_id:
        errors.append("A device with that name already exists.")

    # A host that still has virtual machines cannot be changed into something else
    if device and device["type"] == "host" and dtype != "host":
        children = query("SELECT COUNT(*) AS c FROM devices WHERE parent_id = ?", (device_id,), one=True)["c"]
        if children:
            errors.append(f"{device['name']} still has {children} virtual machines. Move or remove them first.")

    return errors, {"name": name, "role": role, "ip": ip or None, "type": dtype, "parent_id": parent_id}


def _form_page(is_new, device, hosts, device_id=None, status=200):
    """Render the add / edit device form."""
    return render_template(
        "device_form.html", active="network", crumb="Add device" if is_new else "Edit device",
        device=device, device_id=device_id, hosts=hosts, types=DEVICE_TYPES, is_new=is_new,
    ), status


# ----------------------------------------------------------------------- pages
@bp.route("/")
@login_required
def overview():
    cards = _host_cards()
    recent = query(f"SELECT * FROM alerts ORDER BY {ALERT_ORDER} LIMIT 3")
    return render_template("overview.html", active="overview", crumb="Overview",
                           cards=cards, s=_summary(cards), recent=recent)


@bp.route("/servers")
@login_required
def servers():
    cards = _host_cards()
    vms = _decorate_device_rows(query(
        "SELECT d.*, p.name AS parent_name FROM devices d "
        "LEFT JOIN devices p ON p.id = d.parent_id WHERE d.type = 'vm' ORDER BY d.parent_id, d.id"
    ))
    return render_template("servers.html", active="servers", crumb="Servers", cards=cards, vms=vms)


@bp.route("/network", methods=["GET", "POST"])
@login_required
def network():
    if request.method == "POST":
        refresh_switch_ports()
        flash("Switch refresh scheduled.", "info")
        return redirect(url_for("views.network"))
    devices = _decorate_device_rows(query(
        "SELECT d.*, p.name AS parent_name, ap.last_seen AS ap_last_seen, "
        "ap.connected_clients, ap.channel_utilization, ap.avg_rssi, "
        "ap.dns_latency_ms, ap.dhcp_latency_ms FROM devices d "
        "LEFT JOIN devices p ON p.id = d.parent_id "
        "LEFT JOIN access_point_metrics ap ON ap.device_id = d.id ORDER BY d.id"
    ))
    return render_template("network.html", active="network", crumb="Network", devices=devices)


@bp.route("/api/v1/telemetry", methods=["POST"])
@csrf_exempt
def ingest_telemetry():
    """Accept host metrics from a trusted agent using the configured Bearer token."""
    expected_token = current_app.config.get("TELEMETRY_TOKEN", "")
    authorization = request.headers.get("Authorization", "")
    provided_token = authorization[7:] if authorization.startswith("Bearer ") else ""
    token_matches = False
    if isinstance(expected_token, str):
        token_matches = hmac.compare_digest(
            provided_token.encode("utf-8"), expected_token.encode("utf-8")
        )
    if not isinstance(expected_token, str) or len(expected_token) < 32 or not token_matches:
        return jsonify(error="Unauthorized."), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Expected a JSON object."), 400
    device_name = payload.get("device")
    if not isinstance(device_name, str) or not device_name.strip():
        return jsonify(error="A device name is required."), 400
    device = query(
        "SELECT * FROM devices WHERE lower(name) = lower(?)",
        (device_name.strip(),), one=True,
    )
    if device is None:
        return jsonify(error="Unknown device."), 404
    reported_status = payload.get("status")
    if reported_status is not None and reported_status not in DEVICE_STATUSES:
        return jsonify(error="Status must be healthy, warning, threat, down, or unknown."), 400
    raw_metrics = payload.get("metrics")
    if device["type"] in ("host", "server", "vm"):
        if raw_metrics is None:
            if reported_status is None:
                return jsonify(error="Send status or at least one host metric."), 400
            metrics = None
        elif raw_metrics == {} and reported_status is not None:
            metrics = None
        else:
            metrics, error = _validate_host_metrics(raw_metrics)
            if error:
                return jsonify(error=error), 400
        monitoring.apply_host_telemetry(device, metrics, reported_status)
    elif device["type"] == "access_point":
        if raw_metrics is None or raw_metrics == {}:
            if reported_status is None:
                return jsonify(error="Send status or at least one access-point metric."), 400
            metrics = None
        else:
            metrics, error = _validate_access_point_metrics(raw_metrics)
            if error:
                return jsonify(error=error), 400
        monitoring.apply_access_point_telemetry(device, metrics, reported_status)
    elif device["type"] == "wan_link":
        if raw_metrics is not None:
            return jsonify(error="WAN telemetry accepts link status only."), 400
        if reported_status is None:
            return jsonify(error="A WAN link status is required."), 400
        monitoring.apply_wan_telemetry(device, reported_status)
    else:
        return jsonify(error="Telemetry is not supported for this device type."), 400
    return jsonify(status="accepted"), 200


@bp.route("/api/v1/host-metrics")
@login_required
def host_metrics():
    """Small authenticated feed for updating host cards without reloading the page."""
    return jsonify(hosts=[
        {
            "id": host["id"],
            "name": host["name"],
            "state": host["state"],
            "cpu": host["cpu"],
            "memory": host["memory"],
            "disk": host["disk"],
            "has_ip": bool(host["ip"]),
            "last_checked": host["last_checked"],
            "last_check_label": host["last_check_label"],
        }
        for host in _host_cards()
    ])


@bp.route("/api/v1/device-status")
@login_required
def device_status():
    """Authenticated status feed for inventory rows; stale checks are reported unknown."""
    devices = _decorate_device_rows(query(
        "SELECT d.id, d.name, d.ip, d.status, d.last_checked, "
        "ap.connected_clients, ap.channel_utilization, ap.avg_rssi, "
        "ap.dns_latency_ms, ap.dhcp_latency_ms FROM devices d "
        "LEFT JOIN access_point_metrics ap ON ap.device_id = d.id ORDER BY d.id"
    ))
    return jsonify(devices=[
        {
            "id": device["id"],
            "status": device["status"],
            "has_ip": bool(device["ip"]),
            "last_checked": device["last_checked"],
            "last_check_label": device["last_check_label"],
            "connected_clients": device.get("connected_clients"),
            "channel_utilization": device.get("channel_utilization"),
            "avg_rssi": device.get("avg_rssi"),
            "dns_latency_ms": device.get("dns_latency_ms"),
            "dhcp_latency_ms": device.get("dhcp_latency_ms"),
        }
        for device in devices
    ])


@bp.route("/threats")
@login_required
def threats():
    rows, status = _alerts("threat")
    return render_template("threats.html", active="threats", crumb="Threats", alerts=rows, status=status)


@bp.route("/alerts")
@login_required
def alerts():
    rows, status = _alerts()
    return render_template("alerts.html", active="alerts", crumb="Alerts", alerts=rows, status=status)


@bp.route("/alerts/<int:alert_id>/<action>", methods=["POST"])
@login_required
def alert_action(alert_id, action):
    new_status = {"acknowledge": "acknowledged", "resolve": "resolved"}.get(action)
    row = query("SELECT * FROM alerts WHERE id = ?", (alert_id,), one=True)
    if new_status is None or row is None:
        abort(404)
    execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
    audit(f"alert_{new_status}", f"{row['title']} on {row['device_name']}")
    flash(f"Alert {new_status}.", "info")
    return redirect(safe_path(request.form.get("back"), url_for("views.alerts")))


@bp.route("/logs")
@login_required
def logs():
    rows = query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (LOG_LIMIT,))
    return render_template("logs.html", active="logs", crumb="Logs", logs=rows)


@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    options = current_app.config.get(
        "REFRESH_INTERVAL_OPTIONS", ((1800, "30 minutes"), (3600, "1 hour"))
    )
    allowed_seconds = {seconds for seconds, _label in options}
    setting = query(
        "SELECT value FROM app_settings WHERE key = 'refresh_seconds'", one=True
    )
    refresh_seconds = int(setting["value"]) if setting else min(allowed_seconds)

    if request.method == "POST":
        if not is_admin():
            abort(403)
        try:
            requested_seconds = int(request.form.get("refresh_seconds", ""))
        except ValueError:
            requested_seconds = None
        if requested_seconds not in allowed_seconds:
            labels = " or ".join(label for _seconds, label in options)
            flash(f"Choose a refresh interval of {labels}.", "error")
            return render_template(
                "settings.html", active="settings", crumb="Settings",
                refresh_seconds=refresh_seconds, refresh_interval_options=options,
            ), 400
        execute(
            "INSERT INTO app_settings (key, value) VALUES ('refresh_seconds', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(requested_seconds),),
        )
        audit("refresh_interval_updated", f"{requested_seconds // 60} minutes")
        flash("Data refresh interval updated.", "info")
        return redirect(url_for("views.settings"))
    return render_template(
        "settings.html", active="settings", crumb="Settings",
        refresh_seconds=refresh_seconds, refresh_interval_options=options,
    )


# -------------------------------------------------------------- maintenance
def _maintenance_windows_for_page():
    stamp = now_iso()
    return query(
        "SELECT m.*, d.name AS device_name, "
        "CASE WHEN m.is_active = 0 THEN 'Cancelled' "
        "WHEN m.ends_at <= ? THEN 'Ended' "
        "WHEN m.starts_at > ? THEN 'Scheduled' ELSE 'Active' END AS window_state "
        "FROM maintenance_windows m JOIN devices d ON d.id = m.device_id "
        "ORDER BY m.starts_at DESC, m.id DESC LIMIT 100",
        (stamp, stamp),
    )


def _maintenance_page(status=200):
    return render_template(
        "maintenance.html", active="maintenance", crumb="Maintenance",
        windows=_maintenance_windows_for_page(),
        devices=query("SELECT id, name, type FROM devices ORDER BY name"),
    ), status


@bp.route("/maintenance", methods=["GET", "POST"])
@login_required
def maintenance():
    if request.method == "POST":
        if not is_admin():
            abort(403)
        device_id = request.form.get("device_id", type=int)
        device = query("SELECT id, name FROM devices WHERE id = ?", (device_id,), one=True)
        reason = request.form.get("reason", "").strip()
        errors = []
        if device is None:
            errors.append("Choose a device from the inventory.")
        if not reason or len(reason) > 200:
            errors.append("Enter a reason (max 200 characters).")
        try:
            starts = datetime.fromisoformat(request.form.get("starts_at", ""))
            ends = datetime.fromisoformat(request.form.get("ends_at", ""))
            if starts.tzinfo is not None or ends.tzinfo is not None:
                raise ValueError
            if ends <= datetime.now():
                errors.append("The end time must be in the future.")
            if ends <= starts:
                errors.append("The end time must be after the start time.")
        except ValueError:
            starts = ends = None
            errors.append("Enter valid local start and end times.")

        if not errors and device is not None and starts is not None and ends is not None:
            start_text = starts.strftime("%Y-%m-%d %H:%M:%S")
            end_text = ends.strftime("%Y-%m-%d %H:%M:%S")
            overlap = query(
                "SELECT 1 FROM maintenance_windows WHERE device_id = ? AND is_active = 1 "
                "AND starts_at < ? AND ends_at > ? LIMIT 1",
                (device_id, end_text, start_text),
                one=True,
            )
            if overlap:
                errors.append("This window overlaps an existing scheduled or active window.")
        if errors:
            for error in errors:
                flash(error, "error")
            return _maintenance_page(400)

        window_id = execute(
            "INSERT INTO maintenance_windows "
            "(device_id, reason, starts_at, ends_at, created_by, is_active) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (
                device_id, reason, starts.strftime("%Y-%m-%d %H:%M:%S"),
                ends.strftime("%Y-%m-%d %H:%M:%S"), g.user["username"],
            ),
        )
        audit(
            "maintenance_scheduled",
            f"Window {window_id} for {device['name']} "
            f"({starts.strftime('%Y-%m-%d %H:%M')} to {ends.strftime('%Y-%m-%d %H:%M')})",
        )
        flash(f"Maintenance window scheduled for {device['name']}.", "info")
        return redirect(url_for("views.maintenance"))
    return _maintenance_page()


@bp.route("/maintenance/<int:window_id>/cancel", methods=["POST"])
@role_required("admin")
def maintenance_cancel(window_id):
    window = query(
        "SELECT m.id, d.name FROM maintenance_windows m "
        "JOIN devices d ON d.id = m.device_id WHERE m.id = ? AND m.is_active = 1",
        (window_id,),
        one=True,
    )
    if window is None:
        abort(404)
    execute("UPDATE maintenance_windows SET is_active = 0 WHERE id = ?", (window_id,))
    audit("maintenance_cancelled", f"Window {window_id} for {window['name']}")
    flash(f"Maintenance window for {window['name']} ended.", "info")
    return redirect(url_for("views.maintenance"))


# --------------------------------------------------------------- shift handover
HANDOVER_AUDIT_ACTIONS = (
    "login", "login_failed", "login_locked", "logout", "password_changed",
    "user_created", "user_role_changed", "user_disabled", "user_enabled",
    "user_password_reset", "user_deleted", "refresh_interval_updated",
    "device_added", "device_updated", "device_deleted", "switch_updated",
    "maintenance_scheduled", "maintenance_cancelled",
)


@bp.route("/handover")
@role_required("admin", "supervisor")
def handover():
    try:
        hours = int(request.args.get("hours", "8"))
    except ValueError:
        abort(400, "Choose an 8, 12, or 24 hour handover window.")
    if hours not in (8, 12, 24):
        abort(400, "Choose an 8, 12, or 24 hour handover window.")

    now = datetime.now()
    cutoff = now - timedelta(hours=hours)
    cutoff_text = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    unhealthy = _decorate_device_rows(query(
        "SELECT d.*, p.name AS parent_name FROM devices d "
        "LEFT JOIN devices p ON p.id = d.parent_id ORDER BY d.name"
    ))
    unhealthy = [device for device in unhealthy if device["status"] in ("down", "warning", "threat")]
    opened = query(
        "SELECT * FROM alerts WHERE created_at >= ? ORDER BY created_at DESC, id DESC",
        (cutoff_text,),
    )
    acknowledged = query(
        "SELECT ts, actor, action, detail FROM audit_logs "
        "WHERE action = 'alert_acknowledged' AND ts >= ? ORDER BY id DESC",
        (cutoff_text,),
    )
    resolved = query(
        "SELECT ts, actor, action, detail FROM audit_logs "
        "WHERE action = 'alert_resolved' AND ts >= ? ORDER BY id DESC",
        (cutoff_text,),
    )
    wan_events = query(
        "SELECT a.ts, a.actor, a.action, a.detail FROM audit_logs a "
        "JOIN devices d ON d.type = 'wan_link' "
        "AND (substr(a.detail, 1, length(d.name) + 1) = d.name || ':' "
        "OR (a.action IN ('alert_raised', 'alert_resolved') AND instr(a.detail, d.name) > 0)) "
        "WHERE a.ts >= ? ORDER BY a.id DESC",
        (cutoff_text,),
    )
    placeholders = ",".join("?" for _ in HANDOVER_AUDIT_ACTIONS)
    auth_config = query(
        f"SELECT ts, actor, action, detail FROM audit_logs "
        f"WHERE ts >= ? AND action IN ({placeholders}) ORDER BY id DESC LIMIT 100",
        (cutoff_text, *HANDOVER_AUDIT_ACTIONS),
    )
    return render_template(
        "handover.html", active="handover", crumb="Shift handover",
        hours=hours, since=cutoff, generated_at=now,
        unhealthy=unhealthy, opened=opened, acknowledged=acknowledged,
        resolved=resolved, wan_events=wan_events,
        maintenance_windows=active_maintenance_windows(), auth_config=auth_config,
    )


# ---------------------------------------------------------------- device manager
@bp.route("/devices/new", methods=["GET", "POST"])
@role_required("admin")
def device_new():
    hosts = query("SELECT id, name FROM devices WHERE type = 'host' ORDER BY name")
    if request.method == "POST":
        errors, data = _validate_device(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return _form_page(True, request.form, hosts, status=400)
        execute(
            "INSERT INTO devices (name, role, ip, type, parent_id) "
            "VALUES (:name, :role, :ip, :type, :parent_id)", data,
        )
        audit("device_added", f"{data['name']} ({data['type']})")
        flash(f"{data['name']} added.", "info")
        return redirect(url_for("views.network"))
    return _form_page(True, {}, hosts)


@bp.route("/devices/<int:device_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def device_edit(device_id):
    device = query("SELECT * FROM devices WHERE id = ?", (device_id,), one=True)
    if device is None:
        abort(404)
    hosts = query("SELECT id, name FROM devices WHERE type = 'host' AND id != ? ORDER BY name", (device_id,))
    if request.method == "POST":
        errors, data = _validate_device(request.form, device)
        if errors:
            for e in errors:
                flash(e, "error")
            return _form_page(False, request.form, hosts, device_id, status=400)
        data["id"] = device_id
        execute(
            "UPDATE devices SET name = :name, role = :role, ip = :ip, type = :type, "
            "parent_id = :parent_id WHERE id = :id", data,
        )
        audit("device_updated", data["name"])
        flash(f"{data['name']} updated.", "info")
        return redirect(url_for("views.network"))
    return _form_page(False, dict(device), hosts, device_id)


@bp.route("/devices/<int:device_id>/delete", methods=["POST"])
@role_required("admin")
def device_delete(device_id):
    device = query("SELECT * FROM devices WHERE id = ?", (device_id,), one=True)
    if device is None:
        abort(404)
    children = query("SELECT COUNT(*) AS c FROM devices WHERE parent_id = ?", (device_id,), one=True)["c"]
    execute("DELETE FROM devices WHERE id = ?", (device_id,))
    note = f" ({children} virtual machines now have no parent host)" if children else ""
    audit("device_deleted", f"{device['name']}{note}")
    flash(f"{device['name']} removed.{note}", "info")
    return redirect(url_for("views.network"))

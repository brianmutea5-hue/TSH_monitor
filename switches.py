"""Switch pages (grouped by location), port view, SOC notification feed and the sensor API."""
import hmac
import re
from itertools import groupby

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for)

import monitoring
from auth import csrf_exempt, login_required, role_required, safe_path
from database import active_maintenance_device_ids, audit, execute, query

bp = Blueprint("switches", __name__)

KIND_LABEL = {"core": "Core switch", "floor": "Floor switch", "camera": "Camera switch"}
EVENT_LABEL = {
    "port_down": "Port went down", "port_up": "Port came back", "port_disabled": "Port switched off",
    "switch_offline": "Switch went offline", "switch_online": "Switch came back online",
    "switch_reboot": "Switch restarted",
    **{key: t["title"] for key, t in monitoring.THREATS.items()},
}
PORT_TEXT = {  # what each colour means, in words (colour alone is never the only signal)
    "up": "Working", "down": "DOWN - should be working", "attack": "Under attack / suspicious",
    "idle": "Not in use", "off": "Switched off on purpose", "unknown": "Not read yet",
}
SIMULATIONS = [
    ("port_down", "Drop a port (cable unplugged)"),
    ("port_up", "Restore the dropped port"),
    ("switch_offline", "Switch goes offline"),
    ("switch_online", "Switch comes back"),
    ("arp_spoof", "Attack: ARP spoofing (man-in-the-middle)"),
    ("rogue_dhcp", "Attack: rogue DHCP server"),
    ("mac_flood", "Attack: MAC flooding"),
    ("port_security", "Attack: unknown device plugged in"),
    ("stp_loop", "Fault: network loop"),
    ("auth_fail", "Attack: failed management logins"),
    ("config_change", "Change: switch configuration edited"),
    ("clear", "Clear all simulated alerts"),
]
PORT_LABEL = re.compile(r"^\d{1,2}/\d{1,2}/\d{1,3}$")


# --------------------------------------------------------------------- helpers
def _port_sort(label):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[/\s]+", label))


def _classify(port, attacked):
    if port["admin_status"] == "down":
        return "off"
    if port["label"] in attacked:
        return "attack"
    if port["oper_status"] == "up":
        return "up"
    if port["oper_status"] == "down":
        return "down" if port["expected_up"] else "idle"
    return "unknown"


def _build(only_id=None):
    """One dict per switch: the row, its ports (with a colour class), counts and open alerts."""
    switches = [monitoring.get_switch(only_id)] if only_id else monitoring.all_switches()
    if only_id and switches[0] is None:
        abort(404)
    maintenance_ids = active_maintenance_device_ids(
        [switch["device_id"] for switch in switches]
    )
    ports = query("SELECT * FROM switch_ports" + (" WHERE switch_id = ?" if only_id else ""),
                  (only_id,) if only_id else ())
    alerts = query(
        "SELECT * FROM alerts WHERE category IN ('switch', 'switch-security') AND status != 'resolved'"
        + (" AND switch_id = ?" if only_id else "") + " ORDER BY CASE severity WHEN 'threat' THEN 0 ELSE 1 END, id DESC",
        (only_id,) if only_id else ())
    by_switch = {}
    for p in ports:
        by_switch.setdefault(p["switch_id"], []).append(p)
    alerts_by = {}
    for a in alerts:
        alerts_by.setdefault(a["switch_id"], []).append(a)

    result = []
    for sw in switches:
        mine = sorted(by_switch.get(sw["id"], []), key=lambda p: _port_sort(p["label"]))
        attacked = {a["port_label"] for a in alerts_by.get(sw["id"], [])
                    if a["category"] == "switch-security" and a["port_label"]}
        rows = []
        for p in mine:
            cls = _classify(p, attacked)
            tip = f"Port {p['label']}" + (f" - {p['alias']}" if p["alias"] else "") + f" - {PORT_TEXT[cls]}"
            short = "/".join(p["label"].split("/")[-2:]) if p["kind"] == "uplink" else p["label"].split("/")[-1]
            rows.append({**dict(p), "cls": cls, "tip": tip, "num": short, "text": PORT_TEXT[cls]})
        count = lambda c: sum(1 for r in rows if r["cls"] == c)  # noqa: E731
        open_alerts = alerts_by.get(sw["id"], [])
        maintenance = sw["device_id"] in maintenance_ids
        if maintenance:
            health = "maintenance"
        elif sw["state"] == "offline":
            health = "down"
        elif sw["state"] == "unknown":
            health = "unknown"
        elif any(a["severity"] == "threat" for a in open_alerts):
            health = "threat"
        elif open_alerts or count("down"):
            health = "warning"
        else:
            health = "healthy"
        result.append({
            "sw": sw, "kind_label": KIND_LABEL.get(sw["kind"], sw["kind"]), "ports": rows,
            "access": [r for r in rows if r["kind"] == "access"], "uplinks": [r for r in rows if r["kind"] == "uplink"],
            "total": len(rows), "up": count("up"), "down": count("down"), "attack": count("attack"),
            "idle": count("idle"), "off": count("off"), "alerts": open_alerts, "health": health,
            "maintenance": maintenance,
        })
    return result


def _event_rows(switch_id, limit=25):
    return query("SELECT * FROM switch_events WHERE switch_id = ? ORDER BY id DESC LIMIT ?", (switch_id, limit))


# ----------------------------------------------------------------------- pages
@bp.route("/network/switches")
@login_required
def index():
    items = _build()
    groups = [
        {"location": loc, "rows": list(grp)}
        for (_order, loc), grp in groupby(items, key=lambda i: (i["sw"]["floor_order"], i["sw"]["location"]))
    ]
    tiles = {
        "total": len(items),
        "online": sum(1 for i in items if i["sw"]["state"] == "online"),
        "offline": sum(1 for i in items if i["sw"]["state"] == "offline"),
        "unknown": sum(1 for i in items if i["sw"]["state"] == "unknown"),
        "ports_up": sum(i["up"] for i in items),
        "ports_total": sum(i["total"] for i in items),
        "ports_down": sum(i["down"] for i in items),
        "alerts": sum(len(i["alerts"]) for i in items),
    }
    return render_template(
        "switches.html", active="network", crumb="Network · Switches", groups=groups, tiles=tiles,
        threats=list(monitoring.THREATS.values()), port_text=PORT_TEXT,
    )


@bp.route("/network/switches/<int:switch_id>")
@login_required
def detail(switch_id):
    item = _build(switch_id)[0]
    return render_template(
        "switch_detail.html", active="network", crumb=f"Network · {item['sw']['name']}", item=item,
        events=_event_rows(switch_id), event_label=EVENT_LABEL, simulations=SIMULATIONS,
        port_text=PORT_TEXT, autorefresh=True,
    )


@bp.route("/network/switches/<int:switch_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def edit(switch_id):
    sw = monitoring.get_switch(switch_id)
    if sw is None:
        abort(404)
    if request.method == "POST":
        data = {k: request.form.get(k, "").strip() for k in ("location", "model", "serial", "notes")}
        limits = {"location": 80, "model": 60, "serial": 40, "notes": 400}
        errors = [f"{k.capitalize()} is too long (max {n})." for k, n in limits.items() if len(data[k]) > n]
        if not data["location"]:
            errors.append("Location is required, for example '2nd floor'.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("switch_form.html", active="network", crumb="Edit switch", sw=sw, values=data), 400
        execute("UPDATE switches SET location = ?, model = ?, serial = ?, notes = ? WHERE id = ?",
                (data["location"], data["model"], data["serial"], data["notes"], switch_id))
        audit("switch_updated", f"{sw['name']}: location '{data['location']}'")
        flash(f"{sw['name']} updated.", "info")
        return redirect(url_for("switches.detail", switch_id=switch_id))
    return render_template("switch_form.html", active="network", crumb="Edit switch", sw=sw, values=dict(sw))


@bp.route("/network/switches/ports/<int:port_id>/watch", methods=["POST"])
@role_required("admin")
def watch(port_id):
    """Turn "alert me if this port goes down" on or off."""
    port = query("SELECT p.*, d.name AS sw_name FROM switch_ports p JOIN switches s ON s.id = p.switch_id "
                 "JOIN devices d ON d.id = s.device_id WHERE p.id = ?", (port_id,), one=True)
    if port is None:
        abort(404)
    new = 0 if port["expected_up"] else 1
    execute("UPDATE switch_ports SET expected_up = ? WHERE id = ?", (new, port_id))
    if not new:
        monitoring.resolve_alerts(f"port_down:{port['sw_name']}:{port['label']}", "port no longer watched")
    audit("port_watch", f"{port['sw_name']} port {port['label']}: {'watching' if new else 'not watching'}")
    flash(f"Port {port['label']} is now {'watched: you will be alerted if it goes down' if new else 'not watched'}.", "info")
    return redirect(safe_path(request.form.get("back"), url_for("switches.detail", switch_id=port["switch_id"])))


@bp.route("/network/switches/<int:switch_id>/simulate", methods=["POST"])
@role_required("admin")
def simulate(switch_id):
    """Demo mode only: act out a fault so the SOC can see how the screen reacts."""
    if not current_app.config["SIMULATION"]:
        abort(404)
    sw = monitoring.get_switch(switch_id)
    if sw is None:
        abort(404)
    action = request.form.get("action", "")
    if action not in dict(SIMULATIONS):
        abort(400, "Unknown test action.")
    label = request.form.get("port", "").strip()
    if label and not PORT_LABEL.match(label):
        abort(400, "Port must look like 1/1/17.")
    if label and monitoring.get_port(switch_id, label) is None:
        flash(f"{sw['name']} has no port {label}.", "error")
    else:
        message = monitoring.simulate(sw, action, label)
        audit("simulation", f"{sw['name']}: {action} {label}".strip())
        flash(f"Test: {message}", "info")
    return redirect(url_for("switches.detail", switch_id=switch_id))


# ---------------------------------------------------------- SOC notification feed
@bp.route("/api/notifications")
def notifications():
    """Polled by the page every few seconds. Not counted as activity (the page adds ?auto=1)."""
    if not session.get("user"):
        return jsonify(error="signed out"), 401
    since = request.args.get("since", 0, type=int)
    rows = query("SELECT * FROM alerts WHERE id > ? AND status = 'open' ORDER BY id LIMIT 20", (since,))
    open_ids = [r["id"] for r in query("SELECT id FROM alerts WHERE status = 'open' ORDER BY id DESC LIMIT 100")]
    return jsonify(
        summary=monitoring.soc_summary(),
        open_ids=open_ids,
        items=[{
            "id": r["id"], "title": r["title"], "severity": r["severity"], "device": r["device_name"],
            "port": r["port_label"], "message": r["message"], "created_at": r["created_at"],
            "url": url_for("switches.detail", switch_id=r["switch_id"]) if r["switch_id"] else url_for("views.alerts"),
        } for r in rows],
    )


# -------------------------------------------------------------- sensor API (token)
@bp.route("/api/ingest/switch-event", methods=["POST"])
@csrf_exempt
def ingest_event():
    """For outside sensors (Wazuh, Suricata, scripts). Needs INGEST_TOKEN in .env.

    curl -X POST http://SERVER:5000/api/ingest/switch-event -H "Authorization: Bearer TOKEN"
         -H "Content-Type: application/json"
         -d '{"switch": "SW-2ND", "event": "arp_spoof", "port": "1/1/12", "detail": "gateway MAC changed"}'
    """
    token = current_app.config["INGEST_TOKEN"]
    if not token:
        abort(404)
    sent = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(sent.encode(), token.encode()):
        audit("ingest_denied", f"Wrong token from {request.remote_addr}", actor="anonymous")
        return jsonify(error="unauthorised"), 401
    data = request.get_json(silent=True) or {}
    sw = monitoring.find_switch(str(data.get("switch", "")))
    event = str(data.get("event", ""))
    port = str(data.get("port", "")).strip()
    if sw is None:
        return jsonify(error="unknown switch"), 404
    if port and not PORT_LABEL.match(port):
        return jsonify(error="port must look like 1/1/17"), 400
    if event in ("link_down", "link_up"):
        row = monitoring.get_port(sw["id"], port)
        if row is None:
            return jsonify(error="unknown port"), 404
        monitoring.apply_port(sw, row, "down" if event == "link_down" else "up", row["admin_status"])
    elif event in monitoring.ATTACKS:
        monitoring.raise_security_event(sw, event, port, str(data.get("detail", ""))[:300])
    else:
        return jsonify(error="event must be one of: link_down, link_up, " + ", ".join(monitoring.ATTACKS)), 400
    return jsonify(status="ok")

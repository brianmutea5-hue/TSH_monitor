"""SQLite helpers: connection handling, schema, upgrades, seeding, audit log."""
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import current_app, g, has_request_context, session

import seed_data

DEVICE_STATUSES = ("healthy", "warning", "threat", "down", "unknown")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL UNIQUE,
    role      TEXT NOT NULL DEFAULT '',
    ip        TEXT,
    type      TEXT NOT NULL DEFAULT 'vm',          -- host | vm | switch | server | storage
    parent_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    status    TEXT NOT NULL DEFAULT 'unknown',
    last_checked TEXT,
    check_failures INTEGER NOT NULL DEFAULT 0,
    model TEXT NOT NULL DEFAULT '',
    cpu       INTEGER, memory INTEGER, disk INTEGER, temp INTEGER, uptime_hours INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,                  -- threat | warning
    device_name    TEXT NOT NULL,
    message        TEXT NOT NULL,
    recommendation TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged | resolved
    created_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ts TEXT NOT NULL
);

-- Accounts that can sign in. Roles: admin (full control) | supervisor (watch + acknowledge alerts).
CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL DEFAULT 'supervisor',
    is_active            INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    last_login_at        TEXT,
    full_name            TEXT NOT NULL DEFAULT '',
    created_by           TEXT NOT NULL DEFAULT '',
    password_changed_at  TEXT
);
-- Every sign-in, failed sign-in, lock-out and sign-out (shown on the Users page).
CREATE TABLE IF NOT EXISTS login_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    username TEXT NOT NULL,
    ip       TEXT NOT NULL DEFAULT '',
    outcome  TEXT NOT NULL,                          -- success | failed | locked | disabled | logout | password
    detail   TEXT NOT NULL DEFAULT ''
);

-- One row per switch. Name and IP live in the devices table.
CREATE TABLE IF NOT EXISTS switches (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id      INTEGER NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
    location       TEXT NOT NULL DEFAULT '',
    floor_order    INTEGER NOT NULL DEFAULT 0,
    kind           TEXT NOT NULL DEFAULT 'floor',  -- core | floor | camera
    model          TEXT NOT NULL DEFAULT '',
    serial         TEXT NOT NULL DEFAULT '',
    notes          TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL DEFAULT 'unknown',-- online | offline | unknown
    snmp_ok        INTEGER NOT NULL DEFAULT 0,
    miss_count     INTEGER NOT NULL DEFAULT 0,
    uptime_seconds INTEGER,
    last_seen      TEXT,
    last_poll      TEXT,
    discovered     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS switch_ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id    INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    label        TEXT NOT NULL,                    -- e.g. 1/1/17
    kind         TEXT NOT NULL DEFAULT 'access',   -- access | uplink
    alias        TEXT NOT NULL DEFAULT '',         -- the port name set on the switch
    admin_status TEXT NOT NULL DEFAULT 'up',       -- up | down (down = switched off on purpose)
    oper_status  TEXT NOT NULL DEFAULT 'unknown',  -- up | down | unknown
    expected_up  INTEGER NOT NULL DEFAULT 0,       -- 1 = raise an alert when this port goes down
    changed_at   TEXT,
    reported     INTEGER NOT NULL DEFAULT 0,       -- 1 = the switch itself has reported this port
    UNIQUE (switch_id, label)
);
CREATE TABLE IF NOT EXISTS switch_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    switch_id  INTEGER NOT NULL REFERENCES switches(id) ON DELETE CASCADE,
    port_label TEXT NOT NULL DEFAULT '',
    event      TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_switch_events ON switch_events (switch_id, id DESC);

-- Small key/value store, used for the collector heartbeat.
CREATE TABLE IF NOT EXISTS monitor_status (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_telemetry (
    device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    last_seen TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS access_point_metrics (
    device_id INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    connected_clients REAL,
    channel_utilization REAL,
    avg_rssi REAL,
    dns_latency_ms REAL,
    dhcp_latency_ms REAL
);

CREATE TABLE IF NOT EXISTS maintenance_windows (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    reason     TEXT NOT NULL,
    starts_at  TEXT NOT NULL,
    ends_at    TEXT NOT NULL,
    created_by TEXT NOT NULL,
    is_active  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_maintenance_device_window
    ON maintenance_windows (device_id, is_active, starts_at, ends_at);
"""

# Columns added to the alerts table after the first release. Added automatically.
ALERT_COLUMNS = [
    ("category", "TEXT NOT NULL DEFAULT 'general'"),
    ("switch_id", "INTEGER"),
    ("port_label", "TEXT NOT NULL DEFAULT ''"),
    ("fingerprint", "TEXT"),
    ("occurrences", "INTEGER NOT NULL DEFAULT 1"),
    ("last_seen", "TEXT"),
]


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 15000")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid


def audit(action, detail="", actor=None):
    if actor is None:
        actor = session.get("user", "system") if has_request_context() else "system"
    execute(
        "INSERT INTO audit_logs (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now_iso(), actor, action, detail),
    )


def is_in_maintenance(device_id, at=None):
    stamp = at or now_iso()
    return query(
        "SELECT 1 FROM maintenance_windows WHERE device_id = ? AND is_active = 1 "
        "AND starts_at <= ? AND ends_at > ? LIMIT 1",
        (device_id, stamp, stamp),
        one=True,
    ) is not None


def active_maintenance_device_ids(device_ids=None, at=None):
    stamp = at or now_iso()
    sql = (
        "SELECT DISTINCT device_id FROM maintenance_windows "
        "WHERE is_active = 1 AND starts_at <= ? AND ends_at > ?"
    )
    args = [stamp, stamp]
    if device_ids is not None:
        ids = tuple(device_ids)
        if not ids:
            return set()
        sql += " AND device_id IN (" + ",".join("?" for _ in ids) + ")"
        args.extend(ids)
    return {row["device_id"] for row in query(sql, args)}


def active_maintenance_windows(at=None):
    stamp = at or now_iso()
    return query(
        "SELECT m.*, d.name AS device_name, d.type AS device_type "
        "FROM maintenance_windows m JOIN devices d ON d.id = m.device_id "
        "WHERE m.is_active = 1 AND m.starts_at <= ? AND m.ends_at > ? "
        "ORDER BY m.ends_at, d.name",
        (stamp, stamp),
    )


# ------------------------------------------------------------ monitor_status
def set_status(key, value=""):
    execute(
        "INSERT INTO monitor_status (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, str(value), now_iso()),
    )


def get_status(key):
    return query("SELECT * FROM monitor_status WHERE key = ?", (key,), one=True)


# ------------------------------------------------------------------- start-up
def init_db(app):
    """Create tables, upgrade older databases, and load the starting inventory."""
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        db.execute("PRAGMA journal_mode = WAL")  # lets the web app and the collector share the file
        db.executescript(SCHEMA)
        _migrate(db)
        refresh_options = tuple(
            seconds for seconds, _label in app.config.get(
                "REFRESH_INTERVAL_OPTIONS", ((1800, "30 minutes"), (3600, "1 hour"))
            )
        )
        default_refresh = app.config.get("REFRESH_SECONDS", 1800)
        if default_refresh not in refresh_options:
            default_refresh = min(refresh_options)
        db.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('refresh_seconds', ?)",
            (str(default_refresh),),
        )
        db.commit()
        if db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0:
            _seed(db)
        # Also repairs a database made before the switches existed: missing switches are added, existing ones are kept.
        have = db.execute("SELECT COUNT(*) FROM switches").fetchone()[0]
        if have < len(seed_data.SWITCHES):
            seed_switches(db, demo=app.config.get("DEMO_MODE", True))
        _seed_hotel_links(db)


SWITCH_TABLES = ("switch_events", "switch_ports", "switches")   # dependants first
OTHER_REBUILDABLE = ("monitor_status", "audit_logs", "login_attempts")


def _table_info(conn, table):
    return conn.execute(f"PRAGMA table_info({table})").fetchall()


def _repair_tables(db):
    """Bring a database made by an older/different layout up to the current one without losing data.

    - Missing columns on devices/alerts are added when that is safe.
    - A switch, status or log table with the wrong columns is set aside (renamed <name>_old_<time> if it holds
      rows, dropped if empty) and rebuilt. The switches are then re-created from the inventory.
    """
    ref = sqlite3.connect(":memory:")
    ref.executescript(SCHEMA)
    try:
        for table in ("devices", "alerts"):
            have = {r[1] for r in _table_info(db, table)}
            for _cid, name, ctype, notnull, default, _pk in _table_info(ref, table):
                if have and name not in have and not (notnull and default is None):
                    extra = f" DEFAULT {default}" if default is not None else ""
                    db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ctype}{extra}")
        broken = set()
        for table in SWITCH_TABLES + OTHER_REBUILDABLE:
            want = {r[1] for r in _table_info(ref, table)}
            have = {r[1] for r in _table_info(db, table)}
            if have and not want <= have:
                broken.add(table)
        if broken & set(SWITCH_TABLES):
            broken |= set(SWITCH_TABLES)
    finally:
        ref.close()
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    for table in SWITCH_TABLES + OTHER_REBUILDABLE:
        if table not in broken:
            continue
        if db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
            db.execute(f"ALTER TABLE {table} RENAME TO {table}_old_{stamp}")
        else:
            db.execute(f"DROP TABLE {table}")
    db.executescript(SCHEMA)
    db.commit()


def _migrate(db):
    """Add new columns to a database made by an earlier version (keeps your data)."""
    _repair_tables(db)
    have = {row["name"] for row in db.execute("PRAGMA table_info(alerts)")}
    for name, definition in ALERT_COLUMNS:
        if name not in have:
            db.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    for name, definition in (
        ("is_active", "INTEGER NOT NULL DEFAULT 1"),
        ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ("last_login_at", "TEXT"),
        ("full_name", "TEXT NOT NULL DEFAULT ''"),
        ("created_by", "TEXT NOT NULL DEFAULT ''"),
        ("password_changed_at", "TEXT"),
    ):
        if name not in user_columns:
            db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
    if "is_active" not in user_columns and "active" in user_columns:
        db.execute("UPDATE users SET is_active = active")
    if "must_change_password" not in user_columns and "must_change" in user_columns:
        db.execute("UPDATE users SET must_change_password = must_change")
    if "last_login_at" not in user_columns and "last_login" in user_columns:
        db.execute("UPDATE users SET last_login_at = last_login WHERE last_login IS NOT NULL")
    db.execute("UPDATE users SET role = 'admin' WHERE role = 'administrator'")
    telemetry_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(device_telemetry)")
    }
    if "status" not in telemetry_columns:
        db.execute(
            "ALTER TABLE device_telemetry ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown'"
        )
    ap_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(access_point_metrics)")
    }
    if "status" not in ap_columns:
        db.execute(
            "ALTER TABLE access_point_metrics ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown'"
        )
    for name in (
        "connected_clients", "channel_utilization", "avg_rssi",
        "dns_latency_ms", "dhcp_latency_ms",
    ):
        if name not in ap_columns:
            db.execute(f"ALTER TABLE access_point_metrics ADD COLUMN {name} REAL")
    db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts (fingerprint, status)")
    db.commit()


def _seed(db):
    host_ids = {}
    for name, ip, cpu, mem, disk, temp, up in seed_data.HOSTS:
        cur = db.execute(
            "INSERT INTO devices (name, role, ip, type, cpu, memory, disk, temp, uptime_hours)"
            " VALUES (?, 'Hypervisor', ?, 'host', ?, ?, ?, ?, ?)",
            (name, ip, cpu, mem, disk, temp, up),
        )
        host_ids[name] = cur.lastrowid

    for parent, vms in seed_data.VMS.items():
        for name, role, ip in vms:
            db.execute(
                "INSERT INTO devices (name, role, ip, type, parent_id) VALUES (?, ?, ?, 'vm', ?)",
                (name, role, ip, host_ids[parent]),
            )

    for name, role, ip, dtype in seed_data.OTHER_DEVICES:
        db.execute(
            "INSERT INTO devices (name, role, ip, type) VALUES (?, ?, ?, ?)",
            (name, role, ip, dtype),
        )

    for title, sev, device, msg, rec, status in seed_data.ALERTS:
        db.execute(
            "INSERT INTO alerts (title, severity, device_name, message, recommendation, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, sev, device, msg, rec, status, now_iso()),
        )
    db.commit()


def _seed_hotel_links(db):
    """Create the named WAN link placeholders once, preserving operator edits."""
    for name, role in (("WAN 1", "Safaricom"), ("WAN 2", "")):
        db.execute(
            "INSERT OR IGNORE INTO devices (name, role, type, status) "
            "VALUES (?, ?, 'wan_link', 'unknown')",
            (name, role),
        )
    db.commit()


# ------------------------------------------------------------------- switches
def port_layout(model, access, uplinks):
    """Return [(label, kind)] for a switch, using Ruckus ICX naming (stack/slot/port)."""
    ports = [(f"1/1/{n}", "access") for n in range(1, access + 1)]
    if model == "ICX 7150-48P":      # 2 copper uplinks in slot 2, 4 SFP+ in slot 3
        ports += [(f"1/2/{n}", "uplink") for n in range(1, 3)]
        ports += [(f"1/3/{n}", "uplink") for n in range(1, uplinks - 1)]
    else:                            # every other model: uplinks in slot 2
        ports += [(f"1/2/{n}", "uplink") for n in range(1, uplinks + 1)]
    return ports


def seed_switches(db, demo):
    """Create the switch records from the spreadsheet. Demo mode also fills in example port states."""
    stamp = now_iso()
    created = 0
    ips = {n: (r, i) for n, r, i, t in seed_data.OTHER_DEVICES if t == "switch"}
    for index, (name, location, order, kind, model, serial, access, uplinks, note) in enumerate(seed_data.SWITCHES):
        dev = db.execute("SELECT id FROM devices WHERE name = ?", (name,)).fetchone()
        if dev is None and name in ips:  # older database without this switch: add its device record
            role, ip = ips[name]
            cur = db.execute("INSERT INTO devices (name, role, ip, type) VALUES (?, ?, ?, 'switch')", (name, role, ip))
            dev = {"id": cur.lastrowid}
        if dev is None:
            continue
        if db.execute("SELECT 1 FROM switches WHERE device_id = ?", (dev["id"],)).fetchone():
            continue  # already set up: keep its data
        created += 1
        cur = db.execute(
            "INSERT INTO switches (device_id, location, floor_order, kind, model, serial, notes, state, snmp_ok, last_seen, last_poll)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (dev["id"], location, order, kind, model, serial, note,
             "online" if demo else "unknown", 1 if demo else 0, stamp if demo else None, stamp if demo else None),
        )
        switch_id = cur.lastrowid
        if demo:
            db.execute("UPDATE switches SET uptime_seconds = ? WHERE id = ?", ((20 + index * 9) * 86400, switch_id))
        for label, port_kind in port_layout(model, access, uplinks):
            number = int(label.split("/")[-1])
            if not demo:
                # live mode: a port becomes "watched" only after it has been seen working,
                # so an empty spare uplink never raises a false alarm
                oper, expected, reported = "unknown", 0, 0
            elif port_kind == "uplink":
                oper, expected, reported = "up" if number <= 2 else "down", 1 if number <= 2 else 0, 1
            else:
                up = (number * 5 + index * 3) % 10 < 6
                oper, expected, reported = ("up", 1, 1) if up else ("down", 0, 1)
            db.execute(
                "INSERT INTO switch_ports (switch_id, label, kind, oper_status, expected_up, changed_at, reported)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (switch_id, label, port_kind, oper, expected, stamp if reported else None, reported),
            )

    if demo and created:  # one example fault so the SOC screen shows what a port-down alert looks like
        db.execute("INSERT OR REPLACE INTO monitor_status (key, value, updated_at) VALUES ('demo_seeded', '1', ?)", (stamp,))
        row = db.execute(
            "SELECT s.id AS sid, d.name FROM switches s JOIN devices d ON d.id = s.device_id WHERE d.name = 'SW-3RD'"
        ).fetchone()
        if row:
            db.execute("UPDATE switch_ports SET oper_status = 'down', expected_up = 1 "
                       "WHERE switch_id = ? AND label = '1/1/17'", (row["sid"],))
            db.execute(
                "INSERT INTO alerts (title, severity, device_name, message, recommendation, status, created_at,"
                " category, switch_id, port_label, fingerprint, occurrences, last_seen)"
                " VALUES (?, 'warning', ?, ?, ?, 'open', ?, 'switch', ?, '1/1/17', ?, 1, ?)",
                ("Port down", row["name"], "SIMULATED: port 1/1/17 lost its link.",
                 "Check the cable and the device on that port.", stamp, row["sid"],
                 f"port_down:{row['name']}:1/1/17", stamp),
            )
            db.execute("INSERT INTO switch_events (ts, switch_id, port_label, event, detail) VALUES (?, ?, '1/1/17', 'port_down', 'SIMULATED')",
                       (stamp, row["sid"]))
    db.commit()

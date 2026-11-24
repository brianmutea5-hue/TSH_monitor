"""Go-live helper: proves each link in the chain BEFORE the SOC depends on it.

    python go_live.py                      check the settings, database and collector (nothing is changed)
    python go_live.py --switch SW-2ND      test ONE switch: ping, SNMP, uptime and every port (read-only)
    python go_live.py --listen             show the raw syslog lines your switches send, and which
                                           attack rule each one would trigger (stop collector.py first)
    python go_live.py --check-line "text"  test one syslog line against the attack rules

It only reads. It never writes to a switch and never creates alerts.
"""
import argparse
import re
import socket
import sys
import time
from pathlib import Path

from app import app
import monitoring
import snmp
from collector import ping

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
ICX_LABEL = re.compile(r"^\d{1,2}/\d{1,2}/\d{1,3}$")

results = {"fail": 0, "warn": 0}


def show(level, text, fix=""):
    tag = {"pass": "[ PASS ]", "warn": "[ WARN ]", "fail": "[ FAIL ]", "info": "[ INFO ]"}[level]
    if level in results:
        results[level] += 1
    print(f"{tag} {text}")
    if fix and level in ("warn", "fail"):
        print(f"         -> {fix}")


def finish():
    print()
    if results["fail"]:
        print(f"NOT READY: {results['fail']} problem(s) to fix, {results['warn']} warning(s).")
        return 1
    if results["warn"]:
        print(f"READY WITH WARNINGS: {results['warn']} thing(s) worth fixing before the SOC relies on it.")
        return 0
    print("READY: everything checked passed.")
    return 0


# --------------------------------------------------------------- preflight
def preflight():
    cfg = app.config
    print("TSH Monitor - go-live check\n")

    env_file = Path(app.root_path) / ".env"
    show("pass" if env_file.exists() else "fail", f".env file {'found' if env_file.exists() else 'missing'}",
         "Create .env next to app.py (copy .env.example).")
    show("pass" if not cfg["DEMO_MODE"] else "fail",
         "DEMO_MODE is off (real readings)" if not cfg["DEMO_MODE"] else "DEMO_MODE=1: the screen shows simulated switches",
         "Set DEMO_MODE=0 in .env and restart the app.")

    community = cfg["SNMP_COMMUNITY"]
    if not community:
        show("fail", "SNMP_COMMUNITY is empty, so ports cannot be read (ping only)",
             "Set the read-only community in .env. It must match the one configured on the switch.")
    elif community.lower() in ("public", "private"):
        show("warn", "SNMP community is a well-known default ('public'/'private')",
             "Use a long random read-only community. Default names are the first thing an attacker tries.")
    else:
        show("pass", "SNMP community is set (value hidden)")

    import os
    show("pass" if os.environ.get("SECRET_KEY") else "warn",
         "SECRET_KEY is fixed in .env" if os.environ.get("SECRET_KEY") else "SECRET_KEY is not set: everyone is signed out whenever the app restarts",
         "Add SECRET_KEY=<64 random characters> to .env  (python -c \"import secrets;print(secrets.token_hex(32))\").")
    has_admin = bool(cfg["ADMIN_PASSWORD"] or cfg["ADMIN_PASSWORD_HASH"])
    show("pass" if has_admin else "fail", "Admin password is configured" if has_admin else "No admin password in .env",
         "Set ADMIN_PASSWORD (or ADMIN_PASSWORD_HASH) in .env.")
    if cfg["ADMIN_PASSWORD"] and len(cfg["ADMIN_PASSWORD"]) < 12:
        show("warn", "Admin password is shorter than 12 characters", "Use 12 or more characters before going live.")
    if cfg["INGEST_TOKEN"]:
        show("pass" if len(cfg["INGEST_TOKEN"]) >= 24 else "warn", "Sensor API token is set",
             "Use a token of 24+ random characters.")
    else:
        show("info", "INGEST_TOKEN is empty: the outside-sensor API (Wazuh/Suricata) is switched off")

    with app.app_context():
        rows = [s for s in monitoring.all_switches() if s["ip"]]
        show("pass" if rows else "fail", f"{len(rows)} switches have an IP address in the database",
             "Check seed_data.py / the switch edit page: every switch needs its IP.")
        chosen = cfg["LIVE_TRIAL_SWITCHES"]
        if chosen:
            known = {s["name"].lower() for s in rows} | {s["ip"] for s in rows}
            missing = [c for c in chosen if c.lower() not in known]
            show("fail" if missing else "pass",
                 f"Trial mode: watching only {', '.join(chosen)}" if not missing else f"LIVE_TRIAL_SWITCHES names an unknown switch: {', '.join(missing)}",
                 "Use the exact switch name (e.g. SW-2ND) or its IP.")
        else:
            show("info", "LIVE_TRIAL_SWITCHES is empty: every switch will be watched (fine after the trial passes)")
        if cfg["SYSLOG_ENABLED"] is False:
            show("warn", "SYSLOG_ENABLED=0: attacks (ARP spoofing, rogue DHCP...) cannot be detected, only failures",
                 "Set SYSLOG_ENABLED=1 and point the switch's syslog to this server.")
        state, age = monitoring.collector_state()
        if state == "ok":
            show("pass", f"Collector is running (last check {age}s ago)")
        elif state == "stale":
            show("fail", f"Collector stopped {age}s ago", "Start it: python collector.py")
        elif state == "never":
            show("warn", "Collector has never run", "Start it in a second terminal: python collector.py")

    if cfg["SYSLOG_ENABLED"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("0.0.0.0", cfg["SYSLOG_PORT"]))
            show("pass", f"UDP {cfg['SYSLOG_PORT']} is free for the syslog listener")
        except OSError:
            show("pass", f"UDP {cfg['SYSLOG_PORT']} is in use (expected if collector.py is running)")
        finally:
            s.close()
        show("info", f"Windows Firewall must allow inbound UDP {cfg['SYSLOG_PORT']} from the switch network")
    return finish()


# --------------------------------------------------------- one-switch test
def test_switch(ref):
    cfg = app.config
    print(f"TSH Monitor - testing one switch: {ref}\n")
    with app.app_context():
        sw = monitoring.find_switch(ref)
        if sw is None:
            show("fail", f"No switch named or addressed '{ref}'", "Use the exact name or IP from the Switches page.")
            return finish()
        ip = sw["ip"]
        show("info", f"{sw['name']}  {ip}  {sw['model']}  {sw['location']}")
        want_access = len(monitoring.query("SELECT 1 FROM switch_ports WHERE switch_id = ? AND kind = 'access'", (sw["id"],)))
        want_up = len(monitoring.query("SELECT 1 FROM switch_ports WHERE switch_id = ? AND kind = 'uplink'", (sw["id"],)))

    started = time.monotonic()
    alive = ping(ip, 2)
    show("pass" if alive else "warn", f"Ping {ip}: {'replies' if alive else 'no reply'}",
         "Some switches block ping. Carry on: SNMP is the real test. If SNMP also fails, check the IP and routing.")

    if not cfg["SNMP_COMMUNITY"]:
        show("fail", "SNMP_COMMUNITY is empty in .env")
        return finish()
    client = snmp.Snmp(ip, cfg["SNMP_COMMUNITY"], cfg["SNMP_PORT"], max(cfg["SNMP_TIMEOUT"], 3))
    try:
        descr = client.get(SYS_DESCR)
        if descr:
            show("pass", f"SNMP answers: {snmp._text(descr)[:90]}")
    except snmp.SnmpError:
        show("info", "sysDescr not returned (not required)")
    except OSError as exc:
        show("fail", f"Network error talking to {ip}: {exc}")
        return finish()

    try:
        data = snmp.read_switch(ip, cfg["SNMP_COMMUNITY"], cfg["SNMP_PORT"], max(cfg["SNMP_TIMEOUT"], 3))
    except (snmp.SnmpError, OSError) as exc:
        show("fail", f"SNMP read failed: {exc}",
             "On the switch: 'snmp-server community <RO> ro' and allow the monitor server's IP. "
             "Check the community text matches .env exactly, and UDP 161 is not blocked between the networks.")
        return finish()
    took = time.monotonic() - started
    ports = data["ports"]
    show("pass", f"SNMP read OK in {took:.1f}s. Uptime {data['uptime'] // 86400} days {data['uptime'] % 86400 // 3600} h")
    if took > cfg["SWITCH_POLL_SECONDS"] / 2:
        show("warn", f"Reading this switch takes {took:.0f}s, more than half the poll interval",
             "Raise SWITCH_POLL_SECONDS in .env.")

    up = sorted(p for p, v in ports.items() if v["oper"] == "up")
    down = sorted(p for p, v in ports.items() if v["oper"] == "down")
    show("pass" if ports else "fail", f"{len(ports)} ports read: {len(up)} up, {len(down)} down")
    odd = [p for p in ports if not ICX_LABEL.match(p)]
    if odd:
        show("warn", f"{len(odd)} port names are not in 1/1/N form, e.g. {', '.join(odd[:4])}",
             "Alerts for those ports will use these names. Syslog 'port down' lines may not match them.")
    expected = want_access + want_up
    if expected and len(ports) != expected:
        show("warn", f"The inventory expects {expected} ports ({want_access} access + {want_up} uplink) but the switch reports {len(ports)}",
             "Fine if the model differs; correct the model/port counts on the Edit Switch page.")
    named = [p for p in ports if ports[p]["alias"]]
    show("info", f"{len(named)} ports have a name set on the switch (e.g. 'Room 214')")
    print("\nFirst ports as the SOC will see them:")
    for label in sorted(ports, key=lambda x: [int(n) if n.isdigit() else 0 for n in re.split(r"\D+", x)])[:8]:
        v = ports[label]
        print(f"   {label:<10} {v['oper']:<5} admin {v['admin']:<5} {v['alias']}")
    return finish()


# ------------------------------------------------------------ syslog tools
def explain_line(text, source="?"):
    """Which handler would act on this line."""
    if monitoring.LINK_DOWN.search(text):
        return "LINK DOWN  -> port alert"
    if monitoring.LINK_UP.search(text):
        return "LINK UP    -> port recovers"
    for regex, key in monitoring.SYSLOG_RULES:
        if regex.search(text):
            return f"THREAT: {key}  -> {monitoring.THREATS[key]['title']}"
    return "no rule matches (ignored)"


def listen():
    cfg = app.config
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", cfg["SYSLOG_PORT"]))
    except OSError as exc:
        print(f"Cannot listen on UDP {cfg['SYSLOG_PORT']}: {exc}\nStop collector.py first (it uses the same port).")
        return 1
    out = Path(cfg["DATABASE"]).parent / "syslog_capture.log"
    out.parent.mkdir(exist_ok=True)
    print(f"Listening on UDP {cfg['SYSLOG_PORT']}. On the switch cause a real event (unplug a cable, make a wrong login).")
    print(f"Every line is also saved to {out}. Press Ctrl+C to stop.\n")
    try:
        with app.app_context(), open(out, "a", encoding="utf-8") as fh:
            while True:
                data, addr = sock.recvfrom(8192)
                text = data.decode("utf-8", "replace").strip()
                if text.startswith("<") and ">" in text[:6]:
                    text = text.split(">", 1)[1]
                known = monitoring.find_switch(addr[0])
                who = known["name"] if known else "UNKNOWN SOURCE (not an inventory IP: it will be ignored)"
                print(f"{time.strftime('%H:%M:%S')} {addr[0]} [{who}]\n   {text}\n   => {explain_line(text)}\n")
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {addr[0]} {text}\n")
                fh.flush()
    except KeyboardInterrupt:
        print("Stopped.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="TSH go-live checks (read-only)")
    ap.add_argument("--switch", metavar="NAME_OR_IP", help="test one switch end to end")
    ap.add_argument("--listen", action="store_true", help="show raw syslog lines from the switches")
    ap.add_argument("--check-line", metavar="TEXT", help="test one syslog line against the attack rules")
    a = ap.parse_args()
    if a.check_line:
        with app.app_context():
            print(explain_line(a.check_line))
        return 0
    if a.listen:
        return listen()
    if a.switch:
        return test_switch(a.switch)
    return preflight()


if __name__ == "__main__":
    sys.exit(main())

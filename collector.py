"""Switch collector - the part that watches your real switches.

Run it in a second terminal, next to the web app:

    python collector.py            keep watching (leave it running)
    python collector.py --once     check every switch one time, then stop
    python collector.py --reset    forget the demo readings (done automatically when you leave demo mode)

Every SWITCH_POLL_SECONDS it asks each switch, over SNMP (read-only), for its uptime and the
status of every port. A port that was working and is now down becomes an alert on the SOC
screen. If SYSLOG_ENABLED=1 it also listens for the switches' syslog messages, which is how
attacks such as ARP spoofing or a rogue DHCP server are reported.
"""
import argparse
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app import app
import monitoring
import snmp
import switch_monitor
from database import audit, get_status, query, set_status


def log(message):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


# ------------------------------------------------------------------ one switch
def ping(ip, timeout=1):
    """True if the address answers a ping. Returns False if ping itself cannot be run."""
    if platform.system() == "Windows":
        cmd, flags = ["ping", "-n", "1", "-w", str(timeout * 1000), ip], subprocess.CREATE_NO_WINDOW
    else:
        cmd, flags = ["ping", "-c", "1", "-W", str(timeout), ip], 0
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout + 3, creationflags=flags).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def probe(ip, community, port=161, timeout=2):
    """Talk to one switch. Runs in a worker thread, so it must not touch the database."""
    result = {"reachable": False, "snmp_ok": False, "uptime": None, "ports": None, "error": ""}
    if not isinstance(community, str):
        settings = community
        use_snmp = switch_monitor.snmp_configured(settings)
        if use_snmp:
            try:
                data = switch_monitor.read_switch(ip, settings, include_ports=True)
                result.update(
                    reachable=True, snmp_ok=True,
                    uptime=data["uptime"], ports=data["ports"],
                )
                return result
            except Exception as exc:  # one switch must not stop the rest
                result["error"] = f"{type(exc).__name__}: SNMP read failed"
        result["reachable"] = ping(ip, settings.get("SNMP_TIMEOUT", 1))
        return result

    if community:
        try:
            data = snmp.read_switch(ip, community, port, timeout)
            result.update(reachable=True, snmp_ok=True, uptime=data["uptime"], ports=data["ports"])
            return result
        except snmp.SnmpError as exc:
            result["error"] = str(exc)
        except Exception as exc:  # never let one bad reply stop the others
            result["error"] = f"{type(exc).__name__}: {exc}"
    result["reachable"] = ping(ip)
    return result


# ------------------------------------------------------------------ a full round
def watched_switches():
    """Every switch with an IP, or only the trial switches named in LIVE_TRIAL_SWITCHES."""
    chosen = [x.lower() for x in app.config["LIVE_TRIAL_SWITCHES"]]
    rows = [s for s in monitoring.all_switches() if s["ip"]]
    if not chosen:
        return rows
    return [s for s in rows if s["name"].lower() in chosen or s["ip"] in chosen]


def run_round(pool):
    cfg = app.config
    use_snmp = switch_monitor.snmp_configured(cfg)
    with app.app_context():
        switches = watched_switches()
        jobs = [(s, pool.submit(probe, s["ip"], cfg)) for s in switches]
        reachable = down = 0
        for sw, job in jobs:
            try:
                r = job.result()
                fresh = monitoring.get_switch(sw["id"])
                # With no SNMP profile set we only ping, so that is not an SNMP fault.
                monitoring.apply_switch_poll(
                    fresh, r["reachable"], r["snmp_ok"] or not use_snmp,
                    r["uptime"], r["ports"],
                )
                if r["reachable"]:
                    reachable += 1
                else:
                    down += 1
                if r["error"]:
                    log(f"{sw['name']} ({sw['ip']}): {r['error']}")
            except Exception as exc:
                app.logger.exception("Polling %s failed", sw["name"])
                log(f"{sw['name']}: error {type(exc).__name__}: {exc}")
        set_status("collector", f"{reachable} reachable, {down} not reachable")
        return reachable, down


# ---------------------------------------------------------------------- syslog
def syslog_loop(stop):
    cfg = app.config
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", cfg["SYSLOG_PORT"]))
    except OSError as exc:
        log(f"Syslog listener could not start on UDP {cfg['SYSLOG_PORT']}: {exc}")
        return
    sock.settimeout(1.0)
    log(f"Listening for switch syslog on UDP port {cfg['SYSLOG_PORT']}")
    unmatched = Path(cfg["DATABASE"]).parent / "syslog_unmatched.log"
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            continue
        except OSError:
            break
        text = data.decode("utf-8", "replace").strip()
        if text.startswith("<") and ">" in text[:6]:
            text = text.split(">", 1)[1]
        with app.app_context():
            try:
                outcome = monitoring.handle_syslog(addr[0], text)
            except Exception:
                app.logger.exception("Syslog message could not be handled")
                continue
        if outcome:
            log(f"syslog: {outcome}")
        elif cfg["SYSLOG_LOG_UNMATCHED"]:
            with open(unmatched, "a", encoding="utf-8") as fh:
                fh.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {addr[0]} {text}\n")


# ------------------------------------------------------------------------ main
def main():
    parser = argparse.ArgumentParser(description="TSH switch collector")
    parser.add_argument("--once", action="store_true", help="check every switch once, then stop")
    parser.add_argument("--reset", action="store_true", help="forget demo switch readings and stop")
    args = parser.parse_args()
    cfg = app.config

    if args.reset:
        with app.app_context():
            monitoring.reset_switch_data()
        log("Demo switch readings cleared. Ports are now 'unknown' until the first live check.")
        return 0

    if cfg["DEMO_MODE"]:
        log("DEMO_MODE=1 in .env, so the app shows simulated switches and the collector is not needed.")
        log("To watch the real switches: set DEMO_MODE=0 in .env, set SNMP_COMMUNITY, restart the app, run this again.")
        return 1

    with app.app_context():
        if get_status("demo_seeded"):
            monitoring.reset_switch_data()
            log("Cleared the demo switch readings left from demo mode.")
        count = len(watched_switches())
    if cfg["LIVE_TRIAL_SWITCHES"]:
        log(f"TRIAL MODE: only {', '.join(cfg['LIVE_TRIAL_SWITCHES'])} is watched. The other switches stay 'Not read yet'.")
    if not cfg["SNMP_COMMUNITY"]:
        log("WARNING: SNMP_COMMUNITY is not set in .env. Switches are only pinged, so ports cannot be read.")
    log(f"Watching {count} switches every {cfg['SWITCH_POLL_SECONDS']} seconds. Press Ctrl+C to stop.")

    stop = threading.Event()
    if cfg["SYSLOG_ENABLED"] and not args.once:
        threading.Thread(target=syslog_loop, args=(stop,), daemon=True).start()

    rounds = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        try:
            while True:
                started = time.monotonic()
                reachable, down = run_round(pool)
                log(f"Checked {reachable + down} switches: {reachable} reachable, {down} not reachable")
                rounds += 1
                if rounds % 200 == 0:
                    with app.app_context():
                        monitoring.purge_old()
                if args.once:
                    break
                time.sleep(max(1.0, cfg["SWITCH_POLL_SECONDS"] - (time.monotonic() - started)))
        except KeyboardInterrupt:
            log("Stopped.")
        finally:
            stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())

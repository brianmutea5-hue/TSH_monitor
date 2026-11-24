"""Background reachability checks for inventory devices with valid IP addresses."""
import concurrent.futures
import ipaddress
import os
import socket
import subprocess
import threading
import time

import monitoring
from database import DEVICE_STATUSES, query

_POLL_LOCK = threading.Lock()
_START_LOCK = threading.Lock()
_THREADS = {}


def check_device(ip, tcp_ports=(), timeout=1):
    """Return whether ping or any configured TCP port responds."""
    address = str(ipaddress.ip_address(ip))
    if os.name == "nt":
        ping_command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), address]
    else:
        ping_command = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), address]

    try:
        ping_result = subprocess.run(
            ping_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout + 1, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        ping_result = None
    if ping_result is not None and ping_result.returncode == 0:
        return True

    for port in tcp_ports:
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _status_after_check(device, reachable, failure_limit):
    if not reachable:
        failures = int(device.get("check_failures") or 0) + 1
        if failures >= failure_limit:
            status = "down"
        elif device["status"] in ("healthy", "unknown"):
            status = "warning" if device["status"] == "healthy" else "unknown"
        else:
            status = device["status"]
        if status not in DEVICE_STATUSES:
            status = "unknown"
        return status, failures

    active = query(
        "SELECT severity FROM alerts WHERE device_name = ? AND status != 'resolved' "
        "AND (fingerprint IS NULL OR fingerprint != ?)",
        (device["name"], f"device_down:{device['id']}"),
    )
    if any(row["severity"] == "threat" for row in active):
        status = "threat"
    elif any(row["severity"] == "warning" for row in active):
        status = "warning"
    else:
        status = "healthy"
    return status, 0


def poll_once(app, device_ids=None):
    """Check all eligible devices without overlapping another poll."""
    if not _POLL_LOCK.acquire(blocking=False):
        return False
    try:
        with app.app_context():
            sql = (
                "SELECT id, name, ip, status, check_failures FROM devices "
                "WHERE type NOT IN ('switch', 'wan_link') "
                "AND ip IS NOT NULL AND trim(ip) != ''"
            )
            args = ()
            if device_ids is not None:
                ids = tuple(device_ids)
                if not ids:
                    return True
                sql += " AND id IN (" + ",".join("?" for _ in ids) + ")"
                args = ids
            devices = []
            for row in query(sql + " ORDER BY id", args):
                device = dict(row)
                try:
                    device["ip"] = str(ipaddress.ip_address(device["ip"].strip()))
                except ValueError:
                    continue
                devices.append(device)

            if not devices:
                return True

            timeout = app.config["DEVICE_CHECK_TIMEOUT_SECONDS"]
            ports = app.config["DEVICE_CHECK_TCP_PORTS"]
            workers = app.config["DEVICE_CHECK_WORKERS"]
            failure_limit = app.config["DEVICE_CHECK_FAILURE_LIMIT"]
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                checks = {
                    pool.submit(check_device, device["ip"], ports, timeout): device
                    for device in devices
                }
                for future in concurrent.futures.as_completed(checks):
                    device = checks[future]
                    try:
                        reachable = future.result()
                    except Exception:
                        app.logger.exception("Reachability check failed for device %s", device["name"])
                        reachable = False
                    status, failures = _status_after_check(device, reachable, failure_limit)
                    monitoring.apply_device_status(
                        device, status, check_failures=failures
                    )
        return True
    finally:
        _POLL_LOCK.release()


def _run(app):
    interval = app.config["DEVICE_CHECK_INTERVAL_SECONDS"]
    while True:
        started = time.monotonic()
        try:
            poll_once(app)
        except Exception:
            app.logger.exception("Background device status poll failed")
        time.sleep(max(1, interval - (time.monotonic() - started)))


def start_background_monitor(app):
    """Start one daemon poller for this app instance."""
    if not app.config.get("DEVICE_MONITOR_ENABLED", True):
        return None
    app_id = id(app)
    with _START_LOCK:
        existing = _THREADS.get(app_id)
        if existing is not None and existing.is_alive():
            return existing
        thread = threading.Thread(
            target=_run, args=(app,), name="device-status-monitor", daemon=True
        )
        _THREADS[app_id] = thread
        thread.start()
    app.logger.info(
        "Device status monitor started (interval=%ss)",
        app.config["DEVICE_CHECK_INTERVAL_SECONDS"],
    )
    return thread

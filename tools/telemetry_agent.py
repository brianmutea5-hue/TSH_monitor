"""Report this host's CPU, memory, disk, and uptime to the TSH dashboard."""
import argparse
import ctypes
import json
import os
import shutil
import sys
import time
from urllib import error, parse, request


def _windows_cpu_times():
    class FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

        def value(self):
            return (self.high << 32) | self.low

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    idle, kernel, user = FileTime(), FileTime(), FileTime()
    kernel32.GetSystemTimes.argtypes = [
        ctypes.POINTER(FileTime), ctypes.POINTER(FileTime), ctypes.POINTER(FileTime)
    ]
    kernel32.GetSystemTimes.restype = ctypes.c_int
    if not kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        raise OSError(ctypes.get_last_error(), "Unable to read Windows CPU counters")
    return idle.value(), kernel.value() + user.value()


def _linux_cpu_times():
    with open("/proc/stat", encoding="ascii") as stat_file:
        fields = stat_file.readline().split()
    if not fields or fields[0] != "cpu" or len(fields) < 5:
        raise OSError("Unable to read Linux CPU counters")
    values = [int(value) for value in fields[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, sum(values)


def _cpu_times():
    if sys.platform == "win32":
        return _windows_cpu_times()
    if sys.platform.startswith("linux"):
        return _linux_cpu_times()
    raise OSError("This agent supports Windows and Linux hosts")


def cpu_usage_percent(sample_seconds=1.0):
    idle_before, total_before = _cpu_times()
    time.sleep(max(0.0, sample_seconds))
    idle_after, total_after = _cpu_times()
    total_delta = total_after - total_before
    if total_delta <= 0:
        return 0.0
    busy_delta = total_delta - (idle_after - idle_before)
    return round(max(0.0, min(100.0, busy_delta * 100.0 / total_delta)), 1)


def memory_usage_percent():
    if sys.platform == "win32":
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_uint32),
                ("memory_load", ctypes.c_uint32),
                ("total_phys", ctypes.c_uint64),
                ("avail_phys", ctypes.c_uint64),
                ("total_page_file", ctypes.c_uint64),
                ("avail_page_file", ctypes.c_uint64),
                ("total_virtual", ctypes.c_uint64),
                ("avail_virtual", ctypes.c_uint64),
                ("avail_extended_virtual", ctypes.c_uint64),
            ]

        status = MemoryStatusEx()
        status.length = ctypes.sizeof(status)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatusEx)]
        kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) or not status.total_phys:
            raise OSError(ctypes.get_last_error(), "Unable to read Windows memory counters")
        used = status.total_phys - status.avail_phys
        return round(used * 100.0 / status.total_phys, 1)

    if sys.platform.startswith("linux"):
        values = {}
        with open("/proc/meminfo", encoding="ascii") as meminfo:
            for line in meminfo:
                parts = line.split()
                if len(parts) >= 2:
                    values[parts[0].rstrip(":")] = int(parts[1])
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable")
        if available is None:
            available = sum(values.get(key, 0) for key in ("MemFree", "Buffers", "Cached"))
        if total <= 0:
            raise OSError("Unable to read Linux memory counters")
        return round(max(0, total - available) * 100.0 / total, 1)

    raise OSError("This agent supports Windows and Linux hosts")


def disk_usage_percent(path=None):
    if path is None:
        path = os.environ.get("TELEMETRY_DISK_PATH")
    if not path:
        path = (os.environ.get("SystemDrive", "C:") + os.sep) if os.name == "nt" else os.sep
    total, _used, free = shutil.disk_usage(path)
    if total <= 0:
        raise OSError("Unable to read disk capacity")
    return round((total - free) * 100.0 / total, 1)


def uptime_hours():
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetTickCount64.restype = ctypes.c_uint64
        return round(kernel32.GetTickCount64() / 3_600_000.0, 2)
    if sys.platform.startswith("linux"):
        return round(time.monotonic() / 3600.0, 2)
    raise OSError("This agent supports Windows and Linux hosts")


def collect_metrics():
    return {
        "cpu": cpu_usage_percent(),
        "memory": memory_usage_percent(),
        "disk": disk_usage_percent(),
        "uptime_hours": uptime_hours(),
    }


def validate_url(url):
    parsed = parse.urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise ValueError("TELEMETRY_URL must be an absolute HTTP or HTTPS URL.")
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Use HTTPS for telemetry sent to a remote dashboard.")


def send_metrics(url, device, token, metrics):
    body = json.dumps({"device": device, "metrics": metrics}, separators=(",", ":")).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with request.urlopen(req, timeout=5) as response:
        return response.status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="send one reading and exit")
    parser.add_argument("--sample-only", action="store_true", help="print local metrics without sending them")
    args = parser.parse_args()

    if args.sample_only:
        print(json.dumps(collect_metrics(), sort_keys=True))
        return 0

    url = os.environ.get("TELEMETRY_URL", "").strip()
    device = os.environ.get("TELEMETRY_DEVICE_NAME", "").strip()
    token = os.environ.get("TELEMETRY_TOKEN", "")
    try:
        validate_url(url)
    except ValueError as exc:
        parser.error(str(exc))
    if not device:
        parser.error("Set TELEMETRY_DEVICE_NAME to the exact device name in the dashboard inventory.")
    if len(token) < 32:
        parser.error("Set TELEMETRY_TOKEN to the dashboard's configured token.")
    try:
        interval = int(os.environ.get("TELEMETRY_POLL_SECONDS", "30"))
    except ValueError:
        parser.error("TELEMETRY_POLL_SECONDS must be an integer.")
    if interval < 5:
        parser.error("TELEMETRY_POLL_SECONDS must be at least 5.")

    while True:
        try:
            metrics = collect_metrics()
        except OSError:
            print("Metric collection failed; check the host OS and disk path.", file=sys.stderr)
            if args.once:
                return 1
        else:
            try:
                status = send_metrics(url, device, token, metrics)
            except error.HTTPError as exc:
                print(f"Telemetry rejected by dashboard (HTTP {exc.code}).", file=sys.stderr)
                if args.once:
                    return 1
            except error.URLError:
                print("Telemetry could not reach the dashboard.", file=sys.stderr)
                if args.once:
                    return 1
            else:
                print(f"Telemetry sent for {device} (HTTP {status}).")
                if args.once:
                    return 0
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())

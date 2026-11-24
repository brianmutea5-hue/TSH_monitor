"""Application configuration.

Every value can be changed from the .env file (see .env.example). Nothing secret
is written in the code.
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from werkzeug.security import check_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _int(name, default):
    """Read an integer setting; fall back to the default if missing or invalid."""
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _flag(name, default="0"):
    """Read an on/off setting: 1, true, yes, on = True."""
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _ports(name):
    """Parse a comma-separated list of TCP ports and reject invalid configuration."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return ()
    ports = []
    for item in raw.split(","):
        try:
            port = int(item.strip())
        except ValueError as exc:
            raise ValueError(f"{name} must contain comma-separated port numbers.") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"{name} ports must be between 1 and 65535.")
        if port not in ports:
            ports.append(port)
    return tuple(ports)


def production_config_errors(config):
    """Return safe-to-display errors for incomplete production security settings."""
    if config.get("DEMO_MODE", True):
        return []

    errors = []
    secret_key = config.get("SECRET_KEY", "")
    secret_configured = config.get("SECRET_KEY_CONFIGURED", bool(secret_key))
    if (
        not secret_configured
        or not isinstance(secret_key, str)
        or len(secret_key) < 32
    ):
        errors.append("Set SECRET_KEY to a configured, random value of at least 32 characters.")

    username = config.get("ADMIN_USERNAME", "")
    username_configured = config.get("ADMIN_USERNAME_CONFIGURED", bool(username))
    password = config.get("ADMIN_PASSWORD", "")
    password_hash = config.get("ADMIN_PASSWORD_HASH", "")
    if password_hash:
        try:
            credential_ok = (
                isinstance(password_hash, str)
                and len(password_hash) >= 40
                and password_hash.startswith(("scrypt:", "pbkdf2:"))
                and not check_password_hash(password_hash, "configuration-validation")
            )
        except (TypeError, ValueError):
            credential_ok = False
    else:
        credential_ok = (
            isinstance(password, str)
            and len(password) >= 12
            and any(char.isalpha() for char in password)
            and any(char.isdigit() for char in password)
            and (not username or username.casefold() not in password.casefold())
        )
    if not username_configured or not username or not credential_ok:
        errors.append("Configure an admin username and a strong ADMIN_PASSWORD or valid password hash.")

    if not config.get("SESSION_COOKIE_SECURE", False):
        errors.append("Set SESSION_COOKIE_SECURE=1 when running outside demo mode.")

    return errors


class Config:
    # --- Security -----------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    SECRET_KEY_CONFIGURED = bool(os.environ.get("SECRET_KEY"))
    SESSION_COOKIE_NAME = "tsh_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _flag("SESSION_COOKIE_SECURE")  # set 1 when using HTTPS
    # Automatic sign-out after this many idle minutes
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_int("IDLE_TIMEOUT_MINUTES", 15))

    # --- Admin account (no passwords are stored in the code) ----------------
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_USERNAME_CONFIGURED = bool(os.environ.get("ADMIN_USERNAME", "").strip())
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")            # plain, hashed at start-up
    ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")  # or an already hashed one
    ADMIN_INITIALS = os.environ.get("ADMIN_INITIALS", "IT")[:3]
    MAX_LOGIN_ATTEMPTS = _int("MAX_LOGIN_ATTEMPTS", 5)
    LOCKOUT_MINUTES = _int("LOCKOUT_MINUTES", 5)

    # --- Database -----------------------------------------------------------
    DATABASE = os.environ.get("DATABASE_PATH", str(BASE_DIR / "instance" / "monitor.db"))

    # --- Monitoring behaviour ----------------------------------------------
    DEMO_MODE = _flag("DEMO_MODE", "1")  # 1 = simulated readings
    REFRESH_INTERVAL_OPTIONS = ((1800, "30 minutes"), (3600, "1 hour"))
    REFRESH_SECONDS = _int("REFRESH_SECONDS", 1800)
    CPU_WARN = _int("CPU_WARN", 80)        # amber bar at or above this %
    CPU_THREAT = _int("CPU_THREAT", 95)
    MEMORY_WARN = _int("MEMORY_WARN", 85)
    MEMORY_THREAT = _int("MEMORY_THREAT", 98)
    DISK_WARN = _int("DISK_WARN", 85)
    DISK_THREAT = _int("DISK_THREAT", 98)
    AP_CLIENTS_WARN = _int("AP_CLIENTS_WARN", 50)
    AP_CLIENTS_THREAT = _int("AP_CLIENTS_THREAT", 80)
    AP_CHANNEL_WARN = _int("AP_CHANNEL_WARN", 70)
    AP_CHANNEL_THREAT = _int("AP_CHANNEL_THREAT", 90)
    AP_RSSI_WARN = _int("AP_RSSI_WARN", -75)
    AP_RSSI_THREAT = _int("AP_RSSI_THREAT", -85)
    GUEST_DNS_LATENCY_WARN_MS = _int("GUEST_DNS_LATENCY_WARN_MS", 250)
    GUEST_DNS_LATENCY_THREAT_MS = _int("GUEST_DNS_LATENCY_THREAT_MS", 1000)
    GUEST_DHCP_LATENCY_WARN_MS = _int("GUEST_DHCP_LATENCY_WARN_MS", 500)
    GUEST_DHCP_LATENCY_THREAT_MS = _int("GUEST_DHCP_LATENCY_THREAT_MS", 2000)
    TELEMETRY_TOKEN = os.environ.get("TELEMETRY_TOKEN", "")
    TELEMETRY_TOKEN_CONFIGURED = bool(TELEMETRY_TOKEN)
    TELEMETRY_STALE_SECONDS = _int("TELEMETRY_STALE_SECONDS", 180)
    HOST_METRICS_REFRESH_SECONDS = _int("HOST_METRICS_REFRESH_SECONDS", 15)
    DEVICE_MONITOR_ENABLED = _flag(
        "DEVICE_MONITOR_ENABLED", "0" if DEMO_MODE else "1"
    )
    DEVICE_CHECK_INTERVAL_SECONDS = max(5, _int("DEVICE_CHECK_INTERVAL_SECONDS", 30))
    DEVICE_CHECK_TIMEOUT_SECONDS = max(1, _int("DEVICE_CHECK_TIMEOUT_SECONDS", 1))
    DEVICE_CHECK_FAILURE_LIMIT = max(1, _int("DEVICE_CHECK_FAILURE_LIMIT", 2))
    DEVICE_CHECK_WORKERS = max(1, _int("DEVICE_CHECK_WORKERS", 16))
    DEVICE_CHECK_TCP_PORTS = _ports("DEVICE_CHECK_TCP_PORTS")
    WORKSPACE_NAME = "Simulation workspace" if DEMO_MODE else "Production workspace"

    # --- Switch monitoring (live mode) --------------------------------------
    SWITCH_SNMP_VERSION = os.environ.get("SWITCH_SNMP_VERSION", "2c").strip().lower()
    SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "")          # read-only community set on the switches
    SWITCH_SNMP_COMMUNITY = os.environ.get("SWITCH_SNMP_COMMUNITY", SNMP_COMMUNITY)
    SNMP_PORT = _int("SNMP_PORT", 161)
    SNMP_TIMEOUT = _int("SNMP_TIMEOUT", 2)                          # seconds to wait for each reply
    SWITCH_SNMP_V3_USERNAME = os.environ.get("SWITCH_SNMP_V3_USERNAME", "")
    SWITCH_SNMP_V3_SECURITY_LEVEL = os.environ.get("SWITCH_SNMP_V3_SECURITY_LEVEL", "authPriv")
    SWITCH_SNMP_V3_AUTH_KEY = os.environ.get("SWITCH_SNMP_V3_AUTH_KEY", "")
    SWITCH_SNMP_V3_AUTH_PROTOCOL = os.environ.get("SWITCH_SNMP_V3_AUTH_PROTOCOL", "SHA")
    SWITCH_SNMP_V3_PRIV_KEY = os.environ.get("SWITCH_SNMP_V3_PRIV_KEY", "")
    SWITCH_SNMP_V3_PRIV_PROTOCOL = os.environ.get("SWITCH_SNMP_V3_PRIV_PROTOCOL", "AES128")
    SWITCH_MONITOR_ENABLED = _flag(
        "SWITCH_MONITOR_ENABLED", "0" if DEMO_MODE else "1"
    )
    SWITCH_POLL_SECONDS = _int("SWITCH_POLL_SECONDS", 30)           # how often every switch is checked
    MISS_LIMIT = _int("SWITCH_MISS_LIMIT", _int("MISS_LIMIT", 2))                             # missed checks before "switch unreachable"
    FLAP_LIMIT = _int("FLAP_LIMIT", 3)                              # port drops in the window = flapping
    FLAP_WINDOW_MINUTES = _int("FLAP_WINDOW_MINUTES", 10)
    SYSLOG_ENABLED = _flag("SYSLOG_ENABLED")                        # collector listens for switch syslog
    SYSLOG_PORT = _int("SYSLOG_PORT", 5514)                         # use 514 only if run as administrator
    SYSLOG_LOG_UNMATCHED = _flag("SYSLOG_LOG_UNMATCHED")            # write unrecognised lines to instance/syslog_unmatched.log
    INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")               # empty = the /api/ingest endpoint is switched off
    LIVE_TRIAL_SWITCHES = [x.strip() for x in os.environ.get("LIVE_TRIAL_SWITCHES", "").split(",") if x.strip()]  # empty = watch all; else only these names/IPs
    NOTIFY_SECONDS = _int("NOTIFY_SECONDS", 5)                      # how often the screen checks for new alerts
    SIMULATION = DEMO_MODE                                          # test buttons only exist in simulation mode
import asyncio
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UsmUserData,
    UdpTransportTarget,
    bulk_walk_cmd,
    get_cmd,
    usm3DESEDEPrivProtocol,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)


IF_ENTRY_OID = "1.3.6.1.2.1.2.2.1"
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IF_OPER_STATUS_OID = "1.3.6.1.2.1.2.2.1.8"
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"
IF_ALIAS_OID = "1.3.6.1.2.1.31.1.1.1.18"
OPER_LABELS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not present",
    7: "lower layer down",
}
AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol,
    "SHA384": usmHMAC256SHA384AuthProtocol,
    "SHA512": usmHMAC384SHA512AuthProtocol,
}
PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
}


def _setting(settings, name, default=None):
    if isinstance(settings, str):
        return settings if name == "SWITCH_SNMP_COMMUNITY" else default
    if hasattr(settings, "get"):
        return settings.get(name, default)
    return getattr(settings, name, default)


def snmp_configured(settings):
    version = str(_setting(settings, "SWITCH_SNMP_VERSION", "2c")).lower()
    if version in ("2c", "2"):
        return bool(_setting(settings, "SWITCH_SNMP_COMMUNITY", ""))
    if version != "3":
        return False
    try:
        _auth_data(settings)
    except ValueError:
        return False
    return True


def _auth_data(settings):
    version = str(_setting(settings, "SWITCH_SNMP_VERSION", "2c")).lower()
    if version in ("2c", "2"):
        community = _setting(settings, "SWITCH_SNMP_COMMUNITY", "")
        if not community:
            raise ValueError("SNMPv2c community is not configured")
        return CommunityData(community, mpModel=1)
    if version != "3":
        raise ValueError("SWITCH_SNMP_VERSION must be 2c or 3")

    username = _setting(settings, "SWITCH_SNMP_V3_USERNAME", "")
    level = str(_setting(settings, "SWITCH_SNMP_V3_SECURITY_LEVEL", "authPriv")).lower()
    auth_key = _setting(settings, "SWITCH_SNMP_V3_AUTH_KEY", "") or None
    priv_key = _setting(settings, "SWITCH_SNMP_V3_PRIV_KEY", "") or None
    auth_name = str(_setting(settings, "SWITCH_SNMP_V3_AUTH_PROTOCOL", "SHA")).upper()
    priv_name = str(_setting(settings, "SWITCH_SNMP_V3_PRIV_PROTOCOL", "AES128")).upper()

    if not username:
        raise ValueError("SNMPv3 username is not configured")
    if level not in ("authpriv", "authnopriv", "noauthnopriv"):
        raise ValueError("Unsupported SNMPv3 security level")
    if level != "noauthnopriv" and not auth_key:
        raise ValueError("SNMPv3 authentication key is not configured")
    if level == "authpriv" and not priv_key:
        raise ValueError("SNMPv3 privacy key is not configured")
    if level != "noauthnopriv" and len(auth_key) < 8:
        raise ValueError("SNMPv3 authentication key is too short")
    if level == "authpriv" and len(priv_key) < 8:
        raise ValueError("SNMPv3 privacy key is too short")
    if level == "authpriv" and priv_name not in PRIV_PROTOCOLS:
        raise ValueError("Unsupported SNMPv3 privacy protocol")
    if level != "noauthnopriv" and auth_name not in AUTH_PROTOCOLS:
        raise ValueError("Unsupported SNMPv3 authentication protocol")

    use_auth = level != "noauthnopriv"
    use_priv = level == "authpriv"
    return UsmUserData(
        username,
        authKey=auth_key if use_auth else None,
        privKey=priv_key if use_priv else None,
        authProtocol=AUTH_PROTOCOLS[auth_name] if use_auth else usmNoAuthProtocol,
        privProtocol=PRIV_PROTOCOLS[priv_name] if use_priv else usmNoPrivProtocol,
    )


async def _poll_switch(engine, switch, auth_data, settings):
    target = await UdpTransportTarget.create(
        (switch["ip"], _setting(settings, "SNMP_PORT", 161)),
        timeout=_setting(settings, "SNMP_TIMEOUT", 2),
        retries=0,
    )
    ports = {}
    async for indication, status, _, var_binds in bulk_walk_cmd(
        engine,
        auth_data,
        target,
        ContextData(),
        0,
        25,
        ObjectType(ObjectIdentity(IF_ENTRY_OID)),
        lexicographicMode=False,
    ):
        if indication:
            raise RuntimeError(str(indication))
        if status:
            raise RuntimeError(f"SNMP error: {status.prettyPrint()}")
        for oid, value in var_binds:
            parts = [int(part) for part in oid]
            if len(parts) < 2:
                continue
            column, port_index = parts[-2:]
            port = ports.setdefault(port_index, {
                "port_index": port_index,
                "port_name": f"Port {port_index}",
                "if_type": 0,
                "admin_status": 4,
                "oper_status": 4,
            })
            if column == 2:
                port["port_name"] = value.prettyPrint()
            elif column == 3:
                port["if_type"] = int(value)
            elif column == 7:
                port["admin_status"] = int(value)
            elif column == 8:
                port["oper_status"] = int(value)
    return [port for port in ports.values() if port["if_type"] == 6]


async def _poll_all(switches, settings):
    engine = SnmpEngine()
    try:
        auth_data = _auth_data(settings)
        results = await asyncio.gather(
            *(_poll_switch(engine, switch, auth_data, settings) for switch in switches),
            return_exceptions=True,
        )
        return {
            switch["id"]: result
            for switch, result in zip(switches, results)
        }
    finally:
        engine.close_dispatcher()


def poll_switches(switches, settings):
    return asyncio.run(_poll_all(switches, settings))


async def _get_sys_uptime(engine, auth_data, target):
    indication, status, _, var_binds = await get_cmd(
        engine,
        auth_data,
        target,
        ContextData(),
        ObjectType(ObjectIdentity(SYS_UPTIME_OID)),
    )
    if indication:
        raise RuntimeError(str(indication))
    if status:
        raise RuntimeError(f"SNMP error: {status.prettyPrint()}")
    if not var_binds:
        return None
    _, value = var_binds[0]
    return value.prettyPrint()


async def _walk_column(engine, auth_data, target, column_oid):
    values = {}
    async for indication, status, _, var_binds in bulk_walk_cmd(
        engine,
        auth_data,
        target,
        ContextData(),
        0,
        25,
        ObjectType(ObjectIdentity(column_oid)),
        lexicographicMode=False,
    ):
        if indication:
            raise RuntimeError(str(indication))
        if status:
            raise RuntimeError(f"SNMP error: {status.prettyPrint()}")
        for oid, value in var_binds:
            values[int(oid[-1])] = value.prettyPrint()
    return values


async def _read_switch(ip, settings, include_ports=False):
    engine = SnmpEngine()
    try:
        auth_data = _auth_data(settings)
        target = await UdpTransportTarget.create(
            (ip, _setting(settings, "SNMP_PORT", 161)),
            timeout=_setting(settings, "SNMP_TIMEOUT", 2),
            retries=1,
        )
        uptime = await _get_sys_uptime(engine, auth_data, target)
        descriptions, names, statuses = await asyncio.gather(
            _walk_column(engine, auth_data, target, IF_DESCR_OID),
            _walk_column(engine, auth_data, target, IF_NAME_OID),
            _walk_column(engine, auth_data, target, IF_OPER_STATUS_OID),
        )
        if include_ports:
            admins, aliases = await asyncio.gather(
                _walk_column(engine, auth_data, target, IF_ADMIN_STATUS_OID),
                _walk_column(engine, auth_data, target, IF_ALIAS_OID),
            )
        indexes = sorted(set(descriptions) | set(names) | set(statuses))
        result = {
            "sysUpTime": uptime,
            "interfaces": [
                {
                    "ifIndex": index,
                    "ifName": names.get(index),
                    "ifDescr": descriptions.get(index),
                    "ifOperStatus": statuses.get(index),
                }
                for index in indexes
            ],
        }
        if include_ports:
            ports = {}
            for index in indexes:
                status = statuses.get(index)
                try:
                    oper = int(status)
                except (TypeError, ValueError):
                    continue
                if oper not in (1, 2):
                    continue
                label_match = re.search(
                    r"(\d{1,2}/\d{1,2}/\d{1,3})",
                    f"{names.get(index, '')} {descriptions.get(index, '')}",
                )
                if label_match is None:
                    continue
                try:
                    admin = int(admins.get(index, "1"))
                except (TypeError, ValueError):
                    admin = 1
                ports[label_match.group(1)] = {
                    "oper": "up" if oper == 1 else "down",
                    "admin": "down" if admin == 2 else "up",
                    "alias": aliases.get(index, ""),
                }
            uptime_match = re.search(r"\((\d+)\)", str(uptime))
            if uptime_match is None:
                uptime_match = re.match(r"\s*(\d+)", str(uptime))
            result["uptime"] = int(uptime_match.group(1)) // 100 if uptime_match else None
            result["ports"] = ports
        return result
    finally:
        engine.close_dispatcher()


def read_switch(ip, settings, include_ports=False):
    return asyncio.run(_read_switch(ip, settings, include_ports=include_ports))


_REFRESH_LOCK = threading.Lock()
_REFRESHING = set()
_START_LOCK = threading.Lock()
_THREADS = {}


def _read_one(switch, settings, use_snmp):
    if not use_snmp:
        return None
    try:
        return read_switch(switch["ip"], settings, include_ports=True)
    except Exception as exc:
        return exc


def _refresh_worker(app):
    try:
        with app.app_context():
            import device_monitor
            import monitoring

            switches = [dict(row) for row in monitoring.all_switches() if row["ip"]]
            use_snmp = snmp_configured(app.config)
            workers = max(1, min(len(switches), 8))
            if not switches:
                return
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(_read_one, switch, app.config, use_snmp): switch
                    for switch in switches
                }
                for future, switch in futures.items():
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = exc
                    fresh = monitoring.get_switch(switch["id"])
                    if isinstance(result, dict):
                        monitoring.apply_switch_poll(
                            fresh, True, True, result["uptime"], result["ports"]
                        )
                        continue
                    try:
                        reachable = device_monitor.check_device(
                            switch["ip"], timeout=app.config.get("SNMP_TIMEOUT", 2)
                        )
                    except Exception:
                        app.logger.exception("Reachability check failed for switch %s", switch["name"])
                        reachable = False
                    monitoring.apply_switch_poll(
                        fresh, reachable, not use_snmp, None, None
                    )
                    if isinstance(result, Exception):
                        app.logger.warning(
                            "SNMP poll failed for %s (%s)", switch["name"], type(result).__name__
                        )
    except Exception:
        app.logger.exception("Background switch refresh failed")
    finally:
        with _REFRESH_LOCK:
            _REFRESHING.discard(id(app))


def schedule_refresh(app):
    """Schedule an immediate refresh without tying SNMP wait time to a web request."""
    if app.config.get("DEMO_MODE", True) or not app.config.get("SWITCH_MONITOR_ENABLED", True):
        return False
    app_id = id(app)
    with _REFRESH_LOCK:
        if app_id in _REFRESHING:
            return False
        _REFRESHING.add(app_id)
    try:
        threading.Thread(
            target=_refresh_worker, args=(app,), name="switch-refresh", daemon=True
        ).start()
    except RuntimeError:
        with _REFRESH_LOCK:
            _REFRESHING.discard(app_id)
        raise
    return True


def _periodic_refresh(app):
    interval = max(5, int(app.config.get("SWITCH_POLL_SECONDS", 30)))
    while True:
        started = time.monotonic()
        try:
            schedule_refresh(app)
        except Exception:
            app.logger.exception("Could not schedule background switch poll")
        time.sleep(max(1, interval - (time.monotonic() - started)))


def start_background_monitor(app):
    """Start the live switch poller once for this app instance."""
    if app.config.get("DEMO_MODE", True) or not app.config.get("SWITCH_MONITOR_ENABLED", True):
        return None
    app_id = id(app)
    with _START_LOCK:
        existing = _THREADS.get(app_id)
        if existing is not None and existing.is_alive():
            return existing
        thread = threading.Thread(
            target=_periodic_refresh, args=(app,), name="switch-status-monitor", daemon=True
        )
        _THREADS[app_id] = thread
        thread.start()
    app.logger.info(
        "Switch status monitor started (interval=%ss)",
        app.config.get("SWITCH_POLL_SECONDS", 30),
    )
    return thread

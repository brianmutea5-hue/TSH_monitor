# Switch and telemetry monitoring

## Switch diagnostics

The project polls switches through `switch_monitor.py` using PySNMP. It does not
contain the `snmp.py` module described in older deployment notes. To inspect an
actual switch, configure its read-only SNMP profile locally in `.env`, then run:

```powershell
.\.venv\Scripts\python.exe tools\check_switch.py 10.10.0.62
```

The command reports raw `sysUpTime`, `ifName`, `ifDescr`, and `ifOperStatus`
values and never prints credentials. Configure either `SWITCH_SNMP_COMMUNITY`
with `SWITCH_SNMP_VERSION=2c`, or configure the SNMPv3 profile:
`SWITCH_SNMP_V3_USERNAME`, `SWITCH_SNMP_V3_SECURITY_LEVEL`,
`SWITCH_SNMP_V3_AUTH_KEY`, `SWITCH_SNMP_V3_AUTH_PROTOCOL`,
`SWITCH_SNMP_V3_PRIV_KEY`, and `SWITCH_SNMP_V3_PRIV_PROTOCOL`. For
`authNoPriv`, the privacy key is not needed; for `noAuthNoPriv`, neither key is
needed. Use `SWITCH_MONITOR_ENABLED` to enable background polling and
`SWITCH_POLL_INTERVAL_SECONDS` to set its interval. A signed-in operator can
also run a manual poll from the Network page.

Confirm the returned interface names on the target switch before changing any
port-label parsing; the diagnostic intentionally preserves switch-provided
names.

## Host, access-point, and WAN telemetry

Set `TELEMETRY_TOKEN` to a random value of at least 32 characters and send it as
an HTTP Bearer token to `POST /api/v1/telemetry`. The API accepts a `device` matching an existing host, server, VM, access point,
or seeded WAN link. Examples:

```json
{"device":"hypervisor-01","metrics":{"cpu":96,"memory":70,"disk":42}}
```

```json
{"device":"lobby-ap","metrics":{"connected_clients":24,"channel_utilization":72,"avg_rssi":-78,"dns_latency_ms":90,"dhcp_latency_ms":140}}
```

WAN status reports use the same Bearer token and send one of `healthy`, `warning`,
`down`, or `unknown` as `status`:

```json
{"device":"WAN 1","status":"down"}
```

`WAN 1` is Safaricom and `WAN 2` is Airtel. The Network page does not probe ISP
links itself: a trusted router or monitoring agent must report each link's state.
Missing or stale reports remain **Unknown**. A fresh `down` report raises a red
SOC alert; a fresh `healthy` report resolves it. `warning` raises an amber alert.
No additional environment variable is needed beyond `TELEMETRY_TOKEN` and
`TELEMETRY_STALE_SECONDS`.

The workbook inventory is seeded idempotently at startup. It includes the
100 access-point IP/location/model entries, non-credential network-critical
endpoints, WAN links, and switch models. The AP MAC column is intentionally not
imported. Vendor escalation contacts are shown in the SOC Alerts page.

### Live host metrics

The dashboard does not invent CPU, memory, or disk values. Install the standard-
library-only agent on each monitored Windows or Linux host. Set the same
`TELEMETRY_TOKEN` in the dashboard's `.env` and the agent's protected service
environment, then set the agent's `TELEMETRY_URL` to the HTTPS dashboard endpoint
and `TELEMETRY_DEVICE_NAME` to the exact inventory name (for example
`TSHSER001`). The agent defaults to reporting every 30 seconds; it does not print
the token. It sends a one-second CPU sample, physical memory usage, the system
disk usage, and uptime.

On each host, first check local sensor collection, then send one report before
installing it as a scheduled service:

```powershell
python tools\telemetry_agent.py --sample-only
python tools\telemetry_agent.py --once
python tools\telemetry_agent.py
```

`TELEMETRY_POLL_SECONDS` controls the agent interval (minimum 5 seconds).
`TELEMETRY_DISK_PATH` can select another disk or mount point. Use HTTPS for a
remote dashboard; HTTP is accepted only for loopback testing. On the dashboard,
set `DEMO_MODE=0` after the agents are ready. Until a host reports, and whenever
its report is older than `TELEMETRY_STALE_SECONDS`, its CPU, memory, disk,
temperature, and uptime readings show **Unknown**. Reachability status is
reported separately by the device checker.
The host cards request fresh readings every `HOST_METRICS_REFRESH_SECONDS`
without changing the separate 30-minute/1-hour page refresh setting.

Host/server/VM telemetry may include `cpu`, `memory`, `disk`, `temp`, and
`uptime_hours`, and may include a `status` of `healthy`, `warning`, `threat`,
`down`, or `unknown`. A status-only report updates device state without
refreshing or replacing the metrics snapshot.
Access-point metrics are `connected_clients`, `channel_utilization`, `avg_rssi`,
`dns_latency_ms`, and `dhcp_latency_ms`. Configure `TELEMETRY_STALE_SECONDS` to
set the freshness window. Missing or stale live readings are shown as unknown,
not healthy.

Host thresholds are configured with `CPU_WARN`, `CPU_THREAT`, `MEMORY_WARN`,
`MEMORY_THREAT`, `DISK_WARN`, and `DISK_THREAT`. Access-point thresholds are
`AP_CLIENTS_WARN`, `AP_CLIENTS_THREAT`, `AP_CHANNEL_WARN`, `AP_CHANNEL_THREAT`,
`AP_RSSI_WARN`, `AP_RSSI_THREAT`, `GUEST_DNS_LATENCY_WARN_MS`,
`GUEST_DNS_LATENCY_THREAT_MS`, `GUEST_DHCP_LATENCY_WARN_MS`, and
`GUEST_DHCP_LATENCY_THREAT_MS`.

### Device reachability status

When `DEMO_MODE=0`, the app starts a background checker; it never runs network
checks in a page request. By default it checks valid inventory IPs every
`DEVICE_CHECK_INTERVAL_SECONDS` (30 seconds), with a 1-second timeout and two
consecutive failures before marking a device down. It uses ping and, when
configured, treats a successful TCP connection to any `DEVICE_CHECK_TCP_PORTS`
port as reachable. Set a port list such as `443,22` for devices that block ICMP.
`DEVICE_MONITOR_ENABLED=0` disables the checker. The checker uses a bounded
worker pool (`DEVICE_CHECK_WORKERS`) and records `last_checked`; status feeds
refresh independently of the 30-minute/1-hour page refresh.

Devices without an IP are shown as **Not set** and **No IP · not checked**;
they are not probed and do not generate reachability alerts. The Servers and
Network inventory tables show status and last check, with stale status shown as
Unknown. A device becomes Down only after the configured consecutive failures,
and its alert resolves after a successful check. These statuses indicate
network reachability; CPU, memory, disk, and Wi-Fi KPIs still require fresh
telemetry.

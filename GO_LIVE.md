# Go live: one-switch trial, then all 13

Goal: prove the chain **switch -> collector -> database -> SOC screen** on ONE real switch, then widen.
Everything below is read-only on the switch except the two settings you turn on.

## 0. Before you start (5 minutes)
- Pick the trial switch: a floor switch that is **not** carrying critical traffic (e.g. `SW-2ND`).
- The monitoring PC/server must reach the switch IP. Test: `ping <switch ip>`.
- Resolve the sample alerts that came with the demo data (Alerts page), so only real events remain.

## 1. Settings in `.env`
```
DEMO_MODE=0
SECRET_KEY=<python -c "import secrets;print(secrets.token_hex(32))">
ADMIN_PASSWORD=<12+ characters>
SNMP_COMMUNITY=<long random read-only text, not "public">
LIVE_TRIAL_SWITCHES=SW-2ND
SYSLOG_ENABLED=1
SYSLOG_PORT=5514
INGEST_TOKEN=<24+ random characters, only if you use Wazuh/Suricata>
```
Restart the web app after editing `.env`.

## 2. Turn on SNMP read-only on the trial switch (Ruckus ICX)
Commands differ by firmware. **Confirm each against the ICX FastIron guide for your version** before pasting.
```
configure terminal
snmp-server community <READONLY_TEXT> ro
logging host <MONITOR_SERVER_IP> udp-port 5514
write memory
```
Better: restrict SNMP to the monitor server's IP with an access list (see the guide). Never use a read-write community.

## 3. Prove each link
```
python go_live.py                       # settings, database, collector
python go_live.py --switch SW-2ND       # ping + SNMP + every port, read-only
```
Expect `READY`. Fix anything marked `[ FAIL ]` using the hint printed under it.

## 4. Start monitoring
```
python -m waitress --listen=0.0.0.0:5000 app:app     # terminal 1
python collector.py                                   # terminal 2
```
Log in. Network > Switches: SW-2ND is **Online** with real ports; the other 12 say **Not read yet** (trial mode).

## 5. Live drills (do all, tell the SOC first)
| Drill | What you do | Expected on screen |
|---|---|---|
| Port down | Unplug a cable in use on SW-2ND | After the next check (<=30 s) red "Port down" pop-up for that port |
| Recovery | Plug it back | Alert closes by itself |
| Flapping | Plug/unplug 3 times in 10 min | "Port flapping" |
| Switch offline | Unplug the switch uplink (or power) in a maintenance window | After 2 missed checks red "Switch offline" bar + pop-up |
| Attack line | Wrong switch login 3 times | "Repeated failed logins" (needs syslog) |
Syslog tuning: stop `collector.py`, run `python go_live.py --listen`, trigger real events, and read which rule each line hits. Lines marked "no rule matches" need a new pattern in `SYSLOG_RULES` (monitoring.py).

## 6. Widen to all 13
1. Enable SNMP + syslog on the other switches (one at a time).
2. Empty `LIVE_TRIAL_SWITCHES=` and restart `collector.py`.
3. Run `python go_live.py --switch <name>` for each new one.

## 7. Keep it running (Windows)
- Task Scheduler: two tasks "At startup", run `start_live.bat` (or the two commands above), "Run whether user is logged on or not", restart on failure.
- Firewall: allow inbound TCP 5000 (dashboard) and UDP 5514 (syslog).
- Put the dashboard behind HTTPS (reverse proxy such as Caddy/IIS) before exposing beyond the SOC LAN.
- Back up `instance/monitor.db` daily.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| `SNMP read failed: no reply` | Wrong community text, SNMP not enabled, or UDP 161 blocked. Check community matches `.env` exactly. |
| Ports show as `ge1`, `port 3` not `1/1/N` | Switch names ports differently; alerts still work, syslog link lines may not match. |
| Red bar "live monitoring is not running" | `collector.py` stopped. Start it. |
| No attack alerts | `SYSLOG_ENABLED=0`, firewall blocks UDP 5514, or switch not sending. Use `--listen`. |
| Syslog lines show UNKNOWN SOURCE | The switch sends from an IP that is not its inventory IP. Fix the IP on the Edit Switch page. |

# Switch monitoring - setup guide

The dashboard shows every switch by floor and by name, and tells the SOC when a switch or a
port fails, or when a switch reports an attack. It has two parts that run together:

| Part | Command | What it does |
|------|---------|--------------|
| Web app | `python -m waitress --listen=0.0.0.0:5000 app:app` | The dashboard, pop-up alerts, red SOC bar |
| Collector | `python collector.py` | Asks every switch for its ports every 30 s and listens for switch syslog |

`start_live.bat` starts both.

## 1. Go live (3 changes in `.env`)

```
DEMO_MODE=0
SNMP_COMMUNITY=<read-only community configured on the switches>
SYSLOG_ENABLED=1
```

Restart both programs. Until the collector has read a switch, that switch shows **Not read yet**
(grey) and the red bar says "live switch monitoring is not running" if the collector stops.
Nothing is ever shown as healthy unless it was really read.

## 2. Prepare each switch (typical Ruckus ICX commands - confirm with your firmware guide)

```
snmp-server community <READ-ONLY-STRING> ro
logging host <IP-OF-THIS-COMPUTER> udp-port 5514
```

Allow the computer running the collector to reach the switches on UDP 161, and allow the
switches to reach this computer on UDP 5514 (Windows Firewall inbound rule). For the attack
alerts, turn on the switch protections: DHCP snooping, Dynamic ARP Inspection, port security,
BPDU guard. The switch can only report an attack that it has protection turned on for.

## 3. What is detected, and how

| Threat | Detected by |
|--------|-------------|
| Switch unreachable | Collector (ping + SNMP, 2 missed checks) |
| Port down, uplink down | Collector (SNMP port status) |
| Port flapping, unexpected reboot | Collector (history of port changes, uptime) |
| MAC flooding, ARP spoofing, rogue DHCP, unknown device on a port, loop / STP change, failed logins, config change | Switch syslog (needs `SYSLOG_ENABLED=1` and the protections above) |
| Anything else | Other tools can post to `/api/ingest/switch-event` with `INGEST_TOKEN` |

The syslog patterns are starter patterns. After the first days, open
`instance/syslog_unmatched.log` (when `SYSLOG_LOG_UNMATCHED=1`) to see messages that were not
recognised and adjust the rules in `monitoring.py`.

## 4. How the SOC is told

- Red bar under the top of every page while a threat is open or a switch is down.
- A pop-up on every page within `NOTIFY_SECONDS`. Red ones stay until dismissed or acknowledged.
- Optional alert sound (speaker button in the top bar; browsers need one click per page load).
- Tab title shows `(2) ALERT` so it is visible from another tab.
- Every alert is acknowledged and resolved in **Alerts**, and recorded in **Logs**.

## 5. Notes about your spreadsheet

- The core switch model/serial (ICX 7250-24P / DUI3838P05X) are assumed, because that is the
  only entry in the list that does not match a floor. Edit it on the switch page if wrong.
- Camera switch models are not in the spreadsheet; their port lists are read from the switch.
- Subnet masks on the 3rd floor (`255.255.252.1`) and the control room camera switch
  (`255.255.255.2`) are not valid masks - probably typing mistakes. 1st floor uses `/24`
  while the other floors use `/22`.
- The spreadsheet holds passwords in plain text. This app never reads or stores them. Move them
  to a password manager and change them.

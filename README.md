# TSH Hardware Monitor (Flask)

Server and network monitoring dashboard for the hotel IT team.
Python + Flask + Jinja templates + SQLite. Admin login required.

## Folder structure

```
tsh_monitor/
├── app.py                  # starts the app, security headers, template helpers
├── config.py               # settings (read from .env)
├── database.py             # SQLite connection, tables, first-run seeding, audit log
├── seed_data.py            # your inventory: 3 hosts, 19 VMs, switches, NAS (no passwords)
├── auth.py                 # login / logout, CSRF, lockout after 5 failures
├── views.py                # pages: overview, servers, network, threats, alerts, logs, settings
├── requirements.txt
├── .env.example            # copy to .env and edit
├── static/
│   ├── css/style.css       # all colours and layout (white 2 : black 1)
│   └── js/app.js           # refresh, search box, filters, show/hide password
├── templates/
│   ├── base.html           # sidebar + top bar + footer
│   ├── login.html          # admin sign-in page
│   ├── overview.html  servers.html  network.html
│   ├── threats.html   alerts.html   logs.html   settings.html
│   ├── device_form.html    # add / edit / remove device
│   ├── error.html
│   └── partials/
│       ├── _icons.html         # icons
│       └── _components.html    # host card, status pill, tables, alert row
└── instance/               # monitor.db is created here automatically
```

## Run it

```bash
cd tsh_monitor
python -m venv venv
venv\Scripts\activate            # Windows   (Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # Linux/Mac: cp .env.example .env
# open .env and set SECRET_KEY and ADMIN_PASSWORD
python app.py
```

Open http://127.0.0.1:5000 and sign in with the username and password from `.env`.
If ADMIN_PASSWORD is empty, a temporary password is printed in the terminal.

Production (Windows or Linux):  `python -m waitress --listen=0.0.0.0:5000 app:app`
Switch monitoring: run `python collector.py` as well (or double-click `start_live.bat`). See SWITCH_MONITORING.md.
Serve it over HTTPS and set `SESSION_COOKIE_SECURE=1`.

## Colour code

Green = working well · Amber = warning (CPU/memory/disk above threshold) · Red = failure or threat.

## Important: demo data

Readings (CPU, memory, disk, temperature, uptime) and the two alerts are **simulated**.
The app does not yet detect real malware, viruses or man-in-the-middle attacks.
To make it live, add an endpoint that receives data from agents on the servers,
SNMP for switches, and a sensor such as Wazuh or Suricata, then write that data into
the `devices` and `alerts` tables. Set `DEMO_MODE=0` afterwards.

## Security notes

- No passwords are stored in code. Do not put server passwords in this app.
- Passwords are hashed; sessions expire after 15 minutes idle; 5 wrong sign-ins lock for 5 minutes.
- Every form uses a CSRF token; security headers are sent on every response.

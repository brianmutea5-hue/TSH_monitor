"""Stand-alone install check. Run from the project folder:  python check_install.py
Lists any file the switch-monitoring feature needs that is missing. Needs nothing but Python."""
import sys
from pathlib import Path

REQUIRED = """app.py auth.py config.py database.py views.py seed_data.py monitoring.py snmp.py collector.py
switches.py go_live.py requirements.txt .env.example start_live.bat static/css/style.css static/js/app.js
templates/base.html templates/network.html templates/switches.html templates/switch_detail.html
templates/switch_form.html templates/partials/_components.html templates/partials/_switch_components.html
templates/partials/_icons.html accounts.py users.py manage_users.py templates/users.html templates/user_form.html
templates/user_detail.html templates/user_credentials.html templates/change_password.html""".split()

here = Path(__file__).resolve().parent
missing = [f for f in REQUIRED if not (here / f).is_file()]
print(f"Project folder: {here}")
if missing:
    print(f"\nMISSING {len(missing)} of {len(REQUIRED)} files:")
    for f in missing:
        print("  -", f)
    print("\nFix: unzip tsh_monitor_complete.zip into this folder (choose 'replace'). Your .env and instance/ are not in the zip, so they are kept.")
    sys.exit(1)
checks = {
    "monitoring.py": "def apply_switch_poll", "snmp.py": "def read_switch", "collector.py": "def watched_switches",
    "config.py": "LIVE_TRIAL_SWITCHES", "auth.py": "def admin_required", "database.py": "def _repair_tables", "app.py": "switches", "static/js/app.js": "notif",
}
bad = [f"{f} (expected '{t}')" for f, t in checks.items() if t.lower() not in (here / f).read_text(encoding="utf-8", errors="ignore").lower()]
if bad:
    print("\nThese files exist but look like an OLD version:")
    for b in bad:
        print("  -", b)
    sys.exit(1)
print(f"\nOK: all {len(REQUIRED)} files present and current. Next: python go_live.py")

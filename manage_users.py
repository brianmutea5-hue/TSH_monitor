"""Account recovery from the command line (use it if every Administrator is locked out).

    python manage_users.py list                    show all accounts
    python manage_users.py add jwanjiru supervisor "Jane Wanjiru"
    python manage_users.py reset admin             new temporary password for 'admin' (also enables the account)
    python manage_users.py promote jwanjiru        make a user an Administrator

It works on the same database as the app, so run it from the project folder with the virtual environment on.
"""
import sys

import accounts
from app import app
from database import audit, execute


def main(argv):
    if not argv or argv[0] not in ("list", "add", "reset", "promote"):
        print(__doc__)
        return 1
    cmd = argv[0]
    with app.app_context():
        if cmd == "list":
            print(f"{'USERNAME':<20}{'ROLE':<15}{'STATUS':<10}LAST SIGN-IN")
            for u in accounts.all_users():
                print(f"{u['username']:<20}{u['role']:<15}{'active' if u['is_active'] else 'disabled':<10}{u['last_login_at'] or 'never'}")
            s = accounts.summary()
            print(f"\n{s['total']} users: {s['admins']} administrators, {s['supervisors']} supervisors, {s['disabled']} disabled")
            return 0
        if cmd == "add":
            if len(argv) < 3 or argv[2] not in accounts.ROLES:
                print('Usage: python manage_users.py add <username> <admin|supervisor> "<Full name>"')
                return 1
            problems = accounts.username_problems(argv[1])
            if problems:
                print(problems[0])
                return 1
            pw = accounts.generate_password()
            accounts.create_user(argv[1], argv[3] if len(argv) > 3 else argv[1], argv[2], pw, created_by="command line")
            audit("user_created", f"{argv[1]} ({argv[2]}) from the command line", actor="command line")
            print(f"Created {argv[1]}. Temporary password (shown once): {pw}\nThey must change it at first sign-in.")
            return 0
        user = accounts.find_user(argv[1]) if len(argv) > 1 else None
        if user is None:
            print("No such user. Run: python manage_users.py list")
            return 1
        if cmd == "reset":
            pw = accounts.generate_password()
            accounts.set_password(user["id"], pw, must_change=True)
            execute("UPDATE users SET is_active = 1 WHERE id = ?", (user["id"],))
            audit("user_password_reset", f"{user['username']} from the command line", actor="command line")
            print(f"New temporary password for {user['username']} (shown once): {pw}\nThey must change it at next sign-in.")
        elif cmd == "promote":
            execute("UPDATE users SET role = 'admin', is_active = 1 WHERE id = ?", (user["id"],))
            audit("user_role_changed", f"{user['username']} -> Administrator from the command line", actor="command line")
            print(f"{user['username']} is now an Administrator.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

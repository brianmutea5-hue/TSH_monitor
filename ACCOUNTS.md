# Accounts and roles

| | Administrator | Supervisor |
|---|---|---|
| View all pages (overview, servers, network, switches, threats, alerts, logs, settings) | yes | yes |
| Acknowledge / resolve alerts | yes | yes |
| Change own password | yes | yes |
| Add / edit / remove devices | yes | no |
| Edit switches, choose watched ports, demo test panel | yes | no |
| Users page: add, change role, reset password, disable, delete, sign-in activity | yes | no |

The rules are enforced on the server (a Supervisor who types an admin address gets "403 Forbidden"), not just hidden.

## First start
Your `.env` admin (`ADMIN_USERNAME` / `ADMIN_PASSWORD`) becomes the first Administrator. After that the database is in charge: change the password on **your name (top right) > Change password**. Editing `ADMIN_PASSWORD` in `.env` no longer changes anything.

## Adding someone
Users > Add user. You see a temporary password once. The person must choose their own at first sign-in.

## Safeguards
- You cannot disable, delete or demote yourself, or the last active Administrator.
- Disabling a user, changing a role or resetting a password takes effect immediately, even in an open session.
- Changing your password signs out your other devices.
- Passwords: at least 12 characters, letters and numbers, not the username, not a common one. Stored hashed.
- Sign-in lock-out (5 wrong tries, 5 minutes), 15-minute idle sign-out, CSRF protection stay as before.
- Every action is in the Logs page; sign-ins and failures are on the Users page.

## Locked out
`python manage_users.py list` | `reset <username>` | `promote <username>` | `add <username> <role> "<Full name>"`

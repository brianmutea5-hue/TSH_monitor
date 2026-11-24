"""User accounts: roles, password rules and the small database helpers around them."""
import re
import secrets
import string

from werkzeug.security import generate_password_hash

from database import execute, now_iso, query

ROLES = {"admin": "Admin", "supervisor": "Supervisor"}
ROLE_HELP = {
    "admin": "Full control: users, devices, switches, settings and alerts.",
    "supervisor": "Watches everything and can acknowledge or resolve alerts. Cannot change devices, switches, users or settings.",
}
USERNAME_RULE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")
MIN_PASSWORD = 12
_COMMON = {
    "password1234", "123456789012", "qwertyuiop12", "administrator", "welcome12345", "changeme1234",
    "password12345", "letmein12345", "tshmonitor12",
}


# ----------------------------------------------------------------- passwords
def password_problems(password, username="", full_name=""):
    """Return a list of reasons the password is not acceptable (empty list = fine)."""
    problems = []
    if len(password) < MIN_PASSWORD:
        problems.append(f"Use at least {MIN_PASSWORD} characters.")
    if len(password) > 128:
        problems.append("Use at most 128 characters.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        problems.append("Include both letters and numbers.")
    if len(set(password)) < 6:
        problems.append("Too repetitive. Mix in more different characters.")
    low = password.lower()
    if username and username.lower() in low:
        problems.append("The password must not contain the username.")
    if low in _COMMON:
        problems.append("That password is too common.")
    return problems


def generate_password():
    """A strong temporary password that passes the rules above."""
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(14))
        if not password_problems(pw):
            return pw


def hash_password(password):
    return generate_password_hash(password)


# --------------------------------------------------------------------- lookup
def get_user(user_id):
    return query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)


def find_user(username):
    return query("SELECT * FROM users WHERE username = ? COLLATE NOCASE", ((username or "").strip(),), one=True)


def all_users():
    return query("SELECT * FROM users ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END, username")


def active_admin_count(exclude_id=None):
    sql = "SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = 1"
    args = []
    if exclude_id is not None:
        sql += " AND id != ?"
        args.append(exclude_id)
    return query(sql, args, one=True)["c"]


def summary():
    row = query(
        "SELECT COUNT(*) AS total,"
        " COALESCE(SUM(role = 'admin'), 0) AS admins,"
        " COALESCE(SUM(role = 'supervisor'), 0) AS supervisors,"
        " COALESCE(SUM(is_active = 1), 0) AS active,"
        " COALESCE(SUM(is_active = 0), 0) AS disabled FROM users", one=True)
    return dict(row)


def initials(user):
    name = (user["full_name"] or user["username"]).strip()
    parts = re.split(r"[\s._-]+", name)
    letters = "".join(p[0] for p in parts if p)[:2] or name[:2]
    return letters.upper()


# --------------------------------------------------------------------- change
def create_user(username, full_name, role, password, created_by, must_change=True):
    execute(
        "INSERT INTO users (username, password_hash, role, is_active, must_change_password, created_at, "
        "last_login_at, full_name, created_by, password_changed_at)"
        " VALUES (?, ?, ?, 1, ?, ?, NULL, ?, ?, ?)",
        (username, hash_password(password), role, 1 if must_change else 0, now_iso(),
         full_name, created_by, now_iso()),
    )
    return find_user(username)


def set_password(user_id, password, must_change):
    """Store a new password. password_changed_at also signs out every other open session of that user."""
    stamp = now_iso()
    # two changes in the same second must still differ, otherwise an old session would stay valid
    row = get_user(user_id)
    if row and row["password_changed_at"] == stamp:
        stamp = stamp + "+"
    execute("UPDATE users SET password_hash = ?, must_change_password = ?, password_changed_at = ? WHERE id = ?",
            (hash_password(password), 1 if must_change else 0, stamp, user_id))
    return stamp


def record_event(username, outcome, ip="", detail=""):
    execute("INSERT INTO login_events (ts, username, ip, outcome, detail) VALUES (?, ?, ?, ?, ?)",
            (now_iso(), (username or "")[:60], ip[:60], outcome, detail[:200]))
    execute("DELETE FROM login_events WHERE id < (SELECT COALESCE(MAX(id), 0) - 5000 FROM login_events)")


def username_problems(username, exclude_id=None):
    if not USERNAME_RULE.match(username or ""):
        return ["Username must be 3-32 characters: letters, numbers, dot, dash or underscore."]
    row = find_user(username)
    if row and row["id"] != exclude_id:
        return ["That username is already taken."]
    return []

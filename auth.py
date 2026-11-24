"""Sign-in, sign-out, roles, CSRF protection, login lock-out and safe redirects."""
import hmac
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import accounts
from database import audit, execute, now_iso, query

bp = Blueprint("auth", __name__)

# Checked when the username is wrong, so a wrong username and a wrong password
# take about the same time (stops attackers guessing valid usernames).
_DUMMY_HASH = generate_password_hash(secrets.token_hex(8))


# ----------------------------------------------------------------- admin setup
def setup_admin(app):
    """Prepare a hash for the one-time initial admin account."""
    cfg = app.config
    if cfg.get("ADMIN_PASSWORD_HASH"):
        app.config["_ADMIN_HASH"] = cfg["ADMIN_PASSWORD_HASH"]
    elif cfg.get("ADMIN_PASSWORD"):
        app.config["_ADMIN_HASH"] = generate_password_hash(cfg["ADMIN_PASSWORD"])
    else:
        temp = secrets.token_urlsafe(18)
        app.config["_ADMIN_HASH"] = generate_password_hash(temp)
        app.config["_ADMIN_TEMP_PASSWORD"] = temp


def bootstrap_admin(app):
    """First start only: turn the .env admin into the first Administrator account.

    After that the accounts live in the database (Users page). .env no longer controls the password,
    so changing it there has no effect. Lost it? Run:  python manage_users.py reset <username>
    """
    cfg = app.config
    with app.app_context():
        if query("SELECT COUNT(*) AS c FROM users", one=True)["c"]:
            return False
        temporary = not (cfg.get("ADMIN_PASSWORD_HASH") or cfg.get("ADMIN_PASSWORD"))
        execute(
            "INSERT INTO users (username, password_hash, role, is_active, must_change_password, "
            "created_at, last_login_at, full_name, created_by, password_changed_at) "
            "VALUES (?, ?, 'admin', 1, ?, ?, NULL, ?, 'system', ?)",
            (cfg["ADMIN_USERNAME"], cfg["_ADMIN_HASH"], 1 if temporary else 0,
             now_iso(), "System administrator", now_iso()),
        )
        audit("user_created", f"First administrator '{cfg['ADMIN_USERNAME']}' created from .env", actor="system")
        if temporary:
            print("\n" + "=" * 64)
            print("  No ADMIN_PASSWORD set in .env - a temporary one was created:")
            print(f"  username: {cfg['ADMIN_USERNAME']}")
            print(f"  password: {cfg['_ADMIN_TEMP_PASSWORD']}")
            print("  Set ADMIN_PASSWORD in .env to choose your own.")
            print("=" * 64 + "\n")
        return True


# ------------------------------------------------------------------------ CSRF
def csrf_token():
    """Return this session's security token (created on first use)."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def csrf_exempt(view):
    """Mark an API route that is protected by its own secret token instead of the browser token."""
    view._csrf_exempt = True
    return view


def protect_csrf():
    """Registered as before_request: every POST must carry the session token."""
    if request.method == "POST":
        view = current_app.view_functions.get(request.endpoint)
        if view is not None and getattr(view, "_csrf_exempt", False):
            return None
        sent = request.form.get("_csrf", "")
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid or missing security token. Reload the page and try again.")


# -------------------------------------------------------------- safe redirects
def safe_path(target, fallback):
    """Allow only a local path like '/alerts'. Blocks '//evil.com', 'http://...' and '/\\evil.com'."""
    if not target or "\\" in target or not target.startswith("/") or target.startswith("//"):
        return fallback
    parts = urlparse(target)
    if parts.scheme or parts.netloc:
        return fallback
    return target


# ---------------------------------------------------------------- idle timeout
def enforce_idle_timeout():
    """Sign the current user out after the configured idle time.

    "Idle" means no real action by the person. The page refreshes itself every
    few seconds (marked with ?auto=1), and those refreshes must NOT count as
    activity, otherwise a dashboard left open would never sign out.
    """
    if not session.get("user") or request.endpoint == "static":
        return None
    now = time.time()
    limit = current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()
    if now - session.get("last_active", now) > limit:
        session.clear()
        flash("You were signed out after a period of inactivity.", "info")
        return redirect(url_for("auth.login"))
    if request.args.get("auto") != "1":
        session["last_active"] = now
    return None


# ------------------------------------------------------- who is signed in (every request)
_ALLOWED_WHILE_CHANGING = {"users.change_password", "auth.logout", "static", "healthz"}


def load_user():
    """Registered as before_request. Re-reads the account on every request, so disabling a user,
    changing a role or resetting a password takes effect straight away, even in an open session."""
    g.user = None
    if not session.get("user") or request.endpoint in (None, "static"):
        return None
    user = accounts.get_user(session.get("uid")) if session.get("uid") is not None else None
    if user is None or not user["is_active"] or (user["password_changed_at"] or "") != session.get("pv", ""):
        session.clear()
        flash("Your session ended because your account changed. Please sign in again.", "info")
        return redirect(url_for("auth.login"))
    g.user = user
    session["role"] = user["role"]
    if user["must_change_password"] and request.endpoint not in _ALLOWED_WHILE_CHANGING:
        if request.path.startswith("/api/"):
            abort(403, "Choose a new password first.")
        flash("Choose a new password before you continue.", "info")
        return redirect(url_for("users.change_password"))
    return None


def is_admin():
    return bool(getattr(g, "user", None)) and g.user["role"] == "admin"


# ---------------------------------------------------------------- access guard
def login_required(view):
    """Send visitors who are not signed in to the login page."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("Please sign in to continue.", "info")
            return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    """Only signed-in users with one of these current database roles may continue."""
    def decorate(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = g.get("user")
            if user is None or user["role"] not in roles:
                role = user["role"] if user is not None else "none"
                audit("access_denied", f"{request.method} {request.path} (role: {role})")
                abort(403, "Your role does not allow this. Ask an Administrator.")
            return view(*args, **kwargs)

        return wrapped
    return decorate


def admin_required(view):
    """Compatibility decorator for admin-only routes."""
    return role_required("admin")(view)


# --------------------------------------------------------------------- lock-out
def _recent_failures(ip):
    since = datetime.now() - timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
    row = query(
        "SELECT COUNT(*) AS c FROM login_attempts WHERE ip = ? AND ts >= ?",
        (ip, since.strftime("%Y-%m-%d %H:%M:%S")),
        one=True,
    )
    return row["c"]


def _is_locked(ip):
    return _recent_failures(ip) >= current_app.config["MAX_LOGIN_ATTEMPTS"]


# ---------------------------------------------------------------------- routes
@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user"):
        return redirect(url_for("views.overview"))

    cfg = current_app.config
    ip = request.remote_addr or "unknown"
    locked = _is_locked(ip)

    if request.method == "POST":
        if locked:
            flash(f"Too many failed attempts. Try again in {cfg['LOCKOUT_MINUTES']} minutes.", "error")
            return render_template("login.html", locked=True), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = accounts.find_user(username)
        # always check a hash, so a wrong username and a wrong password take the same time
        pass_ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)

        if user and pass_ok and user["is_active"]:
            session.clear()           # new session id after sign-in
            session.permanent = True  # enables the idle timeout
            session["user"] = user["username"]
            session["uid"] = user["id"]
            session["pv"] = user["password_changed_at"] or ""
            session["role"] = user["role"]
            session["last_active"] = time.time()
            csrf_token()
            execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
            execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso(), user["id"]))
            accounts.record_event(user["username"], "success", ip, "role: " + user["role"])
            audit("login", f"Successful sign-in from {ip}", actor=user["username"])
            current_app.logger.info("%s signed in from %s", user["username"], ip)
            if user["must_change_password"]:
                return redirect(url_for("users.change_password"))
            return redirect(safe_path(request.args.get("next"), url_for("views.overview")))

        if user and pass_ok and not user["is_active"]:
            accounts.record_event(username, "disabled", ip, "correct password, account disabled")
            audit("login_failed", f"Disabled account '{username[:40]}' tried to sign in from {ip}", actor="anonymous")
            flash("This account is disabled. Ask an Administrator.", "error")
            return render_template("login.html", locked=locked), 403

        # Wrong details: record it, keep the table small, and tell nothing about which part was wrong
        execute("INSERT INTO login_attempts (ip, ts) VALUES (?, ?)", (ip, now_iso()))
        execute("DELETE FROM login_attempts WHERE ts < datetime('now', 'localtime', '-1 day')")
        accounts.record_event(username, "failed", ip, "wrong username or password")
        audit("login_failed", f"Failed sign-in for '{username[:40]}' from {ip}", actor="anonymous")
        current_app.logger.warning("Failed sign-in for '%s' from %s", username[:40], ip)
        flash("Incorrect username or password.", "error")
        locked = _is_locked(ip)
        if locked:
            accounts.record_event(username, "locked", ip, "too many failed attempts")
            audit("login_locked", f"Sign-in locked for {ip}", actor="anonymous")
            current_app.logger.warning("Sign-in locked for %s", ip)

    return render_template("login.html", locked=locked)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", "Signed out")
    accounts.record_event(session.get("user", ""), "logout", request.remote_addr or "")
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
"""User management (Administrators only) and the change-password page (everyone)."""
from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash

import accounts
from auth import login_required, role_required
from database import audit, execute, get_db, now_iso, query

bp = Blueprint("users", __name__)
EVENT_LIMIT = 80


def _target(user_id):
    user = accounts.get_user(user_id)
    if user is None:
        abort(404)
    return user


def _lockout_reason(user, *, becomes_inactive=False, loses_admin=False):
    """Why this change is not allowed (or None). Stops people locking themselves or everyone out."""
    is_self = user["id"] == g.user["id"]
    if is_self and becomes_inactive:
        return "You cannot disable or delete your own account."
    if is_self and loses_admin:
        return "You cannot remove your own Administrator role. Ask another Administrator."
    if user["role"] == "admin" and user["is_active"] and (becomes_inactive or loses_admin):
        if accounts.active_admin_count(exclude_id=user["id"]) == 0:
            return "That would leave no active Administrator. Create or enable another one first."
    return None


def _history(username=None, limit=EVENT_LIMIT):
    if username:
        return query("SELECT * FROM login_events WHERE username = ? COLLATE NOCASE ORDER BY id DESC LIMIT ?", (username, limit))
    return query("SELECT * FROM login_events ORDER BY id DESC LIMIT ?", (limit,))


def _audit_history(limit=EVENT_LIMIT):
    return query(
        "SELECT ts, actor AS username, '' AS ip, "
        "CASE action WHEN 'login' THEN 'success' WHEN 'login_failed' THEN 'failed' "
        "WHEN 'login_locked' THEN 'locked' "
        "WHEN 'logout' THEN 'logout' WHEN 'password_changed' THEN 'password' "
        "WHEN 'user_password_reset' THEN 'password' WHEN 'user_disabled' THEN 'disabled' "
        "WHEN 'user_enabled' THEN 'enabled' ELSE 'account' END AS outcome, "
        "detail FROM audit_logs WHERE action IN "
        "('login', 'login_failed', 'login_locked', 'logout', 'password_changed', 'user_created', "
        "'user_role_changed', 'user_disabled', 'user_enabled', 'user_password_reset', 'user_deleted') "
        "ORDER BY id DESC LIMIT ?",
        (limit,),
    )


# ------------------------------------------------------------------ the list
@bp.route("/users")
@role_required("admin")
def index():
    return render_template(
        "users.html", active="users", crumb="Users", people=accounts.all_users(), tiles=accounts.summary(),
        events=_audit_history(), roles=accounts.ROLES, me=g.user,
    )


# --------------------------------------------------------------------- add
@bp.route("/users/new", methods=["GET", "POST"])
@role_required("admin")
def new():
    values = {"role": "supervisor"}
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "")
        typed = request.form.get("password", "")
        values = {"username": username, "full_name": full_name, "role": role}
        errors = accounts.username_problems(username)
        if not full_name or len(full_name) > 80:
            errors.append("Full name is required (max 80 characters).")
        if role not in accounts.ROLES:
            errors.append("Choose a role.")
        if typed:
            errors += accounts.password_problems(typed, username, full_name)
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("user_form.html", active="users", crumb="Add user", values=values, roles=accounts.ROLES,
                                   role_help=accounts.ROLE_HELP), 400
        password = typed or accounts.generate_password()
        accounts.create_user(username, full_name, role, password, created_by=g.user["username"])
        audit("user_created", f"{username} ({accounts.ROLES[role]})")
        return render_template("user_credentials.html", active="users", crumb="User created", person=accounts.find_user(username),
                               password=password, heading="User created")
    return render_template("user_form.html", active="users", crumb="Add user", values=values, roles=accounts.ROLES,
                           role_help=accounts.ROLE_HELP)


# ------------------------------------------------------------------- one user
@bp.route("/users/<int:user_id>")
@role_required("admin")
def detail(user_id):
    person = _target(user_id)
    return render_template("user_detail.html", active="users", crumb=f"Users · {person['username']}", person=person,
                           events=_history(person["username"], 30), roles=accounts.ROLES, role_help=accounts.ROLE_HELP,
                           me=g.user, last_admin=person["role"] == "admin" and person["is_active"]
                           and accounts.active_admin_count(person["id"]) == 0)


@bp.route("/users/<int:user_id>/profile", methods=["POST"])
@role_required("admin")
def profile(user_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    person = _target(user_id)
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", person["role"])
    errors = []
    if not full_name or len(full_name) > 80:
        errors.append("Full name is required (max 80 characters).")
    if role not in accounts.ROLES:
        errors.append("Choose a role.")
    if role != person["role"]:
        reason = _lockout_reason(person, loses_admin=person["role"] == "admin" and role != "admin")
        if reason:
            errors.append(reason)
    if errors:
        db.rollback()
        for e in errors:
            flash(e, "error")
        return redirect(url_for("users.detail", user_id=user_id))
    db.execute("UPDATE users SET full_name = ?, role = ? WHERE id = ?", (full_name, role, user_id))
    if role != person["role"]:
        action = "user_role_changed"
        detail = f"{person['username']}: {accounts.ROLES[person['role']]} -> {accounts.ROLES[role]}"
    else:
        action = "user_updated"
        detail = f"{person['username']}: name changed"
    db.execute(
        "INSERT INTO audit_logs (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now_iso(), g.user["username"], action, detail),
    )
    db.commit()
    flash("Saved.", "info")
    return redirect(url_for("users.detail", user_id=user_id))


@bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@role_required("admin")
def toggle(user_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    person = _target(user_id)
    disabling = bool(person["is_active"])
    if disabling:
        reason = _lockout_reason(person, becomes_inactive=True)
        if reason:
            db.rollback()
            flash(reason, "error")
            return redirect(url_for("users.detail", user_id=user_id))
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (0 if disabling else 1, user_id))
    db.execute(
        "INSERT INTO audit_logs (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now_iso(), g.user["username"], "user_disabled" if disabling else "user_enabled", person["username"]),
    )
    db.commit()
    flash(f"{person['username']} {'disabled: they are signed out now' if disabling else 'enabled'}.", "info")
    return redirect(url_for("users.detail", user_id=user_id))


@bp.route("/users/<int:user_id>/reset", methods=["POST"])
@role_required("admin")
def reset(user_id):
    person = _target(user_id)
    typed = request.form.get("password", "")
    if typed:
        problems = accounts.password_problems(typed, person["username"], person["full_name"])
        if problems:
            for e in problems:
                flash(e, "error")
            return redirect(url_for("users.detail", user_id=user_id))
    password = typed or accounts.generate_password()
    accounts.set_password(user_id, password, must_change=True)
    audit("user_password_reset", person["username"])
    return render_template("user_credentials.html", active="users", crumb="Password reset", person=accounts.get_user(user_id),
                           password=password, heading="Password reset")


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def delete(user_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    person = _target(user_id)
    reason = _lockout_reason(person, becomes_inactive=True)
    if reason:
        db.rollback()
        flash(reason, "error")
        return redirect(url_for("users.detail", user_id=user_id))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.execute(
        "INSERT INTO audit_logs (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
        (now_iso(), g.user["username"], "user_deleted",
         f"{person['username']} ({accounts.ROLES.get(person['role'], person['role'])})"),
    )
    db.commit()
    flash(f"{person['username']} deleted.", "info")
    return redirect(url_for("users.index"))


# ------------------------------------------------------- change my own password
@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    me = g.user
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        errors = []
        if not check_password_hash(me["password_hash"], current):
            errors.append("Your current password is not correct.")
            accounts.record_event(me["username"], "failed", request.remote_addr or "", "wrong current password on change")
        if new != confirm:
            errors.append("The new password and its confirmation do not match.")
        if current and new == current:
            errors.append("Choose a password different from the current one.")
        errors += accounts.password_problems(new, me["username"], me["full_name"])
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("change_password.html", active="account", crumb="Change password", forced=bool(me["must_change_password"]),
                                   min_length=accounts.MIN_PASSWORD), 400
        stamp = accounts.set_password(me["id"], new, must_change=False)
        session["pv"] = stamp  # keeps this browser signed in; every other session of this user ends
        accounts.record_event(me["username"], "password", request.remote_addr or "", "password changed")
        audit("password_changed", me["username"])
        flash("Password changed. Other devices signed in as you were signed out.", "info")
        return redirect(url_for("views.overview"))
    return render_template("change_password.html", active="account", crumb="Change password", forced=bool(me["must_change_password"]),
                           min_length=accounts.MIN_PASSWORD)

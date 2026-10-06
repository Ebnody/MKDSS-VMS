import os
import threading
import hashlib
import sqlite3
import re
import secrets
import time
from datetime import datetime, timedelta

from flask import Flask, request, jsonify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vms_accounts.db")
SERVER_PORT = 8765
SESSION_DURATION_HOURS = 8
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

BOOTSTRAP_USERNAME = "admin"
BOOTSTRAP_PASSWORD = "ChangeMe123!"
DEFAULT_NEW_ACCOUNT_PASSWORD = "Mkdss@Reset2026"

HSA_AREAS = []
HIGHEST_SECURITY_AREAS = ["Vault Room", "Data Processing Room", "Server Room"]
VALID_HSA_ENTRIES = HSA_AREAS + ["Highest Security Area"] + HIGHEST_SECURITY_AREAS

VISITOR_COLUMNS = [
    "id", "first_name", "middle_name", "last_name", "gender", "dob", "nationality",
    "mobile", "email", "company", "job_title", "national_id", "vehicle_plate", "notes",
    "purpose", "host", "department", "expected_arrival", "expected_departure",
    "visit_date", "badge_no", "check_in_time", "check_out_time", "face_enrolled", "status",
    "approved_by", "self_approved",
]


def validate_password_policy(password):
    """Enforced here on the server - the real source of truth - not just in
    the client UI, since the client check alone could be bypassed by calling
    this API directly. Policy: 12+ chars, upper, lower, number, special char."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character."
    return True, None


# ----------------------------------------------------------------------
# PASSWORD HASHING
# ----------------------------------------------------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    _, computed = hash_password(password, salt_hex)
    return computed == hash_hex


# ----------------------------------------------------------------------
# DATABASE
# ----------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, user TEXT, action TEXT, result TEXT, detail TEXT
        );
        CREATE TABLE IF NOT EXISTS badges (
            badge_no TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            visitor_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT, middle_name TEXT, last_name TEXT,
            gender TEXT, dob TEXT, nationality TEXT,
            mobile TEXT, email TEXT, company TEXT, job_title TEXT,
            national_id TEXT, vehicle_plate TEXT, notes TEXT,
            purpose TEXT, host TEXT, department TEXT,
            expected_arrival TEXT, expected_departure TEXT, visit_date TEXT,
            badge_no TEXT, check_in_time TEXT, check_out_time TEXT,
            face_enrolled INTEGER DEFAULT 0, status TEXT,
            approved_by TEXT, self_approved INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS visit_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_date TEXT, requested_by TEXT, host_username TEXT, department TEXT,
            company TEXT, purpose TEXT, receiving_by TEXT,
            start_visit TEXT, finish_visit TEXT, visit_date TEXT, notes TEXT,
            status TEXT,
            approved_by TEXT, approver_position TEXT, decision_date TEXT,
            hsa_requested INTEGER DEFAULT 0, hsa_areas TEXT, hsa_escort TEXT, hsa_decision TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS request_visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            first_name TEXT, middle_name TEXT, last_name TEXT, national_id TEXT,
            gender TEXT, dob TEXT, nationality TEXT, mobile TEXT, email TEXT,
            job_title TEXT, vehicle_plate TEXT,
            linked_visitor_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            status TEXT DEFAULT 'unread',
            created_at TEXT NOT NULL,
            related_type TEXT,
            related_id INTEGER,
            dedupe_key TEXT UNIQUE,
            FOREIGN KEY(recipient) REFERENCES users(username)
        );
        CREATE TABLE IF NOT EXISTS visitor_change_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            requested_by TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            reason TEXT,
            new_visit_date TEXT,
            new_start_visit TEXT,
            new_finish_visit TEXT,
            hsa_requested INTEGER DEFAULT 0,
            hsa_areas TEXT,
            hsa_escort TEXT,
            status TEXT DEFAULT 'Pending Security Manager',
            reviewed_by TEXT,
            review_date TEXT,
            review_reason TEXT
        );
    """)
    conn.commit()

    conn.execute("""CREATE TABLE IF NOT EXISTS visitor_change_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        requested_by TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        reason TEXT,
        new_visit_date TEXT,
        new_start_visit TEXT,
        new_finish_visit TEXT,
        hsa_requested INTEGER DEFAULT 0,
        hsa_areas TEXT,
        hsa_escort TEXT,
        status TEXT DEFAULT 'Pending Security Manager',
        reviewed_by TEXT,
        review_date TEXT,
        review_reason TEXT
    )""")
    conn.commit()

    change_cols = {row["name"] for row in conn.execute("PRAGMA table_info(visitor_change_requests)")}
    if "change_type" not in change_cols:
        conn.execute("ALTER TABLE visitor_change_requests ADD COLUMN change_type TEXT NOT NULL DEFAULT 'hsa_schedule'")
        conn.commit()

    # Migration: scheduled visitor reminders use a persistent dedupe key so
    # the same reminder is never generated repeatedly.
    notification_cols = {row["name"] for row in conn.execute("PRAGMA table_info(notifications)")}
    if "dedupe_key" not in notification_cols:
        conn.execute("ALTER TABLE notifications ADD COLUMN dedupe_key TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedupe_key ON notifications(dedupe_key) WHERE dedupe_key IS NOT NULL")
        conn.commit()

    # Migration: existing databases created before account lockout was added
    # won't have these columns yet - add them if missing, without touching
    # any existing data.
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    if "failed_attempts" not in existing_cols:
        conn.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
    if "locked_until" not in existing_cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
    conn.commit()

    # Migration: existing databases created before the officer-assigned
    # factory escort was added won't have this column yet.
    existing_vr_cols = {row["name"] for row in conn.execute("PRAGMA table_info(visit_requests)")}
    if "escort" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN escort TEXT")
    if "escort_assigned_by" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN escort_assigned_by TEXT")
    if "sent_to_guards" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN sent_to_guards INTEGER NOT NULL DEFAULT 0")
    if "sent_to_guards_at" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN sent_to_guards_at TEXT")
    if "sent_to_guards_by" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN sent_to_guards_by TEXT")
    if "origin" not in existing_vr_cols:
        # 'host' = pre-planned request submitted by a Host (existing flow).
        # 'walkin' = visitor who showed up unannounced at the gate - the
        # Guard logs it, and it goes Guard -> Officer -> Security Manager ->
        # Factory Manager before it can be authorized.
        conn.execute("ALTER TABLE visit_requests ADD COLUMN origin TEXT NOT NULL DEFAULT 'host'")
    if "visiting_employee" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN visiting_employee TEXT")
    if "security_reviewed_by" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN security_reviewed_by TEXT")
    if "security_review_date" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN security_review_date TEXT")
    if "security_reject_reason" not in existing_vr_cols:
        conn.execute("ALTER TABLE visit_requests ADD COLUMN security_reject_reason TEXT")
    conn.commit()

    # Migration: track who approved each visitor and whether it was a
    # self-approval (the approver was also the one being visited) - this
    # feeds the "Approved By" column on Reports and the self-approval flag.
    existing_v_cols = {row["name"] for row in conn.execute("PRAGMA table_info(visitors)")}
    if "approved_by" not in existing_v_cols:
        conn.execute("ALTER TABLE visitors ADD COLUMN approved_by TEXT")
    if "self_approved" not in existing_v_cols:
        conn.execute("ALTER TABLE visitors ADD COLUMN self_approved INTEGER DEFAULT 0")
    conn.commit()

    # Migration: gate-entry confirmation, per visitor (the guard confirms each
    # person individually as they actually arrive - a group doesn't always
    # walk through the gate together).
    existing_rv_cols = {row["name"] for row in conn.execute("PRAGMA table_info(request_visitors)")}
    if "gate_entry_confirmed_by" not in existing_rv_cols:
        conn.execute("ALTER TABLE request_visitors ADD COLUMN gate_entry_confirmed_by TEXT")
    if "gate_entry_confirmed_at" not in existing_rv_cols:
        conn.execute("ALTER TABLE request_visitors ADD COLUMN gate_entry_confirmed_at TEXT")
    conn.commit()

    cur = conn.execute("SELECT COUNT(*) FROM badges")
    if cur.fetchone()[0] == 0:
        # Physical badge inventory - real factory hardware, shared by every PC.
        for i in range(1, 21):
            conn.execute("INSERT INTO badges (badge_no, status, visitor_id) VALUES (?, ?, ?)",
                         (f"V-{i:03d}", "Available", None))
        conn.commit()

    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        salt, pwd_hash = hash_password(BOOTSTRAP_PASSWORD)
        conn.execute(
            """INSERT INTO users (username, password_hash, salt, display, role, department,
                                    active, must_change_password)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (BOOTSTRAP_USERNAME, pwd_hash, salt, "System Administrator", "admin", None, 1, 0))
        log(conn, "System", "Server Start", "Success",
            "Database created - 1 bootstrap account seeded")
        conn.commit()
    conn.close()


def log(conn, user, action, result, detail=""):
    conn.execute(
        "INSERT INTO audit_log (timestamp, user, action, result, detail) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user, action, result, detail))
    conn.commit()


def user_row_to_dict(row, include_auth=False):
    is_locked = False
    if row["locked_until"]:
        try:
            is_locked = datetime.fromisoformat(row["locked_until"]) > datetime.now()
        except ValueError:
            is_locked = False
    d = {
        "username": row["username"], "display": row["display"], "role": row["role"],
        "department": row["department"], "active": bool(row["active"]),
        "must_change_password": bool(row["must_change_password"]),
        "locked": is_locked,
    }
    if include_auth:
        d["password_hash"] = row["password_hash"]
        d["salt"] = row["salt"]
    return d


# ----------------------------------------------------------------------
# SESSION TOKENS
# ----------------------------------------------------------------------
# Real authentication - not just "the client says it's an admin." A token is
# issued once at login and must be presented (via the X-Session-Token header)
# on every subsequent request. The server looks up who that token actually
# belongs to itself; it never trusts anything the client claims about its own
# identity or role.
def create_session(conn, username):
    _purge_expired_sessions(conn)
    token = secrets.token_hex(32)
    now = datetime.now()
    expires = now + timedelta(hours=SESSION_DURATION_HOURS)
    conn.execute("INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
                 (token, username, now.isoformat(), expires.isoformat()))
    conn.commit()
    return token


def _purge_expired_sessions(conn):
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
    conn.commit()


def invalidate_session(conn, token):
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()


def get_authenticated_user(req, conn):
    """Returns the user dict for the currently valid session token, or None if
    missing/invalid/expired. This is the ONLY source of truth for who's making
    a request and what role they have - never trust client-supplied fields."""
    token = req.headers.get("X-Session-Token")
    if not token:
        return None
    _purge_expired_sessions(conn)
    row = conn.execute(
        "SELECT username FROM sessions WHERE token=? AND expires_at >= ?",
        (token, datetime.now().isoformat())).fetchone()
    if not row:
        return None
    user_row = conn.execute("SELECT * FROM users WHERE username=?", (row["username"],)).fetchone()
    if not user_row or not user_row["active"]:
        return None
    return user_row_to_dict(user_row)
def create_notification(conn, recipient, notif_type, title, message, related_type=None, related_id=None, dedupe_key=None):
    """Create a persistent notification. A dedupe key makes scheduled/event
    notifications idempotent across server restarts and repeated scheduler runs."""
    try:
        if dedupe_key:
            existing = conn.execute("SELECT id FROM notifications WHERE dedupe_key=?", (dedupe_key,)).fetchone()
            if existing:
                return False
        conn.execute(
            """INSERT INTO notifications
               (recipient, type, title, message, status, created_at, related_type, related_id, dedupe_key)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (recipient, notif_type, title, message, 'unread', datetime.now().isoformat(), related_type, related_id, dedupe_key)
        )
        return True
    except Exception as e:
        print(f"Error creating notification: {e}")
        return False


def _send_visit_arrival_reminder(conn, visitor, reminder_kind):
    """Notify the host, all active Security Managers, Officers and Guards.
    Notifications are generated from the approved visitor record, so they
    remain correct even when the host is not currently logged in."""
    vid = visitor["id"]
    visit_date = str(visitor.get("visit_date") or "")
    expected = str(visitor.get("expected_arrival") or "")
    visitor_name = f'{visitor.get("first_name", "")} {visitor.get("last_name", "")}'.strip() or "Visitor"
    company = visitor.get("company") or "-"
    host = visitor.get("host") or "-"
    if reminder_kind == "day_before":
        title = f"📅 Visitor Tomorrow: {visitor_name}"
        message = (f"{visitor_name} from {company} is expected tomorrow ({visit_date}) "
                   f"at {expected}. Host: {host}.")
        notif_type = "visitor_arrival_tomorrow"
    else:
        title = f"🔔 Visitor Arrival Due: {visitor_name}"
        message = (f"{visitor_name} from {company} is expected now at {expected}. "
                   f"Host: {host}. Please prepare for visitor arrival.")
        notif_type = "visitor_arrival_due"

    recipients = set()
    host_row = conn.execute("SELECT username FROM users WHERE username=? AND active=1", (host,)).fetchone()
    if host_row:
        recipients.add(host_row["username"])
    role_rows = conn.execute(
        "SELECT username FROM users WHERE role IN ('security_manager','officer','guard') AND active=1"
    ).fetchall()
    recipients.update(r["username"] for r in role_rows)

    for recipient in recipients:
        dedupe = f"VISITOR_ARRIVAL:{reminder_kind}:{vid}:{recipient}"
        create_notification(conn, recipient, notif_type, title, message, "visitor", vid, dedupe)


def _run_visitor_reminder_cycle():
    """Server-side reminder worker. Runs independently of desktop clients,
    so notifications are generated even when nobody has the VMS client open."""
    while True:
        try:
            conn = get_db()
            now = datetime.now()
            today = now.date()
            current_hm = now.strftime("%H:%M")
            tomorrow_date = today + timedelta(days=1)
            tomorrow_str = tomorrow_date.isoformat()
            today_str = today.isoformat()

            rows = conn.execute(
                "SELECT * FROM visitors WHERE status='Approved' AND check_in_time IS NULL AND check_out_time IS NULL "
                "AND visit_date IN (?, ?)", (today_str, tomorrow_str)
            ).fetchall()
            for row in rows:
                visitor = dict(row)
                visit_date = str(visitor.get("visit_date") or "")
                expected = str(visitor.get("expected_arrival") or "")[:5]
                if not expected or len(expected) != 5:
                    continue
                try:
                    expected_dt = datetime.strptime(f"{visit_date} {expected}", "%Y-%m-%d %H:%M")
                    delta_seconds = (now - expected_dt).total_seconds()
                except ValueError:
                    continue
                if visit_date == tomorrow_str:
                    reminder_dt = expected_dt - timedelta(days=1)
                    reminder_delta = (now - reminder_dt).total_seconds()
                    if -60 <= reminder_delta <= 300:
                        _send_visit_arrival_reminder(conn, visitor, "day_before")
                elif visit_date == today_str and 0 <= delta_seconds <= 300:
                    _send_visit_arrival_reminder(conn, visitor, "at_time")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Visitor reminder worker error: {e}")
        time.sleep(30)


def start_visitor_reminder_worker():
    worker = threading.Thread(target=_run_visitor_reminder_cycle, name="VisitorReminderWorker", daemon=True)
    worker.start()


# ----------------------------------------------------------------------
# FLASK APP / API ROUTES
# ----------------------------------------------------------------------
app = Flask(__name__)


@app.route("/api/ping", methods=["GET"])
def ping():
    """Simple reachability check - clients use this to verify the server address works."""
    return jsonify({"ok": True, "message": "VMS server is reachable"})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Invalid username or password."}), 401

    # Check lockout BEFORE checking the password, so a locked account can't
    # be probed further while it's locked.
    if row["locked_until"]:
        locked_until = datetime.fromisoformat(row["locked_until"])
        if locked_until > datetime.now():
            minutes_left = max(1, int((locked_until - datetime.now()).total_seconds() // 60) + 1)
            conn.close()
            return jsonify({"ok": False, "error":
                f"This account is temporarily locked after too many failed login attempts. "
                f"Try again in about {minutes_left} minute(s), or contact your System Administrator "
                f"to reset it sooner."}), 403

    if not verify_password(password, row["salt"], row["password_hash"]):
        new_attempts = row["failed_attempts"] + 1
        if new_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
            conn.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE username=?",
                         (locked_until, username))
            log(conn, row["display"], "Login", "Failed",
                f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes after "
                f"{MAX_FAILED_LOGIN_ATTEMPTS} failed attempts")
            conn.commit()
            conn.close()
            return jsonify({"ok": False, "error":
                f"Too many failed attempts. This account is now locked for "
                f"{LOCKOUT_DURATION_MINUTES} minutes."}), 403
        else:
            conn.execute("UPDATE users SET failed_attempts=? WHERE username=?", (new_attempts, username))
            conn.commit()
        conn.close()
        return jsonify({"ok": False, "error": "Invalid username or password."}), 401

    if not row["active"]:
        conn.close()
        return jsonify({"ok": False, "error": "This account has been deactivated. Contact an administrator."}), 403

    # Successful login - clear any prior failed attempts/lockout state.
    conn.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
    result = user_row_to_dict(row)
    token = create_session(conn, result["username"])
    log(conn, result["display"], "Login", "Success", f"Role: {result['role']}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "user": result, "token": token})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    conn = get_db()
    token = request.headers.get("X-Session-Token")
    if token:
        invalidate_session(conn, token)
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    conn = get_db()
    user = get_authenticated_user(request, conn)
    if not user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401

    data = request.get_json(force=True)
    new_password = data.get("new_password") or ""

    ok, error = validate_password_policy(new_password)
    if not ok:
        conn.close()
        return jsonify({"ok": False, "error": error}), 400

    salt, pwd_hash = hash_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash=?, salt=?, must_change_password=0 WHERE username=?",
        (pwd_hash, salt, user["username"]))
    log(conn, user["display"], "Change Password", "Success", "Password updated")
    conn.commit()

    # Issue a fresh token and retire the old one - the account's identity
    # hasn't changed, but this is good hygiene after a credential change.
    old_token = request.headers.get("X-Session-Token")
    if old_token:
        invalidate_session(conn, old_token)
    new_token = create_session(conn, user["username"])

    result = user_row_to_dict(conn.execute(
        "SELECT * FROM users WHERE username=?", (user["username"],)).fetchone())
    conn.close()
    return jsonify({"ok": True, "user": result, "token": new_token})


@app.route("/api/users", methods=["GET"])
def api_list_users():
    conn = get_db()
    if not get_authenticated_user(request, conn):
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    users = [user_row_to_dict(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "users": users})


@app.route("/api/users", methods=["POST"])
def api_create_user():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] != "admin":
        conn.close()
        return jsonify({"ok": False, "error": "Only a System Administrator can create accounts."}), 403

    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    display = (data.get("display") or "").strip()
    role = data.get("role")
    department = data.get("department")

    if not username or not display or role not in ("officer", "host", "admin", "approver", "guard", "security_manager"):
        conn.close()
        return jsonify({"ok": False, "error": "Missing or invalid account details."}), 400
    if role == "host" and not department:
        conn.close()
        return jsonify({"ok": False, "error": "A Host account must be linked to a department."}), 400

    existing = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": f"Username '{username}' is already in use."}), 409

    salt, pwd_hash = hash_password(DEFAULT_NEW_ACCOUNT_PASSWORD)
    conn.execute(
        """INSERT INTO users (username, password_hash, salt, display, role, department,
                                active, must_change_password)
           VALUES (?, ?, ?, ?, ?, ?, 1, 1)""",
        (username, pwd_hash, salt, display, role, department))
    log(conn, acting_user["display"], "User Management", "Success",
        f"Created {role} account '{username}' ({display})" + (f" - Dept: {department}" if department else ""))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "default_password": DEFAULT_NEW_ACCOUNT_PASSWORD})


@app.route("/api/users/toggle", methods=["POST"])
def api_toggle_user():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] != "admin":
        conn.close()
        return jsonify({"ok": False, "error": "Only a System Administrator can manage accounts."}), 403

    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Account not found."}), 404
    if username == acting_user["username"]:
        conn.close()
        return jsonify({"ok": False, "error": "You can't deactivate the account you're logged in as."}), 400

    new_active = 0 if row["active"] else 1
    conn.execute("UPDATE users SET active=? WHERE username=?", (new_active, username))
    log(conn, acting_user["display"], "User Management", "Success",
        f"{'Activated' if new_active else 'Deactivated'} account '{username}'")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "active": bool(new_active)})


@app.route("/api/users/delete", methods=["POST"])
def api_delete_user():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] != "admin":
        conn.close()
        return jsonify({"ok": False, "error": "Only a System Administrator can delete accounts."}), 403

    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    if username == acting_user["username"]:
        conn.close()
        return jsonify({"ok": False, "error": "You can't delete the account you're logged in as."}), 400

    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Account not found."}), 404

    if row["role"] == "admin":
        other_admins = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND username!=?", (username,)).fetchone()[0]
        if other_admins == 0:
            conn.close()
            return jsonify({"ok": False, "error": "Can't delete the last System Administrator account."}), 400

    conn.execute("DELETE FROM users WHERE username=?", (username,))
    log(conn, acting_user["display"], "User Management", "Success",
        f"Deleted account '{username}' ({row['display']})")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/users/reset_password", methods=["POST"])
def api_reset_user_password():
    """Admin-only 'forgot password' fix: resets the account to a fresh temp
    password (same as a brand-new account gets), forces them to set their own
    on next login, and clears any active lockout at the same time."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] != "admin":
        conn.close()
        return jsonify({"ok": False, "error": "Only a System Administrator can reset passwords."}), 403

    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Account not found."}), 404

    salt, pwd_hash = hash_password(DEFAULT_NEW_ACCOUNT_PASSWORD)
    conn.execute(
        """UPDATE users SET password_hash=?, salt=?, must_change_password=1,
                              failed_attempts=0, locked_until=NULL WHERE username=?""",
        (pwd_hash, salt, username))
    # Also invalidate any existing sessions for this account, in case someone
    # else's password was just reset out from under an active login.
    conn.execute("DELETE FROM sessions WHERE username=?", (username,))
    log(conn, acting_user["display"], "User Management", "Success",
        f"Reset password for account '{username}' ({row['display']})")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "temp_password": DEFAULT_NEW_ACCOUNT_PASSWORD})


@app.route("/api/badges", methods=["GET"])
def api_list_badges():
    conn = get_db()
    if not get_authenticated_user(request, conn):
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    rows = conn.execute("SELECT badge_no, status, visitor_id FROM badges ORDER BY badge_no").fetchall()
    badges = [dict(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "badges": badges})


REQUEST_VISITOR_COLUMNS = [
    "first_name", "middle_name", "last_name", "national_id",
    "gender", "dob", "nationality", "mobile", "email", "job_title", "vehicle_plate",
]


def _visit_request_to_dict(conn, row):
    d = dict(row)
    d["hsa_requested"] = bool(d["hsa_requested"])
    d["sent_to_guards"] = bool(d["sent_to_guards"])
    d["hsa_areas"] = d["hsa_areas"].split("|") if d["hsa_areas"] else []
    visitor_rows = conn.execute(
        "SELECT * FROM request_visitors WHERE request_id=? ORDER BY id", (row["id"],)).fetchall()
    d["visitors"] = [dict(v) for v in visitor_rows]
    return d


@app.route("/api/visit_requests", methods=["GET"])
def api_list_visit_requests():
    conn = get_db()
    if not get_authenticated_user(request, conn):
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    rows = conn.execute("SELECT * FROM visit_requests ORDER BY id DESC").fetchall()
    requests_out = [_visit_request_to_dict(conn, r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "requests": requests_out})


@app.route("/api/visit_requests", methods=["POST"])
def api_create_visit_request():
    """A Host (or Security Manager / Factory Manager, submitting for their
    own expected visitors, separate from their review/approval duties)
    submits a group visitor request - one form, up to 10 visitors, matching
    the paper 'Visitor Request form'. This does NOT create real visitor
    records yet - those only appear (in the existing `visitors` table,
    unchanged) once the Factory Manager approves this request."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("host", "security_manager", "approver", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only a Host can submit a visitor request."}), 403

    data = request.get_json(force=True)
    company = (data.get("company") or "").strip()
    purpose = (data.get("purpose") or "").strip()
    visitors = data.get("visitors") or []

    if not company or not purpose:
        conn.close()
        return jsonify({"ok": False, "error": "Company and Visit Purpose are required."}), 400
    if not visitors:
        conn.close()
        return jsonify({"ok": False, "error": "Add at least one visitor to the request."}), 400
    if len(visitors) > 10:
        conn.close()
        return jsonify({"ok": False, "error": "A single request supports up to 10 visitors."}), 400
    for v in visitors:
        if not (v.get("first_name") or "").strip() or not (v.get("last_name") or "").strip():
            conn.close()
            return jsonify({"ok": False, "error": "Every visitor needs at least a first and last name."}), 400

    hsa_requested = bool(data.get("hsa_requested"))
    hsa_areas = data.get("hsa_areas") or []
    # Validate HSA areas: filter to only valid entries (standard areas, highest security marker, and specific rooms)
    hsa_areas = [a for a in hsa_areas if a in VALID_HSA_ENTRIES]
    
    # Enforce HSA hierarchy: if any highest security room is selected, "Highest Security Area" must be present
    highest_security_rooms_selected = [a for a in hsa_areas if a in HIGHEST_SECURITY_AREAS]
    if highest_security_rooms_selected and "Highest Security Area" not in hsa_areas:
        conn.close()
        return jsonify({"ok": False, "error": "Highest Security Area must be selected to access specific rooms."}), 400

    now = datetime.now()
    cur = conn.execute(
        """INSERT INTO visit_requests
           (request_date, requested_by, host_username, department, company, purpose,
            receiving_by, start_visit, finish_visit, visit_date, notes, status,
            hsa_requested, hsa_areas, hsa_escort, hsa_decision, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Approval', ?, ?, ?, ?, ?)""",
        (now.strftime("%Y-%m-%d"), acting_user["display"], acting_user["username"],
         acting_user["department"], company, purpose, data.get("receiving_by", ""),
         data.get("start_visit", ""), data.get("finish_visit", ""),
         data.get("visit_date", now.strftime("%Y-%m-%d")), data.get("notes", ""),
         int(hsa_requested), "|".join(hsa_areas), data.get("hsa_escort", ""), "",
         now.isoformat()))
    rid = cur.lastrowid

    for v in visitors:
        vals = [(v.get(c) or "").strip() if c != "national_id" else (v.get(c) or "").strip()
                 for c in REQUEST_VISITOR_COLUMNS]
        conn.execute(
            f"""INSERT INTO request_visitors (request_id, {','.join(REQUEST_VISITOR_COLUMNS)})
                VALUES (?, {','.join('?' for _ in REQUEST_VISITOR_COLUMNS)})""",
            [rid] + vals)

    log(conn, acting_user["display"], "Visit Request Submitted", "Success",
        f"Request #{rid}: {len(visitors)} visitor(s), company '{company}'"
        + (" - HSA access requested" if hsa_requested else ""))
    
    # Create notification for all approvers
    approvers = conn.execute("SELECT username FROM users WHERE role='approver' AND active=1").fetchall()
    for (approver_user,) in approvers:
        create_notification(
            conn, approver_user, "new_request",
            f"📋 New Request #{rid} Awaiting Approval",
            f"New visitor request from {company} ({len(visitors)} visitor(s)) on {data.get('visit_date', now.strftime('%Y-%m-%d'))}",
            "visit_request", rid
        )
    
    # If HSA access requested, notify security managers
    if hsa_requested:
        security_managers = conn.execute("SELECT username FROM users WHERE role='security_manager' AND active=1").fetchall()
        for (sm_user,) in security_managers:
            create_notification(
                conn, sm_user, "hsa_review",
                f"⚠️ HSA Access Requested - Request #{rid}",
                f"Highest Security Area access requested for {company} - Review access requirements",
                "visit_request", rid
            )
    
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": rid})


@app.route("/api/visit_requests/walkin", methods=["POST"])
def api_create_walkin_request():
    """A visitor shows up unannounced at the gate - the Guard logs their
    details here. Unlike a Host's pre-planned request, this does NOT go
    straight to the Factory Manager: it must first pass through the Officer
    (who forwards it) and the Security Manager (who can approve-and-forward
    or reject it outright) before the Factory Manager ever sees it."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("guard", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only a Gate Guard can log a walk-in visitor."}), 403

    data = request.get_json(force=True)
    company = (data.get("company") or "").strip()
    purpose = (data.get("purpose") or "").strip()
    visiting_employee = (data.get("visiting_employee") or "").strip()
    department = (data.get("department") or "").strip()
    first_name = (data.get("first_name") or "").strip()
    last_name = (data.get("last_name") or "").strip()
    national_id = (data.get("national_id") or "").strip()

    if not first_name or not last_name:
        conn.close()
        return jsonify({"ok": False, "error": "Visitor's first and last name are required."}), 400
    if not company or not purpose:
        conn.close()
        return jsonify({"ok": False, "error": "Company and Visit Purpose are required."}), 400
    if not visiting_employee:
        conn.close()
        return jsonify({"ok": False, "error": "Who they're visiting is required."}), 400

    now = datetime.now()
    cur = conn.execute(
        """INSERT INTO visit_requests
           (request_date, requested_by, host_username, department, company, purpose,
            visit_date, status, hsa_requested, hsa_areas, hsa_escort, hsa_decision,
            created_at, origin, visiting_employee)
           VALUES (?, ?, NULL, ?, ?, ?, ?, 'Pending Officer Review', 0, '', '', '', ?, 'walkin', ?)""",
        (now.strftime("%Y-%m-%d"), acting_user["display"], department, company, purpose,
         now.strftime("%Y-%m-%d"), now.isoformat(), visiting_employee))
    rid = cur.lastrowid

    conn.execute(
        f"""INSERT INTO request_visitors (request_id, {','.join(REQUEST_VISITOR_COLUMNS)})
            VALUES (?, {','.join('?' for _ in REQUEST_VISITOR_COLUMNS)})""",
        [rid, first_name, "", last_name, national_id, "", "", "", "", "", "", ""])

    log(conn, acting_user["display"], "Walk-In Visitor Logged", "Success",
        f"Request #{rid}: {first_name} {last_name} ({company}) - visiting {visiting_employee}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": rid})


@app.route("/api/visit_requests/<int:rid>/forward_to_security", methods=["POST"])
def api_forward_to_security(rid):
    """The Officer reviews what the Guard logged and forwards it on to the
    Security Manager - a pass-through checkpoint, not a decision point."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only an Officer can forward this to the Security Manager."}), 403

    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if row["origin"] != "walkin" or row["status"] != "Pending Officer Review":
        conn.close()
        return jsonify({"ok": False, "error": "This request isn't waiting on Officer review."}), 400

    conn.execute("UPDATE visit_requests SET status='Pending Security Review' WHERE id=?", (rid,))
    log(conn, acting_user["display"], "Forwarded to Security Manager", "Success",
        f"Request #{rid} ({row['company']})")
    
    # Notify security managers
    security_managers = conn.execute(
        "SELECT username FROM users WHERE role='security_manager' AND active=1"
    ).fetchall()
    for (sm_user,) in security_managers:
        create_notification(
            conn, sm_user, "new_request",
            f"📋 Security Review Needed for Request #{rid}",
            f"Request from {row['company']} forwarded for security review",
            "visit_request", rid
        )
    
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visit_requests/<int:rid>/security_review", methods=["POST"])
def api_security_review(rid):
    """The Security Manager reviews the walk-in - can forward it on to the
    Factory Manager for authorization, or reject it outright right here,
    before the Factory Manager ever needs to see it."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only the Security Manager can review this."}), 403

    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if row["origin"] != "walkin" or row["status"] != "Pending Security Review":
        conn.close()
        return jsonify({"ok": False, "error": "This request isn't waiting on Security Manager review."}), 400

    data = request.get_json(force=True)
    decision = data.get("decision")
    if decision not in ("Forward", "Reject"):
        conn.close()
        return jsonify({"ok": False, "error": "Invalid decision."}), 400

    now = datetime.now()
    if decision == "Forward":
        conn.execute(
            """UPDATE visit_requests SET status='Pending Factory Authorization',
                                          security_reviewed_by=?, security_review_date=? WHERE id=?""",
            (acting_user["display"], now.strftime("%Y-%m-%d %H:%M"), rid))
        
        # Notify approvers that security review is complete
        approvers = conn.execute("SELECT username FROM users WHERE role='approver' AND active=1").fetchall()
        for (approver_user,) in approvers:
            create_notification(
                conn, approver_user, "new_request",
                f"📋 Request #{rid} Forwarded for Approval",
                f"Security review complete for {row['company']} - Ready for approval",
                "visit_request", rid
            )
    else:
        reason = (data.get("reason") or "").strip()
        conn.execute(
            """UPDATE visit_requests SET status='Rejected by Security Manager',
                                          security_reviewed_by=?, security_review_date=?,
                                          security_reject_reason=? WHERE id=?""",
            (acting_user["display"], now.strftime("%Y-%m-%d %H:%M"), reason, rid))
        
        # Notify requester/officer that security rejected
        requester = row["requested_by"]
        create_notification(
            conn, requester, "security_rejected",
            f"❌ Request #{rid} Rejected by Security",
            f"Security review rejected request from {row['company']}. Reason: {reason if reason else 'Not specified'}",
            "visit_request", rid
        )

    is_self_review = acting_user["display"] == (row["host_username"] or row["requested_by"])
    log(conn, acting_user["display"], "Security Review", "Success",
        ("SELF-REVIEW - security manager is the visited host - " if is_self_review else "")
        + f"Request #{rid} ({row['company']}) - {decision}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visit_requests/<int:rid>/decide", methods=["POST"])
def api_decide_visit_request(rid):
    """The Factory Manager (role 'approver') reviews a group request - this
    mirrors part II of the paper form (Approve / Not Approve, date, approved
    by, position), plus the HSA decision if that was requested.

    On approval, one row is created in the existing `visitors` table per
    person in the request - this is the ONLY place that happens, so every
    already-working page (Check-In, Check-Out, Badges, Dashboard, Search,
    Reports) picks these visitors up automatically with no changes needed."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("approver", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only the Factory Manager (Approver) can decide visit requests."}), 403

    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if row["status"] not in ("Pending Approval", "Pending Factory Authorization"):
        conn.close()
        return jsonify({"ok": False, "error": "This request has already been decided."}), 400

    data = request.get_json(force=True)
    decision = data.get("decision")
    if decision not in ("Approved", "Not Approved"):
        conn.close()
        return jsonify({"ok": False, "error": "Invalid decision."}), 400
    position = (data.get("position") or "Factory Manager").strip()
    # HSA is a separate security-control decision. The Factory Manager may
    # approve the visitor request, but cannot grant HSA access. Security
    # Manager must make the HSA decision through /hsa_decide.
    hsa_decision = ""

    now = datetime.now()
    conn.execute(
        """UPDATE visit_requests SET status=?, approved_by=?, approver_position=?,
                                      decision_date=?, hsa_decision=? WHERE id=?""",
        (decision, acting_user["display"], position, now.strftime("%Y-%m-%d %H:%M"), hsa_decision, rid))

    visiting_host = row["host_username"] or row["requested_by"]
    is_self_decision = acting_user["display"] == visiting_host

    created_ids = []
    if decision == "Approved":
        visitor_rows = conn.execute(
            "SELECT * FROM request_visitors WHERE request_id=?", (rid,)).fetchall()
        for v in visitor_rows:
            fields = {c: "" for c in VISITOR_COLUMNS if c != "id"}
            fields.update({
                "first_name": v["first_name"], "middle_name": v["middle_name"],
                "last_name": v["last_name"], "gender": v["gender"], "dob": v["dob"],
                "nationality": v["nationality"], "mobile": v["mobile"], "email": v["email"],
                "company": row["company"], "job_title": v["job_title"],
                "national_id": v["national_id"], "vehicle_plate": v["vehicle_plate"],
                "notes": row["notes"], "purpose": row["purpose"],
                "host": row["host_username"] or row["requested_by"],
                "department": row["department"], "expected_arrival": row["start_visit"],
                "expected_departure": row["finish_visit"], "visit_date": row["visit_date"],
                "face_enrolled": 0, "status": "Approved",
                "approved_by": acting_user["display"], "self_approved": int(is_self_decision),
            })
            cols = [c for c in VISITOR_COLUMNS if c != "id"]
            cur = conn.execute(
                f"INSERT INTO visitors ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
                [fields[c] for c in cols])
            new_vid = cur.lastrowid
            created_ids.append(new_vid)
            conn.execute("UPDATE request_visitors SET linked_visitor_id=? WHERE id=?",
                         (new_vid, v["id"]))

    log(conn, acting_user["display"], "Visit Request Decision", "Success",
        ("SELF-APPROVAL - approver is the visited host - " if is_self_decision else "")
        + f"{decision} request #{rid} ({row['requested_by']}, {row['company']})"
        + (f" - HSA: {hsa_decision}" if row["hsa_requested"] else "")
        + (f" - {len(created_ids)} visitor(s) now Approved for check-in" if created_ids else ""))
    
    # Create notification for the host
    host_user = row["host_username"] or row["requested_by"]
    if decision == "Approved":
        create_notification(
            conn, host_user, "approval_approved",
            f"✅ Request #{rid} Approved",
            f"Your visitor request for {row['company']} on {row['visit_date']} has been approved.",
            "visit_request", rid
        )
        
        # Create notification for Security Officers
        visitor_count = len(created_ids) if created_ids else "1"
        officers = conn.execute(
            "SELECT username FROM users WHERE role IN ('officer', 'guard', 'security_manager') AND active=1"
        ).fetchall()
        for (officer_user,) in officers:
            create_notification(
                conn, officer_user, "checkin_ready",
                f"✅ Request #{rid} Ready for Check-In",
                f"{visitor_count} visitor(s) from {row['company']} approved for {row['visit_date']} - Assign badge and check in",
                "visit_request", rid
            )
    else:
        create_notification(
            conn, host_user, "approval_rejected",
            f"❌ Request #{rid} Not Approved",
            f"Your visitor request for {row['company']} on {row['visit_date']} was not approved.",
            "visit_request", rid
        )
    
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "created_visitor_ids": created_ids})


@app.route("/api/visit_requests/<int:rid>/assign_escort", methods=["POST"])
def api_assign_escort(rid):
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only an Officer or Security Manager can assign an escort."}), 403

    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if row["status"] != "Approved":
        conn.close()
        return jsonify({"ok": False, "error": "Only an approved request can have an escort assigned."}), 400

    escort = (request.get_json(force=True).get("escort") or "").strip()
    if not escort:
        conn.close()
        return jsonify({"ok": False, "error": "Escort name is required."}), 400

    conn.execute("UPDATE visit_requests SET escort=?, escort_assigned_by=? WHERE id=?",
                 (escort, acting_user["display"], rid))
    log(conn, acting_user["display"], "Escort Assigned", "Success",
        f"Request #{rid} ({row['company']}) - escort: {escort}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visit_requests/<int:rid>/send_to_guards", methods=["POST"])
def api_send_to_guards(rid):
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only an Officer or Security Manager can send an authorization to the guards."}), 403

    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if row["status"] != "Approved":
        conn.close()
        return jsonify({"ok": False, "error": "Only an approved request can be sent to the guards."}), 400
    if not row["escort"]:
        conn.close()
        return jsonify({"ok": False, "error": "Assign a factory escort before sending to the guards."}), 400
    if row["sent_to_guards"]:
        conn.close()
        return jsonify({"ok": False, "error": "This authorization has already been sent to the guards and is now in history."}), 400

    now = datetime.now()
    conn.execute(
        "UPDATE visit_requests SET sent_to_guards=1, sent_to_guards_at=?, sent_to_guards_by=? WHERE id=?",
        (now.strftime("%Y-%m-%d %H:%M"), acting_user["display"], rid))
    log(conn, acting_user["display"], "Sent to Guards", "Success",
        f"Request #{rid} ({row['company']}) sent electronically to gate guards")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visit_requests/<int:rid>/visitors/<int:rvid>/gate_entry", methods=["POST"])
def api_confirm_gate_entry(rid, rvid):
    """The Guard confirms one specific visitor has actually arrived and been
    let through the gate - each person is confirmed individually since a
    group doesn't always arrive together. This is a gate log, separate from
    the badge Check-In that still happens at the Officer's desk inside."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("guard", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only a Gate Guard can confirm entry."}), 403

    req_row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not req_row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if not req_row["sent_to_guards"]:
        conn.close()
        return jsonify({"ok": False, "error": "This authorization hasn't been sent to the guards yet."}), 400

    v_row = conn.execute("SELECT * FROM request_visitors WHERE id=? AND request_id=?",
                          (rvid, rid)).fetchone()
    if not v_row:
        conn.close()
        return jsonify({"ok": False, "error": "Visitor not found on this request."}), 404

    now = datetime.now()
    conn.execute(
        "UPDATE request_visitors SET gate_entry_confirmed_by=?, gate_entry_confirmed_at=? WHERE id=?",
        (acting_user["display"], now.strftime("%Y-%m-%d %H:%M"), rvid))
    log(conn, acting_user["display"], "Gate Entry Confirmed", "Success",
        f"Request #{rid} ({req_row['company']}) - {v_row['first_name']} {v_row['last_name']}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visitors", methods=["GET"])
def api_list_visitors():
    conn = get_db()
    if not get_authenticated_user(request, conn):
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    # Also return a server-derived checkout date so the client can reliably
    # filter "Checked Out Today" without guessing from a display-formatted time.
    visitor_select = f"{','.join(VISITOR_COLUMNS)}, date(check_out_time) AS check_out_date"
    rows = conn.execute(
        f"SELECT {visitor_select} FROM visitors ORDER BY id").fetchall()
    visitors = [dict(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "visitors": visitors})


@app.route("/api/visitors", methods=["POST"])
def api_register_visitor():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only a Security Officer can register visitors."}), 403

    data = request.get_json(force=True)
    fields = {c: data.get(c) for c in VISITOR_COLUMNS if c != "id"}
    if not fields.get("status"):
        fields["status"] = "Pending Approval"
    if not fields.get("face_enrolled"):
        fields["face_enrolled"] = 0
    if fields.get("self_approved") is None:
        fields["self_approved"] = 0

    cols = [c for c in VISITOR_COLUMNS if c != "id"]
    placeholders = ",".join("?" for _ in cols)
    values = [fields.get(c) for c in cols]

    cur = conn.execute(f"INSERT INTO visitors ({','.join(cols)}) VALUES ({placeholders})", values)
    vid = cur.lastrowid
    log(conn, acting_user["display"], "Visitor Registration", "Success",
        f"Registered visitor #{vid}: {fields.get('first_name','')} {fields.get('last_name','')}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": vid})


@app.route("/api/visitors/<int:vid>/decide", methods=["POST"])
def api_decide_visitor(vid):
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401

    row = conn.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visitor not found."}), 404

    # Only the actual assigned host can approve/reject their own visitors -
    # not just "someone with the host role."
    if acting_user["role"] != "host" or acting_user["display"] != row["host"]:
        conn.close()
        return jsonify({"ok": False, "error": "You can only approve or reject visitors assigned to you."}), 403

    data = request.get_json(force=True)
    decision = data.get("decision")
    if decision not in ("Approved", "Rejected"):
        conn.close()
        return jsonify({"ok": False, "error": "Invalid decision."}), 400

    conn.execute("UPDATE visitors SET status=? WHERE id=?", (decision, vid))
    log(conn, acting_user["display"], "Visitor Approval" if decision == "Approved" else "Visitor Rejection",
        "Success", f"{decision} visitor #{vid} ({row['first_name']} {row['last_name']})")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visit_requests/<int:rid>/hsa_decide", methods=["POST"])
def api_hsa_decide_visit_request(rid):
    """Security Manager independently approves/rejects HSA access for a request."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only the Security Manager can decide HSA access."}), 403
    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if not row["hsa_requested"]:
        conn.close()
        return jsonify({"ok": False, "error": "This request does not contain an HSA request."}), 400
    if row["status"] not in ("Approved", "Pending Approval", "Pending Factory Authorization"):
        conn.close()
        return jsonify({"ok": False, "error": "This request is not eligible for HSA review."}), 400
    decision = (request.get_json(force=True).get("decision") or "").strip()
    if decision not in ("Approved", "Not Approved"):
        conn.close()
        return jsonify({"ok": False, "error": "Invalid HSA decision."}), 400
    now = datetime.now()
    conn.execute("UPDATE visit_requests SET hsa_decision=? WHERE id=?", (decision, rid))
    host_user = row["host_username"] or row["requested_by"]
    create_notification(conn, host_user, "hsa_decision",
                        f"HSA Request #{rid}: {decision}",
                        f"Security Manager {acting_user['display']} has {decision.lower()} HSA access for {row['company']}.",
                        "visit_request", rid)
    log(conn, acting_user["display"], "HSA Decision", "Success",
        f"{decision} HSA access for request #{rid} ({row['company']})")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "decision": decision})


@app.route("/api/visit_requests/<int:rid>/change_request", methods=["POST"])
def api_create_visitor_change_request(rid):
    """Host submits a schedule, HSA, or combined change request.
    The Security Manager can only review the request; the approved appointment
    is not modified until the request is approved.
    """
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    row = conn.execute("SELECT * FROM visit_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visit request not found."}), 404
    if acting_user["role"] != "host" or acting_user["username"] != row["host_username"]:
        conn.close()
        return jsonify({"ok": False, "error": "Only the assigned Host can request changes to this visit."}), 403
    if row["status"] != "Approved":
        conn.close()
        return jsonify({"ok": False, "error": "Only an approved visit can be changed through this workflow."}), 400
    linked = conn.execute("SELECT linked_visitor_id FROM request_visitors WHERE request_id=? AND linked_visitor_id IS NOT NULL", (rid,)).fetchall()
    if not linked:
        conn.close()
        return jsonify({"ok": False, "error": "No approved visitor is linked to this request."}), 400
    if any(conn.execute("SELECT 1 FROM visitors WHERE id=? AND check_in_time IS NOT NULL AND check_in_time!=''", (r[0],)).fetchone() for r in linked):
        conn.close()
        return jsonify({"ok": False, "error": "A checked-in visitor cannot be rescheduled or have HSA added through this workflow."}), 400

    data = request.get_json(force=True) or {}
    change_type = (data.get("change_type") or "").strip().lower()
    if change_type not in ("schedule", "hsa", "hsa_schedule"):
        conn.close()
        return jsonify({"ok": False, "error": "Select Schedule, HSA, or HSA + Schedule as the request type."}), 400

    include_schedule = change_type in ("schedule", "hsa_schedule")
    include_hsa = change_type in ("hsa", "hsa_schedule")
    new_date = (data.get("visit_date") or row["visit_date"] or "").strip()
    new_start = (data.get("start_visit") or row["start_visit"] or "").strip()
    new_finish = (data.get("finish_visit") or row["finish_visit"] or "").strip()
    reason = (data.get("reason") or "").strip()

    if include_schedule:
        try:
            datetime.strptime(new_date, "%Y-%m-%d")
            start_dt = datetime.strptime(new_start, "%H:%M")
            finish_dt = datetime.strptime(new_finish, "%H:%M")
        except ValueError:
            conn.close()
            return jsonify({"ok": False, "error": "Use date YYYY-MM-DD and time HH:MM."}), 400
        if finish_dt < start_dt:
            conn.close()
            return jsonify({"ok": False, "error": "Departure time cannot be earlier than arrival time."}), 400
    else:
        # HSA-only requests must never alter the appointment schedule.
        new_date = row["visit_date"] or ""
        new_start = row["start_visit"] or ""
        new_finish = row["finish_visit"] or ""

    if not reason:
        conn.close()
        return jsonify({"ok": False, "error": "A reason is required for the request."}), 400

    if include_hsa:
        hsa_requested = True
        hsa_areas = [a for a in (data.get("hsa_areas") or []) if a in VALID_HSA_ENTRIES]
        hsa_escort = (data.get("hsa_escort") or "").strip()
        if not hsa_areas:
            conn.close()
            return jsonify({"ok": False, "error": "Select at least one HSA area."}), 400
    else:
        # Schedule-only request preserves the current HSA state if the request is approved.
        hsa_requested = bool(row["hsa_requested"])
        hsa_areas = [a for a in (str(row["hsa_areas"] or "").split("|") if row["hsa_areas"] else []) if a]
        hsa_escort = row["hsa_escort"] or ""

    existing = conn.execute("SELECT id FROM visitor_change_requests WHERE request_id=? AND status='Pending Security Manager'", (rid,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"ok": False, "error": f"Change request #{existing['id']} is already pending Security Manager approval."}), 400

    now = datetime.now()
    cur = conn.execute("""INSERT INTO visitor_change_requests
        (request_id, requested_by, requested_at, reason, new_visit_date, new_start_visit, new_finish_visit,
         hsa_requested, hsa_areas, hsa_escort, status, change_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Security Manager', ?)""",
        (rid, acting_user["username"], now.isoformat(), reason, new_date, new_start, new_finish,
         int(hsa_requested), "|".join(hsa_areas), hsa_escort, change_type))
    change_id = cur.lastrowid
    type_label = {"schedule": "Schedule Change", "hsa": "HSA Access", "hsa_schedule": "HSA + Schedule"}[change_type]
    sms = conn.execute("SELECT username FROM users WHERE role='security_manager' AND active=1").fetchall()
    for (sm_user,) in sms:
        create_notification(conn, sm_user, "visitor_change_request",
                            f"{type_label} Request #{change_id}",
                            f"Host {acting_user['display']} submitted a {type_label} request for {row['company']} (Visit Request #{rid}). Review it from HSA & Schedule Requests.",
                            "visitor_change_request", change_id)
    log(conn, acting_user["display"], "Host Change Requested", "Success",
        f"Change #{change_id} [{type_label}] for visit request #{rid}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "id": change_id, "change_type": change_type})


@app.route("/api/visitor_change_requests", methods=["GET"])
def api_list_visitor_change_requests():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("security_manager", "admin", "host"):
        conn.close()
        return jsonify({"ok": False, "error": "Access denied."}), 403
    if acting_user["role"] == "host":
        rows = conn.execute("SELECT * FROM visitor_change_requests WHERE requested_by=? ORDER BY id DESC", (acting_user["username"],)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM visitor_change_requests ORDER BY id DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        vr = conn.execute("SELECT company, host_username FROM visit_requests WHERE id=?", (r["request_id"],)).fetchone()
        if vr:
            d.update(dict(vr))
        d["change_type"] = d.get("change_type") or "hsa_schedule"
        d["hsa_requested"] = bool(d.get("hsa_requested"))
        d["hsa_areas"] = d.get("hsa_areas", "").split("|") if d.get("hsa_areas") else []
        out.append(d)
    conn.close()
    return jsonify({"ok": True, "requests": out})


@app.route("/api/visitor_change_requests/<int:cid>/decide", methods=["POST"])
def api_decide_visitor_change_request(cid):
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only the Security Manager can decide Host change requests."}), 403
    cr = conn.execute("SELECT * FROM visitor_change_requests WHERE id=?", (cid,)).fetchone()
    if not cr:
        conn.close()
        return jsonify({"ok": False, "error": "Change request not found."}), 404
    if cr["status"] != "Pending Security Manager":
        conn.close()
        return jsonify({"ok": False, "error": "This change request has already been decided."}), 400
    vr = conn.execute("SELECT * FROM visit_requests WHERE id=?", (cr["request_id"],)).fetchone()
    if not vr or vr["status"] != "Approved":
        conn.close()
        return jsonify({"ok": False, "error": "The linked visit is no longer eligible for change."}), 400

    data = request.get_json(force=True) or {}
    decision = (data.get("decision") or "").strip()
    if decision not in ("Approved", "Rejected"):
        conn.close()
        return jsonify({"ok": False, "error": "Invalid decision."}), 400
    now = datetime.now()
    reason = (data.get("reason") or "").strip()
    change_type = cr["change_type"] or "hsa_schedule"
    include_schedule = change_type in ("schedule", "hsa_schedule")
    include_hsa = change_type in ("hsa", "hsa_schedule")

    if decision == "Approved":
        if include_schedule and include_hsa:
            conn.execute("""UPDATE visit_requests
                SET visit_date=?, start_visit=?, finish_visit=?, hsa_requested=?, hsa_areas=?, hsa_escort=?, hsa_decision=?
                WHERE id=?""",
                (cr["new_visit_date"], cr["new_start_visit"], cr["new_finish_visit"], cr["hsa_requested"], cr["hsa_areas"], cr["hsa_escort"], "Approved", vr["id"]))
        elif include_schedule:
            # Schedule-only: preserve all existing HSA fields.
            conn.execute("UPDATE visit_requests SET visit_date=?, start_visit=?, finish_visit=? WHERE id=?",
                         (cr["new_visit_date"], cr["new_start_visit"], cr["new_finish_visit"], vr["id"]))
        elif include_hsa:
            # HSA-only: preserve the existing appointment schedule.
            conn.execute("UPDATE visit_requests SET hsa_requested=?, hsa_areas=?, hsa_escort=?, hsa_decision=? WHERE id=?",
                         (1, cr["hsa_areas"], cr["hsa_escort"], "Approved", vr["id"]))

        if include_schedule:
            linked = conn.execute("SELECT linked_visitor_id FROM request_visitors WHERE request_id=? AND linked_visitor_id IS NOT NULL", (vr["id"],)).fetchall()
            for lr in linked:
                conn.execute("""UPDATE visitors
                    SET visit_date=?, expected_arrival=?, expected_departure=?
                    WHERE id=? AND (check_in_time IS NULL OR check_in_time='')""",
                    (cr["new_visit_date"], cr["new_start_visit"], cr["new_finish_visit"], lr["linked_visitor_id"]))

    conn.execute("UPDATE visitor_change_requests SET status=?, reviewed_by=?, review_date=?, review_reason=? WHERE id=?",
                 (decision, acting_user["display"], now.strftime("%Y-%m-%d %H:%M"), reason, cid))
    host_user = vr["host_username"] or vr["requested_by"]
    type_label = {"schedule": "Schedule Change", "hsa": "HSA Access", "hsa_schedule": "HSA + Schedule"}.get(change_type, "Change")
    create_notification(conn, host_user, "visitor_change_decision",
                        f"{type_label} #{cid}: {decision}",
                        f"Security Manager {acting_user['display']} has {decision.lower()} your {type_label.lower()} request for {vr['company']}." + (f" Reason: {reason}" if reason else ""),
                        "visitor_change_request", cid)
    log(conn, acting_user["display"], "Host Change Decision", "Success",
        f"{decision} {type_label} #{cid} for visit request #{vr['id']}")
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visitors/<int:vid>/reschedule", methods=["POST"])
def api_reschedule_visitor(vid):
    """Move an approved, not-yet-arrived visitor to a new scheduled date/time.
    The original appointment remains in the audit log and the linked request
    is updated so the request and visitor stay synchronized."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "security_manager", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only Security Officer or Administrator can perform a direct operational reschedule."}), 403
    row = conn.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visitor not found."}), 404
    if row["status"] != "Approved" or row["check_in_time"]:
        conn.close()
        return jsonify({"ok": False, "error": "Only an approved visitor who has not checked in can be rescheduled."}), 400
    data = request.get_json(force=True)
    new_date = (data.get("visit_date") or "").strip()
    new_arrival = (data.get("expected_arrival") or "").strip()
    new_departure = (data.get("expected_departure") or "").strip()
    try:
        datetime.strptime(new_date, "%Y-%m-%d")
        datetime.strptime(new_arrival, "%H:%M")
        datetime.strptime(new_departure, "%H:%M")
    except ValueError:
        conn.close()
        return jsonify({"ok": False, "error": "Use date YYYY-MM-DD and times HH:MM."}), 400
    if new_departure < new_arrival:
        conn.close()
        return jsonify({"ok": False, "error": "Expected departure cannot be earlier than expected arrival."}), 400
    old_date, old_arrival, old_departure = row["visit_date"], row["expected_arrival"], row["expected_departure"]
    conn.execute("UPDATE visitors SET visit_date=?, expected_arrival=?, expected_departure=? WHERE id=?",
                 (new_date, new_arrival, new_departure, vid))
    # Keep the group request synchronized when this visitor came from an approved request.
    linked = conn.execute("SELECT request_id FROM request_visitors WHERE linked_visitor_id=?", (vid,)).fetchone()
    if linked:
        conn.execute("UPDATE visit_requests SET visit_date=?, start_visit=?, finish_visit=? WHERE id=?",
                     (new_date, new_arrival, new_departure, linked["request_id"]))
    log(conn, acting_user["display"], "Visitor Rescheduled", "Success",
        f"Visitor #{vid}: {old_date} {old_arrival}-{old_departure} -> {new_date} {new_arrival}-{new_departure}")
    if row["host"]:
        create_notification(conn, row["host"], "visitor_rescheduled",
            "📅 Visitor Rescheduled",
            f"Your visitor from {row['company']} was rescheduled to {new_date} at {new_arrival}.",
            "visitor", vid)
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/visitors/<int:vid>/checkin", methods=["POST"])
def api_checkin_visitor(vid):
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only a Security Officer can check visitors in."}), 403

    data = request.get_json(force=True)
    enroll_face = bool(data.get("enroll_face", False))

    row = conn.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visitor not found."}), 404
    if row["status"] != "Approved":
        conn.close()
        return jsonify({"ok": False, "error": "This visitor must be approved by their host before check-in."}), 400

    badge_row = conn.execute(
        "SELECT badge_no FROM badges WHERE status='Available' ORDER BY badge_no LIMIT 1").fetchone()
    if not badge_row:
        conn.close()
        return jsonify({"ok": False, "error": "No badges are currently available."}), 400
    badge_no = badge_row["badge_no"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("UPDATE badges SET status='Assigned', visitor_id=? WHERE badge_no=?", (vid, badge_no))
    conn.execute(
        "UPDATE visitors SET status='Checked In', badge_no=?, check_in_time=?, face_enrolled=? WHERE id=?",
        (badge_no, now, int(enroll_face), vid))
    log(conn, acting_user["display"], "Check-In", "Success",
        f"Checked in visitor #{vid} - badge {badge_no}" + (" + face enrolled" if enroll_face else ""))
    log(conn, acting_user["display"], "ACS Synchronization", "Success",
        f"Access activated in Face Biometric ACS for visitor #{vid}")
    
    # Create notification for the host
    if row["host"]:
        create_notification(
            conn, row["host"], "checkin",
            f"✅ Visitor Checked In",
            f"Your visitor from {row['company']} has checked in (Badge: {badge_no})",
            "visitor", vid
        )
    
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "badge_no": badge_no})


@app.route("/api/visitors/<int:vid>/checkout", methods=["POST"])
def api_checkout_visitor(vid):
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("officer", "admin"):
        conn.close()
        return jsonify({"ok": False, "error": "Only a Security Officer can check visitors out."}), 403

    row = conn.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Visitor not found."}), 404

    badge_no = row["badge_no"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if badge_no:
        conn.execute("UPDATE badges SET status='Available', visitor_id=NULL WHERE badge_no=?", (badge_no,))
    conn.execute("UPDATE visitors SET status='Checked Out', check_out_time=? WHERE id=?", (now, vid))
    log(conn, acting_user["display"], "Check-Out", "Success",
        f"Checked out visitor #{vid}, badge {badge_no} released")
    log(conn, acting_user["display"], "ACS Synchronization", "Success",
        f"Access deactivated in ACS for visitor #{vid}")
    
    # Create notification for the host
    if row["host"]:
        create_notification(
            conn, row["host"], "checkout",
            f"👋 Visitor Checked Out",
            f"Your visitor from {row['company']} has checked out.",
            "visitor", vid
        )
    
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/log", methods=["POST"])
def api_log_action():
    """For client-only actions with no other server state to change (report
    generation/export, logout) - keeps ONE unified audit trail across every PC
    instead of each client keeping its own separate local log."""
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    data = request.get_json(force=True)
    log(conn, acting_user["display"], data.get("action", "-"),
        data.get("result", "Success"), data.get("detail", ""))
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/audit_log", methods=["GET"])
def api_audit_log():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] not in ("admin", "officer"):
        conn.close()
        return jsonify({"ok": False, "error": "You don't have access to the audit log."}), 403
    rows = conn.execute("SELECT timestamp, user, action, result, detail FROM audit_log ORDER BY id DESC").fetchall()
    entries = [list(r) for r in rows]
    conn.close()
    return jsonify({"ok": True, "entries": entries})


@app.route("/api/delete_history", methods=["POST"])
def api_delete_history():
    """Delete COMPLETED history from today back to X days (admin only).
    
    SAFE DELETION - Only deletes FINISHED records:
    - Visitors who have CHECKED OUT (check_out_time is set)
    - Visit requests that are COMPLETED (all visitors checked out or rejected)
    - Associated badges (only if visitor is deleted)
    - Audit logs from the deletion date range
    
    DOES NOT DELETE:
    - Active visitors (checked in without checkout)
    - Active badges
    - Active/pending requests
    - In-progress visits
    
    Date range: Includes today back to X days ago
    Example: Last 90 days = today back 90 days (inclusive)
    """
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    if acting_user["role"] != "admin":
        conn.close()
        return jsonify({"ok": False, "error": "Only System Administrators can delete history."}), 403
    
    data = request.get_json() or {}
    days = data.get("days")
    
    if days is None or not isinstance(days, int) or days < 1:
        conn.close()
        return jsonify({"ok": False, "error": "Invalid days value. Must be >= 1"}), 400
    
    # Calculate date range: from today back X days (inclusive)
    today = datetime.now().date()
    cutoff_date = today - timedelta(days=days-1)  # -1 to include today in count
    cutoff_iso = cutoff_date.isoformat()
    
    try:
        # STEP 1: Find COMPLETED visitors (who have checked out)
        completed_visitors = conn.execute(
            """SELECT id FROM visitors 
               WHERE check_out_time IS NOT NULL 
               AND date(check_out_time) <= ? """,
            (cutoff_iso,)
        ).fetchall()
        completed_visitor_ids = [v[0] for v in completed_visitors]
        
        # STEP 2: Find COMPLETED visit requests
        # A request is complete if:
        # - It was rejected, OR
        # - All its visitors have checked out
        completed_requests = conn.execute(
            """SELECT DISTINCT vr.id FROM visit_requests vr
               WHERE date(vr.created_at) <= ? AND (
                   -- Request was rejected/denied
                   vr.status IN ('Rejected', 'Rejected by Security Manager', 'Not Approved')
                   OR
                   -- Request is approved AND all associated visitors have checked out
                   (vr.status IN ('Approved', 'Approved for check-in') AND 
                    NOT EXISTS (
                        SELECT 1 FROM visitors v 
                        WHERE v.request_id = vr.id 
                        AND v.check_out_time IS NULL
                    ))
               )""",
            (cutoff_iso,)
        ).fetchall()
        completed_request_ids = [r[0] for r in completed_requests]
        
        # COUNT RECORDS BEFORE DELETION
        visitors_count = len(completed_visitor_ids)
        requests_count = len(completed_request_ids)
        
        # Get badge count (badges assigned to deleted visitors)
        badges_count = 0
        if completed_visitor_ids:
            badges_count = conn.execute(
                "SELECT COUNT(*) FROM badges WHERE visitor_id IN ({})".format(
                    ",".join("?" * len(completed_visitor_ids))
                ),
                completed_visitor_ids
            ).fetchone()[0]
        
        # Get audit log count
        audit_count = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE date(timestamp) <= ?",
            (cutoff_iso,)
        ).fetchone()[0]
        
        total_count = visitors_count + requests_count + badges_count + audit_count
        
        # SAFETY CHECK: Make sure we're not deleting too much
        if total_count == 0:
            conn.close()
            return jsonify({
                "ok": True, 
                "message": f"No completed records found from {cutoff_date.isoformat()} to today",
                "deleted": 0
            })
        
        # STEP 3: Delete badges for completed visitors
        if completed_visitor_ids:
            conn.execute(
                "DELETE FROM badges WHERE visitor_id IN ({})".format(
                    ",".join("?" * len(completed_visitor_ids))
                ),
                completed_visitor_ids
            )
        
        # STEP 4: Delete completed visitor records
        if completed_visitor_ids:
            conn.execute(
                "DELETE FROM visitors WHERE id IN ({})".format(
                    ",".join("?" * len(completed_visitor_ids))
                ),
                completed_visitor_ids
            )
        
        # STEP 5: Delete request_visitors entries for completed requests
        if completed_request_ids:
            conn.execute(
                "DELETE FROM request_visitors WHERE request_id IN ({})".format(
                    ",".join("?" * len(completed_request_ids))
                ),
                completed_request_ids
            )
            
            # Delete completed visit requests
            conn.execute(
                "DELETE FROM visit_requests WHERE id IN ({})".format(
                    ",".join("?" * len(completed_request_ids))
                ),
                completed_request_ids
            )
        
        # STEP 6: Delete audit logs from this date range
        conn.execute(
            "DELETE FROM audit_log WHERE date(timestamp) <= ?",
            (cutoff_iso,)
        )
        
        # STEP 7: Delete old notifications (more than 30 days old, regardless of other deletions)
        old_notif_cutoff = (today - timedelta(days=30)).isoformat()
        conn.execute(
            "DELETE FROM notifications WHERE date(created_at) <= ?",
            (old_notif_cutoff,)
        )
        
        conn.commit()
        
        # STEP 8: Log the deletion
        day_labels = {1: "today", 7: "last 7 days", 30: "last 30 days", 90: "last 90 days"}
        period_label = day_labels.get(days, f"last {days} days")
        
        log_detail = (
            f"Safely deleted {total_count} COMPLETED records from {period_label} "
            f"(ending {cutoff_date.isoformat()}): "
            f"{visitors_count} checked-out visitors, "
            f"{badges_count} badges, "
            f"{requests_count} completed requests, "
            f"{audit_count} audit logs. "
            f"NOTE: Active visitors and pending requests were NOT deleted."
        )
        
        conn.execute(
            "INSERT INTO audit_log (timestamp, user, action, result, detail) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), acting_user["username"], "System History Cleanup", "Success", log_detail)
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            "ok": True, 
            "message": f"Safely deleted {total_count} completed records",
            "detail": log_detail,
            "breakdown": {
                "checked_out_visitors": visitors_count,
                "badges_returned": badges_count,
                "completed_requests": requests_count,
                "audit_logs": audit_count
            }
        })
    
    except Exception as e:
        conn.close()
        return jsonify({"ok": False, "error": f"Deletion failed: {str(e)}"}), 500


# ---- NOTIFICATION ENDPOINTS ----
@app.route("/api/notifications", methods=["GET"])
def api_get_notifications():
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401

    unread_count = conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE recipient = ? AND status = 'unread'",
        (acting_user["username"],)
    ).fetchone()[0]

    rows = conn.execute(
        "SELECT * FROM notifications WHERE recipient = ? ORDER BY id DESC LIMIT 50",
        (acting_user["username"],)
    ).fetchall()

    notifications = [dict(row) for row in rows]
    conn.close()

    return jsonify({"ok": True, "unread_count": unread_count, "notifications": notifications})

@app.route("/api/notifications/<int:notif_id>/read", methods=["POST"])
def api_mark_notification_read(notif_id):
    
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    
    # Verify notification belongs to user
    notif = conn.execute(
        "SELECT recipient FROM notifications WHERE id = ?", (notif_id,)
    ).fetchone()
    
    if not notif or notif["recipient"] != acting_user["username"]:
        conn.close()
        return jsonify({"ok": False, "error": "Notification not found or access denied."}), 404
    
    conn.execute("UPDATE notifications SET status = 'read' WHERE id = ?", (notif_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"ok": True, "message": "Notification marked as read"})


@app.route("/api/notifications/<int:notif_id>/delete", methods=["POST"])
def api_delete_notification(notif_id):
    
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    
    # Verify notification belongs to user
    notif = conn.execute(
        "SELECT recipient FROM notifications WHERE id = ?", (notif_id,)
    ).fetchone()
    
    if not notif or notif["recipient"] != acting_user["username"]:
        conn.close()
        return jsonify({"ok": False, "error": "Notification not found or access denied."}), 404
    
    conn.execute("DELETE FROM notifications WHERE id = ?", (notif_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"ok": True, "message": "Notification deleted"})


@app.route("/api/notifications/mark_all_read", methods=["POST"])
def api_mark_all_read():
   
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    
    conn.execute(
        "UPDATE notifications SET status = 'read' WHERE recipient = ? AND status = 'unread'",
        (acting_user["username"],)
    )
    conn.commit()
    conn.close()
    
    return jsonify({"ok": True, "message": "All notifications marked as read"})


@app.route("/api/notifications/delete_all", methods=["POST"])
def api_delete_all_notifications():
    
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    
    conn.execute("DELETE FROM notifications WHERE recipient = ?", (acting_user["username"],))
    conn.commit()
    conn.close()
    
    return jsonify({"ok": True, "message": "All notifications deleted"})


@app.route("/api/notifications/unread_count", methods=["GET"])
def api_unread_count():
    
    conn = get_db()
    acting_user = get_authenticated_user(request, conn)
    if not acting_user:
        conn.close()
        return jsonify({"ok": False, "error": "Session expired or invalid. Please log in again."}), 401
    
    count = conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE recipient = ? AND status = 'unread'",
        (acting_user["username"],)
    ).fetchone()[0]
    
    conn.close()
    return jsonify({"ok": True, "unread_count": count})


if __name__ == "__main__":
    init_db()
    start_visitor_reminder_worker()
    print(f"VMS server starting on port {SERVER_PORT}...")
    print(f"Database: {DB_PATH}")

    try:
        from waitress import serve
        print("Using Waitress (production-grade server).")
        print("Leave this window open, or install it as a Windows service - see")
        print("install_service.bat for that. Press Ctrl+C to stop.")
        serve(app, host="0.0.0.0", port=SERVER_PORT)
    except ImportError:
        print("NOTE: 'waitress' isn't installed, so falling back to Flask's built-in "
              "server, which isn't meant for permanent use.")
        print("Run this once to fix that:   pip install waitress")
        print("Leave this window open. Press Ctrl+C to stop the server.")
        app.run(host="0.0.0.0", port=SERVER_PORT)

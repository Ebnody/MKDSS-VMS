"""
Visitor Management System (VMS) - Desktop Application (Demo/Prototype)
Smart Card Manufacturing Factory

Working, click-through DEMO built with Python's built-in Tkinter toolkit.

HOW TO RUN
----------
1. Python 3.9+ required.
2. Windows/Mac: Tkinter ships with Python by default.
3. Linux: sudo apt install python3-tk (if you get "No module named tkinter").

NOTE: This is a UI/workflow prototype. Data (visitors, badges, accounts) is
stored in memory only and resets every time you close the app. The
production build would use ASP.NET Core 9 + PostgreSQL + React with real
persistent storage and password hashing.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, date
import csv
import random
import os
import sys
import subprocess
import webbrowser
import sqlite3
import hashlib

APP_TITLE = "MKDSS Smart Card Factory VMS"

# Reports are saved in a "reports" folder next to this script - not a hardcoded
# path - so this works correctly on whatever machine the app runs on.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH = os.path.join(BASE_DIR, "mkdss_logo_transparent.png")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# All accounts, visitors, badges, and audit log entries persist here across
# restarts. SQLite is built into Python - no extra install needed - and is a
# real database rather than a flat file, which matters for something storing
# account credentials.
DB_PATH = os.path.join(BASE_DIR, "vms_data.db")


def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256 password hashing. Returns (salt_hex, hash_hex).
    Passwords are never stored in plain text once persisted to disk."""
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    _, computed = hash_password(password, salt_hex)
    return computed == hash_hex

# Scanned ID/passport images are saved here (from the printer/MFP's scanner).
SCANS_DIR = os.path.join(BASE_DIR, "scans")
os.makedirs(SCANS_DIR, exist_ok=True)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# WIA (Windows Image Acquisition) lets us trigger the printer/MFP's built-in
# scanner directly, the same way Windows' own "Scan" app does. Windows-only.
try:
    import win32com.client
    WIA_AVAILABLE = True
except ImportError:
    WIA_AVAILABLE = False

# Pillow: needed to load/preview the scanned image inside the app.
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# pytesseract: runs OCR (text recognition) on the scanned image. Requires the
# separate Tesseract OCR *engine* to be installed on the machine, not just
# the Python package - see https://github.com/UB-Mannheim/tesseract/wiki
try:
    import pytesseract

    # The pip package alone can't find the Tesseract .exe if the installer
    # didn't add it to PATH (very common on Windows). Check the standard
    # install locations before giving up.
    def _locate_tesseract_binary():
        candidates = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            "/usr/bin/tesseract",
            "/usr/local/bin/tesseract",
            "/opt/homebrew/bin/tesseract",
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        return None

    try:
        pytesseract.get_tesseract_version()
        OCR_AVAILABLE = True
    except Exception:
        found = _locate_tesseract_binary()
        if found:
            pytesseract.pytesseract.tesseract_cmd = found
            try:
                pytesseract.get_tesseract_version()
                OCR_AVAILABLE = True
            except Exception:
                OCR_AVAILABLE = False
        else:
            OCR_AVAILABLE = False
except ImportError:
    OCR_AVAILABLE = False

# OpenCV: used for webcam capture (an alternative to the printer/WIA scanner -
# works on Windows, Mac, and Linux with any USB or built-in webcam).
try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

# pyzbar: decodes QR codes / barcodes from the scanned image. This is a bonus,
# best-effort feature - we don't know the internal data format used by every
# country's ID (e.g. Ethiopia's Fayda ID), so we surface the raw decoded
# content for the officer to review rather than guessing at field meanings.
try:
    from pyzbar.pyzbar import decode as zbar_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


# ----------------------------------------------------------------------
# MRZ (Machine Readable Zone) PARSING
# ----------------------------------------------------------------------
# Passports and ID cards print a standardized block of text (ICAO Doc 9303)
# that OCR can read reliably even when the rest of the document's layout
# varies. There are two common formats:
#   TD3 - passports: 2 lines of 44 characters
#   TD1 - ID cards:  3 lines of 30 characters (this is what most national
#                     ID cards, including Ethiopia's, use)
# Documents with neither fall back to showing the raw OCR text for manual entry.
MRZ_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")


def find_mrz_lines(raw_text):
    """
    Return candidate MRZ lines from OCR text. Real-world OCR on a webcam photo
    (vs. a clean document scan) often inserts stray noise characters - spaces
    mid-word, a stray '(' or '?' from a smudge, etc. Rejecting the whole line
    over one bad character throws away otherwise-good reads, so instead we
    strip anything that isn't a valid MRZ character and judge the result by
    length. A genuine MRZ line should reduce to a long, near-complete string of
    valid characters even after OCR does mangle a character or two.
    """
    candidates = []
    for line in raw_text.splitlines():
        stripped = "".join(c for c in line.strip().upper().replace(" ", "") if c in MRZ_CHARS)
        if len(stripped) >= 25:
            candidates.append(stripped)
    return candidates


def _parse_yymmdd(s):
    try:
        yy, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return f"{year:04d}-{mm:02d}-{dd:02d}"
    except (ValueError, IndexError):
        return ""


def parse_td3_mrz(line1, line2):
    """Parse a 2x44 passport MRZ (ICAO 9303 TD3 format) into visitor fields."""
    def clean(s):
        return s.replace("<", " ").strip()

    names_field = line1[5:44]
    surname, _, given = names_field.partition("<<")
    surname = clean(surname)
    given = clean(given)

    doc_number = line2[0:9].replace("<", "")
    nationality = line2[10:13]
    dob_raw = line2[13:19]      # YYMMDD
    sex = line2[20] if len(line2) > 20 else ""
    result_first = given.split(" ")[0] if given else ""

    return {
        "first_name": result_first,
        "last_name": surname,
        "national_id": doc_number,
        "nationality": nationality,
        "gender": {"M": "Male", "F": "Female"}.get(sex, "Other"),
        "dob": _parse_yymmdd(dob_raw),
    }


def parse_td1_mrz(line1, line2, line3):
    """Parse a 3x30 ID-card MRZ (ICAO 9303 TD1 format) into visitor fields.
    This is the format most national ID cards use, including Ethiopia's."""
    def clean(s):
        return s.replace("<", " ").strip()

    doc_number = line1[5:14].replace("<", "")

    dob_raw = line2[0:6]                       # YYMMDD
    sex = line2[7] if len(line2) > 7 else ""
    nationality = line2[15:18] if len(line2) > 18 else ""

    surname, _, given = line3.partition("<<")
    surname = clean(surname)
    given = clean(given)
    result_first = given.split(" ")[0] if given else ""

    return {
        "first_name": result_first,
        "last_name": surname,
        "national_id": doc_number,
        "nationality": nationality,
        "gender": {"M": "Male", "F": "Female"}.get(sex, "Other"),
        "dob": _parse_yymmdd(dob_raw),
    }


def preprocess_for_ocr(image_path):
    """
    Clean up a document photo before handing it to OCR. Phone/webcam photos of
    text are much harder for Tesseract than clean document scans, so this:
      - converts to grayscale (color adds no information, only noise, for text)
      - upscales small images (OCR does much better with more pixels per character)
      - boosts contrast and sharpness (helps separate text from background)
    """
    from PIL import ImageEnhance
    img = Image.open(image_path).convert("L")  # grayscale

    if img.width < 1600:
        scale = 1600 / img.width
        img = img.resize((int(img.width * scale), int(img.height * scale)), Image.LANCZOS)

    img = ImageEnhance.Contrast(img).enhance(1.8)
    img = ImageEnhance.Sharpness(img).enhance(2.0)
    return img


def _pad_to_length(s, length):
    """MRZ lines end in filler '<' characters, so padding a slightly-short
    OCR read is a safe way to tolerate a dropped trailing character."""
    return (s + "<" * length)[:length]


def extract_id_data_from_image(image_path):
    """
    Run OCR on a scanned document image and try to parse an MRZ out of it -
    tries the passport format (TD3) first, then the ID-card format (TD1).
    Returns (parsed_fields_dict_or_None, raw_ocr_text).
    """
    processed = preprocess_for_ocr(image_path)
    raw_text = pytesseract.image_to_string(processed)
    mrz_lines = find_mrz_lines(raw_text)

    TOLERANCE = 4  # real OCR is rarely pixel-perfect; allow a few dropped/misread chars

    # TD3 - passport: 2 lines x 44 chars
    if len(mrz_lines) >= 2:
        line1, line2 = mrz_lines[-2], mrz_lines[-1]
        if len(line1) >= 44 - TOLERANCE and len(line2) >= 44 - TOLERANCE:
            return parse_td3_mrz(_pad_to_length(line1, 44), _pad_to_length(line2, 44)), raw_text

    # TD1 - ID card: 3 lines x 30 chars
    if len(mrz_lines) >= 3:
        line1, line2, line3 = mrz_lines[-3], mrz_lines[-2], mrz_lines[-1]
        if (len(line1) >= 30 - TOLERANCE and len(line2) >= 30 - TOLERANCE
                and len(line3) >= 30 - TOLERANCE):
            return parse_td1_mrz(_pad_to_length(line1, 30), _pad_to_length(line2, 30),
                                  _pad_to_length(line3, 30)), raw_text

    return None, raw_text


def open_in_file_explorer(path):
    """Open the folder containing `path` in the OS file browser, cross-platform."""
    folder = path if os.path.isdir(path) else os.path.dirname(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(folder)  # noqa: Windows-only, fine on Windows
        elif sys.platform == "darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder])
    except Exception:
        pass  # non-fatal - the message box already shows the path


# ----------------------------------------------------------------------
# THEME
# ----------------------------------------------------------------------
COLOR_SIDEBAR = "#1a2332"
COLOR_SIDEBAR_ACTIVE = "#2d3e57"
COLOR_ACCENT = "#2f80ed"
COLOR_BG = "#f4f6f9"
COLOR_CARD = "#ffffff"
COLOR_TEXT = "#1a2332"
COLOR_MUTED = "#6b7688"
COLOR_SUCCESS = "#27ae60"
COLOR_WARNING = "#e2a03f"
COLOR_DANGER = "#eb5757"

FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_H2 = ("Segoe UI", 13, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_STAT = ("Segoe UI", 22, "bold")

DEPARTMENTS = ["Production Floor", "R&D Lab", "Quality Assurance",
               "Warehouse", "Admin Office", "IT / Server Room"]

# NOTE: There is no hardcoded account list. Accounts are created in-app via
# the "User Management" page (System Administrator role only) and stored in
# STORE.users. Exactly one bootstrap Administrator account is seeded below
# so there's a way to log in for the first time and create real accounts.
BOOTSTRAP_USERNAME = "admin"
BOOTSTRAP_PASSWORD = "ChangeMe123!"

# Every new account created via User Management starts with this password
# and is FORCED to set a real one on first login (must_change_password flag).
DEFAULT_NEW_ACCOUNT_PASSWORD = "Mkdss@123"

STATUS_COLORS = {
    "Pending Approval": COLOR_WARNING,
    "Approved": COLOR_ACCENT,
    "Checked In": COLOR_SUCCESS,
    "Checked Out": COLOR_MUTED,
    "Rejected": COLOR_DANGER,
}


# ----------------------------------------------------------------------
# IN-MEMORY DATA STORE
# ----------------------------------------------------------------------
class Store:
    VISITOR_COLUMNS = [
        "id", "first_name", "middle_name", "last_name", "gender", "dob", "nationality",
        "mobile", "email", "company", "job_title", "national_id", "vehicle_plate", "notes",
        "purpose", "host", "department", "expected_arrival", "expected_departure",
        "visit_date", "badge_no", "check_in_time", "check_out_time", "face_enrolled", "status",
    ]

    def __init__(self):
        self.next_visitor_id = 1
        self.visitors = []       # list of dict
        self.badges = []         # list of dict
        self.audit_log = []      # list of 5-tuples: (timestamp, user, action, result, detail)
        self.users = []          # list of dict: username, password_hash, salt, display, role, department
        self.db = sqlite3.connect(DB_PATH)
        self.db.execute("PRAGMA foreign_keys = ON")
        self._init_schema()
        self._load_from_db()

    # ---------------- schema / loading ----------------
    def _init_schema(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                display TEXT NOT NULL,
                role TEXT NOT NULL,
                department TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS badges (
                badge_no TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                visitor_id INTEGER
            );
            CREATE TABLE IF NOT EXISTS visitors (
                id INTEGER PRIMARY KEY,
                first_name TEXT, middle_name TEXT, last_name TEXT,
                gender TEXT, dob TEXT, nationality TEXT,
                mobile TEXT, email TEXT, company TEXT, job_title TEXT,
                national_id TEXT, vehicle_plate TEXT, notes TEXT,
                purpose TEXT, host TEXT, department TEXT,
                expected_arrival TEXT, expected_departure TEXT, visit_date TEXT,
                badge_no TEXT, check_in_time TEXT, check_out_time TEXT,
                face_enrolled INTEGER DEFAULT 0, status TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, user TEXT, action TEXT, result TEXT, detail TEXT
            );
        """)
        self.db.commit()

    def _seed_fresh(self):
        """Only runs the very first time the app is started - the database file
        doesn't exist yet, so there's a physical badge inventory to record and a
        bootstrap admin account to create so someone can log in at all."""
        for i in range(1, 21):
            self.db.execute("INSERT INTO badges (badge_no, status, visitor_id) VALUES (?, ?, ?)",
                             (f"V-{i:03d}", "Available", None))
        salt, pwd_hash = hash_password(BOOTSTRAP_PASSWORD)
        self.db.execute(
            """INSERT INTO users (username, password_hash, salt, display, role, department,
                                    active, must_change_password)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (BOOTSTRAP_USERNAME, pwd_hash, salt, "System Administrator", "admin", None, 1, 0))
        self.db.execute(
            "INSERT INTO audit_log (timestamp, user, action, result, detail) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "System", "System Start", "Success",
             "Database created - 1 bootstrap account and 20 badges seeded"))
        self.db.commit()

    def _load_from_db(self):
        cur = self.db.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            self._seed_fresh()

        self.users = []
        for row in self.db.execute(
                "SELECT username, password_hash, salt, display, role, department, active, "
                "must_change_password FROM users"):
            self.users.append({
                "username": row[0], "password_hash": row[1], "salt": row[2],
                "display": row[3], "role": row[4], "department": row[5],
                "active": bool(row[6]), "must_change_password": bool(row[7]),
            })

        self.badges = []
        for row in self.db.execute("SELECT badge_no, status, visitor_id FROM badges ORDER BY badge_no"):
            self.badges.append({"badge_no": row[0], "status": row[1], "visitor_id": row[2]})

        self.visitors = []
        max_id = 0
        cols = self.VISITOR_COLUMNS
        for row in self.db.execute(f"SELECT {','.join(cols)} FROM visitors ORDER BY id"):
            record = dict(zip(cols, row))
            record["face_enrolled"] = bool(record["face_enrolled"])
            if record["visit_date"]:
                record["visit_date"] = date.fromisoformat(record["visit_date"])
            self.visitors.append(record)
            max_id = max(max_id, record["id"])
        self.next_visitor_id = max_id + 1

        self.audit_log = []
        for row in self.db.execute(
                "SELECT timestamp, user, action, result, detail FROM audit_log ORDER BY id"):
            self.audit_log.append(tuple(row))

    # ---------------- persistence writes ----------------
    def save_visitor(self, v):
        cols = self.VISITOR_COLUMNS
        row = []
        for c in cols:
            val = v.get(c)
            if c == "visit_date" and isinstance(val, date):
                val = val.isoformat()
            elif c == "face_enrolled":
                val = 1 if val else 0
            row.append(val)
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        self.db.execute(
            f"INSERT INTO visitors ({','.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {updates}", row)
        self.db.commit()

    def save_badge(self, b):
        self.db.execute(
            "INSERT INTO badges (badge_no, status, visitor_id) VALUES (?, ?, ?) "
            "ON CONFLICT(badge_no) DO UPDATE SET status=excluded.status, visitor_id=excluded.visitor_id",
            (b["badge_no"], b["status"], b["visitor_id"]))
        self.db.commit()

    def save_user(self, u):
        self.db.execute(
            """INSERT INTO users (username, password_hash, salt, display, role, department,
                                    active, must_change_password)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET
                   password_hash=excluded.password_hash, salt=excluded.salt,
                   display=excluded.display, role=excluded.role, department=excluded.department,
                   active=excluded.active, must_change_password=excluded.must_change_password""",
            (u["username"], u["password_hash"], u["salt"], u["display"], u["role"],
             u["department"], int(u["active"]), int(u["must_change_password"])))
        self.db.commit()

    def _add_visitor(self, **kwargs):
        vid = self.next_visitor_id
        self.next_visitor_id += 1
        record = {
            "id": vid, "middle_name": "", "gender": "N/A", "dob": "",
            "nationality": "", "vehicle_plate": "", "notes": "",
            "badge_no": None, "check_in_time": None, "check_out_time": None,
            "face_enrolled": False, "expected_arrival": "09:00",
            "expected_departure": "17:00",
        }
        record.update(kwargs)
        self.visitors.append(record)
        return vid

    def add_visitor(self, **kwargs):
        kwargs.setdefault("status", "Pending Approval")
        kwargs.setdefault("visit_date", date.today())
        vid = self._add_visitor(**kwargs)
        self.save_visitor(self.get_visitor(vid))
        self.log(kwargs.get("host", "-"), "Visitor Registration", "Success",
                  f"Registered visitor #{vid}: {kwargs.get('first_name','')} {kwargs.get('last_name','')}")
        return vid

    def get_visitor(self, vid):
        for v in self.visitors:
            if v["id"] == vid:
                return v
        return None

    def available_badges(self):
        return [b for b in self.badges if b["status"] == "Available"]

    def log(self, user, action, result, detail=""):
        entry = (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user, action, result, detail)
        self.audit_log.append(entry)
        self.db.execute(
            "INSERT INTO audit_log (timestamp, user, action, result, detail) VALUES (?, ?, ?, ?, ?)", entry)
        self.db.commit()

    # ---------------- account management ----------------
    def get_user(self, username):
        username = (username or "").strip().lower()
        for u in self.users:
            if u["username"] == username:
                return u
        return None

    def username_taken(self, username):
        return self.get_user(username) is not None

    def add_user(self, username, password, display, role, department=None):
        username = username.strip().lower()
        salt, pwd_hash = hash_password(password)
        record = {
            "username": username, "password_hash": pwd_hash, "salt": salt,
            "display": display.strip(), "role": role, "department": department,
            "active": True, "must_change_password": True,
        }
        self.users.append(record)
        self.save_user(record)
        self.log("System Administrator", "User Management", "Success",
                  f"Created {role} account '{username}' ({display})"
                  + (f" - Dept: {department}" if department else ""))

    def hosts(self):
        """Active host accounts, each tied to a department."""
        return [u for u in self.users if u["role"] == "host" and u["active"]]

    def toggle_user_active(self, username):
        u = self.get_user(username)
        if u:
            u["active"] = not u["active"]
            self.save_user(u)
            self.log("System Administrator", "User Management", "Success",
                      f"{'Activated' if u['active'] else 'Deactivated'} account '{username}'")

    def delete_user(self, username, deleted_by="System Administrator"):
        u = self.get_user(username)
        if u:
            self.users = [x for x in self.users if x["username"] != username]
            self.db.execute("DELETE FROM users WHERE username=?", (username,))
            self.db.commit()
            self.log(deleted_by, "User Management", "Success",
                      f"Deleted account '{username}' ({u['display']})")


STORE = Store()


# ----------------------------------------------------------------------
# REUSABLE UI HELPERS
# ----------------------------------------------------------------------
def load_logo_photo(max_height):
    """Load the bundled MKDSS logo scaled to max_height px, preserving aspect
    ratio. Returns None (never raises) if Pillow or the logo file is missing -
    callers should fall back to text-only in that case."""
    if not PIL_AVAILABLE or not os.path.isfile(LOGO_PATH):
        return None
    try:
        img = Image.open(LOGO_PATH).convert("RGBA")
        ratio = max_height / img.height
        img = img.resize((max(1, int(img.width * ratio)), max_height), Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None


def stat_card(parent, label, value, color=COLOR_ACCENT):
    card = tk.Frame(parent, bg=COLOR_CARD, highlightbackground="#e2e6ec",
                     highlightthickness=1, bd=0)
    bar = tk.Frame(card, bg=color, width=4)
    bar.pack(side="left", fill="y")
    inner = tk.Frame(card, bg=COLOR_CARD)
    inner.pack(side="left", fill="both", expand=True, padx=14, pady=12)
    tk.Label(inner, text=str(value), font=FONT_STAT, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w")
    tk.Label(inner, text=label, font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w")
    return card


def status_pill(parent, status):
    color = STATUS_COLORS.get(status, COLOR_MUTED)
    lbl = tk.Label(parent, text=status, font=("Segoe UI", 8, "bold"),
                    bg=color, fg="white", padx=8, pady=2)
    return lbl


def section_title(parent, text, subtitle=None):
    frame = tk.Frame(parent, bg=COLOR_BG)
    tk.Label(frame, text=text, font=FONT_TITLE, bg=COLOR_BG, fg=COLOR_TEXT).pack(anchor="w")
    if subtitle:
        tk.Label(frame, text=subtitle, font=FONT_BODY, bg=COLOR_BG, fg=COLOR_MUTED).pack(anchor="w")
    return frame


def make_table(parent, columns, widths):
    tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)
    for c, w in zip(columns, widths):
        tree.heading(c, text=c)
        tree.column(c, width=w, anchor="w")
    return tree


def labeled_entry(parent, label, row, col, width=24, kind="entry", values=None):
    tk.Label(parent, text=label, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(
        row=row * 2, column=col, sticky="w", padx=6, pady=(8, 0))
    if kind == "entry":
        var = tk.StringVar()
        w = ttk.Entry(parent, textvariable=var, width=width)
    elif kind == "combo":
        var = tk.StringVar()
        w = ttk.Combobox(parent, textvariable=var, values=values, width=width - 2, state="readonly")
    w.grid(row=row * 2 + 1, column=col, sticky="w", padx=6, pady=(0, 4))
    return var


# ----------------------------------------------------------------------
# MAIN APPLICATION
# ----------------------------------------------------------------------
class VMSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x900")
        self.minsize(1280, 900)
        self.configure(bg=COLOR_BG)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", font=FONT_BODY, rowheight=26, background="white",
                         fieldbackground="white")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("TNotebook", background=COLOR_BG)
        style.configure("Accent.TButton", background=COLOR_ACCENT, foreground="white",
                         font=("Segoe UI", 10, "bold"), padding=8)
        style.map("Accent.TButton", background=[("active", "#2566c4")])
        style.configure("TButton", font=FONT_BODY, padding=6)

        self.current_user = None
        self.current_role = None
        self.host_name = None
        self.current_username = None
        self.show_login()

    # ---------------- LOGIN ----------------
    def show_login(self):
        for w in self.winfo_children():
            w.destroy()

        outer = tk.Frame(self, bg=COLOR_SIDEBAR)
        outer.pack(fill="both", expand=True)
        box = tk.Frame(outer, bg=COLOR_CARD, padx=36, pady=32)
        box.place(relx=0.5, rely=0.5, anchor="center")

        header_row = tk.Frame(box, bg=COLOR_CARD)
        header_row.pack(anchor="w", fill="x")
        self._login_logo_photo = load_logo_photo(40)
        if self._login_logo_photo:
            tk.Label(header_row, image=self._login_logo_photo, bg=COLOR_CARD).pack(side="left", padx=(0, 10))
        tk.Label(header_row, text="VMS Login", font=("Segoe UI", 18, "bold"),
                 bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
        tk.Label(box, text=APP_TITLE, font=FONT_SMALL,
                 bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", pady=(2, 20))

        tk.Label(box, text="Username", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w")
        user_var = tk.StringVar()
        user_entry = ttk.Entry(box, textvariable=user_var, width=30)
        user_entry.pack(anchor="w", pady=(2, 0))

        tk.Label(box, text="Password", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", pady=(10, 0))
        pass_var = tk.StringVar()
        pass_entry = ttk.Entry(box, textvariable=pass_var, show="•", width=30)
        pass_entry.pack(anchor="w", pady=(2, 0))

        error_lbl = tk.Label(box, text="", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_DANGER,
                              wraplength=280, justify="left")
        error_lbl.pack(anchor="w", pady=(8, 0))

        def do_login():
            uname = user_var.get().strip().lower()
            pwd = pass_var.get()
            acct = STORE.get_user(uname)
            if not acct or not verify_password(pwd, acct["salt"], acct["password_hash"]):
                error_lbl.configure(text="Invalid username or password.")
                return
            if not acct["active"]:
                error_lbl.configure(text="This account has been deactivated. Contact an administrator.")
                return
            if acct.get("must_change_password", False):
                self.change_password(acct)
                return
            self._finish_login(acct)

        btn_row = tk.Frame(box, bg=COLOR_CARD)
        btn_row.pack(anchor="w", pady=(18, 0))
        ttk.Button(btn_row, text="Log In", style="Accent.TButton", command=do_login).pack(side="left")

        # Only show bootstrap hint if that account still exists and is the only one -
        # i.e. nobody has created real accounts yet.
        if len(STORE.users) == 1 and STORE.users[0]["username"] == BOOTSTRAP_USERNAME:
            tk.Label(box, text=f"First time setup: log in with the bootstrap admin account\n"
                                f"({BOOTSTRAP_USERNAME} / {BOOTSTRAP_PASSWORD}) and create real\n"
                                f"Officer, Host, and Administrator accounts under 'User Management'.",
                      font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, justify="left").pack(anchor="w", pady=(16, 0))

        pass_entry.bind("<Return>", lambda e: do_login())
        user_entry.focus_set()

    def _finish_login(self, acct):
        """Common landing logic shared by normal login and post-password-change login."""
        self.current_user = acct["display"]
        self.current_role = acct["role"]
        self.host_name = acct["display"] if acct["role"] == "host" else None
        self.current_username = acct["username"]
        STORE.log(self.current_user, "Login", "Success", f"Role: {self.current_role}")
        self._build_shell()
        default_page = {"officer": "Dashboard", "host": "My Overview", "admin": "User Management"}
        self.show_page(default_page[self.current_role])

    def change_password(self, acct):
        """Forced password-change dialog shown on first login for new accounts."""
        win = tk.Toplevel(self)
        win.title("Change Password")
        win.geometry("420x340")
        win.configure(bg=COLOR_CARD)
        win.grab_set()
        win.resizable(False, False)

        tk.Label(win, text="You must set a new password", font=FONT_H2,
                 bg=COLOR_CARD, fg=COLOR_TEXT).pack(pady=(20, 4))
        tk.Label(win, text=f"Account: {acct['display']} ({acct['username']})", font=FONT_SMALL,
                 bg=COLOR_CARD, fg=COLOR_MUTED).pack(pady=(0, 16))

        tk.Label(win, text="New Password", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=30)
        newpass = tk.StringVar()
        ttk.Entry(win, textvariable=newpass, show="•", width=30).pack(padx=30, pady=(2, 10))

        tk.Label(win, text="Confirm Password", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=30)
        confirm = tk.StringVar()
        confirm_entry = ttk.Entry(win, textvariable=confirm, show="•", width=30)
        confirm_entry.pack(padx=30, pady=(2, 10))

        error_lbl = tk.Label(win, text="", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_DANGER,
                              wraplength=340, justify="left")
        error_lbl.pack(padx=30, pady=(0, 6))

        def save():
            if newpass.get() != confirm.get():
                error_lbl.configure(text="Passwords do not match.")
                return
            if len(newpass.get()) < 8:
                error_lbl.configure(text="Password must be at least 8 characters.")
                return
            salt, pwd_hash = hash_password(newpass.get())
            acct["salt"] = salt
            acct["password_hash"] = pwd_hash
            acct["must_change_password"] = False
            STORE.save_user(acct)
            STORE.log(acct["display"], "Change Password", "Success", "Password updated on first login")
            messagebox.showinfo("Success", "Password updated.")
            win.destroy()
            self._finish_login(acct)

        ttk.Button(win, text="Save Password", style="Accent.TButton", command=save).pack(pady=16)
        confirm_entry.bind("<Return>", lambda e: save())

    def logout(self):
        if self.current_user:
            STORE.log(self.current_user, "Logout", "Success", "")
        self.current_user = None
        self.current_role = None
        self.host_name = None
        self.current_username = None
        self.show_login()

    # ---------------- shell / navigation ----------------
    def _build_shell(self):
        for w in self.winfo_children():
            w.destroy()

        sidebar = tk.Frame(self, bg=COLOR_SIDEBAR, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        header_row = tk.Frame(sidebar, bg=COLOR_SIDEBAR)
        header_row.pack(anchor="w", fill="x", padx=20, pady=(24, 2))
        self._sidebar_logo_photo = load_logo_photo(28)
        if self._sidebar_logo_photo:
            tk.Label(header_row, image=self._sidebar_logo_photo, bg=COLOR_SIDEBAR).pack(side="left", padx=(0, 8))
        tk.Label(header_row, text="VMS", font=("Segoe UI", 16, "bold"),
                 bg=COLOR_SIDEBAR, fg="white").pack(side="left")

        if self.current_role == "admin":
            role_label = "System Administrator"
        elif self.current_role == "officer":
            role_label = "Security Officer"
        else:
            role_label = "Host / Employee"
        tk.Label(sidebar, text=role_label, font=FONT_SMALL,
                 bg=COLOR_SIDEBAR, fg="#8a93a6").pack(anchor="w", padx=20, pady=(0, 24))

        self.nav_buttons = {}
        if self.current_role == "admin":
            # Admin is focused on account control + oversight, not day-to-day
            # visitor operations - that separation of duties is the whole
            # point of splitting this out. (Flagged for you - see chat.)
            pages = [
                ("User Management", "👥"), ("System Monitor", "🖥️"),
                ("Dashboard", "📊"), ("Audit Log", "🧾"),
            ]
        elif self.current_role == "officer":
            pages = [
                ("Dashboard", "📊"), ("Visitor Registration", "📝"),
                ("Check-In", "✅"), ("Check-Out", "🚪"),
                ("Badge Management", "🪪"), ("Search", "🔍"),
                ("Reports", "📈"),
            ]
        else:
            pages = [
                ("My Overview", "📊"), ("My Approvals", "🗳️"), ("My Visit History", "🕘"),
            ]

        for name, icon in pages:
            btn = tk.Label(sidebar, text=f"  {icon}   {name}", font=FONT_BODY,
                            bg=COLOR_SIDEBAR, fg="#c7cedb", anchor="w", padx=8, pady=10)
            btn.pack(fill="x", padx=10)
            btn.bind("<Button-1>", lambda e, n=name: self.show_page(n))
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg=COLOR_SIDEBAR_ACTIVE))
            btn.bind("<Leave>", lambda e, b=btn, n=name: b.configure(
                bg=COLOR_SIDEBAR_ACTIVE if self.active_page == n else COLOR_SIDEBAR))
            self.nav_buttons[name] = btn

        tk.Frame(sidebar, bg=COLOR_SIDEBAR).pack(fill="both", expand=True)
        tk.Label(sidebar, text=f"👤 {self.current_user}", font=FONT_SMALL,
                 bg=COLOR_SIDEBAR, fg="#8a93a6", wraplength=190, justify="left").pack(
            anchor="w", padx=20, pady=(16, 4))
        logout_btn = tk.Label(sidebar, text="⏻  Log Out", font=FONT_SMALL,
                               bg=COLOR_SIDEBAR, fg="#e2a03f", anchor="w", cursor="hand2")
        logout_btn.pack(anchor="w", padx=20, pady=(0, 20))
        logout_btn.bind("<Button-1>", lambda e: self.logout())

        self.active_page = None
        self.content = tk.Frame(self, bg=COLOR_BG)
        self.content.pack(side="left", fill="both", expand=True)

    def show_page(self, name):
        if self.active_page and self.active_page in self.nav_buttons:
            self.nav_buttons[self.active_page].configure(bg=COLOR_SIDEBAR)
        self.active_page = name
        self.nav_buttons[name].configure(bg=COLOR_SIDEBAR_ACTIVE)

        for w in self.content.winfo_children():
            w.destroy()

        builders = {
            "Dashboard": self.page_dashboard,
            "Visitor Registration": self.page_registration,
            "Check-In": self.page_checkin,
            "Check-Out": self.page_checkout,
            "Badge Management": self.page_badges,
            "Search": self.page_search,
            "Reports": self.page_reports,
            "Audit Log": self.page_audit,
            "User Management": self.page_user_management,
            "System Monitor": self.page_system_monitor,
            "My Overview": self.page_host_overview,
            "My Approvals": self.page_host_approvals,
            "My Visit History": self.page_host_history,
        }
        builders[name]()

    # ---------------- DASHBOARD ----------------
    def page_dashboard(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)

        section_title(wrap, "Dashboard", "Live overview of today's visitor activity").pack(
            anchor="w", pady=(0, 16))

        today = date.today()
        expected_today = [v for v in STORE.visitors if v["visit_date"] == today]
        inside = [v for v in STORE.visitors if v["status"] == "Checked In"]
        checked_out = [v for v in STORE.visitors if v["status"] == "Checked Out"]
        pending = [v for v in STORE.visitors if v["status"] == "Pending Approval"]
        available_badges = STORE.available_badges()

        stats = tk.Frame(wrap, bg=COLOR_BG)
        stats.pack(fill="x", pady=(0, 20))
        cards = [
            ("Expected Today", len(expected_today), COLOR_ACCENT),
            ("Currently Inside", len(inside), COLOR_SUCCESS),
            ("Checked Out Today", len(checked_out), COLOR_MUTED),
            ("Pending Approvals", len(pending), COLOR_WARNING),
            ("Available Badges", len(available_badges), COLOR_ACCENT),
        ]
        for i, (label, value, color) in enumerate(cards):
            c = stat_card(stats, label, value, color)
            c.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="ew")
            stats.grid_columnconfigure(i, weight=1)

        lower = tk.Frame(wrap, bg=COLOR_BG)
        lower.pack(fill="both", expand=True)
        lower.grid_columnconfigure(0, weight=3)
        lower.grid_columnconfigure(1, weight=2)

        left = tk.Frame(lower, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        tk.Label(left, text="Recent Visitor Activity", font=FONT_H2, bg=COLOR_CARD,
                  fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
        cols = ("Visitor", "Host", "Department", "Status")
        tree = make_table(left, cols, (150, 130, 140, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        for v in sorted(STORE.visitors, key=lambda x: -x["id"]):
            tree.insert("", "end", values=(f'{v["first_name"]} {v["last_name"]}',
                                            v["host"], v["department"], v["status"]))

        right = tk.Frame(lower, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        right.grid(row=0, column=1, sticky="nsew")
        tk.Label(right, text="Live Occupancy by Department", font=FONT_H2, bg=COLOR_CARD,
                  fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 10))
        for dept in DEPARTMENTS:
            count = len([v for v in inside if v["department"] == dept])
            row = tk.Frame(right, bg=COLOR_CARD)
            row.pack(fill="x", padx=14, pady=4)
            tk.Label(row, text=dept, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT,
                      width=18, anchor="w").pack(side="left")
            bar_bg = tk.Frame(row, bg="#eef1f6", width=120, height=10)
            bar_bg.pack(side="left", padx=6)
            bar_bg.pack_propagate(False)
            fill_w = min(120, count * 30 + (6 if count else 0))
            tk.Frame(bar_bg, bg=COLOR_ACCENT, width=fill_w, height=10).place(x=0, y=0)
            tk.Label(row, text=str(count), font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED).pack(side="left")

    # ---------------- VISITOR REGISTRATION ----------------
    def page_registration(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Visitor Registration",
                      "Register a new visitor manually, or scan an ID/passport to auto-fill the form").pack(
            anchor="w", pady=(0, 16))

        scan_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        scan_card.pack(fill="x", pady=(0, 14))
        scan_inner = tk.Frame(scan_card, bg=COLOR_CARD)
        scan_inner.pack(fill="x", padx=16, pady=12)

        btn_col = tk.Frame(scan_inner, bg=COLOR_CARD)
        btn_col.pack(side="left", anchor="n")
        ttk.Button(btn_col, text="📷  Scan via Webcam",
                   command=self._scan_via_webcam).pack(anchor="w", pady=(0, 6))
        ttk.Button(btn_col, text="🖨️  Scan via Printer / Scanner",
                   command=self._scan_via_printer).pack(anchor="w", pady=(0, 6))

        tk.Label(scan_inner, text= "Review and correct before "
                                   "saving - this never touches the ACS or any government system.",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, justify="left").pack(
            side="left", padx=(16, 0), anchor="n")

        self.reg_scan_preview_label = tk.Label(
            scan_inner, text="No document\nscanned yet", font=FONT_SMALL, bg="#eef1f6",
            fg=COLOR_MUTED, width=26, height=7, justify="center")
        self.reg_scan_preview_label.pack(side="right", anchor="n")

        # Persistent, always-populated recognized-text panel - shows literally everything
        # OCR could read off the card (not just the MRZ), so the officer can select any
        # part of it with the mouse and copy/paste it into a field, the same way you'd
        # select text out of a photo on a phone. This works even when the MRZ itself
        # is too small/blurry to auto-fill from.
        ocr_frame = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        ocr_frame.pack(fill="x", pady=(0, 14))
        tk.Label(ocr_frame, text="Recognized Text From Last Scan  (select any part, then Ctrl+C to "
                                  "copy it into a field below)",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=12, pady=(10, 4))
        self.reg_ocr_text_box = tk.Text(ocr_frame, font=("Consolas", 10), height=5, wrap="word",
                                          bg="#fbfbfb")
        self.reg_ocr_text_box.pack(fill="x", padx=12, pady=(0, 6))
        self.reg_ocr_text_box.insert("1.0", "(Nothing scanned yet - use one of the buttons above.)")
        self.reg_ocr_text_box.configure(state="disabled")

        diag_link = tk.Label(ocr_frame, text="View technical scan details (advanced)", font=FONT_SMALL,
                              bg=COLOR_CARD, fg=COLOR_ACCENT, cursor="hand2")
        diag_link.pack(anchor="w", padx=12, pady=(0, 10))
        diag_link.bind("<Button-1>", lambda e: self._show_last_scan_diagnostics())

        missing = []
        if not CV2_AVAILABLE:
            missing.append("Webcam scan needs: pip install opencv-python")
        if not WIA_AVAILABLE:
            missing.append("Printer scan needs: pip install pywin32 (Windows only)")
        if not OCR_AVAILABLE:
            missing.append("Text extraction needs: pip install pytesseract  +  the Tesseract OCR engine "
                            "(https://github.com/UB-Mannheim/tesseract/wiki)")
        if missing:
            tk.Label(wrap, text="⚠ " + "   |   ".join(missing), font=FONT_SMALL, bg=COLOR_BG,
                      fg=COLOR_WARNING, wraplength=1000, justify="left").pack(anchor="w", pady=(0, 10))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        form = tk.Frame(card, bg=COLOR_CARD)
        form.pack(fill="x", padx=20, pady=16)

        self.reg_vars = {}
        self.reg_vars["first_name"] = labeled_entry(form, "First Name *", 0, 0)
        self.reg_vars["middle_name"] = labeled_entry(form, "Middle Name", 0, 1)
        self.reg_vars["last_name"] = labeled_entry(form, "Last Name *", 0, 2)
        self.reg_vars["gender"] = labeled_entry(form, "Gender", 1, 0, kind="combo",
                                                 values=["Male", "Female"])
        self.reg_vars["dob"] = labeled_entry(form, "Date of Birth (YYYY-MM-DD)", 1, 1)
        self.reg_vars["nationality"] = labeled_entry(form, "Nationality", 1, 2)
        self.reg_vars["mobile"] = labeled_entry(form, "Mobile Number *", 2, 0)
        self.reg_vars["email"] = labeled_entry(form, "Email Address", 2, 1)
        self.reg_vars["company"] = labeled_entry(form, "Company *", 2, 2)
        self.reg_vars["job_title"] = labeled_entry(form, "Job Title", 3, 0)
        self.reg_vars["national_id"] = labeled_entry(form, "National ID / Passport # *", 3, 1)
        self.reg_vars["vehicle_plate"] = labeled_entry(form, "Vehicle Plate (optional)", 3, 2)
        self.reg_vars["purpose"] = labeled_entry(form, "Purpose of Visit *", 4, 0)

        host_accounts = STORE.hosts()
        host_display_to_dept = {u["display"]: u["department"] for u in host_accounts}
        host_values = [u["display"] for u in host_accounts]
        self.reg_vars["host"] = labeled_entry(form, "Host Employee *", 4, 1, kind="combo", values=host_values)
        self.reg_vars["department"] = labeled_entry(form, "Department to Visit *", 4, 2,
                                                      kind="combo", values=DEPARTMENTS)

        def on_host_selected(*_):
            dept = host_display_to_dept.get(self.reg_vars["host"].get())
            if dept:
                self.reg_vars["department"].set(dept)
        self.reg_vars["host"].trace_add("write", on_host_selected)

        if not host_accounts:
            tk.Label(form, text="⚠ No host accounts exist yet. Ask a System Administrator to create "
                                 "host accounts under 'User Management' first - each one is tied to a "
                                 "department.",
                      font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_WARNING, wraplength=700,
                      justify="left").grid(row=9, column=0, columnspan=3, sticky="w", padx=6, pady=(4, 0))

        self.reg_vars["expected_arrival"] = labeled_entry(form, "Expected Arrival (HH:MM)", 5, 0)
        self.reg_vars["expected_departure"] = labeled_entry(form, "Expected Departure (HH:MM)", 5, 1)
        self.reg_vars["visit_date"] = labeled_entry(form, "Visit Date (YYYY-MM-DD)", 5, 2)
        self.reg_vars["visit_date"].set(date.today().isoformat())
        self.reg_vars["expected_arrival"].set("09:00")
        self.reg_vars["expected_departure"].set("17:00")

        tk.Label(form, text="Notes", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(
            row=12, column=0, sticky="w", padx=6, pady=(8, 0))
        self.reg_notes = tk.Text(form, width=80, height=3, font=FONT_BODY)
        self.reg_notes.grid(row=13, column=0, columnspan=3, sticky="w", padx=6, pady=(0, 10))

        btn_row = tk.Frame(card, bg=COLOR_CARD)
        btn_row.pack(fill="x", padx=20, pady=(0, 16))
        ttk.Button(btn_row, text="Submit for Host Approval",
                   style="Accent.TButton", command=self._submit_registration).pack(side="left")
        tk.Label(btn_row, text="  Host will be notified to approve or reject this visit.",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED).pack(side="left")

    # ---------------- REAL ID/PASSPORT SCANNING ----------------
    def _scan_via_webcam(self):
        if not CV2_AVAILABLE:
            messagebox.showerror("Webcam Not Available",
                "The 'opencv-python' package isn't installed, so the app can't access a webcam yet.\n\n"
                "Run this once:\n   pip install opencv-python\n\nThen restart the app.")
            return
        if not PIL_AVAILABLE:
            messagebox.showerror("Pillow Not Available",
                "The 'Pillow' package isn't installed.\n\nRun this once:\n   pip install pillow\n\n"
                "Then restart the app.")
            return

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            messagebox.showerror("Webcam Not Found",
                "Could not open a webcam. Make sure one is connected and not already in use by "
                "another application (e.g. Zoom, Teams, another browser tab).")
            return

        # Most webcams default to a low resolution (often 640x480) unless asked
        # for more. MRZ text is small, so we request the highest resolution the
        # camera supports - this alone often fixes "OCR found nothing" problems.
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1920)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 1080)

        win = tk.Toplevel(self)
        win.title("Scan ID / Passport - Webcam")
        win.configure(bg=COLOR_CARD)
        win.grab_set()
        win.resizable(False, False)

        tk.Label(win, text="Hold the ID/passport's photo page flat and steady, filling as much "
                            "of the frame as possible. Wait until the text below looks sharp - "
                            "webcams often need a second to focus on something this close - then "
                            "click Capture. Good, even lighting matters a lot.",
                  font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT, wraplength=480, justify="left").pack(
            padx=16, pady=(16, 8))

        video_label = tk.Label(win, bg="black", width=480, height=320)
        video_label.pack(padx=16, pady=8)

        state = {"running": True, "frame": None}

        def update_frame():
            if not state["running"]:
                return
            ret, frame = cap.read()
            if ret:
                state["frame"] = frame
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(rgb).resize((480, 320))
                photo = ImageTk.PhotoImage(img)
                video_label.configure(image=photo)
                video_label.image = photo  # keep a reference or Tkinter will garbage-collect it
            if state["running"]:
                win.after(66, update_frame)  # ~15 fps

        def do_capture():
            state["running"] = False
            frame = state["frame"]
            cap.release()
            win.destroy()
            if frame is None:
                messagebox.showerror("Capture Failed", "No frame was captured from the webcam.")
                return
            save_path = os.path.join(SCANS_DIR, f"webcam_scan_{datetime.now():%Y%m%d_%H%M%S}.jpg")
            cv2.imwrite(save_path, frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
            self._process_scanned_image(save_path)

        def do_cancel():
            state["running"] = False
            cap.release()
            win.destroy()

        btn_row = tk.Frame(win, bg=COLOR_CARD)
        btn_row.pack(pady=(8, 16))
        ttk.Button(btn_row, text="Capture", style="Accent.TButton", command=do_capture).pack(
            side="left", padx=6)
        ttk.Button(btn_row, text="Cancel", command=do_cancel).pack(side="left", padx=6)

        win.protocol("WM_DELETE_WINDOW", do_cancel)
        update_frame()

    def _scan_via_printer(self):
        """Trigger the connected printer/MFP's built-in scanner via Windows Image
        Acquisition (WIA) - works like Windows' own 'Scan' app, no vendor SDK needed."""
        if not WIA_AVAILABLE:
            messagebox.showerror("Scanner Not Available",
                "The 'pywin32' package isn't installed, so the app can't reach Windows scanners yet.\n\n"
                "Run this once:\n   pip install pywin32\n\nThen restart the app.\n\n"
                "(This only works on Windows.)")
            return

        save_path = os.path.join(SCANS_DIR, f"printer_scan_{datetime.now():%Y%m%d_%H%M%S}.jpg")
        try:
            wia = win32com.client.Dispatch("WIA.CommonDialog")
            image = wia.ShowAcquireImage()
        except Exception as e:
            messagebox.showerror("Scan Failed",
                f"Could not reach a scanner. Make sure the printer/MFP is connected, turned on, "
                f"and its Windows scanner driver is installed.\n\nDetails: {e}")
            return

        if image is None:
            return  # user cancelled the native Windows scan dialog

        try:
            image.SaveFile(save_path)
        except Exception as e:
            messagebox.showerror("Scan Failed", f"Scan succeeded but saving the image failed:\n{e}")
            return

        self._process_scanned_image(save_path)

    def _decode_qr_or_barcode(self, image_path):
        """Best-effort QR/barcode decode. Returns a list of decoded text strings."""
        if not PYZBAR_AVAILABLE or not PIL_AVAILABLE:
            return []
        try:
            results = zbar_decode(Image.open(image_path))
            return [r.data.decode("utf-8", errors="replace") for r in results]
        except Exception:
            return []

    def _update_ocr_text_panel(self, text):
        if not hasattr(self, "reg_ocr_text_box"):
            return
        self.reg_ocr_text_box.configure(state="normal")
        self.reg_ocr_text_box.delete("1.0", "end")
        self.reg_ocr_text_box.insert("1.0", text.strip() or "(No text could be read from this image.)")
        # Leave it selectable/copyable, just like phone photo text-selection - "disabled"
        # in Tkinter still allows mouse selection and Ctrl+C, it only blocks typing.
        self.reg_ocr_text_box.configure(state="disabled")

    def _process_scanned_image(self, save_path):
        """Shared by both webcam and printer scans: preview the image, then run OCR + QR decode."""
        self._show_scan_preview(save_path)

        qr_results = self._decode_qr_or_barcode(save_path)

        if not OCR_AVAILABLE:
            msg = ("The document was scanned and saved, but text extraction isn't available yet.\n\n"
                   "To auto-fill fields from scans, install:\n"
                   "   pip install pytesseract\n"
                   "...and the Tesseract OCR engine itself from:\n"
                   "   https://github.com/UB-Mannheim/tesseract/wiki\n\n"
                   "For now, please fill in the form fields manually using the preview shown.")
            if qr_results:
                msg += "\n\nA QR/barcode was found on the document:\n" + "\n".join(qr_results)
            messagebox.showinfo("Scanned - Text Extraction Not Installed", msg)
            return

        try:
            data, raw_text = extract_id_data_from_image(save_path)
        except Exception as e:
            messagebox.showerror("Text Extraction Failed",
                f"The document was scanned and saved, but reading the text failed:\n{e}\n\n"
                "Please fill in the form fields manually.")
            return

        # Always show everything OCR could read, whether or not the MRZ auto-fill
        # worked - this is the "select text from a photo" panel, and it's often
        # more useful than the MRZ itself since the big printed fields on the card
        # (name, ID number, etc.) are much easier for OCR to read correctly than
        # the tiny MRZ strip.
        self._update_ocr_text_panel(raw_text)
        self.reg_last_scan = {"path": save_path, "raw_text": raw_text, "qr_results": qr_results}

        if data:
            for field in ("first_name", "last_name", "gender", "dob", "nationality", "national_id"):
                if data.get(field):
                    self.reg_vars[field].set(data[field])
            msg = ("The document's machine-readable zone (MRZ) was read successfully and the "
                   "fields below were auto-filled.\nPlease review them before saving. The full "
                   "recognized text is also shown below the scan buttons if you need to copy "
                   "anything else from it.")
            if qr_results:
                msg += "\n\nA QR/barcode was also found:\n" + "\n".join(qr_results)
                msg += "\n(Shown for your reference - not auto-filled, since its format isn't known.)"
            messagebox.showinfo("Scan Complete", msg)
        else:
            msg = ("The MRZ (machine-readable zone) wasn't clear enough to auto-fill the form - "
                   "this needs the small strip of text to be nearly perfect. But everything OCR "
                   "could read off the card is shown below the scan buttons - select any part of "
                   "it and Ctrl+C to copy it into a field, the same way you'd select text from a "
                   "photo on your phone.")
            if qr_results:
                msg += "\n\nA QR/barcode was found on the document:\n" + "\n".join(qr_results)
            messagebox.showinfo("Scanned - Use Recognized Text Below", msg)

    def _show_last_scan_diagnostics(self):
        last = getattr(self, "reg_last_scan", None)
        if not last:
            messagebox.showinfo("No Scan Yet", "Scan a document first, then this will show technical "
                                                 "details about what OCR read from it.")
            return
        self._show_ocr_debug_dialog(last["raw_text"], last["qr_results"], last["path"])

    def _show_ocr_debug_dialog(self, raw_text, qr_results, save_path):
        """Shown when no MRZ was detected - surfaces exactly what OCR read off the
        document so we can tell whether it's an image-quality issue or a genuine
        format mismatch, instead of just saying 'didn't work' with no way to diagnose."""
        candidates = find_mrz_lines(raw_text)

        # Save the raw text next to the scan for easy reference/sharing.
        txt_path = save_path.rsplit(".", 1)[0] + "_ocr_text.txt"
        try:
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(raw_text)
        except Exception:
            txt_path = None

        win = tk.Toplevel(self)
        win.title("Scanned - No MRZ Found")
        win.geometry("640x520")
        win.configure(bg=COLOR_CARD)
        win.grab_set()

        tk.Label(win, text="No machine-readable zone (MRZ) was detected.", font=FONT_H2,
                 bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=16, pady=(16, 4))
        tk.Label(win, text="This shows exactly what the OCR engine read off the document, so you "
                            "can tell whether the image was too blurry/small, or the format just "
                            "doesn't match what this app looks for. Please fill in the form fields "
                            "manually using the scanned image shown on the Registration page.",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=600, justify="left").pack(
            anchor="w", padx=16, pady=(0, 10))

        if qr_results:
            tk.Label(win, text="QR/barcode found: " + " | ".join(qr_results), font=FONT_SMALL,
                      bg=COLOR_CARD, fg=COLOR_SUCCESS, wraplength=600, justify="left").pack(
                anchor="w", padx=16, pady=(0, 10))

        tk.Label(win, text="Raw text read from the image (longest candidate lines checked "
                            f"for an MRZ pattern: {len(candidates)} found, none matched a known length):",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_TEXT, wraplength=600, justify="left").pack(
            anchor="w", padx=16, pady=(0, 4))

        text_frame = tk.Frame(win, bg=COLOR_CARD)
        text_frame.pack(fill="both", expand=True, padx=16, pady=(0, 10))
        text_box = tk.Text(text_frame, font=("Consolas", 9), wrap="word", height=14)
        scrollbar = ttk.Scrollbar(text_frame, command=text_box.yview)
        text_box.configure(yscrollcommand=scrollbar.set)
        text_box.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        display_text = raw_text.strip() or "(OCR returned no text at all - the image may be too dark, blurry, or the document wasn't in frame.)"
        if candidates:
            display_text += "\n\n--- Candidate MRZ-like lines found (with lengths) ---\n"
            for c in candidates:
                display_text += f"[{len(c)} chars] {c}\n"
        text_box.insert("1.0", display_text)
        text_box.configure(state="disabled")

        if txt_path:
            tk.Label(win, text=f"Also saved to: {txt_path}", font=FONT_SMALL, bg=COLOR_CARD,
                      fg=COLOR_MUTED).pack(anchor="w", padx=16, pady=(0, 6))

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 16))


    def _show_scan_preview(self, image_path):
        if not PIL_AVAILABLE or not hasattr(self, "reg_scan_preview_label"):
            return
        try:
            img = Image.open(image_path)
            img.thumbnail((220, 140))
            photo = ImageTk.PhotoImage(img)
            self.reg_scan_preview_label.configure(image=photo, text="")
            self.reg_scan_preview_label.image = photo  # keep a reference
        except Exception:
            pass  # preview is a nice-to-have, never block the rest of the flow over it

    def _submit_registration(self):
        required = ["first_name", "last_name", "mobile", "company",
                    "national_id", "purpose", "host", "department"]
        missing = [r for r in required if not self.reg_vars[r].get().strip()]
        if missing:
            messagebox.showerror("Missing Information",
                                  "Please fill in all required fields (*) before submitting.")
            return
        try:
            visit_date = datetime.strptime(self.reg_vars["visit_date"].get(), "%Y-%m-%d").date()
        except ValueError:
            visit_date = date.today()

        vid = STORE.add_visitor(
            first_name=self.reg_vars["first_name"].get(),
            middle_name=self.reg_vars["middle_name"].get(),
            last_name=self.reg_vars["last_name"].get(),
            gender=self.reg_vars["gender"].get() or "N/A",
            dob=self.reg_vars["dob"].get(),
            nationality=self.reg_vars["nationality"].get(),
            mobile=self.reg_vars["mobile"].get(),
            email=self.reg_vars["email"].get(),
            company=self.reg_vars["company"].get(),
            job_title=self.reg_vars["job_title"].get(),
            national_id=self.reg_vars["national_id"].get(),
            vehicle_plate=self.reg_vars["vehicle_plate"].get(),
            purpose=self.reg_vars["purpose"].get(),
            host=self.reg_vars["host"].get(),
            department=self.reg_vars["department"].get(),
            expected_arrival=self.reg_vars["expected_arrival"].get(),
            expected_departure=self.reg_vars["expected_departure"].get(),
            visit_date=visit_date,
            notes=self.reg_notes.get("1.0", "end").strip(),
        )
        messagebox.showinfo("Registered",
                             f"Visitor registered (ID #{vid}).\nStatus: Pending Approval.\n"
                             f"Host '{self.reg_vars['host'].get()}' will be notified.")
        self.show_page("Visitor Registration")

    # ---------------- CHECK-IN ----------------
    def page_checkin(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Visitor Check-In",
                      "Only visitors already approved by their host can be checked in").pack(
            anchor="w", pady=(0, 16))

        pending = [v for v in STORE.visitors if v["status"] == "Pending Approval"]
        if pending:
            tk.Label(wrap, text=f"⏳ {len(pending)} visitor(s) still awaiting host approval - "
                                 "they'll appear below once their host approves them.",
                      font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_WARNING).pack(anchor="w", pady=(0, 10))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Company", "Host", "Department", "Status")
        tree = make_table(card, cols, (40, 150, 150, 120, 140, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        approved = [v for v in STORE.visitors if v["status"] == "Approved"]
        for v in approved:
            tree.insert("", "end", iid=v["id"], values=(
                v["id"], f'{v["first_name"]} {v["last_name"]}', v["company"],
                v["host"], v["department"], v["status"]))
        if not approved:
            tk.Label(card, text="No approved visitors ready for check-in right now.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))

        def checkin():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a visitor", "Please select a visitor first.")
                return
            v = STORE.get_visitor(int(sel[0]))
            if v["status"] != "Approved":
                messagebox.showerror("Not Approved",
                                      "This visitor must be approved by their host before check-in.")
                return
            avail = STORE.available_badges()
            if not avail:
                messagebox.showerror("No Badges", "No badges are currently available.")
                return
            badge = avail[0]
            badge["status"] = "Assigned"
            badge["visitor_id"] = v["id"]
            v["badge_no"] = badge["badge_no"]
            v["status"] = "Checked In"
            v["check_in_time"] = datetime.now().strftime("%H:%M")
            v["face_enrolled"] = enroll_face.get()
            STORE.save_badge(badge)
            STORE.save_visitor(v)
            STORE.log(self.current_user, "Check-In", "Success",
                      f"Checked in visitor #{v['id']} - badge {badge['badge_no']}"
                      f"{' + face enrolled' if v['face_enrolled'] else ''}")
            STORE.log(self.current_user, "ACS Synchronization", "Success",
                      f"Access activated in Face Biometric ACS for visitor #{v['id']}")
            messagebox.showinfo("Checked In",
                                 f"{v['first_name']} {v['last_name']} checked in.\n"
                                 f"Badge assigned: {badge['badge_no']}\n"
                                 f"ACS access: Activated"
                                 f"{'  |  Face enrollment: Complete' if v['face_enrolled'] else ''}")
            self.show_page("Check-In")

        enroll_face = tk.BooleanVar(value=True)
        tk.Checkbutton(btns, text="Enroll face in Biometric ACS (required for restricted areas)",
                        variable=enroll_face, bg=COLOR_CARD, font=FONT_BODY).pack(side="left")
        ttk.Button(btns, text="Check In + Assign Badge", style="Accent.TButton",
                   command=checkin).pack(side="right")

    # ---------------- CHECK-OUT ----------------
    def page_checkout(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Visitor Check-Out",
                      "Visitors currently inside the factory").pack(anchor="w", pady=(0, 16))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Badge", "Department", "Check-In Time")
        tree = make_table(card, cols, (40, 160, 100, 150, 130))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        inside = [v for v in STORE.visitors if v["status"] == "Checked In"]
        for v in inside:
            tree.insert("", "end", iid=v["id"], values=(
                v["id"], f'{v["first_name"]} {v["last_name"]}', v["badge_no"],
                v["department"], v["check_in_time"]))

        def checkout():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a visitor", "Please select a visitor first.")
                return
            v = STORE.get_visitor(int(sel[0]))
            badge = next(b for b in STORE.badges if b["badge_no"] == v["badge_no"])
            badge["status"] = "Available"
            badge["visitor_id"] = None
            v["status"] = "Checked Out"
            v["check_out_time"] = datetime.now().strftime("%H:%M")
            STORE.save_badge(badge)
            STORE.save_visitor(v)
            STORE.log(self.current_user, "Check-Out", "Success",
                      f"Checked out visitor #{v['id']}, badge {badge['badge_no']} released")
            STORE.log(self.current_user, "ACS Synchronization", "Success",
                      f"Access deactivated in ACS for visitor #{v['id']}")
            messagebox.showinfo("Checked Out",
                                 f"{v['first_name']} {v['last_name']} checked out.\n"
                                 f"Badge {badge['badge_no']} is now Available for reuse.\n"
                                 f"ACS access: Deactivated")
            self.show_page("Check-Out")

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Check Out + Release Badge", style="Accent.TButton",
                   command=checkout).pack(side="right")

    # ---------------- BADGE MANAGEMENT ----------------
    def page_badges(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Badge Management",
                      "Reusable badges with permanent QR codes - only the assigned visitor changes").pack(
            anchor="w", pady=(0, 16))

        top = tk.Frame(wrap, bg=COLOR_BG)
        top.pack(fill="x", pady=(0, 14))
        avail = len(STORE.available_badges())
        assigned = len(STORE.badges) - avail
        stat_card(top, "Total Badges", len(STORE.badges), COLOR_ACCENT).pack(side="left", padx=(0, 10))
        stat_card(top, "Available", avail, COLOR_SUCCESS).pack(side="left", padx=(0, 10))
        stat_card(top, "Assigned", assigned, COLOR_WARNING).pack(side="left")

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("Badge #", "Status", "Assigned Visitor", "Department", "QR Payload (illustrative)")
        tree = make_table(card, cols, (100, 110, 180, 150, 260))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        for b in STORE.badges:
            visitor_name = "-"
            dept = "-"
            if b["visitor_id"]:
                v = STORE.get_visitor(b["visitor_id"])
                visitor_name = f'{v["first_name"]} {v["last_name"]}'
                dept = v["department"]
            qr_payload = f'{{"badgeId":"{b["badge_no"]}","token":"enc:{random.randint(1000,9999)}","sig":"…"}}'
            tree.insert("", "end", values=(b["badge_no"], b["status"], visitor_name, dept, qr_payload))

        tk.Label(wrap, text="Note: QR codes never contain personal information - only badge ID, an "
                             "encrypted token, and a digital signature. Scanning resolves visitor "
                             "details server-side.",
                  font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_MUTED, wraplength=900, justify="left").pack(
            anchor="w", pady=(10, 0))

    # ---------------- SEARCH ----------------
    def page_search(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Search", "Search visitors by name, ID, badge, company, host or department").pack(
            anchor="w", pady=(0, 16))

        bar = tk.Frame(wrap, bg=COLOR_BG)
        bar.pack(fill="x", pady=(0, 14))
        query = tk.StringVar()
        ttk.Entry(bar, textvariable=query, width=40, font=FONT_BODY).pack(side="left", ipady=3)

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "National ID", "Company", "Host", "Badge", "Status")
        tree = make_table(card, cols, (40, 150, 110, 150, 120, 80, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        def refresh(*_):
            tree.delete(*tree.get_children())
            q = query.get().lower().strip()
            for v in STORE.visitors:
                haystack = " ".join(str(x) for x in [
                    v["first_name"], v["last_name"], v["national_id"], v["company"],
                    v["host"], v["department"], v["badge_no"], v["status"]]).lower()
                if q in haystack:
                    tree.insert("", "end", values=(
                        v["id"], f'{v["first_name"]} {v["last_name"]}', v["national_id"],
                        v["company"], v["host"], v["badge_no"] or "-", v["status"]))

        ttk.Button(bar, text="Search", command=refresh, style="Accent.TButton").pack(side="left", padx=8)
        query.trace_add("write", refresh)
        refresh()

    # ---------------- REPORTS ----------------
    def page_reports(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Reports", "Generate and export visitor reports").pack(anchor="w", pady=(0, 16))

        bar = tk.Frame(wrap, bg=COLOR_BG)
        bar.pack(fill="x", pady=(0, 14))
        report_type = tk.StringVar(value="Daily Visitor Report")
        options = ["Daily Visitor Report", "Weekly Visitor Report", "Monthly Visitor Report",
                   "Visitors Currently Inside", "Overstayed Visitors", "Badge Usage Report",
                   "Department Visitor Report", "Host Visitor Report"]
        ttk.Combobox(bar, textvariable=report_type, values=options, state="readonly",
                     width=32).pack(side="left")

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True, pady=(14, 0))
        cols = ("Visitor", "Company", "Host", "Department", "Badge", "Status")
        tree = make_table(card, cols, (160, 160, 130, 150, 90, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        def generate():
            tree.delete(*tree.get_children())
            rtype = report_type.get()
            rows = STORE.visitors
            if rtype == "Visitors Currently Inside":
                rows = [v for v in rows if v["status"] == "Checked In"]
            elif rtype == "Overstayed Visitors":
                rows = [v for v in rows if v["status"] == "Checked In"]  # illustrative
            for v in rows:
                tree.insert("", "end", values=(
                    f'{v["first_name"]} {v["last_name"]}', v["company"], v["host"],
                    v["department"], v["badge_no"] or "-", v["status"]))
            STORE.log(self.current_user, "Report Generation", "Success", rtype)

        def export_csv():
            filename = f"{report_type.get().replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M%S}.csv"
            path = os.path.join(REPORTS_DIR, filename)
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                for iid in tree.get_children():
                    writer.writerow(tree.item(iid)["values"])
            STORE.log(self.current_user, "Report Export", "Success", f"CSV: {filename}")
            if messagebox.askyesno("Exported",
                                    f"Report saved as:\n{path}\n\nOpen the folder now?"):
                open_in_file_explorer(path)

        def export_pdf():
            filename = f"{report_type.get().replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M%S}.pdf"
            path = os.path.join(REPORTS_DIR, filename)
            rows_data = [cols] + [tree.item(iid)["values"] for iid in tree.get_children()]

            if REPORTLAB_AVAILABLE:
                doc = SimpleDocTemplate(path, pagesize=landscape(A4),
                                         topMargin=1.5 * cm, bottomMargin=1.5 * cm)
                styles = getSampleStyleSheet()
                elements = [
                    Paragraph(APP_TITLE, styles["Title"]),
                    Paragraph(report_type.get(), styles["Heading2"]),
                    Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M} by {self.current_user}",
                              styles["Normal"]),
                    Spacer(1, 12),
                ]
                table = Table(rows_data, repeatRows=1)
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]))
                elements.append(table)
                doc.build(elements)
                STORE.log(self.current_user, "Report Export", "Success", f"PDF: {filename}")
                if messagebox.askyesno("Exported", f"PDF saved as:\n{path}\n\nOpen the folder now?"):
                    open_in_file_explorer(path)
            else:
                html_path = os.path.join(REPORTS_DIR, filename.replace(".pdf", ".html"))
                html_rows = "".join(
                    "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows_data[1:])
                html_head = "".join(f"<th>{c}</th>" for c in cols)
                html = f"""<html><head><meta charset="utf-8"><title>{report_type.get()}</title>
                <style>
                body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; }}
                h1 {{ font-size: 18px; }} h2 {{ font-size: 14px; color: #444; font-weight: normal; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
                th, td {{ border: 1px solid #ccc; padding: 6px 10px; font-size: 12px; text-align: left; }}
                th {{ background: #1a2332; color: white; }}
                tr:nth-child(even) {{ background: #f4f6f9; }}
                </style></head><body>
                <h1>{APP_TITLE}</h1>
                <h2>{report_type.get()} &middot; Generated {datetime.now():%Y-%m-%d %H:%M} by {self.current_user}</h2>
                <table><tr>{html_head}</tr>{html_rows}</table>
                </body></html>"""
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html)
                STORE.log(self.current_user, "Report Export", "Success", f"HTML (PDF fallback): {filename}")
                webbrowser.open(f"file://{html_path}")
                messagebox.showinfo(
                    "PDF library not installed",
                    "The 'reportlab' package isn't installed, so a print-ready HTML "
                    "version was opened in your browser instead.\n\n"
                    "In the browser: press Ctrl+P -> 'Save as PDF' to get a real PDF.\n\n"
                    "To enable direct one-click PDF export next time, run this once:\n"
                    "   pip install reportlab")

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Generate", style="Accent.TButton", command=generate).pack(side="left")
        ttk.Button(btns, text="Export CSV", command=export_csv).pack(side="left", padx=8)
        ttk.Button(btns, text="Export PDF", command=export_pdf).pack(side="left")
        tk.Label(wrap, text=f"Reports are saved to: {REPORTS_DIR}", font=FONT_SMALL,
                  bg=COLOR_BG, fg=COLOR_MUTED).pack(anchor="w", pady=(8, 0))
        generate()

    # ---------------- HOST: MY OVERVIEW ----------------
    def page_host_overview(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, f"Welcome, {self.host_name}",
                      "Visit requests and visitors associated with you").pack(anchor="w", pady=(0, 16))

        mine = [v for v in STORE.visitors if v["host"] == self.host_name]
        pending = [v for v in mine if v["status"] == "Pending Approval"]
        inside = [v for v in mine if v["status"] == "Checked In"]
        today = [v for v in mine if v["visit_date"] == date.today()]

        stats = tk.Frame(wrap, bg=COLOR_BG)
        stats.pack(fill="x", pady=(0, 20))
        cards = [
            ("Awaiting My Approval", len(pending), COLOR_WARNING),
            ("My Visitors Today", len(today), COLOR_ACCENT),
            ("Currently With Me", len(inside), COLOR_SUCCESS),
        ]
        for i, (label, value, color) in enumerate(cards):
            c = stat_card(stats, label, value, color)
            c.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="ew")
            stats.grid_columnconfigure(i, weight=1)

        if pending:
            banner = tk.Frame(wrap, bg="#fff4e0", highlightbackground=COLOR_WARNING, highlightthickness=1)
            banner.pack(fill="x", pady=(0, 16))
            tk.Label(banner, text=f"🔔 You have {len(pending)} visit request(s) waiting for your approval.",
                      font=("Segoe UI", 10, "bold"), bg="#fff4e0", fg="#8a5a00").pack(
                anchor="w", padx=14, pady=10, side="left")
            ttk.Button(banner, text="Review Now",
                       command=lambda: self.show_page("My Approvals")).pack(side="right", padx=14, pady=8)

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        tk.Label(card, text="Recent Activity For My Visits", font=FONT_H2, bg=COLOR_CARD,
                  fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
        cols = ("Visitor", "Company", "Purpose", "Status")
        tree = make_table(card, cols, (170, 170, 200, 130))
        tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        for v in sorted(mine, key=lambda x: -x["id"]):
            tree.insert("", "end", values=(f'{v["first_name"]} {v["last_name"]}', v["company"],
                                            v["purpose"], v["status"]))

    # ---------------- HOST: MY APPROVALS ----------------
    def page_host_approvals(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "My Approvals",
                      "Visit requests where you are listed as the host - approve or reject").pack(
            anchor="w", pady=(0, 16))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Company", "Department", "Purpose", "Visit Date")
        tree = make_table(card, cols, (40, 150, 150, 140, 180, 100))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        pending = [v for v in STORE.visitors
                   if v["host"] == self.host_name and v["status"] == "Pending Approval"]
        for v in pending:
            tree.insert("", "end", iid=v["id"], values=(
                v["id"], f'{v["first_name"]} {v["last_name"]}', v["company"],
                v["department"], v["purpose"], v["visit_date"]))
        if not pending:
            tk.Label(card, text="No pending requests. You're all caught up.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 14))

        def decide(new_status):
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a request", "Please select a visit request first.")
                return
            v = STORE.get_visitor(int(sel[0]))
            v["status"] = new_status
            STORE.save_visitor(v)
            STORE.log(self.current_user, "Visitor Approval" if new_status == "Approved" else "Visitor Rejection",
                      "Success", f"{new_status} visitor #{v['id']} ({v['first_name']} {v['last_name']})")
            messagebox.showinfo("Done", f"{v['first_name']} {v['last_name']} has been {new_status.lower()}.")
            self.show_page("My Approvals")

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Reject", command=lambda: decide("Rejected")).pack(side="right")
        ttk.Button(btns, text="Approve", style="Accent.TButton",
                   command=lambda: decide("Approved")).pack(side="right", padx=(0, 8))

    # ---------------- HOST: MY VISIT HISTORY ----------------
    def page_host_history(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "My Visit History", "All visits, past and present, where you are the host").pack(
            anchor="w", pady=(0, 16))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("Visitor", "Company", "Purpose", "Visit Date", "Badge", "Status")
        tree = make_table(card, cols, (150, 150, 180, 100, 80, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        mine = [v for v in STORE.visitors if v["host"] == self.host_name]
        for v in sorted(mine, key=lambda x: -x["id"]):
            tree.insert("", "end", values=(f'{v["first_name"]} {v["last_name"]}', v["company"],
                                            v["purpose"], v["visit_date"], v["badge_no"] or "-", v["status"]))
        if not mine:
            tk.Label(card, text="No visit history yet.", font=FONT_BODY, bg=COLOR_CARD,
                      fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 14))

    # ---------------- SYSTEM MONITOR (admin only) ----------------
    def page_system_monitor(self):
        if self.current_role != "admin":
            messagebox.showerror("Access Denied", "Only the System Administrator can access this page.")
            return

        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "System Monitor", "Monitor system health, users, and visitor statistics.").pack(
            anchor="w", pady=(0, 16))

        stats = tk.Frame(wrap, bg=COLOR_BG)
        stats.pack(fill="x", pady=(0, 20))
        total_users = len(STORE.users)
        total_visitors = len(STORE.visitors)
        active_visitors = len([v for v in STORE.visitors if v["status"] == "Checked In"])
        cards = [
            ("Users", total_users, COLOR_ACCENT),
            ("Visitors", total_visitors, COLOR_SUCCESS),
            ("Inside Factory", active_visitors, COLOR_WARNING),
        ]
        for i, (label, value, color) in enumerate(cards):
            c = stat_card(stats, label, value, color)
            c.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="ew")
            stats.grid_columnconfigure(i, weight=1)

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        tk.Label(card, text="System Status", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=20, pady=(15, 10))

        # NOTE: These are illustrative/static for the demo - a real build would
        # poll actual service health (DB connection, ACS API, scanner drivers).
        statuses = [
            ("Database", "🟢 Online"),
            ("Visitor Management", "🟢 Running"),
            ("Access Control (ACS)", "🟢 Connected"),
            ("Camera System", "🟢 Connected"),
            ("ID Scanner", "🟢 Ready"),
            ("Passport Scanner", "🟢 Ready"),
        ]
        for name, status in statuses:
            row = tk.Frame(card, bg=COLOR_CARD)
            row.pack(fill="x", padx=20, pady=4)
            tk.Label(row, text=name, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
            tk.Label(row, text=status, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_SUCCESS).pack(side="right")
        tk.Label(card, text="", bg=COLOR_CARD).pack(pady=6)  # bottom padding

    # ---------------- USER MANAGEMENT (admin only) ----------------
    def page_user_management(self):
        if self.current_role != "admin":
            messagebox.showerror("Access Denied", "Only the System Administrator can manage user accounts.")
            return

        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "User Management",
                      "Only System Administrators can create or delete accounts. Every Host "
                      "account is tied to a department.").pack(anchor="w", pady=(0, 16))

        if len(STORE.users) == 1 and STORE.users[0]["username"] == BOOTSTRAP_USERNAME:
            banner = tk.Frame(wrap, bg="#fff4e0", highlightbackground=COLOR_WARNING, highlightthickness=1)
            banner.pack(fill="x", pady=(0, 16))
            tk.Label(banner, text="⚠ You're still using the bootstrap admin account. Create a real "
                                   "System Administrator account for yourself below, then consider "
                                   "deleting 'admin' once it's no longer needed.",
                      font=FONT_SMALL, bg="#fff4e0", fg="#8a5a00", wraplength=800, justify="left").pack(
                anchor="w", padx=14, pady=10)

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="x", pady=(0, 16))
        form = tk.Frame(card, bg=COLOR_CARD)
        form.pack(fill="x", padx=20, pady=16)

        tk.Label(form, text="Create New Account", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        role_var = labeled_entry(form, "Account Type *", 1, 0, kind="combo",
                                  values=["Security Officer", "Host / Employee", "System Administrator"])
        role_var.set("Security Officer")
        display_var = labeled_entry(form, "Full Name *", 1, 1)
        username_var = labeled_entry(form, "Username *", 1, 2)

        dept_label = tk.Label(form, text="Department *", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT)
        dept_var = tk.StringVar()
        dept_combo = ttk.Combobox(form, textvariable=dept_var, values=DEPARTMENTS, width=22, state="readonly")

        def place_dept_field():
            if role_var.get() == "Host / Employee":
                dept_label.grid(row=3, column=0, sticky="w", padx=6, pady=(8, 0))
                dept_combo.grid(row=4, column=0, sticky="w", padx=6, pady=(0, 4))
            else:
                dept_label.grid_forget()
                dept_combo.grid_forget()
        role_var.trace_add("write", lambda *_: place_dept_field())
        place_dept_field()

        tk.Label(form, text=f"New accounts are created with the default password "
                             f"'{DEFAULT_NEW_ACCOUNT_PASSWORD}'. The user must set their own "
                             f"password the first time they log in.",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=520, justify="left").grid(
            row=5, column=0, columnspan=2, sticky="w", padx=6, pady=(10, 0))

        def auto_username(*_):
            if display_var.get().strip() and not username_var.get().strip():
                username_var.set(display_var.get().strip().lower().replace(" ", "."))
        display_var.trace_add("write", auto_username)

        ROLE_MAP = {"Security Officer": "officer", "Host / Employee": "host",
                    "System Administrator": "admin"}

        def create_account():
            role_choice = role_var.get()
            display = display_var.get().strip()
            username = username_var.get().strip().lower()
            department = dept_var.get() if role_choice == "Host / Employee" else None

            if not display or not username:
                messagebox.showerror("Missing Information", "Full name and username are required.")
                return
            if role_choice == "Host / Employee" and not department:
                messagebox.showerror("Missing Department",
                                      "A Host / Employee account must be linked to a department.")
                return
            if STORE.username_taken(username):
                messagebox.showerror("Username Taken", f"The username '{username}' is already in use.")
                return

            STORE.add_user(username, DEFAULT_NEW_ACCOUNT_PASSWORD, display, ROLE_MAP[role_choice], department)
            messagebox.showinfo("Account Created",
                                 f"{role_choice} account created for {display}.\n"
                                 f"Username: {username}\n"
                                 f"Default Password: {DEFAULT_NEW_ACCOUNT_PASSWORD}\n"
                                 + (f"Department: {department}\n" if department else "")
                                 + "They'll be asked to set their own password on first login.")
            self.show_page("User Management")

        ttk.Button(form, text="Create Account", style="Accent.TButton",
                   command=create_account).grid(row=6, column=0, sticky="w", padx=6, pady=(12, 0))

        # existing accounts table
        list_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        list_card.pack(fill="both", expand=True)
        tk.Label(list_card, text="All Accounts", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=14, pady=(12, 6))
        cols = ("Username", "Full Name", "Role", "Department", "Status")
        tree = make_table(list_card, cols, (140, 180, 150, 160, 100))
        tree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        role_display = {"officer": "Security Officer", "host": "Host / Employee",
                         "admin": "System Administrator"}
        for u in STORE.users:
            tree.insert("", "end", iid=u["username"], values=(
                u["username"], u["display"], role_display[u["role"]],
                u["department"] or "-", "Active" if u["active"] else "Deactivated"))

        def get_selected_username():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select an account", "Please select an account first.")
                return None
            return sel[0]

        def toggle_selected():
            username = get_selected_username()
            if not username:
                return
            if username == self.current_username:
                messagebox.showerror("Not Allowed", "You can't deactivate the account you're logged in as.")
                return
            STORE.toggle_user_active(username)
            self.show_page("User Management")

        def delete_selected():
            username = get_selected_username()
            if not username:
                return
            if username == self.current_username:
                messagebox.showerror("Not Allowed", "You can't delete the account you're logged in as.")
                return
            target = STORE.get_user(username)
            other_admins = [u for u in STORE.users if u["role"] == "admin" and u["username"] != username]
            if target["role"] == "admin" and not other_admins:
                messagebox.showerror("Not Allowed", "You can't delete the last System Administrator account.")
                return
            if messagebox.askyesno("Confirm Delete",
                                    f"Permanently delete the account '{username}' ({target['display']})?\n"
                                    "This cannot be undone."):
                STORE.delete_user(username, deleted_by=self.current_user)
                self.show_page("User Management")

        btn_row = tk.Frame(list_card, bg=COLOR_CARD)
        btn_row.pack(anchor="w", padx=14, pady=(0, 14))
        ttk.Button(btn_row, text="Activate / Deactivate Selected", command=toggle_selected).pack(side="left")
        ttk.Button(btn_row, text="Delete Selected Account", command=delete_selected).pack(side="left", padx=(8, 0))

    # ---------------- AUDIT LOG ----------------
    def page_audit(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Audit Log", "Every important system action is logged for compliance").pack(
            anchor="w", pady=(0, 16))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("Timestamp", "User", "Action", "Result", "Detail")
        tree = make_table(card, cols, (150, 160, 160, 90, 320))
        tree.pack(fill="both", expand=True, padx=14, pady=14)
        if not STORE.audit_log:
            tk.Label(card, text="No activity yet.", font=FONT_BODY, bg=COLOR_CARD,
                      fg=COLOR_MUTED).pack(anchor="w", padx=18, pady=10)
        for entry in reversed(STORE.audit_log):
            tree.insert("", "end", values=entry)


if __name__ == "__main__":
    app = VMSApp()
    app.mainloop()

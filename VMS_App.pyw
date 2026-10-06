
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime, date, timedelta
import csv
import random
import os
import sys
import subprocess
import webbrowser
import json
import re
import urllib.request
import urllib.error
import configparser
import calendar
from functools import partial

APP_TITLE = "MKDSS Smart Card Factory VMS"

# Reports/config/scans need to persist across runs, so they must live next to
# the actual .exe - not inside PyInstaller's temporary extraction folder,
# which is deleted every time a packaged app closes. Bundled read-only assets
# (like the logo) are a separate concern and DO live in that temp folder.
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)        # persistent data goes here
    BUNDLE_DIR = getattr(sys, "_MEIPASS", BASE_DIR)    # bundled read-only assets live here
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = BASE_DIR

LOGO_PATH = os.path.join(BUNDLE_DIR, "mkdss_logo_transparent.png")
ICON_PATH = os.path.join(BUNDLE_DIR, "mkdss_icon.ico")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
def format_report_time(value):
    """Return a reliable HH:MM:SS time for report output.

    Visitor timestamps can be stored as ``YYYY-MM-DD HH:MM:SS`` or ISO-8601
    values using ``T``. Older records may contain a time-only value. The
    previous report code only handled the space-separated format, which made
    valid ISO timestamps appear as ``-`` in generated reports.
    """
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%H:%M:%S")
    text = str(value).strip()
    if not text:
        return "-"
    # ISO-8601 / normal datetime values.
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        pass
    # Legacy/simple values.
    if " " in text:
        candidate = text.rsplit(" ", 1)[1]
    elif "T" in text:
        candidate = text.rsplit("T", 1)[1]
    else:
        candidate = text
    candidate = candidate.split("+", 1)[0].split("Z", 1)[0].strip()
    if len(candidate) >= 8 and candidate[2] == ":" and candidate[5] == ":":
        return candidate[:8]
    if len(candidate) >= 5 and candidate[2] == ":":
        return candidate[:5]
    return "-"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ----------------------------------------------------------------------
# SERVER CONNECTION (accounts are now centralized on one server - see
# vms_server.py - instead of each client keeping its own local copy)
# ----------------------------------------------------------------------
SERVER_CONFIG_PATH = os.path.join(BASE_DIR, "vms_config.ini")
SERVER_PORT = 8765


def load_server_address():
    config = configparser.ConfigParser()
    if os.path.isfile(SERVER_CONFIG_PATH):
        config.read(SERVER_CONFIG_PATH)
        if config.has_option("server", "ip"):
            return config.get("server", "ip").strip()
    return None


def save_server_address(ip):
    config = configparser.ConfigParser()
    config["server"] = {"ip": ip}
    with open(SERVER_CONFIG_PATH, "w") as f:
        config.write(f)


def validate_password_policy(password):
    """Mirrors the server's policy (see vms_server.py) for instant feedback
    before making a network call. The server enforces this too - this client
    check is just for a faster, friendlier error message."""
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


_session_token = None  # set on login, cleared on logout - see api_login/api_logout below


def api_call(method, path, payload=None, timeout=5):
    """Make a request to the VMS server. Returns (ok, data_or_error_message).
    Never raises - all network/server errors are caught and turned into a
    friendly message, since a client PC losing network to the server is an
    expected, recoverable situation, not a bug."""
    server_ip = load_server_address()
    if not server_ip:
        return False, "No server address configured yet."
    url = f"http://{server_ip}:{SERVER_PORT}{path}"
    try:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if _session_token:
            headers["X-Session-Token"] = _session_token
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return True, body
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
            return False, body.get("error", f"Server returned an error ({e.code}).")
        except Exception:
            return False, f"Server returned an error ({e.code})."
    except urllib.error.URLError as e:
        return False, (f"Can't reach the VMS server at {server_ip}:{SERVER_PORT}. "
                        f"Make sure the server program is running and this PC can reach it "
                        f"on the network.\n\nDetails: {e.reason}")
    except Exception as e:
        return False, f"Unexpected error talking to the server: {e}"


def api_ping():
    return api_call("GET", "/api/ping")


def api_login(username, password):
    """On success, remembers the session token for every subsequent request."""
    global _session_token
    ok, result = api_call("POST", "/api/login", {"username": username, "password": password})
    if ok:
        _session_token = result.get("token")
    return ok, result


def api_change_password(new_password):
    """Requires an existing valid session (from api_login) - the server
    identifies whose password to change from that, not a username field."""
    global _session_token
    ok, result = api_call("POST", "/api/change_password", {"new_password": new_password})
    if ok:
        _session_token = result.get("token")
    return ok, result


def api_logout():
    global _session_token
    ok, result = api_call("POST", "/api/logout")
    _session_token = None
    return ok, result


def api_list_users():
    return api_call("GET", "/api/users")


def api_create_user(username, display, role, department=None):
    return api_call("POST", "/api/users", {
        "username": username, "display": display, "role": role, "department": department,
    })


def api_toggle_user(username):
    return api_call("POST", "/api/users/toggle", {"username": username})


def api_delete_user(username):
    return api_call("POST", "/api/users/delete", {"username": username})


def api_reset_user_password(username):
    return api_call("POST", "/api/users/reset_password", {"username": username})


def api_get_audit_log():
    return api_call("GET", "/api/audit_log")


def api_get_notifications():
    """Get all notifications for current user."""
    return api_call("GET", "/api/notifications")


def api_unread_count():
    """Get count of unread notifications."""
    return api_call("GET", "/api/notifications/unread_count")


def api_mark_notification_read(notif_id):
    """Mark a notification as read."""
    return api_call("POST", f"/api/notifications/{notif_id}/read", {})


def api_delete_notification(notif_id):
    """Delete a notification."""
    return api_call("POST", f"/api/notifications/{notif_id}/delete", {})


def api_mark_all_read():
    """Mark all notifications as read."""
    return api_call("POST", "/api/notifications/mark_all_read", {})


def api_delete_all_notifications():
    """Delete all notifications."""
    return api_call("POST", "/api/notifications/delete_all", {})


def api_log(action, result="Success", detail=""):
    return api_call("POST", "/api/log", {"action": action, "result": result, "detail": detail})


def api_list_badges():
    return api_call("GET", "/api/badges")


def api_list_visitors():
    return api_call("GET", "/api/visitors")


def api_register_visitor(fields):
    return api_call("POST", "/api/visitors", fields)


def api_decide_visitor(vid, decision):
    return api_call("POST", f"/api/visitors/{vid}/decide", {"decision": decision})


def api_checkin_visitor(vid, enroll_face):
    return api_call("POST", f"/api/visitors/{vid}/checkin", {"enroll_face": enroll_face})



def api_create_change_request(rid, fields):
    return api_call("POST", f"/api/visit_requests/{rid}/change_request", fields)

def api_list_change_requests():
    return api_call("GET", "/api/visitor_change_requests")

def api_decide_change_request(cid, decision, reason=""):
    return api_call("POST", f"/api/visitor_change_requests/{cid}/decide", {"decision": decision, "reason": reason})


def api_reschedule_visitor(vid, visit_date, expected_arrival, expected_departure):
    return api_call("POST", f"/api/visitors/{vid}/reschedule", {
        "visit_date": visit_date,
        "expected_arrival": expected_arrival,
        "expected_departure": expected_departure,
    })

def api_checkout_visitor(vid):
    return api_call("POST", f"/api/visitors/{vid}/checkout")

def api_create_visit_request(fields):
    return api_call("POST", "/api/visit_requests", fields)

def api_list_visit_requests():
    return api_call("GET", "/api/visit_requests")

def api_decide_visit_request(rid, decision, position=None, hsa_decision=None):
    payload = {"decision": decision, "position": position}
    if hsa_decision is not None:
        payload["hsa_decision"] = hsa_decision
    return api_call("POST", f"/api/visit_requests/{rid}/decide", payload)


def api_hsa_decide_visit_request(rid, decision):
    return api_call("POST", f"/api/visit_requests/{rid}/hsa_decide", {"decision": decision})


def api_assign_escort(rid, escort):
    return api_call("POST", f"/api/visit_requests/{rid}/assign_escort", {"escort": escort})


def api_send_to_guards(rid):
    return api_call("POST", f"/api/visit_requests/{rid}/send_to_guards")


def api_confirm_gate_entry(rid, rvid):
    return api_call("POST", f"/api/visit_requests/{rid}/visitors/{rvid}/gate_entry")


def api_create_walkin_request(fields):
    return api_call("POST", "/api/visit_requests/walkin", fields)


def api_forward_to_security(rid):
    return api_call("POST", f"/api/visit_requests/{rid}/forward_to_security")


def api_security_review(rid, decision, reason=None):
    payload = {"decision": decision}
    if reason is not None:
        payload["reason"] = reason
    return api_call("POST", f"/api/visit_requests/{rid}/security_review", payload)


def format_hsa_details_for_report(r, approved=False):
    """Format HSA area details in detailed format for reports.
    Returns a list of (label, value) tuples."""
    details = []
    hsa_areas = set(r["hsa_areas"]) if approved else set()
    
    details.append(("HSA Requested", "Yes" if r["hsa_requested"] else "No"))
    if r["hsa_requested"]:
        details.append(("Highest Security Area", "Yes" if "Highest Security Area" in hsa_areas else "No"))
        for room in HIGHEST_SECURITY_AREAS:
            details.append((room, "Yes" if room in hsa_areas else "No"))
        details.append(("Escorted by", r.get("hsa_escort") or "-"))
    
    return details

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
except Exception:
    # Broad except, not just ImportError: a packaged .exe with a missing DLL
    # raises a PyInstaller-specific error, not ImportError - and a missing
    # optional feature should never crash the whole app on startup.
    REPORTLAB_AVAILABLE = False

# WIA (Windows Image Acquisition) lets us trigger the printer/MFP's built-in
# scanner directly, the same way Windows' own "Scan" app does. Windows-only.
try:
    import win32com.client
    WIA_AVAILABLE = True
except Exception:
    WIA_AVAILABLE = False

# Pillow: needed to load/preview the scanned image inside the app.
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except Exception:
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
except Exception:
    OCR_AVAILABLE = False

# OpenCV: used for webcam capture (an alternative to the printer/WIA scanner -
# works on Windows, Mac, and Linux with any USB or built-in webcam).
try:
    import cv2
    CV2_AVAILABLE = True
except Exception:
    CV2_AVAILABLE = False

# pyzbar: decodes QR codes / barcodes from the scanned image. This is a bonus,
# best-effort feature - we don't know the internal data format used by every
# country's ID (e.g. Ethiopia's Fayda ID), so we surface the raw decoded
# content for the officer to review rather than guessing at field meanings.
try:
    from pyzbar.pyzbar import decode as zbar_decode
    PYZBAR_AVAILABLE = True
except Exception:
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
        "gender": {"M": "Male", "F": "Female"}.get(sex, ""),
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
        "gender": {"M": "Male", "F": "Female"}.get(sex, ""),
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

DEPARTMENTS = ["Marketing and Finance", "Head Office", "HR", "Production",
               "Quality", "IT & Security", "Technic", "Utility"]

# Original HSA room list used by the New Visitor Request checkbox.
HIGHEST_SECURITY_AREAS = ["Vault Room", "Data Processing Room", "Server Room"]

# NOTE: Accounts (including the bootstrap admin account and default new-account
# password) now live entirely on the VMS server - see vms_server.py. This
# client no longer has any account credentials baked into it.

STATUS_COLORS = {
    "Pending Approval": COLOR_WARNING,
    "Approved": COLOR_ACCENT,
    "Checked In": COLOR_SUCCESS,
    "Checked Out": COLOR_MUTED,
    "Rejected": COLOR_DANGER,
}

# NOTE: Visitors, badges, and the audit log all live on the VMS server now
# (see vms_server.py) - there is no local data store left in this client.
# Everything goes through the api_* functions defined above.


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


def set_window_icon(window):
    """Set the MKDSS icon on the window (appears on taskbar and title bar)."""
    if os.path.isfile(ICON_PATH):
        try:
            window.iconbitmap(ICON_PATH)
        except Exception:
            pass  # Icon file missing or invalid, continue without it


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


def show_toast(root_window, title, message, duration_ms=5000, bg_color="#4CAF50", text_color="white"):
    """Show a temporary notification pop-up in bottom right corner."""
    toast = tk.Toplevel(root_window)
    toast.geometry("360x100+{}+{}".format(
        root_window.winfo_screenwidth() - 390,
        root_window.winfo_screenheight() - 140
    ))
    toast.configure(bg=bg_color, highlightbackground=bg_color, highlightthickness=0)
    toast.attributes('-topmost', True)
    
    title_label = tk.Label(toast, text=title, font=("Segoe UI", 10, "bold"), 
                          bg=bg_color, fg=text_color, justify="left")
    title_label.pack(anchor="nw", padx=12, pady=(8, 0))
    
    msg_label = tk.Label(toast, text=message, font=("Segoe UI", 9), 
                        bg=bg_color, fg=text_color, wraplength=330, justify="left")
    msg_label.pack(anchor="nw", padx=12, pady=(2, 8))
    
    toast.after(duration_ms, lambda: toast.destroy() if toast.winfo_exists() else None)


def get_notification_type_icon(notif_type):
    """Return icon and color for notification type."""
    icons = {
        "approval_approved": ("✅", "#4CAF50"),      # Green
        "approval_rejected": ("❌", "#f44336"),      # Red
        "security_rejected": ("❌", "#f44336"),      # Red - Security rejected
        "checkin": ("✅", "#4CAF50"),               # Green
        "checkout": ("👋", "#9E9E9E"),             # Gray
        "checkin_ready": ("🔔", "#FF9800"),        # Orange - Ready for check-in
        "new_request": ("📋", "#2196F3"),          # Blue
        "hsa_review": ("⚠️", "#FF9800"),           # Orange - HSA review needed
        "system_alert": ("⚠️", "#f44336"),         # Red
    }
    return icons.get(notif_type, ("ℹ️", "#2196F3"))


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
# SIMPLE BUILT-IN CALENDAR DATE PICKER
# ----------------------------------------------------------------------
def open_date_picker(parent, target_var, initial_value=None):
    """Dependency-free calendar popup used for visit scheduling and monitoring."""
    try:
        selected = datetime.strptime(initial_value or target_var.get(), "%Y-%m-%d").date()
    except (TypeError, ValueError):
        selected = date.today()
    state = {"year": selected.year, "month": selected.month}
    win = tk.Toplevel(parent)
    win.title("Select Visit Date")
    win.configure(bg=COLOR_CARD)
    win.resizable(False, False)
    win.transient(parent)
    win.grab_set()

    header = tk.Frame(win, bg=COLOR_CARD)
    header.pack(fill="x", padx=12, pady=(12, 6))
    body = tk.Frame(win, bg=COLOR_CARD)
    body.pack(padx=12, pady=(0, 12))

    def redraw():
        for w in body.winfo_children():
            w.destroy()
        for w in header.winfo_children():
            w.destroy()
        month_name = calendar.month_name[state["month"]]
        ttk.Button(header, text="‹", width=3, command=prev_month).pack(side="left")
        tk.Label(header, text=f"{month_name} {state['year']}", font=FONT_H2,
                 bg=COLOR_CARD, fg=COLOR_TEXT, width=18).pack(side="left", padx=8)
        ttk.Button(header, text="›", width=3, command=next_month).pack(side="left")
        for col, name in enumerate(("Mo", "Tu", "We", "Th", "Fr", "Sa", "Su")):
            tk.Label(body, text=name, font=("Segoe UI", 9, "bold"),
                     bg=COLOR_CARD, fg=COLOR_MUTED, width=4).grid(row=0, column=col, pady=3)
        cal = calendar.monthcalendar(state["year"], state["month"])
        for r, week in enumerate(cal, start=1):
            for c, day_num in enumerate(week):
                if not day_num:
                    tk.Label(body, text="", bg=COLOR_CARD, width=4).grid(row=r, column=c)
                    continue
                d = date(state["year"], state["month"], day_num)
                btn = ttk.Button(body, text=str(day_num), width=3,
                                 command=lambda d=d: choose(d))
                btn.grid(row=r, column=c, padx=1, pady=1)

    def choose(d):
        target_var.set(d.isoformat())
        win.destroy()

    def prev_month():
        if state["month"] == 1:
            state["month"], state["year"] = 12, state["year"] - 1
        else:
            state["month"] -= 1
        redraw()

    def next_month():
        if state["month"] == 12:
            state["month"], state["year"] = 1, state["year"] + 1
        else:
            state["month"] += 1
        redraw()

    redraw()


# ----------------------------------------------------------------------
# MAIN APPLICATION
# ----------------------------------------------------------------------
class VMSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        set_window_icon(self)  # Set the MKDSS icon on window/taskbar
        self.title(APP_TITLE)
        self.geometry("1180x720")
        self.minsize(1024, 640)
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

        server_ip = load_server_address()
        if not server_ip:
            self._show_server_setup()
            return

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
                              wraplength=320, justify="left")
        error_lbl.pack(anchor="w", pady=(8, 0))

        def do_login():
            uname = user_var.get().strip().lower()
            pwd = pass_var.get()
            if not uname or not pwd:
                error_lbl.configure(text="Please enter both username and password.")
                return
            ok, result = api_login(uname, pwd)
            if not ok:
                error_lbl.configure(text=result if isinstance(result, str) else "Login failed.")
                return
            acct = result["user"]
            if acct.get("must_change_password", False):
                self.change_password(acct)
                return
            self._finish_login(acct)

        btn_row = tk.Frame(box, bg=COLOR_CARD)
        btn_row.pack(anchor="w", pady=(18, 0))
        ttk.Button(btn_row, text="Log In", style="Accent.TButton", command=do_login).pack(side="left")

        server_link = tk.Label(box, text=f"Server: {server_ip}   (change)", font=FONT_SMALL,
                                bg=COLOR_CARD, fg=COLOR_MUTED, cursor="hand2")
        server_link.pack(anchor="w", pady=(10, 0))

        def change_server():
            if os.path.isfile(SERVER_CONFIG_PATH):
                os.remove(SERVER_CONFIG_PATH)
            self._show_server_setup()
        server_link.bind("<Button-1>", lambda e: change_server())

        pass_entry.bind("<Return>", lambda e: do_login())
        user_entry.focus_set()

    def _show_server_setup(self):
        """Shown when this PC hasn't been told where the VMS server is yet -
        a one-time setup step per PC, not per login."""
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
        tk.Label(header_row, text="First-Time Setup", font=("Segoe UI", 18, "bold"),
                 bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
        tk.Label(box, text=APP_TITLE, font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED).pack(
            anchor="w", pady=(2, 20))

        tk.Label(box, text="This PC needs to know where the VMS server is running.\n"
                            "Ask your System Administrator for its IP address.",
                  font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT, wraplength=340, justify="left").pack(
            anchor="w", pady=(0, 14))

        tk.Label(box, text="Server IP Address", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w")
        ip_var = tk.StringVar()
        ip_entry = ttk.Entry(box, textvariable=ip_var, width=30)
        ip_entry.pack(anchor="w", pady=(2, 0))

        error_lbl = tk.Label(box, text="", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_DANGER,
                              wraplength=340, justify="left")
        error_lbl.pack(anchor="w", pady=(8, 0))

        def do_connect():
            ip = ip_var.get().strip()
            if not ip:
                error_lbl.configure(text="Please enter the server's IP address.")
                return
            save_server_address(ip)
            ok, result = api_ping()
            if not ok:
                error_lbl.configure(text=result if isinstance(result, str) else "Could not reach the server.")
                if os.path.isfile(SERVER_CONFIG_PATH):
                    os.remove(SERVER_CONFIG_PATH)
                return
            self.show_login()

        ttk.Button(box, text="Connect", style="Accent.TButton", command=do_connect).pack(
            anchor="w", pady=(16, 0))
        ip_entry.bind("<Return>", lambda e: do_connect())
        ip_entry.focus_set()

    def _finish_login(self, acct):
        """Common landing logic shared by normal login and post-password-change login.
        (The server already logs the login event itself inside /api/login.)"""
        self.current_user = acct["display"]
        self.current_role = acct["role"]
        self.host_name = acct["username"] if acct["role"] == "host" else None
        self.current_username = acct["username"]
        self._build_shell()
        default_page = {"officer": "Dashboard", "host": "My Overview", "admin": "User Management",
                         "approver": "Approve Requests", "guard": "Gate Approvals",
                         "security_manager": "Security Review"}
        self.show_page(default_page[self.current_role])
        self._start_notification_refresh()

    def change_password(self, acct):
        """Forced password-change dialog shown on first login for new accounts."""
        win = tk.Toplevel(self)
        win.title("Change Password")
        win.geometry("440x400")
        win.configure(bg=COLOR_CARD)
        win.grab_set()
        win.resizable(False, False)

        tk.Label(win, text="You must set a new password", font=FONT_H2,
                 bg=COLOR_CARD, fg=COLOR_TEXT).pack(pady=(20, 4))
        tk.Label(win, text=f"Account: {acct['display']} ({acct['username']})", font=FONT_SMALL,
                 bg=COLOR_CARD, fg=COLOR_MUTED).pack(pady=(0, 10))
        tk.Label(win, text="Must be at least 12 characters, and include an uppercase letter, "
                            "a lowercase letter, a number, and a special character.",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=360, justify="left").pack(
            padx=30, pady=(0, 14))

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
                              wraplength=360, justify="left")
        error_lbl.pack(padx=30, pady=(0, 6))

        def save():
            if newpass.get() != confirm.get():
                error_lbl.configure(text="Passwords do not match.")
                return
            policy_ok, policy_error = validate_password_policy(newpass.get())
            if not policy_ok:
                error_lbl.configure(text=policy_error)
                return
            ok, result = api_change_password(newpass.get())
            if not ok:
                error_lbl.configure(text=result if isinstance(result, str) else "Could not update password.")
                return
            messagebox.showinfo("Success", "Password updated.")
            win.destroy()
            self._finish_login(result["user"])

        ttk.Button(win, text="Save Password", style="Accent.TButton", command=save).pack(pady=16)
        confirm_entry.bind("<Return>", lambda e: save())

    def logout(self):
        if self.current_user:
            api_log("Logout", "Success", "")  # while the token is still valid
            api_logout()  # invalidates the token server-side
        if getattr(self, "_notification_after_id", None):
            self.after_cancel(self._notification_after_id)
            self._notification_after_id = None
        self.current_user = None
        self.current_role = None
        self.host_name = None
        self.current_username = None
        self.show_login()

    def _start_notification_refresh(self):
        """Start auto-refresh of notification bell every 30 seconds."""
        def refresh_notifications():
            if not self.winfo_exists():
                return
            ok, result = api_unread_count()
            if ok:
                unread = result.get("unread_count", 0)
                if hasattr(self, 'notification_bell_label'):
                    self.notification_bell_label.configure(text=f"🔔 {unread}")
            
            # Schedule next refresh in 30 seconds
            self._notification_after_id = self.after(30000, refresh_notifications)
        
        refresh_notifications()

    # --------------- shell / navigation ----------------
    def _build_shell(self):
        # _build_shell runs again on every login/role-switch. The mousewheel
        # bindings set up below are global (bind_all), so without this they'd
        # pile up across logins and reference already-destroyed canvases.
        self.unbind_all("<MouseWheel>")
        self.unbind_all("<Button-4>")
        self.unbind_all("<Button-5>")
        if getattr(self, "_notification_after_id", None):
            self.after_cancel(self._notification_after_id)
            self._notification_after_id = None

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
        elif self.current_role == "approver":
            role_label = "Factory Manager (Approver)"
        elif self.current_role == "guard":
            role_label = "Security Guard (Gate)"
        elif self.current_role == "security_manager":
            role_label = "Security Manager"
        else:
            role_label = "Host / Employee"
        tk.Label(sidebar, text=role_label, font=FONT_SMALL,
                 bg=COLOR_SIDEBAR, fg="#8a93a6").pack(anchor="w", padx=20, pady=(0, 24))

        self.nav_buttons = {}
        if self.current_role == "admin":
            # Admin is focused on account control + oversight, not day-to-day
            # visitor operations - that separation of duties is the whole
            # point of splitting this out. (Flagged for you - see chat.)
            # Approve Requests / Security Review are included here too, but
            # only as a neutral fallback for conflict-of-interest cases (e.g.
            # the Factory Manager or Security Manager is the one being
            # visited) - not for routine day-to-day approvals.
            pages = [
                ("User Management", "👥"), ("System Monitor", "🖥️"),
                ("Dashboard", "📊"), ("Notifications", "🔔"),
                ("Audit Log", "🧾"),
                ("Approve Requests", "🗳️"), ("Security Review", "🛡️"),
            ]
        elif self.current_role == "officer":
            pages = [
                ("Dashboard", "📊"), ("Notifications", "🔔"),
                ("Visitor Registration", "📝"),
                ("Walk-In Requests", "🚶"),
                ("Check-In", "✅"), ("Check-Out", "🚪"),
                ("Authorization Forms", "🖨️"),
                ("Badge Management", "🪪"), ("Search", "🔍"),
                ("Reports", "📈"),
            ]
        elif self.current_role == "approver":
            # Factory Manager: reviews group Visitor Requests submitted by Hosts
            # (mirrors Part II - Approval - of the paper Visitor Request form),
            # and walk-in requests forwarded by the Security Manager. They can
            # ALSO submit their own pre-planned visitor requests, same as a
            # Host, for visitors expected to see them specifically.
            pages = [
                ("Approve Requests", "🗳️"),
                ("Notifications", "🔔"),
                ("New Visitor Request", "📝"), ("My Requests", "🧾"),
            ]
        elif self.current_role == "guard":
            # Gate Guard: logs unannounced walk-ins, and sees authorizations
            # the Officer/Security Manager has explicitly sent electronically.
            pages = [
                ("Report Walk-In Visitor", "🚶"), ("Gate Approvals", "🛂"),
                ("Notifications", "🔔"),
            ]
        elif self.current_role == "security_manager":
            # Security Manager: middle checkpoint for walk-in visitors -
            # reviews what the Officer forwarded (can reject outright, or
            # forward to the Factory Manager), then after authorization,
            # assigns the escort and sends to the guards. They can ALSO
            # submit their own pre-planned visitor requests, same as a Host,
            # for visitors expected to see them specifically.
            pages = [
                ("Security Review", "🛡️"), ("Security Review History", "📋"),
                ("HSA & Schedule Requests", "🔐"),
                ("Walk-In Authorization", "🖨️"),
                ("Notifications", "🔔"),
                ("New Visitor Request", "📝"), ("My Requests", "🧾"),
            ]
        else:
            # Host: submits group visitor requests (mirrors the paper Visitor
            # Request form) - the Factory Manager approves/rejects them, the
            # host does NOT approve their own requests.
            pages = [
                ("My Overview", "📊"), ("New Visitor Request", "📝"),
                ("Notifications", "🔔"),
                ("My Requests", "🧾"), ("My Visit History", "🕘"),
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
        logout_btn = tk.Label(sidebar, text="⏻  Log Out", font=FONT_SMALL,
                               bg=COLOR_SIDEBAR, fg="#e2a03f", anchor="w", cursor="hand2")
        logout_btn.pack(anchor="w", padx=20, pady=(0, 20))
        logout_btn.bind("<Button-1>", lambda e: self.logout())

        self.active_page = None

        # Top bar with notification bell
        top_bar = tk.Frame(self, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        top_bar.pack(side="top", fill="x", padx=0, pady=0)
        
        top_bar_inner = tk.Frame(top_bar, bg=COLOR_CARD)
        top_bar_inner.pack(fill="x", padx=20, pady=10)
        
        # Notification bell (left side for balance)
        self.notification_bell_label = tk.Label(
            top_bar_inner, text="🔔 0", font=("Segoe UI", 10),
            bg=COLOR_CARD, fg=COLOR_ACCENT, cursor="hand2"
        )
        self.notification_bell_label.pack(side="left")
        self.notification_bell_label.bind("<Button-1>", lambda e: self.show_page("Notifications"))
        
        # Spacer
        tk.Frame(top_bar_inner, bg=COLOR_CARD).pack(side="left", fill="x", expand=True)
        
        # User info (right side)
        user_info_frame = tk.Frame(top_bar_inner, bg=COLOR_CARD)
        user_info_frame.pack(side="right")
        tk.Label(user_info_frame, text=f"👤 {self.current_user}", font=FONT_SMALL,
                 bg=COLOR_CARD, fg=COLOR_MUTED).pack(side="right")

        # Admin-only: Change My Password button
        if self.current_role == "admin":
            ttk.Button(
                user_info_frame,
                text="Change My Password",
                command=self.admin_change_password
            ).pack(side="right", padx=(0, 12))
        # Scrollable content area - some pages (like Visitor Registration)
        # have more content than fits in the window, and there was previously
        # no way to reach anything below the fold. Every page still just
        # builds into self.content exactly as before; the scrolling is
        # transparent to them.
        content_container = tk.Frame(self, bg=COLOR_BG)
        content_container.pack(side="left", fill="both", expand=True)

        canvas = tk.Canvas(content_container, bg=COLOR_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(content_container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.content = tk.Frame(canvas, bg=COLOR_BG)
        content_window = canvas.create_window((0, 0), window=self.content, anchor="nw")

        def on_content_configure(event, canvas=canvas):
            canvas.configure(scrollregion=canvas.bbox("all"))
        self.content.bind("<Configure>", on_content_configure)

        def on_canvas_configure(event, canvas=canvas, window=content_window):
            canvas.itemconfig(window, width=event.width)
        canvas.bind("<Configure>", on_canvas_configure)

        def on_mousewheel(event, canvas=canvas):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        def on_mousewheel_linux_up(event, canvas=canvas):
            canvas.yview_scroll(-1, "units")
        def on_mousewheel_linux_down(event, canvas=canvas):
            canvas.yview_scroll(1, "units")
        canvas.bind_all("<MouseWheel>", on_mousewheel)         # Windows / Mac
        canvas.bind_all("<Button-4>", on_mousewheel_linux_up)   # Linux scroll up
        canvas.bind_all("<Button-5>", on_mousewheel_linux_down)  # Linux scroll down

        if self.current_role in ("host", "security_manager", "approver"):
            self._start_host_notification_polling()
        elif self.current_role == "guard":
            self._start_guard_notification_polling()

    def _start_host_notification_polling(self):
        """While a Host (or Security Manager / Factory Manager, for their own
        submitted requests) is logged in with the app open, quietly check
        every 30 seconds for the Factory Manager's decision on requests they
        submitted, and pop up an alert only for newly-decided ones (no
        external email/SMS needed - this only works while the app itself is
        open). They do NOT approve anything themselves - they're just
        notified once the Factory Manager (Approver) has made a decision."""
        self._known_decided_ids = None  # None = "not established yet", set on first check
        self._poll_host_notifications()

    def _poll_host_notifications(self):
        if self.current_role not in ("host", "security_manager", "approver") or not self.current_user:
            return  # user logged out or switched roles - stop polling
        ok, result = api_list_visit_requests()
        if ok:
            mine_decided = {r["id"]: r for r in result["requests"]
                             if r["host_username"] == self.current_username
                             and r["status"] != "Pending Approval"}
            if self._known_decided_ids is None:
                # First check after login - these are already visible on
                # "My Requests", so don't pop up for ones already decided.
                self._known_decided_ids = set(mine_decided.keys())
            else:
                new_ids = set(mine_decided.keys()) - self._known_decided_ids
                if new_ids:
                    self._show_decision_popup([mine_decided[i] for i in new_ids])
                self._known_decided_ids = set(mine_decided.keys())
        # Keep polling regardless of success - a momentary network hiccup
        # shouldn't permanently stop notifications.
        self._notification_after_id = self.after(30000, self._poll_host_notifications)

    def _show_decision_popup(self, decided_requests):
        count = len(decided_requests)
        lines = "\n".join(
            f"  • Request #{r['id']} ({r['company']}) - {r['status']}"
            + (f"  |  HSA: {r['hsa_decision']}" if r.get("hsa_requested") else "")
            for r in decided_requests)
        messagebox.showinfo(
            "Visit Request Decided" if count == 1 else "Visit Requests Decided",
            f"The Factory Manager has decided on {count} of your visit request{'s' if count > 1 else ''}:\n\n"
            f"{lines}\n\nCheck 'My Requests' for details.")

    def _start_guard_notification_polling(self):
        """While a guard is logged in with the app open, quietly check every 30
        seconds for newly-sent authorizations from the Officer, and pop up an
        alert for new ones - this is what replaces physically walking a
        printed form out to the gate."""
        self._known_sent_ids = None  # None = "not established yet", set on first check
        self._poll_guard_notifications()

    def _poll_guard_notifications(self):
        if self.current_role != "guard" or not self.current_user:
            return  # user logged out or switched roles - stop polling
        ok, result = api_list_visit_requests()
        if ok:
            sent = {r["id"]: r for r in result["requests"] if r["sent_to_guards"]}
            if self._known_sent_ids is None:
                # First check after login - these are already visible on
                # "Gate Approvals", so don't pop up for them.
                self._known_sent_ids = set(sent.keys())
            else:
                new_ids = set(sent.keys()) - self._known_sent_ids
                if new_ids:
                    self._show_new_authorization_popup([sent[i] for i in new_ids])
                self._known_sent_ids = set(sent.keys())
        self._notification_after_id = self.after(30000, self._poll_guard_notifications)

    def _show_new_authorization_popup(self, new_requests):
        count = len(new_requests)
        lines = "\n".join(
            f"  • {r['company']} - {len(r['visitors'])} visitor(s) - Escort: {r['escort']}"
            for r in new_requests)
        messagebox.showinfo(
            "New Authorization Received" if count == 1 else "New Authorizations Received",
            f"{count} new visitor authorization{'s' if count > 1 else ''} sent from the Officer:\n\n"
            f"{lines}\n\nCheck 'Gate Approvals' to review.")

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
            "Notifications": self.page_notifications,
            "User Management": self.page_user_management,
            "System Monitor": self.page_system_monitor,
            "My Overview": self.page_host_overview,
            "New Visitor Request": self.page_host_new_request,
            "My Requests": self.page_host_my_requests,
            "My Visit History": self.page_host_history,
            "Approve Requests": self.page_approver_requests,
            "Authorization Forms": self.page_authorization_forms,
            "Gate Approvals": self.page_guard_approvals,
            "Report Walk-In Visitor": self.page_guard_report_walkin,
            "Walk-In Requests": self.page_officer_walkin_requests,
            "Security Review": self.page_security_review,
            "HSA & Schedule Requests": self.page_hsa_schedule_requests,
            "Security Review History": self.page_security_review_history,
            "Walk-In Authorization": self.page_security_walkin_authorization,
        }
        builders[name]()

    # ---------------- DASHBOARD ----------------
    def page_dashboard(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)

        section_title(wrap, "Dashboard", "Live overview of today's visitor activity").pack(
            anchor="w", pady=(0, 16))

        ok_v, res_v = api_list_visitors()
        ok_b, res_b = api_list_badges()
        if not ok_v or not ok_b:
            tk.Label(wrap, text=f"⚠ Could not load data from the server:\n{res_v if not ok_v else res_b}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        visitors = res_v["visitors"]
        badges = res_b["badges"]

        today_str = date.today().isoformat()
        expected_today = [v for v in visitors if v["visit_date"] == today_str]
        inside = [v for v in visitors if v["status"] == "Checked In"]
        def dashboard_checkout_is_today(v):
            value = str(v.get("check_out_time") or "").strip()
            if not value:
                return False
            try:
                if "T" in value:
                    return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat() == today_str
                if " " in value:
                    return datetime.fromisoformat(value).date().isoformat() == today_str
                if len(value) == 5 and value[2] == ":":
                    return str(v.get("visit_date") or "") == today_str
            except (TypeError, ValueError):
                pass
            return False
        checked_out = [v for v in visitors if v["status"] == "Checked Out" and dashboard_checkout_is_today(v)]
        pending = [v for v in visitors if v["status"] == "Pending Approval"]
        available_badges = [b for b in badges if b["status"] == "Available"]

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
        for v in sorted(visitors, key=lambda x: -x["id"]):
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

        tk.Label(scan_inner, text="  Reads the document's MRZ (machine-readable zone) via OCR "
                                    "and auto-fills the form below.\n  Review and correct before "
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
        card.pack(fill="x")
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

        ok, result = api_list_users()
        host_accounts = [u for u in result["users"] if u["role"] == "host" and u["active"]] if ok else []
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

        if not ok:
            tk.Label(form, text=f"⚠ Could not load host accounts from the server: {result}",
                      font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_DANGER, wraplength=700,
                      justify="left").grid(row=9, column=0, columnspan=3, sticky="w", padx=6, pady=(4, 0))
        elif not host_accounts:
            tk.Label(form, text="⚠ No host accounts exist yet. Ask a System Administrator to create "
                                 "host accounts under 'User Management' first - each one is tied to a "
                                 "department.",
                      font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_WARNING, wraplength=700,
                      justify="left").grid(row=9, column=0, columnspan=3, sticky="w", padx=6, pady=(4, 0))

        self.reg_vars["expected_arrival"] = labeled_entry(form, "Expected Arrival (HH:MM)", 5, 0)
        self.reg_vars["expected_departure"] = labeled_entry(form, "Expected Departure (HH:MM)", 5, 1)
        self.reg_vars["visit_date"] = labeled_entry(form, "Visit Date (YYYY-MM-DD)", 5, 2)
        self.reg_vars["visit_date"].set(date.today().isoformat())
        ttk.Button(form, text="📅 Calendar", command=lambda: open_date_picker(
            self, self.reg_vars["visit_date"])).grid(row=11, column=3, sticky="w", padx=6, pady=(0, 4))
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

        fields = dict(
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
            visit_date=visit_date.isoformat(),
            notes=self.reg_notes.get("1.0", "end").strip(),
            # Direct officer registration (e.g. walk-ins) is already vouched
            # for by the officer on the spot, so it goes straight to Approved
            # and can be checked in right away - it does NOT go through the
            # Factory Manager approval step (that's for group visitor
            # requests submitted by a Host - see "New Visitor Request").
            status="Approved",
        )
        ok, result = api_register_visitor(fields)
        if not ok:
            messagebox.showerror("Could Not Register Visitor", result if isinstance(result, str) else str(result))
            return
        vid = result["id"]
        messagebox.showinfo("Registered",
                             f"Visitor registered (ID #{vid}) and approved for check-in.\n"
                             f"Host '{self.reg_vars['host'].get()}' has been recorded.")
        self.show_page("Visitor Registration")

    # ---------------- CHECK-IN ----------------
    def page_checkin(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Visitor Check-In",
                      "Only visitors already approved by their host can be checked in").pack(
            anchor="w", pady=(0, 16))

        ok, result = api_list_visitors()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load visitors from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        visitors = result["visitors"]

        pending = [v for v in visitors if v["status"] == "Pending Approval"]
        if pending:
            tk.Label(wrap, text=f"⏳ {len(pending)} visitor(s) still awaiting host approval - "
                                 "they'll appear below once their host approves them.",
                      font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_WARNING).pack(anchor="w", pady=(0, 10))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Company", "Host", "Department", "Status")
        tree = make_table(card, cols, (40, 150, 150, 120, 140, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        approved = [v for v in visitors if v["status"] == "Approved"]
        now = datetime.now()
        for v in approved:
            display_status = "Expected"
            try:
                scheduled = datetime.strptime(f"{v.get('visit_date')} {str(v.get('expected_arrival') or '')[:5]}", "%Y-%m-%d %H:%M")
                if scheduled < now:
                    display_status = "Late"
                elif scheduled.date() > now.date():
                    display_status = "Future"
            except (TypeError, ValueError):
                pass
            tree.insert("", "end", iid=v["id"], values=(
                v["id"], f'{v["first_name"]} {v["last_name"]}', v["company"],
                v["host"], v["department"], display_status))
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
            vid = int(sel[0])
            v = next(x for x in visitors if x["id"] == vid)
            ok, result = api_checkin_visitor(vid, enroll_face.get())
            if not ok:
                messagebox.showerror("Check-In Failed", result if isinstance(result, str) else str(result))
                return
            badge_no = result["badge_no"]
            messagebox.showinfo("Checked In",
                                 f"{v['first_name']} {v['last_name']} checked in.\n"
                                 f"Badge assigned: {badge_no}\n"
                                 f"ACS access: Activated"
                                 f"{'  |  Face enrollment: Complete' if enroll_face.get() else ''}")
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

        ok, result = api_list_visitors()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load visitors from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        visitors = result["visitors"]

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Badge", "Department", "Check-In Time")
        tree = make_table(card, cols, (40, 160, 100, 150, 130))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        inside = [v for v in visitors if v["status"] == "Checked In"]
        for v in inside:
            tree.insert("", "end", iid=v["id"], values=(
                v["id"], f'{v["first_name"]} {v["last_name"]}', v["badge_no"],
                v["department"], v["check_in_time"]))

        def checkout():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a visitor", "Please select a visitor first.")
                return
            vid = int(sel[0])
            v = next(x for x in visitors if x["id"] == vid)
            ok, result = api_checkout_visitor(vid)
            if not ok:
                messagebox.showerror("Check-Out Failed", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Checked Out",
                                 f"{v['first_name']} {v['last_name']} checked out.\n"
                                 f"Badge {v['badge_no']} is now Available for reuse.\n"
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

        ok_b, res_b = api_list_badges()
        ok_v, res_v = api_list_visitors()
        if not ok_b or not ok_v:
            tk.Label(wrap, text=f"⚠ Could not load data from the server:\n{res_b if not ok_b else res_v}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        badges = res_b["badges"]
        visitors_by_id = {v["id"]: v for v in res_v["visitors"]}

        top = tk.Frame(wrap, bg=COLOR_BG)
        top.pack(fill="x", pady=(0, 14))
        avail = len([b for b in badges if b["status"] == "Available"])
        assigned = len(badges) - avail
        stat_card(top, "Total Badges", len(badges), COLOR_ACCENT).pack(side="left", padx=(0, 10))
        stat_card(top, "Available", avail, COLOR_SUCCESS).pack(side="left", padx=(0, 10))
        stat_card(top, "Assigned", assigned, COLOR_WARNING).pack(side="left")

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("Badge #", "Status", "Assigned Visitor", "Department", "QR Payload (illustrative)")
        tree = make_table(card, cols, (100, 110, 180, 150, 260))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        for b in badges:
            visitor_name = "-"
            dept = "-"
            if b["visitor_id"]:
                v = visitors_by_id.get(b["visitor_id"])
                if v:
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

        ok, result = api_list_visitors()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load visitors from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        visitors = result["visitors"]

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
            for v in visitors:
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

        ok, result = api_list_visitors()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load visitors from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        all_visitors = result["visitors"]

        bar = tk.Frame(wrap, bg=COLOR_BG)
        bar.pack(fill="x", pady=(0, 14))
        
        # Report type selector
        report_type = tk.StringVar(value="Daily Visitor Report")
        options = ["Daily Visitor Report", "Weekly Visitor Report", "Monthly Visitor Report",
                   "Visitors Currently Inside", "Overstayed Visitors", "Badge Usage Report",
                   "Department Visitor Report", "Host Visitor Report"]
        ttk.Combobox(bar, textvariable=report_type, values=options, state="readonly",
                     width=32).pack(side="left", padx=(0, 10))
        
        # Date picker for report date
        tk.Label(bar, text="Report Date:", bg=COLOR_BG, font=FONT_BODY).pack(side="left")
        report_date = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
        ttk.Entry(bar, textvariable=report_date, width=12, font=FONT_SMALL).pack(side="left", padx=5)
        tk.Label(bar, text="(YYYY-MM-DD)", bg=COLOR_BG, font=FONT_SMALL, fg=COLOR_MUTED).pack(side="left")

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True, pady=(14, 0))
        cols = ("Visitor", "Visit Date", "Check-In Time", "Check-Out Time", "Company", "Host", "Department", "Badge", "Status")
        tree = make_table(card, cols, (120, 90, 100, 100, 120, 100, 110, 70, 100))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        def generate():
            tree.delete(*tree.get_children())
            rtype = report_type.get()
            selected_date_str = report_date.get().strip()
            
            # Fetch fresh visitor data
            ok, response = api_call("GET", "/api/visitors")
            if not ok:
                messagebox.showerror("Error", f"Could not fetch visitor data from server")
                return
            
            # Extract visitors from response - API returns {"ok": True, "visitors": [...]}
            rows = []
            if isinstance(response, dict) and "visitors" in response:
                rows = response["visitors"]
            elif isinstance(response, list):
                rows = response
            else:
                messagebox.showerror("Error", "Unexpected data format from server")
                return
            
            if not rows:
                messagebox.showinfo("No Data", "No visitors found in database")
                return
            
            # Parse selected date for filtering
            selected_date = None
            try:
                if selected_date_str:
                    selected_date = datetime.strptime(selected_date_str, "%Y-%m-%d").date()
            except:
                messagebox.showerror("Invalid Date", f"Please use format: YYYY-MM-DD")
                return
            
            # Filter and display rows
            rows_count = 0
            for v in rows:
                try:
                    # Get visitor name
                    first_name = v.get("first_name", "")
                    last_name = v.get("last_name", "")
                    visitor_name = f"{first_name} {last_name}".strip() or "-"
                    
                    # Get visit_date (YYYY-MM-DD format from database)
                    visit_date = v.get("visit_date", "-")
                    
                    # Filter based on report type and date
                    include = True
                    
                    if rtype == "Daily Visitor Report" and selected_date:
                        # Show only visitors for the selected date
                        include = str(visit_date) == selected_date_str
                    elif rtype == "Weekly Visitor Report" and selected_date:
                        # Show visitors from the week containing selected date
                        try:
                            visitor_date = datetime.strptime(str(visit_date), "%Y-%m-%d").date()
                            week_start = selected_date - timedelta(days=selected_date.weekday())
                            week_end = week_start + timedelta(days=6)
                            include = week_start <= visitor_date <= week_end
                        except:
                            include = False
                    elif rtype == "Monthly Visitor Report" and selected_date:
                        # Show visitors from the month containing selected date
                        try:
                            visitor_date = datetime.strptime(str(visit_date), "%Y-%m-%d").date()
                            include = visitor_date.year == selected_date.year and visitor_date.month == selected_date.month
                        except:
                            include = False
                    elif rtype == "Visitors Currently Inside":
                        # Show only checked-in visitors (no date filter)
                        include = v.get("status") == "Checked In"
                    elif rtype == "Overstayed Visitors":
                        # Show only checked-in visitors (no date filter)
                        include = v.get("status") == "Checked In"
                    
                    if include:
                        # Get other fields
                        company = v.get("company", "-")
                        host = v.get("host", "-")
                        department = v.get("department", "-")
                        badge_no = v.get("badge_no") or "-"
                        status = v.get("status", "-")
                        
                        # Normalize timestamps for both the on-screen report and
                        # CSV/PDF exports. Handles normal and ISO-8601 timestamps.
                        check_in_time = format_report_time(v.get("check_in_time"))
                        check_out_time = format_report_time(v.get("check_out_time"))
                        
                        tree.insert("", "end", values=(
                            visitor_name, visit_date, check_in_time, check_out_time, company, host,
                            department, badge_no, status))
                        rows_count += 1
                except Exception as e:
                    # Skip malformed records
                    continue
            
            if rows_count == 0:
                if rtype in ["Daily Visitor Report", "Weekly Visitor Report", "Monthly Visitor Report"]:
                    messagebox.showinfo("No Results", f"No visitors found for {rtype}\nDate: {selected_date_str}")
                else:
                    messagebox.showinfo("No Results", "No visitors match the criteria")
            
            api_log("Report Generation", "Success", f"{rtype} - {rows_count} rows")

        def export_csv():
            filename = f"{report_type.get().replace(' ', '_')}_{datetime.now():%Y%m%d_%H%M%S}.csv"
            path = os.path.join(REPORTS_DIR, filename)
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                for iid in tree.get_children():
                    writer.writerow(tree.item(iid)["values"])
            api_log("Report Export", "Success", f"CSV: {filename}")
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
                # Explicit widths keep Check-In/Check-Out columns visible on
                # landscape A4 instead of allowing automatic sizing to squeeze
                # or clip the time columns.
                table = Table(
                    rows_data,
                    colWidths=[100, 55, 70, 70, 90, 80, 90, 60, 75],
                    repeatRows=1,
                )
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
                api_log("Report Export", "Success", f"PDF: {filename}")
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
                api_log("Report Export", "Success", f"HTML (PDF fallback): {filename}")
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

    # ---------------- OFFICER: AUTHORIZATION FORMS ----------------
    def page_authorization_forms(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Authorization Forms",
                      "Assign a factory escort, then send the authorization electronically to the "
                      "gate guards (or print it) for approved requests").pack(anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load requests from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        approved = [r for r in result["requests"] if r["status"] == "Approved"]

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Requested By", "Company", "Purpose", "Visitors", "HSA", "Escort", "Sent to Guards")
        tree = make_table(card, cols, (40, 120, 130, 140, 60, 90, 130, 110))
        tree.pack(fill="both", expand=True, padx=14, pady=14)
        for r in approved:
            hsa_text = "-"
            if r["hsa_requested"]:
                hsa_text = r["hsa_decision"] or "Pending"
            tree.insert("", "end", iid=r["id"], values=(
                r["id"], r["requested_by"], r["company"], r["purpose"],
                len(r["visitors"]), hsa_text, r["escort"] or "⚠ Not assigned",
                f'✓ {r["sent_to_guards_at"]}' if r["sent_to_guards"] else "Not sent"))
        if not approved:
            tk.Label(card, text="No approved requests yet. Once the Factory Manager approves a "
                                 "Host's visit request, it will appear here.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=700, justify="left").pack(
                anchor="w", padx=14, pady=(0, 14))

        tk.Label(card, text="Every visitor must have a factory escort assigned - someone who "
                             "accompanies them everywhere on site - before you can send the "
                             "authorization to the guards or print it.", font=FONT_SMALL, bg=COLOR_CARD,
                  fg=COLOR_MUTED, wraplength=900, justify="left").pack(anchor="w", padx=14, pady=(0, 8))

        def get_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a request", "Please select an approved request first.")
                return None
            rid = int(sel[0])
            return next(x for x in approved if x["id"] == rid)

        def assign_escort():
            r = get_selected()
            if not r:
                return
            self._open_assign_escort_dialog(r)

        def require_escort(r):
            if not r["escort"]:
                messagebox.showerror("Escort Not Assigned",
                                      "This visitor(s) don't have a factory escort assigned yet.\n\n"
                                      "Click 'Assign Escort' first.")
                return False
            return True

        def send_to_guards():
            r = get_selected()
            if not r or not require_escort(r):
                return
            ok, result = api_send_to_guards(r["id"])
            if not ok:
                messagebox.showerror("Could Not Send", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Sent to Guards",
                                 f"Authorization for request #{r['id']} ({r['company']}) has been sent "
                                 f"electronically to the gate guards. They'll see it immediately on "
                                 f"their 'Gate Approvals' screen.")
            self.show_page("Authorization Forms")

        def generate():
            r = get_selected()
            if not r or not require_escort(r):
                return
            self._generate_authorization_form(r)

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Assign Escort", command=assign_escort).pack(side="left")
        ttk.Button(btns, text="Send to Guards", style="Accent.TButton",
                   command=send_to_guards).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Generate Authorization Form (PDF)",
                   command=generate).pack(side="left", padx=(8, 0))

    def _open_assign_escort_dialog(self, r):
        win = tk.Toplevel(self)
        win.title(f"Assign Escort - Request #{r['id']}")
        win.configure(bg=COLOR_CARD)
        win.grab_set()
        win.resizable(False, False)

        tk.Label(win, text="Assign Factory Escort", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=18, pady=(16, 4))
        visitor_names = ", ".join(f'{v["first_name"]} {v["last_name"]}' for v in r["visitors"])
        tk.Label(win, text=f"For: {visitor_names}\nCompany: {r['company']}", font=FONT_SMALL,
                  bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=380, justify="left").pack(
            anchor="w", padx=18, pady=(0, 12))

        tk.Label(win, text="Escort Name (factory staff who will accompany them everywhere on site) *",
                  font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT, wraplength=380, justify="left").pack(
            anchor="w", padx=18)
        escort_var = tk.StringVar(value=r["escort"] or "")
        entry = ttk.Entry(win, textvariable=escort_var, width=34)
        entry.pack(anchor="w", padx=18, pady=(4, 12))

        error_lbl = tk.Label(win, text="", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_DANGER,
                              wraplength=380, justify="left")
        error_lbl.pack(anchor="w", padx=18)

        def save():
            name = escort_var.get().strip()
            if not name:
                error_lbl.configure(text="Escort name is required.")
                return
            ok, result = api_assign_escort(r["id"], name)
            if not ok:
                error_lbl.configure(text=result if isinstance(result, str) else "Could not assign escort.")
                return
            win.destroy()
            self.show_page("Authorization Forms")

        ttk.Button(win, text="Save Escort", style="Accent.TButton", command=save).pack(
            anchor="w", padx=18, pady=(0, 16))
        entry.bind("<Return>", lambda e: save())
        entry.focus_set()

    def _generate_authorization_form(self, r):
        """Builds the printable Visitor Authorization Form for the security guards,
        matching MKDSS's actual paper template (To / From / Subject / Organization /
        Purpose / Authorized Department / Visitor Names / Security Instructions)."""
        filename = f"Visitor_Authorization_Request_{r['id']}_{datetime.now():%Y%m%d_%H%M%S}.pdf"
        path = os.path.join(REPORTS_DIR, filename)

        visitor_names = [f'{v["first_name"]} {v["last_name"]}' for v in r["visitors"]]
        hsa_approved = r["hsa_requested"] and r["hsa_decision"] == "Approved"
        checked_areas = set(r["hsa_areas"]) if hsa_approved else set()
        if not r["hsa_requested"]:
            # A plain (non-HSA) approved request is understood as office-area access,
            # matching the paper form's default reading for a normal business visit.
            checked_areas = {"Office area"}

        if REPORTLAB_AVAILABLE:
            doc = SimpleDocTemplate(path, pagesize=A4, topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                                     leftMargin=2 * cm, rightMargin=2 * cm)
            styles = getSampleStyleSheet()
            bold = styles["Normal"].clone("bold")
            bold.fontName = "Helvetica-Bold"

            def field(label, value):
                return Paragraph(f"<b>{label}:</b> {value}", styles["Normal"])

            elements = [
                Paragraph("MKDSS Smart Card Factory - Visitor Authorization", styles["Title"]),
                Spacer(1, 4),
                field("To", "Security Guards - Main Gate &amp; Production Area Checkpoints"),
                field("From", r["approved_by"] or "-"),
                field("Date", r["decision_date"] or "-"),
                Spacer(1, 10),
                Paragraph("<u><b>Subject: Approval for Visitor Access to visit the Factory</b></u>",
                          styles["Normal"]),
                Spacer(1, 10),
                field("Organization / Company", r["company"]),
                field("Purpose of Visit", r["purpose"]),
                field("Authorized Department", r["department"] or "-"),
                field("Date &amp; Time of Visit", f'{r["visit_date"]}   {r["start_visit"]} - {r["finish_visit"]}'),
                field("Requested By (Host)", r["requested_by"]),
                Spacer(1, 10),
                Paragraph(f'<b>Factory Escort (accompanies visitor(s) at all times):</b> '
                          f'<font color="#c0392b"><b>{r["escort"] or "NOT ASSIGNED"}</b></font>',
                          styles["Normal"]),
                Spacer(1, 10),
                Paragraph("<b>Name of Visitor(s):</b>", styles["Normal"]),
            ]
            for i, name in enumerate(visitor_names, start=1):
                elements.append(Paragraph(f"{i}. {name}", styles["Normal"]))
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("<b>Security Instructions - HSA Access Details:</b>",
                                       styles["Normal"]))
            hsa_details = format_hsa_details_for_report(r, approved=hsa_approved)
            for label, value in hsa_details:
                elements.append(Paragraph(f"&nbsp;&nbsp;<b>{label}:</b> {value}", styles["Normal"]))
            elements.append(Spacer(1, 20))
            elements.append(Paragraph(
                "Your strict compliance with the Factory Security procedure and instructions is "
                "mandatory to maintain the integrity and confidentiality of our operations. Please "
                "report any irregularity immediately to the Factory Manager's Office.",
                styles["Normal"]))
            elements.append(Spacer(1, 24))
            elements.append(Paragraph(f"Approved by: {r['approved_by'] or '-'}  "
                                       f"({r['approver_position'] or 'Factory Manager'})", styles["Normal"]))
            elements.append(Paragraph(f"Printed by: {self.current_user}  on  "
                                       f"{datetime.now():%Y-%m-%d %H:%M}", styles["Normal"]))

            doc.build(elements)
            api_log("Authorization Form", "Success", f"Generated for request #{r['id']}: {filename}")
            if messagebox.askyesno("Generated", f"Authorization Form saved as:\n{path}\n\nOpen the folder now?"):
                open_in_file_explorer(path)
        else:
            html_path = path.replace(".pdf", ".html")
            hsa_details = format_hsa_details_for_report(r, approved=hsa_approved)
            hsa_detail_rows = "".join(
                f'<p style="margin-left: 20px;"><b>{label}:</b> {value}</p>' 
                for label, value in hsa_details)
            visitor_rows = "".join(f"<li>{n}</li>" for n in visitor_names)
            html = f"""<html><head><meta charset="utf-8"><title>Visitor Authorization</title>
            <style>body {{ font-family: Segoe UI, Arial, sans-serif; margin: 30px; }}
            h1 {{ font-size: 18px; }} p {{ margin: 4px 0; }}</style></head><body>
            <h1>MKDSS Smart Card Factory - Visitor Authorization</h1>
            <p><b>To:</b> Security Guards - Main Gate &amp; Production Area Checkpoints</p>
            <p><b>From:</b> {r["approved_by"] or "-"}</p>
            <p><b>Date:</b> {r["decision_date"] or "-"}</p>
            <p><u><b>Subject: Approval for Visitor Access to visit the Factory</b></u></p>
            <p><b>Organization / Company:</b> {r["company"]}</p>
            <p><b>Purpose of Visit:</b> {r["purpose"]}</p>
            <p><b>Authorized Department:</b> {r["department"] or "-"}</p>
            <p><b>Date &amp; Time of Visit:</b> {r["visit_date"]} {r["start_visit"]} - {r["finish_visit"]}</p>
            <p><b>Requested By (Host):</b> {r["requested_by"]}</p>
            <p><b>Factory Escort (accompanies visitor(s) at all times):</b>
               <span style="color:#c0392b"><b>{r["escort"] or "NOT ASSIGNED"}</b></span></p>
            <p><b>Name of Visitor(s):</b></p><ul>{visitor_rows}</ul>
            <p><b>Security Instructions - HSA Access Details:</b></p>
            {hsa_detail_rows}
            <p><b>Approved by:</b> {r["approved_by"] or "-"} ({r["approver_position"] or "Factory Manager"})</p>
            </body></html>"""
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)
            api_log("Authorization Form", "Success", f"HTML (PDF fallback) for request #{r['id']}: {filename}")
            webbrowser.open(f"file://{html_path}")
            messagebox.showinfo("PDF library not installed",
                                 "The 'reportlab' package isn't installed, so a print-ready HTML "
                                 "version was opened in your browser instead.\n\n"
                                 "In the browser: press Ctrl+P -> 'Save as PDF' to get a real PDF.\n\n"
                                 "To enable direct one-click PDF export next time, run this once:\n"
                                 "   pip install reportlab")

    # ---------------- GUARD: GATE APPROVALS ----------------
    def page_guard_approvals(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Gate Approvals",
                      "Visitor authorizations sent electronically by the Officer - confirm each "
                      "visitor's arrival as they come through the gate").pack(anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load authorizations from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        sent = [r for r in result["requests"] if r["sent_to_guards"]]

        if not sent:
            card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
            card.pack(fill="both", expand=True)
            tk.Label(card, text="No authorizations have been sent yet. They'll appear here as soon "
                                 "as an Officer sends one.", font=FONT_BODY, bg=COLOR_CARD,
                      fg=COLOR_MUTED, wraplength=700, justify="left").pack(anchor="w", padx=14, pady=14)
            return

        for r in sorted(sent, key=lambda x: -x["id"]):
            arrived = sum(1 for v in r["visitors"] if v["gate_entry_confirmed_at"])
            total = len(r["visitors"])
            card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
            card.pack(fill="x", pady=(0, 12))
            top = tk.Frame(card, bg=COLOR_CARD)
            top.pack(fill="x", padx=16, pady=(12, 4))
            tk.Label(top, text=f"{r['company']}  -  {r['purpose']}", font=FONT_H2, bg=COLOR_CARD,
                      fg=COLOR_TEXT).pack(side="left")
            status_text = f"{arrived}/{total} arrived" if arrived < total else "All arrived"
            status_color = COLOR_SUCCESS if arrived == total else COLOR_WARNING
            tk.Label(top, text=status_text, font=("Segoe UI", 9, "bold"), bg=status_color,
                      fg="white", padx=8, pady=2).pack(side="right")

            info = (f"Requested by: {r['requested_by']}   |   Department: {r['department'] or '-'}\n"
                    f"Escort: {r['escort']}\n"
                    f"Visit: {r['visit_date']}   {r['start_visit']} - {r['finish_visit']}")
            tk.Label(card, text=info, font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED,
                      justify="left").pack(anchor="w", padx=16)

            if r["hsa_requested"]:
                # Show which specific rooms are approved (if any)
                rooms = [a for a in r["hsa_areas"] if a in HIGHEST_SECURITY_AREAS]
                hsa_status = "Highest Security Area: " + (", ".join(rooms) if rooms else "No specific rooms")
                tk.Label(card, text=f"⚠ HSA access: {r['hsa_decision'] or 'Pending'}  -  {hsa_status}",
                          font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_WARNING).pack(anchor="w", padx=16, pady=(2, 0))

            vlist = tk.Frame(card, bg=COLOR_CARD)
            vlist.pack(fill="x", padx=16, pady=(8, 12))
            for v in r["visitors"]:
                vrow = tk.Frame(vlist, bg=COLOR_CARD)
                vrow.pack(fill="x", pady=2)
                idtext = f"  (ID: {v['national_id']})" if v["national_id"] else ""
                tk.Label(vrow, text=f'{v["first_name"]} {v["last_name"]}{idtext}', font=FONT_BODY,
                          bg=COLOR_CARD, fg=COLOR_TEXT, width=32, anchor="w").pack(side="left")
                if v["gate_entry_confirmed_at"]:
                    tk.Label(vrow, text=f'✓ Entered {v["gate_entry_confirmed_at"]}  ({v["gate_entry_confirmed_by"]})',
                              font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_SUCCESS).pack(side="left")
                else:
                    def confirm(rid=r["id"], rvid=v["id"]):
                        ok, result = api_confirm_gate_entry(rid, rvid)
                        if not ok:
                            messagebox.showerror("Could Not Confirm", result if isinstance(result, str) else str(result))
                            return
                        self.show_page("Gate Approvals")
                    ttk.Button(vrow, text="Confirm Entry", style="Accent.TButton",
                               command=confirm).pack(side="left")

    # ---------------- GUARD: REPORT WALK-IN VISITOR ----------------
    def page_guard_report_walkin(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Report Walk-In Visitor",
                      "Log a visitor who showed up unannounced - this goes to the Officer, then "
                      "the Security Manager, then the Factory Manager before they're authorized").pack(
            anchor="w", pady=(0, 16))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        form = tk.Frame(card, bg=COLOR_CARD)
        form.pack(fill="x", padx=20, pady=16)

        v = {}
        v["first_name"] = labeled_entry(form, "First Name *", 0, 0)
        v["last_name"] = labeled_entry(form, "Last Name *", 0, 1)
        v["national_id"] = labeled_entry(form, "ID / Passport No. (if any)", 0, 2)
        v["company"] = labeled_entry(form, "Company *", 1, 0)
        v["purpose"] = labeled_entry(form, "Purpose of Visit *", 1, 1)
        v["visiting_employee"] = labeled_entry(form, "Visiting Employee *", 1, 2)
        v["department"] = labeled_entry(form, "Department", 2, 0, kind="combo", values=DEPARTMENTS)

        def submit():
            required = ["first_name", "last_name", "company", "purpose", "visiting_employee"]
            missing = [r for r in required if not v[r].get().strip()]
            if missing:
                messagebox.showerror("Missing Information",
                                      "Please fill in all required fields (*) before submitting.")
                return
            fields = {k: var.get().strip() for k, var in v.items()}
            ok, result = api_create_walkin_request(fields)
            if not ok:
                messagebox.showerror("Could Not Submit", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Logged",
                                 f"Walk-in visitor logged (request #{result['id']}).\n"
                                 f"This has been sent to the Officer for review.")
            self.show_page("Report Walk-In Visitor")

        ttk.Button(form, text="Submit to Officer", style="Accent.TButton", command=submit).grid(
            row=6, column=0, sticky="w", padx=6, pady=(14, 0))

    # ---------------- OFFICER: WALK-IN REQUESTS ----------------
    def page_officer_walkin_requests(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Walk-In Requests",
                      "Unannounced visitors logged by a Guard - review and forward to the "
                      "Security Manager").pack(anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load requests from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        pending = [r for r in result["requests"]
                   if r["origin"] == "walkin" and r["status"] == "Pending Officer Review"]

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Company", "Purpose", "Visiting", "Logged By")
        tree = make_table(card, cols, (40, 160, 150, 160, 150, 130))
        tree.pack(fill="both", expand=True, padx=14, pady=14)
        for r in pending:
            v = r["visitors"][0] if r["visitors"] else {}
            tree.insert("", "end", iid=r["id"], values=(
                r["id"], f'{v.get("first_name","")} {v.get("last_name","")}', r["company"],
                r["purpose"], r["visiting_employee"], r["requested_by"]))
        if not pending:
            tk.Label(card, text="No walk-ins waiting for review right now.", font=FONT_BODY,
                      bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 14))

        def forward():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a request", "Please select a walk-in request first.")
                return
            rid = int(sel[0])
            ok, result = api_forward_to_security(rid)
            if not ok:
                messagebox.showerror("Could Not Forward", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Forwarded", "Sent to the Security Manager for review.")
            self.show_page("Walk-In Requests")

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Forward to Security Manager", style="Accent.TButton",
                   command=forward).pack(side="left")

    # ---------------- SECURITY MANAGER: SECURITY REVIEW ----------------
    def _open_host_change_request_dialog(self, r, mode="hsa_schedule"):
        """Host-only request dialog. Security Manager reviews; it never edits the appointment here."""
        labels = {
            "schedule": ("Request Schedule Change", "Change the visit date/time. Security Manager will review your request."),
            "hsa": ("Request HSA Access", "Request High Security Area access for this approved visit."),
            "hsa_schedule": ("Request HSA + Schedule Change", "Request both a schedule change and High Security Area access."),
        }
        title, subtitle = labels.get(mode, labels["hsa_schedule"])
        include_schedule = mode in ("schedule", "hsa_schedule")
        include_hsa = mode in ("hsa", "hsa_schedule")

        win = tk.Toplevel(self)
        win.title(f"{title} #{r['id']}")
        win.geometry("620x650" if include_hsa else "620x470")
        win.configure(bg=COLOR_CARD); win.grab_set(); win.resizable(False, False)
        tk.Label(win, text=title, font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=18, pady=(16, 4))
        tk.Label(win, text=f"Request #{r['id']} | {r['company']}\nCurrent: {r['visit_date']}  {r['start_visit']} - {r['finish_visit']}\n{subtitle}",
                 font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT, justify="left", wraplength=560).pack(anchor="w", padx=18, pady=(0, 12))

        form = tk.Frame(win, bg=COLOR_CARD); form.pack(fill="x", padx=18)
        date_var = tk.StringVar(value=r.get("visit_date") or date.today().isoformat())
        arrival_var = tk.StringVar(value=str(r.get("start_visit") or "09:00")[:5])
        departure_var = tk.StringVar(value=str(r.get("finish_visit") or "17:00")[:5])

        if include_schedule:
            tk.Label(form, text="New Visit Date", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(row=0, column=0, sticky="w")
            ttk.Entry(form, textvariable=date_var, width=14).grid(row=1, column=0, sticky="w", pady=(2, 10))
            ttk.Button(form, text="📅 Calendar", command=lambda: open_date_picker(win, date_var)).grid(row=1, column=1, padx=6, sticky="w")
            tk.Label(form, text="Arrival (HH:MM)", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(row=2, column=0, sticky="w")
            ttk.Entry(form, textvariable=arrival_var, width=14).grid(row=3, column=0, sticky="w", pady=(2, 10))
            tk.Label(form, text="Departure (HH:MM)", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(row=2, column=1, sticky="w")
            ttk.Entry(form, textvariable=departure_var, width=14).grid(row=3, column=1, sticky="w", padx=6, pady=(2, 10))
        else:
            tk.Label(form, text=f"Schedule remains unchanged: {date_var.get()}  {arrival_var.get()} - {departure_var.get()}",
                     font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED, justify="left").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        hsa_var = tk.BooleanVar(value=False)
        area_vars = {room: tk.BooleanVar(value=False) for room in HIGHEST_SECURITY_AREAS}
        escort_var = tk.StringVar(value=r.get("hsa_escort") or "")
        if include_hsa:
            hsa_var.set(True)
            tk.Label(win, text="High Security Area Access", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=18, pady=(4, 6))
            tk.Label(win, text="Select the HSA areas required for this visit.", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=18, pady=(0, 4))
            for room, var in area_vars.items():
                tk.Checkbutton(win, text=room, variable=var, bg=COLOR_CARD, font=FONT_SMALL).pack(anchor="w", padx=34)
            tk.Label(win, text="Escort (if required)", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=18, pady=(4, 0))
            ttk.Entry(win, textvariable=escort_var, width=34).pack(anchor="w", padx=18, pady=(2, 8))

        tk.Label(win, text="Reason *", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=18)
        reason_box = tk.Text(win, height=5 if include_hsa else 4, width=68, wrap="word", font=("Segoe UI", 9))
        reason_box.pack(padx=18, pady=(2, 12))

        def submit():
            if include_schedule:
                try:
                    datetime.strptime(date_var.get().strip(), "%Y-%m-%d")
                    a = datetime.strptime(arrival_var.get().strip(), "%H:%M")
                    d = datetime.strptime(departure_var.get().strip(), "%H:%M")
                except ValueError:
                    messagebox.showerror("Invalid Date/Time", "Use date YYYY-MM-DD and time HH:MM."); return
                if d < a:
                    messagebox.showerror("Invalid Time", "Departure time cannot be earlier than arrival time."); return
            reason = reason_box.get("1.0", "end").strip()
            if not reason:
                messagebox.showerror("Reason Required", "Enter a reason for the request."); return
            selected = [room for room, var in area_vars.items() if var.get()]
            if include_hsa and not selected:
                messagebox.showerror("HSA Area Required", "Select at least one HSA area."); return
            areas = ["Highest Security Area"] + selected if include_hsa else []
            payload = {
                "change_type": mode,
                "visit_date": date_var.get().strip(),
                "start_visit": arrival_var.get().strip(),
                "finish_visit": departure_var.get().strip(),
                "reason": reason,
                "hsa_requested": bool(include_hsa),
                "hsa_areas": areas,
                "hsa_escort": escort_var.get().strip() if include_hsa else "",
            }
            ok, res = api_create_change_request(r["id"], payload)
            if not ok:
                messagebox.showerror("Could Not Submit", res if isinstance(res, str) else str(res)); return
            win.destroy()
            messagebox.showinfo("Request Submitted", f"{title} #{res['id']} was sent to the Security Manager for approval.")
            self.show_page("My Requests")

        ttk.Button(win, text="Send to Security Manager", style="Accent.TButton", command=submit).pack(pady=(0, 18))

    def page_hsa_schedule_requests(self):
        wrap=tk.Frame(self.content,bg=COLOR_BG); wrap.pack(fill="both",expand=True,padx=28,pady=22)
        section_title(wrap,"HSA & Schedule Requests","Host requests for High Security Area access and appointment changes requiring Security Manager approval").pack(anchor="w",pady=(0,16))
        ok,result=api_list_change_requests()
        if not ok: tk.Label(wrap,text=f"Could not load requests:\n{result}",font=FONT_BODY,bg=COLOR_BG,fg=COLOR_DANGER).pack(anchor="w",pady=20); return
        pending=[x for x in result["requests"] if x["status"]=="Pending Security Manager"]
        card=tk.Frame(wrap,bg=COLOR_CARD,highlightbackground="#e2e6ec",highlightthickness=1); card.pack(fill="both",expand=True)
        tree=make_table(card,("ID","Type","Visit Request","Host","Company","New Date","New Time","HSA","Reason"),(45,130,90,120,130,100,120,70,240)); tree.pack(fill="both",expand=True,padx=14,pady=14)
        type_labels={"schedule":"Schedule Change","hsa":"HSA Access","hsa_schedule":"HSA + Schedule"}
        for x in pending:
            change_type=x.get("change_type") or "hsa_schedule"
            type_label=type_labels.get(change_type,"HSA + Schedule")
            tree.insert("","end",iid=str(x["id"]),values=(x["id"],type_label,x["request_id"],x.get("requested_by","-"),x.get("company","-"),x.get("new_visit_date","-"),f"{x.get('new_start_visit','-')} - {x.get('new_finish_visit','-')}","Yes" if change_type in ("hsa","hsa_schedule") else "No",x.get("reason","-")))
        if not pending: tk.Label(card,text="No HSA or schedule changes are waiting for approval.",font=FONT_BODY,bg=COLOR_CARD,fg=COLOR_MUTED).pack(anchor="w",padx=14,pady=(0,14))
        def decide_change(decision):
            sel=tree.selection()
            if not sel: messagebox.showwarning("Select Request","Select a pending request first."); return
            cid=int(sel[0]); reason=""
            if decision=="Rejected": reason=simpledialog.askstring("Rejection Reason","Enter the reason for rejection:",parent=self) or ""; 
            if decision=="Rejected" and not reason: return
            ok,res=api_decide_change_request(cid,decision,reason)
            if not ok: messagebox.showerror("Could Not Decide",res if isinstance(res,str) else str(res)); return
            messagebox.showinfo("Decision Recorded",f"Change request #{cid} has been {decision.lower()}."); self.show_page("HSA & Schedule Requests")
        btn=tk.Frame(wrap,bg=COLOR_BG); btn.pack(fill="x",pady=(10,0)); ttk.Button(btn,text="Approve Selected",style="Accent.TButton",command=lambda:decide_change("Approved")).pack(side="left"); ttk.Button(btn,text="Reject Selected",command=lambda:decide_change("Rejected")).pack(side="left",padx=8)
        hsa_ok,hsa_res=api_list_visit_requests()
        if hsa_ok:
            hsa_pending=[r for r in hsa_res["requests"] if r.get("hsa_requested") and not r.get("hsa_decision") and r.get("status") in ("Approved","Pending Approval","Pending Factory Authorization")]
            hcard=tk.Frame(wrap,bg=COLOR_CARD,highlightbackground="#e2e6ec",highlightthickness=1); hcard.pack(fill="both",expand=True,pady=(16,0)); tk.Label(hcard,text="Initial HSA Requests Awaiting Security Manager Decision",font=FONT_H2,bg=COLOR_CARD,fg=COLOR_TEXT).pack(anchor="w",padx=14,pady=(12,6))
            ht=make_table(hcard,("Request","Host","Company","Visit Date","HSA Areas"),(70,130,150,100,300)); ht.pack(fill="both",expand=True,padx=14,pady=(0,8))
            for r in hsa_pending: ht.insert("","end",iid=str(r["id"]),values=(r["id"],r.get("requested_by","-"),r.get("company","-"),r.get("visit_date","-"),", ".join(r.get("hsa_areas",[]))))
            def decide_initial(decision):
                sel=ht.selection()
                if not sel: messagebox.showwarning("Select Request","Select an HSA request first."); return
                ok,res=api_hsa_decide_visit_request(int(sel[0]),decision)
                if not ok: messagebox.showerror("Could Not Decide",res if isinstance(res,str) else str(res)); return
                self.show_page("HSA & Schedule Requests")
            hb=tk.Frame(hcard,bg=COLOR_CARD); hb.pack(fill="x",padx=14,pady=(0,14)); ttk.Button(hb,text="Approve HSA",style="Accent.TButton",command=lambda:decide_initial("Approved")).pack(side="left"); ttk.Button(hb,text="Reject HSA",command=lambda:decide_initial("Not Approved")).pack(side="left",padx=8)

    def page_security_review(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Security Manager - Review & Monitoring",
                      "Approve walk-in visitors and monitor visitor activity by scheduled date").pack(
            anchor="w", pady=(0, 10))

        date_bar = tk.Frame(wrap, bg=COLOR_BG)
        date_bar.pack(fill="x", pady=(0, 14))
        tk.Label(date_bar, text="Visit Date:", font=FONT_BODY, bg=COLOR_BG, fg=COLOR_TEXT).pack(side="left")
        selected_date_var = tk.StringVar(value=getattr(self, "security_selected_date", date.today().isoformat()))
        ttk.Entry(date_bar, textvariable=selected_date_var, width=13).pack(side="left", padx=(8, 5))
        ttk.Button(date_bar, text="📅 Calendar",
                   command=lambda: open_date_picker(self, selected_date_var)).pack(side="left")
        ttk.Button(date_bar, text="Today",
                   command=lambda: selected_date_var.set(date.today().isoformat())).pack(side="left", padx=(5, 0))
        ttk.Button(date_bar, text="Apply Date", style="Accent.TButton",
                   command=lambda: (setattr(self, "security_selected_date", selected_date_var.get().strip()), self.show_page("Security Review"))).pack(side="left", padx=(5, 0))
        tk.Label(date_bar, text="Select any previous, current, or future date to review scheduled visits.",
                 font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_MUTED).pack(side="left", padx=12)

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load requests from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        all_requests = result["requests"]

        # IMPORTANT: visit_requests.status is the approval/workflow status.
        # It is NOT the visitor's live check-in/check-out status. The live
        # state is stored in the visitors table, so Security Manager monitoring
        # must use the linked visitor records as the source of truth.
        ok_v, result_v = api_list_visitors()
        if not ok_v:
            tk.Label(wrap, text=f"⚠ Could not load visitor status from the server:\n{result_v}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        all_visitors = result_v["visitors"]

        # Walk-in visitors pending Security Manager approval (NOT YET APPROVED).
        # These requests have no linked visitor record yet, so they remain
        # request-based.
        walkin_pending = [r for r in all_requests if r["origin"] == "walkin" and r["status"] == "Pending Security Review"]

        # Build a request lookup from request_visitors.linked_visitor_id.
        # Each approved visitor gets its own monitoring row, which correctly
        # handles group requests where one visitor may be inside while another
        # has already checked out.
        request_by_visitor_id = {}
        for request_row in all_requests:
            for request_visitor in request_row.get("visitors", []):
                linked_id = request_visitor.get("linked_visitor_id")
                if linked_id is not None:
                    try:
                        request_by_visitor_id[int(linked_id)] = request_row
                    except (TypeError, ValueError):
                        pass

        monitoring_rows = []
        for visitor in all_visitors:
            # Visitor records are the authoritative source for live status.
            # Do NOT discard a visitor merely because request_visitors.linked_visitor_id
            # is missing or stale. This was the reason checked-out visitors could
            # disappear from Monitoring while still appearing in History.
            request_row = request_by_visitor_id.get(visitor.get("id"))
            row_for_monitoring = dict(request_row) if request_row else {}
            row_for_monitoring["_visitor"] = visitor
            row_for_monitoring["visitors"] = [visitor]
            row_for_monitoring["status"] = visitor.get("status")
            row_for_monitoring["check_in_time"] = visitor.get("check_in_time")
            row_for_monitoring["check_out_time"] = visitor.get("check_out_time")
            row_for_monitoring["checkout_date"] = visitor.get("checkout_date")
            row_for_monitoring["visiting_employee"] = (
                request_row.get("visiting_employee")
                or visitor.get("host")
                or "-"
            )
            row_for_monitoring["department"] = visitor.get("department") or request_row.get("department") or "-"
            monitoring_rows.append(row_for_monitoring)

        # Categorize by the visitor's ACTUAL live status, not visit_requests.status.
        # "Expected to Arrive" is specifically TODAY: an approved visitor whose
        # visit_date is yesterday (or another date) must not remain in today's
        # expected list just because the workflow status is still Approved.
        selected_date_str = selected_date_var.get().strip()
        try:
            datetime.strptime(selected_date_str, "%Y-%m-%d")
        except ValueError:
            selected_date_str = date.today().isoformat()
            selected_date_var.set(selected_date_str)

        expected = [
            r for r in monitoring_rows
            if r.get("status") == "Approved"
            and str(r["_visitor"].get("visit_date") or "") == selected_date_str
            and not r.get("check_in_time")
            and not r.get("check_out_time")
            # Once a walk-in has been authorized and sent to the guards,
            # remove it from the Expected Visitors action list. The same
            # request remains available in Security Review History.
            and not (r.get("origin") == "walkin" and r.get("sent_to_guards"))
        ]
        overdue = [
            r for r in monitoring_rows
            if r.get("status") == "Approved"
            and not r.get("check_in_time")
            and not r.get("check_out_time")
            and str(r["_visitor"].get("visit_date") or "") < date.today().isoformat()
            and not (r.get("origin") == "walkin" and r.get("sent_to_guards"))
        ]
        inside = [
            r for r in monitoring_rows
            if r.get("status") == "Checked In"
            and not r.get("check_out_time")
        ]

        today_str = date.today().isoformat()

        def checkout_date_is_today(value, visitor=None):
            """Identify a checkout that belongs to today.

            Supports the current full timestamp format and legacy records that
            stored only HH:MM. Legacy records have no checkout date, so their
            visit_date is used as the compatibility date signal. Date strings
            are normalized so YYYY-MM-DD, ISO datetime, and slash-separated
            dates do not get lost by the Monitoring filter.
            """
            # Server supplies checkout_date from the audit trail for legacy
            # HH:MM records. Prefer that authoritative date when available.
            if checkout_date:
                value = checkout_date
            if not value:
                return False

            def normalize_date(value_text):
                text = str(value_text or "").strip()
                if not text:
                    return ""
                try:
                    if "T" in text:
                        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
                    if " " in text:
                        return datetime.fromisoformat(text).date().isoformat()
                    if len(text) == 10 and text[4] == "-" and text[7] == "-":
                        return datetime.strptime(text, "%Y-%m-%d").date().isoformat()
                    if len(text) == 10 and text[2] == "/" and text[5] == "/":
                        return datetime.strptime(text, "%d/%m/%Y").date().isoformat()
                except (TypeError, ValueError):
                    return ""
                return ""

            text = str(value).strip()
            parsed_date = normalize_date(text)
            if parsed_date:
                return parsed_date == today_str

            # Legacy checkout values are only HH:MM. Since the old database
            # did not retain a checkout date, use the visitor's scheduled
            # visit_date so today's legacy check-outs remain visible.
            if len(text) == 5 and text[2] == ":" and visitor:
                return normalize_date(visitor.get("visit_date")) == today_str

            return False

        def checkout_date_matches_selected(value, visitor=None, checkout_date=None):
            """Return True when a checkout belongs to the calendar date selected above.

            Current records store a full timestamp. Legacy records stored only HH:MM,
            so their visitor visit_date is used as the best available historical date.
            """
            # For legacy HH:MM values, checkout_date comes from the server audit trail.
            if checkout_date:
                value = checkout_date
            if not value:
                return False

            def normalize_date(value_text):
                text = str(value_text or "").strip()
                if not text:
                    return ""
                try:
                    if "T" in text:
                        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
                    if " " in text:
                        return datetime.fromisoformat(text).date().isoformat()
                    if len(text) == 10 and text[4] == "-" and text[7] == "-":
                        return datetime.strptime(text, "%Y-%m-%d").date().isoformat()
                    if len(text) == 10 and text[2] == "/" and text[5] == "/":
                        return datetime.strptime(text, "%d/%m/%Y").date().isoformat()
                except (TypeError, ValueError):
                    return ""
                return ""

            text = str(value).strip()
            parsed_date = normalize_date(text)
            if parsed_date:
                return parsed_date == selected_date_str

            # Legacy HH:MM records have no checkout date.
            if len(text) == 5 and text[2] == ":" and visitor:
                return normalize_date(visitor.get("visit_date")) == selected_date_str

            return False

        checkout_today = [
            r for r in monitoring_rows
            if r.get("status") == "Checked Out"
            and checkout_date_matches_selected(
                r.get("check_out_time"), r.get("_visitor"), r.get("checkout_date")
            )
        ]
        rejected = [r for r in all_requests if "Rejected" in r["status"]]

        # ==================== WALK-IN VISITORS REQUIRING APPROVAL ====================
        if walkin_pending:
            walkin_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
            walkin_card.pack(fill="both", expand=True, pady=(0, 14))
            tk.Label(walkin_card, text=f"Walk-In Visitors Pending Approval ({len(walkin_pending)})", 
                      font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
            
            wcols = ("ID", "Visitor Name", "Company", "Purpose", "Logged By", "Time")
            wtree = make_table(walkin_card, wcols, (40, 140, 130, 130, 130, 100))
            wtree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
            for r in walkin_pending:
                v = r["visitors"][0] if r["visitors"] else {}
                visitor_name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip()
                created_time = r.get("created_at", "-")
                if created_time and " " in created_time:
                    created_time = created_time.split(" ")[1]
                wtree.insert("", "end", iid=r["id"], values=(
                    r["id"], visitor_name, r.get("company", "-"),
                    r.get("purpose", "-"), r.get("requested_by", "-"), created_time))
            
            def review_walkin():
                sel = wtree.selection()
                if not sel:
                    messagebox.showwarning("Select a request", "Please select a walk-in visitor first.")
                    return
                rid = int(sel[0])
                r = next(x for x in walkin_pending if x["id"] == rid)
                self._open_security_review_dialog(r)
            
            wbtns = tk.Frame(walkin_card, bg=COLOR_CARD)
            wbtns.pack(fill="x", padx=14, pady=(0, 14))
            ttk.Button(wbtns, text="Review Selected Walk-In", style="Accent.TButton", command=review_walkin).pack(side="left")

        # ==================== CURRENTLY INSIDE ====================
        inside_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        inside_card.pack(fill="both", expand=True, pady=(0, 14))
        tk.Label(inside_card, text=f"Currently Inside Factory ({len(inside)} visitors)", 
                  font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
        
        if inside:
            icols = ("ID", "Visitor Name", "Visiting", "Department", "Check-In Time", "Company")
            itree = make_table(inside_card, icols, (40, 140, 120, 130, 130, 120))
            itree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
            for r in inside:
                v = r["visitors"][0] if r["visitors"] else {}
                visitor_name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip()
                checkin_time = r.get("check_in_time", "-")
                if checkin_time and " " in checkin_time:
                    checkin_time = checkin_time.split(" ")[1]  # Extract just time
                itree.insert("", "end", values=(
                    r["_visitor"].get("id", r["id"]), visitor_name, r.get("visiting_employee", "-"),
                    r.get("department", "-"), checkin_time, r.get("company", "-")))
        else:
            tk.Label(inside_card, text="No visitors currently inside the factory.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        # ==================== EXPECTED VISITORS (Approved, not yet checked in) ====================
        expected_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        expected_card.pack(fill="both", expand=True, pady=(0, 14))
        tk.Label(expected_card, text=f"Expected to Arrive on {selected_date_str} ({len(expected)} visitors)", 
                  font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
        
        if expected:
            ecols = ("ID", "Visitor Name", "Expected Time", "Visiting", "Company", "Purpose", "HSA")
            etree = make_table(expected_card, ecols, (40, 140, 110, 120, 120, 140, 50))
            etree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
            for r in expected:
                v = r["visitors"][0] if r["visitors"] else {}
                visitor_name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip()
                hsa_status = "✓" if r.get("hsa_requested") else "-"
                etree.insert("", "end", values=(
                    r["_visitor"].get("id", r["id"]), visitor_name, r["_visitor"].get("expected_arrival", "-"),
                    r.get("visiting_employee", "-"), r.get("company", "-"), r.get("purpose", "-"), hsa_status))
        else:
            tk.Label(expected_card, text="No visitors waiting to check in.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        # ==================== CHECKED OUT TODAY ====================
        checkout_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        checkout_card.pack(fill="both", expand=True, pady=(0, 14))
        tk.Label(checkout_card, text=f"Checked Out on {selected_date_str} ({len(checkout_today)} visitors)", 
                  font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
        
        if checkout_today:
            cols = ("ID", "Visitor Name", "Visited", "Check-Out Time")
            tree = make_table(checkout_card, cols, (40, 150, 150, 140))
            tree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
            for r in checkout_today:
                v = r["visitors"][0] if r["visitors"] else {}
                visitor_name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip()
                checkout_time = r.get("check_out_time", "-")
                if checkout_time and " " in checkout_time:
                    checkout_time = checkout_time.split(" ")[1]
                tree.insert("", "end", values=(
                    r["_visitor"].get("id", r["id"]), visitor_name, r.get("visiting_employee", "-"), checkout_time))
        else:
            tk.Label(checkout_card, text="No visitors have checked out yet today.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        # ==================== OVERDUE / PREVIOUS APPOINTMENTS ====================
        if selected_date_str == today_str and overdue:
            overdue_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
            overdue_card.pack(fill="both", expand=True, pady=(0, 14))
            tk.Label(overdue_card, text=f"Overdue / Previous Appointments ({len(overdue)} visitors)",
                     font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
            ocols = ("ID", "Visitor", "Scheduled Date", "Expected Time", "Host", "Company", "Action")
            otree = make_table(overdue_card, ocols, (40, 140, 100, 100, 120, 120, 120))
            otree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
            for r in overdue:
                v = r["_visitor"]
                name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip()
                otree.insert("", "end", iid=str(v.get("id")), values=(
                    v.get("id"), name, v.get("visit_date", "-"), v.get("expected_arrival", "-"),
                    v.get("host", "-"), v.get("company", "-"), "Needs Action"))

            tk.Label(overdue_card,
                     text="No direct rescheduling is performed here. The Host must submit a Schedule Change request from My Requests.",
                     font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=900, justify="left").pack(anchor="w", padx=14, pady=(0, 14))

        # ==================== REJECTED/CANCELLED ====================
        rejected_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        rejected_card.pack(fill="both", expand=True)
        tk.Label(rejected_card, text=f"Rejected/Cancelled ({len(rejected)} requests)", 
                  font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=14, pady=(12, 6))
        
        if rejected:
            rcols = ("ID", "Visitor", "Company", "Reason")
            rtree = make_table(rejected_card, rcols, (40, 140, 140, 300))
            rtree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
            for r in rejected:
                v = r["visitors"][0] if r["visitors"] else {}
                visitor_name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip()
                reason = r.get("security_reject_reason") or r.get("reject_reason") or "-"
                rtree.insert("", "end", values=(
                    r["id"], visitor_name, r.get("company", "-"), reason))
        else:
            tk.Label(rejected_card, text="No rejected or cancelled requests today.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

    def _open_reschedule_dialog(self, visitor):
            win = tk.Toplevel(self)
            win.title(f"Reschedule Visitor #{visitor['id']}")
            win.configure(bg=COLOR_CARD)
            win.grab_set()
            win.resizable(False, False)

            tk.Label(win, text="Reschedule Visitor", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=18, pady=(16, 4))
            name = f"{visitor.get('first_name','')} {visitor.get('last_name','')}".strip()
            tk.Label(win, text=f"Visitor: {name}\nOriginal: {visitor.get('visit_date','-')} at {visitor.get('expected_arrival','-')}",
                     font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT, justify="left").pack(anchor="w", padx=18, pady=(0, 12))
            form = tk.Frame(win, bg=COLOR_CARD)
            form.pack(fill="x", padx=18)
            tk.Label(form, text="New Visit Date", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(row=0, column=0, sticky="w")
            date_var = tk.StringVar(value=date.today().isoformat())
            ttk.Entry(form, textvariable=date_var, width=14).grid(row=1, column=0, sticky="w", pady=(2, 10))
            ttk.Button(form, text="📅 Calendar", command=lambda: open_date_picker(win, date_var)).grid(row=1, column=1, padx=6, pady=(2, 10), sticky="w")
            tk.Label(form, text="Arrival (HH:MM)", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(row=2, column=0, sticky="w")
            arrival_var = tk.StringVar(value=str(visitor.get("expected_arrival") or "09:00")[:5])
            ttk.Entry(form, textvariable=arrival_var, width=14).grid(row=3, column=0, sticky="w", pady=(2, 10))
            tk.Label(form, text="Departure (HH:MM)", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(row=2, column=1, sticky="w")
            departure_var = tk.StringVar(value=str(visitor.get("expected_departure") or "17:00")[:5])
            ttk.Entry(form, textvariable=departure_var, width=14).grid(row=3, column=1, sticky="w", padx=6, pady=(2, 10))

            def save():
                try:
                    datetime.strptime(date_var.get().strip(), "%Y-%m-%d")
                    datetime.strptime(arrival_var.get().strip(), "%H:%M")
                    datetime.strptime(departure_var.get().strip(), "%H:%M")
                except ValueError:
                    messagebox.showerror("Invalid Date/Time", "Use date YYYY-MM-DD and time HH:MM.")
                    return
                ok, result = api_reschedule_visitor(visitor["id"], date_var.get().strip(), arrival_var.get().strip(), departure_var.get().strip())
                if not ok:
                    messagebox.showerror("Could Not Reschedule", result if isinstance(result, str) else str(result))
                    return
                win.destroy()
                messagebox.showinfo("Rescheduled", f"{name} has been rescheduled to {date_var.get()} at {arrival_var.get()}.")
                self.show_page("Security Review")

            ttk.Button(win, text="Save Reschedule", style="Accent.TButton", command=save).pack(pady=(4, 18))

    def _defer_to_admin(self, win):
        """Closes a pending-decision dialog without deciding anything, for
        conflict-of-interest cases (the reviewer is the one being visited).
        The request stays exactly where it is - Admin accounts now have
        their own 'Approve Requests' / 'Security Review' pages and can pick
        it up from there as a neutral third party."""
        win.destroy()
        messagebox.showinfo("Left Pending for Admin",
                             "This request has been left pending - it will still show up here if "
                             "you come back to it, but an Administrator can also now review it "
                             "from their own 'Approve Requests' / 'Security Review' page.")

    def _open_security_review_dialog(self, r):
        win = tk.Toplevel(self)
        win.title(f"Security Review - Request #{r['id']}")
        win.geometry("500x420")
        win.configure(bg=COLOR_CARD)
        win.grab_set()

        v = r["visitors"][0] if r["visitors"] else {}
        tk.Label(win, text=f"Walk-In Request #{r['id']}", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=18, pady=(16, 4))
        info = (f'Visitor: {v.get("first_name","")} {v.get("last_name","")}'
                f'  (ID: {v.get("national_id") or "-"})\n'
                f"Company: {r['company']}\nPurpose: {r['purpose']}\n"
                f"Visiting: {r['visiting_employee']}  ({r['department'] or '-'})\n"
                f"Logged by (Guard): {r['requested_by']}")
        tk.Label(win, text=info, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT,
                  wraplength=460, justify="left").pack(anchor="w", padx=18, pady=(0, 12))

        if r["visiting_employee"] == self.current_user:
            warn = tk.Frame(win, bg="#fdecea", highlightbackground=COLOR_DANGER, highlightthickness=1)
            warn.pack(fill="x", padx=18, pady=(0, 10))
            tk.Label(warn, text="⚠ This visitor is here to see you. For proper segregation of "
                                 "duties, consider having an Administrator review this instead - "
                                 "click 'Let Admin Decide' to leave it pending for them, or "
                                 "proceed yourself (this will be clearly noted in the Audit Log).",
                      font=FONT_SMALL, bg="#fdecea", fg=COLOR_DANGER, wraplength=420,
                      justify="left").pack(anchor="w", padx=10, pady=(8, 4))
            ttk.Button(warn, text="Let Admin Decide Instead",
                       command=lambda: self._defer_to_admin(win)).pack(anchor="w", padx=10, pady=(0, 8))

        tk.Label(win, text="Reason (required if rejecting)", font=FONT_BODY, bg=COLOR_CARD,
                  fg=COLOR_TEXT).pack(anchor="w", padx=18)
        reason_box = tk.Text(win, width=48, height=4, font=FONT_BODY)
        reason_box.pack(anchor="w", padx=18, pady=(4, 12))

        def decide(decision):
            reason = reason_box.get("1.0", "end").strip()
            if decision == "Reject" and not reason:
                messagebox.showerror("Reason Required", "Please give a reason for rejecting this visitor.")
                return
            ok, result = api_security_review(r["id"], decision, reason if decision == "Reject" else None)
            if not ok:
                messagebox.showerror("Could Not Update", result if isinstance(result, str) else str(result))
                return
            win.destroy()
            messagebox.showinfo("Done",
                                 "Forwarded to the Factory Manager for authorization." if decision == "Forward"
                                 else "Rejected. This visitor will not proceed further.")
            self.show_page("Security Review")

        btn_row = tk.Frame(win, bg=COLOR_CARD)
        btn_row.pack(pady=(6, 16))
        ttk.Button(btn_row, text="Reject", command=lambda: decide("Reject")).pack(side="left", padx=6)
        ttk.Button(btn_row, text="Forward to Factory Manager", style="Accent.TButton",
                   command=lambda: decide("Forward")).pack(side="left", padx=6)

    # ---------------- SECURITY MANAGER: SECURITY REVIEW HISTORY ----------------
    def page_security_review_history(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Security Review History",
                      "All visitor requests with the current live visitor status").pack(
            anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        ok_v, result_v = api_list_visitors()
        if not ok or not ok_v:
            error = result if not ok else result_v
            tk.Label(wrap, text=f"⚠ Could not load history from the server:\n{error}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER,
                      wraplength=800, justify="left").pack(anchor="w", pady=20)
            return

        all_requests = result["requests"]
        all_visitors = result_v["visitors"]

        # visit_requests.status represents the approval workflow and can remain
        # "Approved" after the visitor checks out. The visitors table contains
        # the authoritative live status, so history must use that status.
        request_by_visitor_id = {}
        for request_row in all_requests:
            for request_visitor in request_row.get("visitors", []):
                linked_id = request_visitor.get("linked_visitor_id")
                if linked_id is not None:
                    try:
                        request_by_visitor_id[int(linked_id)] = request_row
                    except (TypeError, ValueError):
                        pass

        history_rows = []
        for visitor in all_visitors:
            request_row = request_by_visitor_id.get(visitor.get("id"))
            if not request_row:
                continue
            row = dict(request_row)
            row["_visitor"] = visitor
            row["live_status"] = visitor.get("status") or request_row.get("status", "Unknown")
            row["check_in_time"] = visitor.get("check_in_time")
            row["check_out_time"] = visitor.get("check_out_time")
            history_rows.append(row)

        # Requests without a linked visitor are still shown (for example,
        # pending/rejected requests and other workflow-only records).
        linked_request_ids = {id(row) for row in history_rows}
        for request_row in all_requests:
            has_linked = any(
                request_visitor.get("linked_visitor_id") is not None
                for request_visitor in request_row.get("visitors", [])
            )
            if not has_linked:
                row = dict(request_row)
                row["_visitor"] = (request_row.get("visitors") or [{}])[0]
                row["live_status"] = request_row.get("status", "Unknown")
                row["check_in_time"] = None
                row["check_out_time"] = None
                history_rows.append(row)

        history_rows.sort(
            key=lambda r: (
                r.get("_visitor", {}).get("visit_date", ""),
                r.get("created_at", "")
            ),
            reverse=True
        )

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        tk.Label(card, text=f"Visitor History ({len(history_rows)} visitors)",
                 font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
                     anchor="w", padx=14, pady=(12, 6))

        cols = ("ID", "Visitor", "Host", "Company", "Status", "Visit Date", "Check-In", "Check-Out", "HSA")
        tree = make_table(card, cols, (45, 140, 120, 120, 120, 100, 120, 120, 55))
        tree.pack(fill="both", expand=True, padx=14, pady=(0, 8))

        for index, row in enumerate(history_rows):
            v = row.get("_visitor") or {}
            visitor_name = f'{v.get("first_name","")} {v.get("last_name","")}'.strip() or "-"
            host_name = row.get("visiting_employee") or v.get("host") or "-"
            hsa_status = "✓ HSA" if row.get("hsa_requested") else "-"
            tree.insert("", "end", iid=f"history_{v.get('id', row.get('id', index))}_{index}",
                        values=(
                            v.get("id", row.get("id", "-")),
                            visitor_name,
                            host_name,
                            row.get("company", "-"),
                            row.get("live_status", "Unknown"),
                            v.get("visit_date", "-"),
                            row.get("check_in_time") or "-",
                            row.get("check_out_time") or "-",
                            hsa_status
                        ))

        if not history_rows:
            tk.Label(card, text="No visitor history found in the system.",
                     font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(
                         anchor="w", padx=14, pady=(0, 10))

        # Summary statistics use live visitor status, not request approval status.
        checked_out = len([r for r in history_rows if r.get("live_status") == "Checked Out"])
        checked_in = len([r for r in history_rows if r.get("live_status") == "Checked In"])
        expected = len([r for r in history_rows if r.get("live_status") == "Approved"])
        rejected = len([r for r in history_rows if "Rejected" in str(r.get("live_status", ""))])
        hsa_requests = len([r for r in history_rows if r.get("hsa_requested")])

        stats_frame = tk.Frame(wrap, bg=COLOR_BG)
        stats_frame.pack(fill="x", pady=(14, 0))
        summary_text = (
            f"Summary: {expected} Expected  |  {checked_in} Inside  |  "
            f"{checked_out} Checked Out  |  {rejected} Rejected  |  {hsa_requests} HSA Requests"
        )
        tk.Label(stats_frame, text=summary_text, font=FONT_BODY,
                 bg=COLOR_BG, fg=COLOR_MUTED).pack(anchor="w")

    # ---------------- SECURITY MANAGER: WALK-IN AUTHORIZATION ----------------
    def page_security_walkin_authorization(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Walk-In Authorization",
                      "For walk-in visitors authorized by the Factory Manager - assign the escort "
                      "and send to the guards yourself").pack(anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load requests from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        # Only unsent authorized walk-ins belong in this action queue.
        # After Send to Guards, the record remains in Security Review History.
        approved = [
            r for r in result["requests"]
            if r["origin"] == "walkin"
            and r["status"] == "Approved"
            and not r.get("sent_to_guards")
        ]

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Visitor", "Company", "Purpose", "Escort", "Sent to Guards")
        tree = make_table(card, cols, (40, 160, 150, 160, 140, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)
        for r in approved:
            v = r["visitors"][0] if r["visitors"] else {}
            tree.insert("", "end", iid=r["id"], values=(
                r["id"], f'{v.get("first_name","")} {v.get("last_name","")}', r["company"],
                r["purpose"], r["escort"] or "⚠ Not assigned",
                f'✓ {r["sent_to_guards_at"]}' if r["sent_to_guards"] else "Not sent"))
        if not approved:
            tk.Label(card, text="No authorized walk-ins waiting right now.", font=FONT_BODY,
                      bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 14))

        def get_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a request", "Please select an authorized walk-in first.")
                return None
            rid = int(sel[0])
            return next(x for x in approved if x["id"] == rid)

        def assign_escort():
            r = get_selected()
            if not r:
                return
            self._open_assign_escort_dialog(r)

        def send_to_guards():
            r = get_selected()
            if not r:
                return
            if not r["escort"]:
                messagebox.showerror("Escort Not Assigned", "Assign an escort first.")
                return
            ok, result = api_send_to_guards(r["id"])
            if not ok:
                messagebox.showerror("Could Not Send", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Sent to Guards", "The gate guards can now see this authorization.")
            self.show_page("Walk-In Authorization")

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Assign Escort", command=assign_escort).pack(side="left")
        ttk.Button(btns, text="Send to Guards", style="Accent.TButton",
                   command=send_to_guards).pack(side="left", padx=(8, 0))

    # ---------------- HOST: MY OVERVIEW ----------------
    def page_host_overview(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, f"Welcome, {self.host_name}",
                      "Visit requests and visitors associated with you").pack(anchor="w", pady=(0, 16))

        ok, result = api_list_visitors()
        ok_r, result_r = api_list_visit_requests()
        if not ok or not ok_r:
            tk.Label(wrap, text=f"⚠ Could not load data from the server:\n{result if not ok else result_r}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return

        mine = [v for v in result["visitors"] if v["host"] == self.host_name]
        my_requests = [r for r in result_r["requests"] if r["host_username"] == self.current_username]
        pending_requests = [r for r in my_requests if r["status"] == "Pending Approval"]
        inside = [v for v in mine if v["status"] == "Checked In"]
        today = [v for v in mine if v["visit_date"] == date.today().isoformat()]

        stats = tk.Frame(wrap, bg=COLOR_BG)
        stats.pack(fill="x", pady=(0, 20))
        cards = [
            ("Requests Awaiting Approval", len(pending_requests), COLOR_WARNING),
            ("My Visitors Today", len(today), COLOR_ACCENT),
            ("Currently With Me", len(inside), COLOR_SUCCESS),
        ]
        for i, (label, value, color) in enumerate(cards):
            c = stat_card(stats, label, value, color)
            c.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="ew")
            stats.grid_columnconfigure(i, weight=1)

        if pending_requests:
            banner = tk.Frame(wrap, bg="#fff4e0", highlightbackground=COLOR_WARNING, highlightthickness=1)
            banner.pack(fill="x", pady=(0, 16))
            tk.Label(banner, text=f"🔔 {len(pending_requests)} of your visit request(s) are still awaiting "
                                    "the Factory Manager's approval.",
                      font=("Segoe UI", 10, "bold"), bg="#fff4e0", fg="#8a5a00").pack(
                anchor="w", padx=14, pady=10, side="left")
            ttk.Button(banner, text="View My Requests",
                       command=lambda: self.show_page("My Requests")).pack(side="right", padx=14, pady=8)

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

    # ---------------- HOST: NEW VISITOR REQUEST ----------------
    def page_host_new_request(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "New Visitor Request",
                      "Submit a group visitor request for the Factory Manager's approval - "
                      "mirrors the paper Visitor Request form").pack(anchor="w", pady=(0, 16))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        form = tk.Frame(card, bg=COLOR_CARD)
        form.pack(fill="x", padx=20, pady=16)

        req_vars = {}
        req_vars["company"] = labeled_entry(form, "Company *", 0, 0)
        req_vars["purpose"] = labeled_entry(form, "Visit Purpose *", 0, 1)
        req_vars["receiving_by"] = labeled_entry(form, "Receiving By", 0, 2)
        req_vars["visit_date"] = labeled_entry(form, "Visit Date (YYYY-MM-DD)", 1, 0)
        req_vars["visit_date"].set(date.today().isoformat())
        req_vars["start_visit"] = labeled_entry(form, "Start Visit (HH:MM)", 1, 1)
        req_vars["start_visit"].set("09:00")
        req_vars["finish_visit"] = labeled_entry(form, "Finish Visit (HH:MM)", 1, 2)
        req_vars["finish_visit"].set("17:00")

        tk.Label(form, text="Notes", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).grid(
            row=4, column=0, sticky="w", padx=6, pady=(8, 0))
        notes_box = tk.Text(form, width=80, height=2, font=FONT_BODY)
        notes_box.grid(row=5, column=0, columnspan=3, sticky="w", padx=6, pady=(0, 10))

        # ---- List of visitors (up to 10, matching the paper form) ----
        tk.Label(card, text="Visitors (up to 10)", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=20, pady=(6, 6))
        visitors_wrap = tk.Frame(card, bg=COLOR_CARD)
        visitors_wrap.pack(fill="x", padx=20)
        visitor_rows = []  # list of (frame, first_var, last_var, id_var)

        def add_visitor_row():
            if len(visitor_rows) >= 10:
                messagebox.showinfo("Limit Reached", "A single request supports up to 10 visitors.")
                return
            row_frame = tk.Frame(visitors_wrap, bg=COLOR_CARD)
            row_frame.pack(fill="x", pady=3)
            n = len(visitor_rows) + 1
            tk.Label(row_frame, text=f"{n}.", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED,
                      width=3).pack(side="left")
            fn = tk.StringVar()
            ttk.Entry(row_frame, textvariable=fn, width=18).pack(side="left", padx=(0, 4))
            ln = tk.StringVar()
            ttk.Entry(row_frame, textvariable=ln, width=18).pack(side="left", padx=(0, 4))
            idn = tk.StringVar()
            ttk.Entry(row_frame, textvariable=idn, width=20).pack(side="left", padx=(0, 4))
            tk.Label(row_frame, text="(First / Last / ID-Passport No. if any)", font=FONT_SMALL,
                      bg=COLOR_CARD, fg=COLOR_MUTED).pack(side="left", padx=(6, 0))
            visitor_rows.append((row_frame, fn, ln, idn))

        btn_add_row = tk.Frame(card, bg=COLOR_CARD)
        btn_add_row.pack(anchor="w", padx=20, pady=(4, 10))
        ttk.Button(btn_add_row, text="+ Add Visitor", command=add_visitor_row).pack(side="left")
        for _ in range(3):  # start with 3 blank rows, host can add more
            add_visitor_row()

        # ---- HSA (High Security Area) access request ----
        hsa_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        hsa_card.pack(fill="x", pady=(14, 0))
        hsa_inner = tk.Frame(hsa_card, bg=COLOR_CARD)
        hsa_inner.pack(fill="x", padx=20, pady=14)
        hsa_requested_var = tk.BooleanVar(value=False)
        highest_security_var = tk.BooleanVar(value=False)
        highest_security_rooms_vars = {room: tk.BooleanVar(value=False) for room in HIGHEST_SECURITY_AREAS}
        hsa_escort_var = tk.StringVar()

        # Main HSA checkbox
        tk.Checkbutton(hsa_inner, text="This request also needs access to a High Security Area (HSA) - "
                                        "raises a separate approval alongside the main request",
                        variable=hsa_requested_var, bg=COLOR_CARD, font=FONT_BODY,
                        command=lambda: update_hsa_ui()).pack(anchor="w")

        # Container for all HSA-related content
        hsa_content_frame = tk.Frame(hsa_inner, bg=COLOR_CARD)
        
        # Highest Security Area section
        highest_security_container = tk.Frame(hsa_content_frame, bg=COLOR_CARD)
        tk.Checkbutton(highest_security_container, text="Highest Security Area",
                       variable=highest_security_var, bg=COLOR_CARD, font=FONT_BODY,
                       command=lambda: update_hsa_ui()).pack(anchor="w", padx=(20, 0), pady=(8, 0))
        
        # Individual room checkboxes (shown when Highest Security Area is checked)
        rooms_frame = tk.Frame(highest_security_container, bg=COLOR_CARD)
        for room in HIGHEST_SECURITY_AREAS:
            tk.Checkbutton(rooms_frame, text=room, variable=highest_security_rooms_vars[room],
                            bg=COLOR_CARD, font=FONT_SMALL).pack(anchor="w", padx=(40, 0))

        # Escort row
        escort_row = tk.Frame(hsa_content_frame, bg=COLOR_CARD)
        escort_row.pack(anchor="w", pady=(6, 0), padx=(20, 0))
        tk.Label(escort_row, text="Escorted by:", font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
        ttk.Entry(escort_row, textvariable=hsa_escort_var, width=24).pack(side="left", padx=(6, 0))

        def update_hsa_ui():
            """Toggle visibility of HSA sections based on checkbox states."""
            if hsa_requested_var.get():
                hsa_content_frame.pack(anchor="w", pady=(8, 0), fill="x")
                highest_security_container.pack(anchor="w", pady=(0, 8), fill="x")
                if highest_security_var.get():
                    rooms_frame.pack(anchor="w", pady=(0, 8))
                else:
                    rooms_frame.pack_forget()
            else:
                hsa_content_frame.pack_forget()

        def submit():
            company = req_vars["company"].get().strip()
            purpose = req_vars["purpose"].get().strip()
            if not company or not purpose:
                messagebox.showerror("Missing Information", "Company and Visit Purpose are required.")
                return
            visitors_payload = []
            for _, fn, ln, idn in visitor_rows:
                if fn.get().strip() or ln.get().strip():
                    if not fn.get().strip() or not ln.get().strip():
                        messagebox.showerror("Incomplete Visitor",
                                              "Every visitor row needs both a first and last name.")
                        return
                    visitors_payload.append({"first_name": fn.get().strip(), "last_name": ln.get().strip(),
                                              "national_id": idn.get().strip()})
            if not visitors_payload:
                messagebox.showerror("No Visitors", "Add at least one visitor to the request.")
                return

            # Collect HSA areas: only "Highest Security Area" marker + specific rooms
            selected_hsa_areas = []
            if highest_security_var.get():
                selected_hsa_areas.append("Highest Security Area")
                selected_hsa_areas.extend([r for r, v in highest_security_rooms_vars.items() if v.get()])
            
            fields = dict(
                company=company, purpose=purpose, receiving_by=req_vars["receiving_by"].get().strip(),
                start_visit=req_vars["start_visit"].get().strip(),
                finish_visit=req_vars["finish_visit"].get().strip(),
                visit_date=req_vars["visit_date"].get().strip(),
                notes=notes_box.get("1.0", "end").strip(),
                hsa_requested=hsa_requested_var.get(),
                hsa_areas=selected_hsa_areas,
                hsa_escort=hsa_escort_var.get().strip(),
                visitors=visitors_payload,
            )
            ok, result = api_create_visit_request(fields)
            if not ok:
                messagebox.showerror("Could Not Submit Request", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Request Submitted",
                                 f"Visit request #{result['id']} submitted with {len(visitors_payload)} visitor(s).\n"
                                 "The Factory Manager will review it - you'll be notified once it's decided.")
            self.show_page("New Visitor Request")

        btn_row2 = tk.Frame(wrap, bg=COLOR_BG)
        btn_row2.pack(fill="x", pady=(14, 0))
        ttk.Button(btn_row2, text="Submit for Approval", style="Accent.TButton", command=submit).pack(anchor="w")

    # ---------------- HOST: MY REQUESTS ----------------
    def page_host_my_requests(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "My Requests", "Status of visit requests you've submitted").pack(
            anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load requests from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return

        mine = [r for r in result["requests"] if r["host_username"] == self.current_username]

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("ID", "Company", "Purpose", "Visitors", "HSA", "Status", "Decided By", "Decision Date")
        tree = make_table(card, cols, (40, 140, 160, 70, 90, 120, 130, 130))
        tree.pack(fill="both", expand=True, padx=14, pady=14)
        for r in mine:
            hsa_text = "-"
            if r["hsa_requested"]:
                hsa_text = r["hsa_decision"] or "Pending"
            tree.insert("", "end", iid=str(r["id"]), values=(
                r["id"], r["company"], r["purpose"], len(r["visitors"]), hsa_text,
                r["status"], r["approved_by"] or "-", r["decision_date"] or "-"))
        if not mine:
            tk.Label(card, text="You haven't submitted any visit requests yet.", font=FONT_BODY,
                      bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 14))

        def selected_approved_request():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a request", "Select one of your approved visit requests first.")
                return None
            rid = int(sel[0])
            r = next((x for x in mine if x["id"] == rid), None)
            if not r:
                return None
            if r["status"] != "Approved":
                messagebox.showerror("Cannot Request Change", "Only an approved visit can be changed through this workflow.")
                return None
            return r

        def request_schedule():
            r = selected_approved_request()
            if r: self._open_host_change_request_dialog(r, "schedule")

        def request_hsa():
            r = selected_approved_request()
            if r: self._open_host_change_request_dialog(r, "hsa")

        def request_both():
            r = selected_approved_request()
            if r: self._open_host_change_request_dialog(r, "hsa_schedule")

        btns = tk.Frame(wrap, bg=COLOR_BG)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Request Schedule Change", style="Accent.TButton", command=request_schedule).pack(side="left")
        ttk.Button(btns, text="Request HSA Access", command=request_hsa).pack(side="left", padx=8)
        ttk.Button(btns, text="Request HSA + Schedule", command=request_both).pack(side="left")
        tk.Label(wrap, text="The Host submits the request. The Security Manager only approves/rejects it; no appointment is changed directly from Security Review.",
                 font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_MUTED, wraplength=900, justify="left").pack(anchor="w", pady=(8, 0))

    # ---------------- APPROVER (FACTORY MANAGER): APPROVE REQUESTS ----------------
    def page_approver_requests(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Approve Requests",
                      "Group visitor requests submitted by Hosts, and walk-in visitors forwarded "
                      "by the Security Manager - mirrors Part II of the paper Visitor Request form").pack(
            anchor="w", pady=(0, 16))

        ok, result = api_list_visit_requests()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load requests from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        all_requests = result["requests"]
        pending = [r for r in all_requests
                   if r["status"] in ("Pending Approval", "Pending Factory Authorization")]
        decided = [r for r in all_requests if r["status"] in ("Approved", "Not Approved")]

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        tk.Label(card, text="Pending Requests", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=14, pady=(12, 6))
        cols = ("ID", "Origin", "Requested By", "Department", "Company", "Purpose", "Visitors", "HSA")
        tree = make_table(card, cols, (40, 80, 130, 120, 120, 140, 60, 70))
        tree.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        for r in pending:
            origin_text = "Walk-In" if r["origin"] == "walkin" else "Host Request"
            requested_by_text = r["requested_by"]
            visiting_host = r["visiting_employee"] or r["requested_by"]
            if visiting_host == self.current_user:
                requested_by_text = f"⚠ {requested_by_text} (visiting you)"
            tree.insert("", "end", iid=r["id"], values=(
                r["id"], origin_text, requested_by_text, r["department"] or "-", r["company"], r["purpose"],
                len(r["visitors"]), "Yes" if r["hsa_requested"] else "No"))
        if not pending:
            tk.Label(card, text="No pending requests. You're all caught up.",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=14, pady=(0, 10))

        def view_and_decide():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select a request", "Please select a pending request first.")
                return
            rid = int(sel[0])
            r = next(x for x in pending if x["id"] == rid)
            self._open_request_decision_dialog(r)

        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        ttk.Button(btns, text="Review Selected Request", style="Accent.TButton",
                   command=view_and_decide).pack(side="left")

        hist_card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        hist_card.pack(fill="both", expand=True, pady=(14, 0))
        tk.Label(hist_card, text="Decision History", font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=14, pady=(12, 6))
        hcols = ("ID", "Origin", "Requested By", "Company", "Status", "HSA Decision", "Decision Date")
        htree = make_table(hist_card, hcols, (40, 80, 140, 150, 110, 110, 140))
        htree.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        for r in decided:
            origin_text = "Walk-In" if r["origin"] == "walkin" else "Host Request"
            htree.insert("", "end", values=(
                r["id"], origin_text, r["requested_by"], r["company"], r["status"],
                (r["hsa_decision"] or "-") if r["hsa_requested"] else "-", r["decision_date"] or "-"))

    def _open_request_decision_dialog(self, r):
        """Shows full detail of one pending group request - visitor list, HSA
        info - and lets the Factory Manager Approve / Not Approve it, with an
        optional separate HSA decision if HSA access was requested."""
        win = tk.Toplevel(self)
        win.title(f"Visit Request #{r['id']}")
        win.geometry("560x600")
        win.configure(bg=COLOR_CARD)
        win.grab_set()

        tk.Label(win, text=f"Visit Request #{r['id']}"
                            + ("  (Walk-In)" if r["origin"] == "walkin" else ""),
                  font=FONT_H2, bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w", padx=18, pady=(16, 4))
        if r["origin"] == "walkin":
            info_lines = (f"Logged by (Guard): {r['requested_by']}\n"
                          f"Visiting: {r['visiting_employee']}  ({r['department'] or '-'})\n"
                          f"Company: {r['company']}\n"
                          f"Purpose: {r['purpose']}\n"
                          f"Security Manager review: {r['security_reviewed_by'] or '-'} "
                          f"on {r['security_review_date'] or '-'}")
        else:
            info_lines = (f"Requested by: {r['requested_by']}  ({r['department'] or '-'})\n"
                          f"Company: {r['company']}\n"
                          f"Purpose: {r['purpose']}\n"
                          f"Visit date: {r['visit_date']}   {r['start_visit']} - {r['finish_visit']}\n"
                          f"Receiving by: {r['receiving_by'] or '-'}")
        if r["notes"]:
            info_lines += f"\nNotes: {r['notes']}"
        tk.Label(win, text=info_lines, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT,
                  wraplength=520, justify="left").pack(anchor="w", padx=18, pady=(0, 10))

        visiting_host = r["visiting_employee"] or r["requested_by"]
        if visiting_host == self.current_user:
            warn = tk.Frame(win, bg="#fdecea", highlightbackground=COLOR_DANGER, highlightthickness=1)
            warn.pack(fill="x", padx=18, pady=(0, 10))
            tk.Label(warn, text="⚠ This visitor is here to see you. For proper segregation of "
                                 "duties, consider having an Administrator make this decision "
                                 "instead - click 'Let Admin Decide' to leave it pending for them, "
                                 "or proceed yourself (this will be clearly noted in the Audit Log).",
                      font=FONT_SMALL, bg="#fdecea", fg=COLOR_DANGER, wraplength=480,
                      justify="left").pack(anchor="w", padx=10, pady=(8, 4))
            ttk.Button(warn, text="Let Admin Decide Instead",
                       command=lambda: self._defer_to_admin(win)).pack(anchor="w", padx=10, pady=(0, 8))

        tk.Label(win, text="Visitors:", font=("Segoe UI", 10, "bold"), bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=18)
        vlist = tk.Frame(win, bg=COLOR_CARD)
        vlist.pack(anchor="w", padx=18, pady=(2, 10), fill="x")
        for i, v in enumerate(r["visitors"], start=1):
            idtext = f"  /  ID: {v['national_id']}" if v["national_id"] else ""
            tk.Label(vlist, text=f"{i}. {v['first_name']} {v['last_name']}{idtext}", font=FONT_SMALL,
                      bg=COLOR_CARD, fg=COLOR_TEXT).pack(anchor="w")

        hsa_decision_var = tk.StringVar(value="Approved")
        if r["hsa_requested"]:
            hsa_frame = tk.Frame(win, bg="#fff4e0", highlightbackground=COLOR_WARNING, highlightthickness=1)
            hsa_frame.pack(fill="x", padx=18, pady=(0, 10))
            
            # Format HSA details in detailed format
            hsa_details = format_hsa_details_for_report(r, approved=False)
            hsa_details_text = "\n".join(f"{label}: {value}" for label, value in hsa_details)
            
            tk.Label(hsa_frame, text=f"⚠ HSA access also requested\n{hsa_details_text}",
                      font=FONT_SMALL, bg="#fff4e0", fg="#8a5a00", justify="left", wraplength=500).pack(
                anchor="w", padx=10, pady=8)
            tk.Label(hsa_frame, text="HSA Decision:", font=FONT_SMALL, bg="#fff4e0", fg="#8a5a00").pack(
                anchor="w", padx=10)
            hsa_row = tk.Frame(hsa_frame, bg="#fff4e0")
            hsa_row.pack(anchor="w", padx=10, pady=(0, 8))
            ttk.Radiobutton(hsa_row, text="Approve HSA Access", variable=hsa_decision_var,
                             value="Approved").pack(side="left")
            ttk.Radiobutton(hsa_row, text="Do Not Approve HSA Access", variable=hsa_decision_var,
                             value="Not Approved").pack(side="left", padx=(10, 0))

        tk.Label(win, text="Approved By / Position", font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(
            anchor="w", padx=18, pady=(4, 0))
        position_var = tk.StringVar(value="Factory Manager")
        ttk.Entry(win, textvariable=position_var, width=30).pack(anchor="w", padx=18, pady=(2, 10))

        def decide(decision):
            hsa_dec = hsa_decision_var.get() if r["hsa_requested"] else None
            ok, result = api_decide_visit_request(r["id"], decision, position_var.get().strip(), hsa_dec)
            if not ok:
                messagebox.showerror("Could Not Update Request", result if isinstance(result, str) else str(result))
                return
            win.destroy()
            messagebox.showinfo("Done",
                                 f"Request #{r['id']} has been {decision.lower()}."
                                 + (f"\nVisitors are now approved for check-in." if decision == "Approved" else ""))
            self.show_page("Approve Requests")

        btn_row = tk.Frame(win, bg=COLOR_CARD)
        btn_row.pack(pady=(6, 16))
        ttk.Button(btn_row, text="Not Approve", command=lambda: decide("Not Approved")).pack(side="left", padx=6)
        ttk.Button(btn_row, text="Approve", style="Accent.TButton",
                   command=lambda: decide("Approved")).pack(side="left", padx=6)

    # ---------------- HOST: MY VISIT HISTORY ----------------
    def page_host_history(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "My Visit History", "All visits, past and present, where you are the host").pack(
            anchor="w", pady=(0, 16))

        ok, result = api_list_visitors()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load visitors from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("Visitor", "Company", "Purpose", "Visit Date", "Badge", "Status")
        tree = make_table(card, cols, (150, 150, 180, 100, 80, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        mine = [v for v in result["visitors"] if v["host"] == self.host_name]
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
        ok, result = api_list_users()
        total_users = len(result["users"]) if ok else "?"
        ok_v, result_v = api_list_visitors()
        total_visitors = len(result_v["visitors"]) if ok_v else "?"
        active_visitors = len([v for v in result_v["visitors"] if v["status"] == "Checked In"]) if ok_v else "?"
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

        # Check real system statuses
        db_status = "🟢 Online" if ok else "🔴 Offline"
        
        # Check if visitor management API works
        vm_status = "🟢 Running" if ok_v else "🔴 Error"
        
        # ID Scanner and Passport Scanner - check if configured
        id_scanner_status = "🟢 Ready"  # Will be ready if system is running
        passport_scanner_status = "🟢 Ready"  # Will be ready if system is running
        
        statuses = [
            ("Database", db_status),
            ("Visitor Management", vm_status),
            ("ID Scanner", id_scanner_status),
            ("Passport Scanner", passport_scanner_status),
        ]
        for name, status in statuses:
            row = tk.Frame(card, bg=COLOR_CARD)
            row.pack(fill="x", padx=20, pady=4)
            tk.Label(row, text=name, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
            tk.Label(row, text=status, font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_SUCCESS).pack(side="right")
        tk.Label(card, text="", bg=COLOR_CARD).pack(pady=6)  # bottom padding

    # ---------------- USER MANAGEMENT (admin only) ----------------
    def admin_change_password(self):
        if self.current_role != "admin":
            messagebox.showerror(
                "Access Denied",
                "Only the System Administrator can change this password."
            )
            return

        win = tk.Toplevel(self)
        win.title("Change My Password")
        win.geometry("440x300")
        win.configure(bg=COLOR_CARD)
        win.grab_set()
        win.resizable(False, False)

        tk.Label(
           win,
           text="Change My Password",
           font=FONT_H2,
           bg=COLOR_CARD,
           fg=COLOR_TEXT
        ).pack(pady=(20, 6))

        form = tk.Frame(win, bg=COLOR_CARD)
        form.pack(fill="x", padx=35)

        tk.Label(
           form,
           text="New Password",
           font=FONT_BODY,
           bg=COLOR_CARD,
           fg=COLOR_TEXT
        ).pack(anchor="w")

        new_password_var = tk.StringVar()
        ttk.Entry(
            form,
            textvariable=new_password_var,
            show="•",
            width=32
        ).pack(anchor="w", pady=(3, 12))

        tk.Label(
           form,
           text="Confirm New Password",
           font=FONT_BODY,
           bg=COLOR_CARD,
           fg=COLOR_TEXT
        ).pack(anchor="w")

        confirm_password_var = tk.StringVar()
        ttk.Entry(
            form,
            textvariable=confirm_password_var,
            show="•",
            width=32
        ).pack(anchor="w", pady=(3, 15))

        def save_password():
            new_password = new_password_var.get()
            confirm_password = confirm_password_var.get()

            ok, error = validate_password_policy(new_password)
            if not ok:
               messagebox.showerror(
                   "Invalid Password",
                   error,
                   parent=win
                )
                return

            if new_password != confirm_password:
                messagebox.showerror(
                    "Password Mismatch",
                    "The two passwords do not match.",
                    parent=win
            )
            return

            if not messagebox.askyesno(
               "Confirm Password Change",
               "Are you sure you want to change the Administrator password?",
               parent=win
            ):
               return

            ok, result = api_change_password(new_password)

            if not ok:
                messagebox.showerror(
                   "Could Not Change Password",
                   str(result),
                   parent=win
                )
                return

            win.destroy()

            messagebox.showinfo(
                "Password Changed",
                "Your Administrator password has been changed successfully."
            )

        ttk.Button(
            win,
            text="Change Password",
            style="Accent.TButton",
            command=save_password
        ).pack(pady=(4, 8))

        ttk.Button(
            win,
            text="Cancel",
            command=win.destroy
        ).pack()

    def page_user_management(self):
        if self.current_role != "admin":
            messagebox.showerror("Access Denied", "Only the System Administrator can manage user accounts.")
            return

        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "User Management",
                      "Only System Administrators can create or delete accounts. Every Host "
                      "account is tied to a department. Accounts are shared across every PC "
                      "connected to the VMS server.").pack(anchor="w", pady=(0, 16))

        ok, result = api_list_users()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load accounts from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        users = result["users"]

        if len(users) == 1 and users[0]["username"] == "admin":
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
                                  values=["Security Officer", "Host / Employee", "System Administrator",
                                          "Approver (Factory Manager)", "Security Guard (Gate)",
                                          "Security Manager"])
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

        tk.Label(form, text="New accounts are created with a default password shown after creation. "
                             "The user must set their own password the first time they log in.",
                  font=FONT_SMALL, bg=COLOR_CARD, fg=COLOR_MUTED, wraplength=520, justify="left").grid(
            row=5, column=0, columnspan=2, sticky="w", padx=6, pady=(10, 0))

        def auto_username(*_):
            if display_var.get().strip() and not username_var.get().strip():
                username_var.set(display_var.get().strip().lower().replace(" ", "."))
        display_var.trace_add("write", auto_username)

        ROLE_MAP = {"Security Officer": "officer", "Host / Employee": "host",
                    "System Administrator": "admin", "Approver (Factory Manager)": "approver",
                    "Security Guard (Gate)": "guard", "Security Manager": "security_manager"}

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

            ok, result = api_create_user(username, display, ROLE_MAP[role_choice], department)
            if not ok:
                messagebox.showerror("Could Not Create Account", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Account Created",
                                 f"{role_choice} account created for {display}.\n"
                                 f"Username: {username}\n"
                                 f"Default Password: {result['default_password']}\n"
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
        tree = make_table(list_card, cols, (140, 180, 150, 160, 120))
        tree.pack(fill="both", expand=True, padx=14, pady=(0, 8), side="top")
        role_display = {"officer": "Security Officer", "host": "Host / Employee",
                         "admin": "System Administrator", "approver": "Approver (Factory Manager)",
                         "guard": "Security Guard (Gate)", "security_manager": "Security Manager"}
        for u in users:
            if not u["active"]:
                status_text = "Deactivated"
            elif u.get("locked"):
                status_text = "🔒 Locked"
            else:
                status_text = "Active"
            tree.insert("", "end", iid=u["username"], values=(
                u["username"], u["display"], role_display[u["role"]],
                u["department"] or "-", status_text))

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
            ok, result = api_toggle_user(username)
            if not ok:
                messagebox.showerror("Could Not Update Account", result if isinstance(result, str) else str(result))
                return
            self.show_page("User Management")

        def reset_password_selected():
            username = get_selected_username()
            if not username:
                return
            target = next((u for u in users if u["username"] == username), None)
            name = target["display"] if target else username
            if not messagebox.askyesno("Confirm Reset Password",
                                        f"Reset the password for '{name}' ({username})?\n\n"
                                        "This immediately replaces their current password with a new "
                                        "temporary one and signs them out of any active session. "
                                        "It also clears an account lockout, if any."):
                return
            ok, result = api_reset_user_password(username)
            if not ok:
                messagebox.showerror("Could Not Reset Password", result if isinstance(result, str) else str(result))
                return
            messagebox.showinfo("Password Reset",
                                 f"Password for '{name}' ({username}) has been reset.\n\n"
                                 f"Temporary password: {result['temp_password']}\n\n"
                                 "Share this with them securely. They'll be required to set "
                                 "their own password the next time they log in.")
            self.show_page("User Management")

        def delete_selected():
            username = get_selected_username()
            if not username:
                return
            if username == self.current_username:
                messagebox.showerror("Not Allowed", "You can't delete the account you're logged in as.")
                return
            target = next((u for u in users if u["username"] == username), None)
            if messagebox.askyesno("Confirm Delete",
                                    f"Permanently delete the account '{username}' "
                                    f"({target['display'] if target else username})?\nThis cannot be undone."):
                ok, result = api_delete_user(username)
                if not ok:
                    messagebox.showerror("Could Not Delete Account", result if isinstance(result, str) else str(result))
                    return
                self.show_page("User Management")

        btn_row = tk.Frame(list_card, bg=COLOR_CARD)
        btn_row.pack(anchor="w", padx=14, pady=(0, 14))
        ttk.Button(btn_row, text="Activate / Deactivate Selected", command=toggle_selected).pack(side="left")
        ttk.Button(btn_row, text="Reset Password", command=reset_password_selected).pack(side="left", padx=(8, 0))
        ttk.Button(
            btn_row,
            text="Change My Password",
            command=self.admin_change_password
        ).pack(side="left", padx=(8, 0))
        ttk.Button(btn_row, text="Delete Selected Account", command=delete_selected).pack(side="left", padx=(8, 0))

    # ---------------- AUDIT LOG ----------------
    def page_audit(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        section_title(wrap, "Audit Log", "Every important system action is logged for compliance").pack(
            anchor="w", pady=(0, 16))

        ok, result = api_get_audit_log()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load the audit log from the server:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        all_entries = result["entries"]  # server already returns these newest-first

        # ---- Date Filter Bar ----
        filter_bar = tk.Frame(wrap, bg=COLOR_BG)
        filter_bar.pack(fill="x", pady=(0, 14))
        
        tk.Label(filter_bar, text="View logs for date:", font=FONT_BODY, bg=COLOR_BG).pack(side="left")
        selected_date = tk.StringVar(value=datetime.now().strftime("%Y-%m-%d"))
        date_entry = ttk.Entry(filter_bar, textvariable=selected_date, width=12)
        date_entry.pack(side="left", padx=(8, 0))
        tk.Label(filter_bar, text="(YYYY-MM-DD)", font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_MUTED).pack(
            side="left", padx=(4, 0))

        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        cols = ("Timestamp", "User", "Action", "Result", "Detail")
        tree = make_table(card, cols, (150, 160, 160, 90, 320))
        tree.pack(fill="both", expand=True, padx=14, pady=14)

        def filter_by_date():
            """Filter and display entries for the selected date."""
            tree.delete(*tree.get_children())
            try:
                filter_date = selected_date.get().strip()
                # Parse the date to validate format
                datetime.strptime(filter_date, "%Y-%m-%d")
            except ValueError:
                tk.Label(card, text=f"Invalid date format: {selected_date.get()}. Use YYYY-MM-DD",
                          font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_DANGER).pack(anchor="w", padx=18, pady=10)
                return
            
            filtered = [e for e in all_entries if e[0].startswith(filter_date)]
            if not filtered:
                tk.Label(card, text=f"No activity on {filter_date}.", font=FONT_BODY, bg=COLOR_CARD,
                          fg=COLOR_MUTED).pack(anchor="w", padx=18, pady=10)
            else:
                for entry in filtered:
                    tree.insert("", "end", values=entry)

        # Load initial (today's) entries
        filter_by_date()

        def export_csv():
            if not tree.get_children():
                messagebox.showwarning("Nothing to export", "No entries to export for this date.")
                return
            filename = f"Audit_Log_{selected_date.get()}_{datetime.now():%H%M%S}.csv"
            path = os.path.join(REPORTS_DIR, filename)
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(cols)
                for iid in tree.get_children():
                    writer.writerow(tree.item(iid)["values"])
            api_log("Audit Log Export", "Success", f"CSV: {filename}")
            if messagebox.askyesno("Exported", f"Audit log saved as:\n{path}\n\nOpen the folder now?"):
                open_in_file_explorer(path)

        def export_pdf():
            if not tree.get_children():
                messagebox.showwarning("Nothing to export", "No entries to export for this date.")
                return
            filename = f"Audit_Log_{selected_date.get()}_{datetime.now():%H%M%S}.pdf"
            path = os.path.join(REPORTS_DIR, filename)
            row_values = [tree.item(iid)["values"] for iid in tree.get_children()]

            if REPORTLAB_AVAILABLE:
                doc = SimpleDocTemplate(path, pagesize=landscape(A4),
                                         topMargin=1.5 * cm, bottomMargin=1.5 * cm)
                styles = getSampleStyleSheet()
                cell_style = styles["Normal"].clone("cell")
                cell_style.fontSize = 8
                elements = [
                    Paragraph(APP_TITLE, styles["Title"]),
                    Paragraph(f"Audit Log - {selected_date.get()}", styles["Heading2"]),
                    Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M} by {self.current_user}",
                              styles["Normal"]),
                    Spacer(1, 12),
                ]
                header_row = [Paragraph(f"<b>{c}</b>", cell_style) for c in cols]
                data_rows = [[Paragraph(str(v), cell_style) for v in row] for row in row_values]
                table = Table([header_row] + data_rows, repeatRows=1,
                               colWidths=[75, 90, 90, 55, 300])
                table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f9")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]))
                elements.append(table)
                doc.build(elements)
                api_log("Audit Log Export", "Success", f"PDF: {filename}")
                if messagebox.askyesno("Exported", f"PDF saved as:\n{path}\n\nOpen the folder now?"):
                    open_in_file_explorer(path)
            else:
                html_path = path.replace(".pdf", ".html")
                html_rows = "".join(
                    "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in row_values)
                html_head = "".join(f"<th>{c}</th>" for c in cols)
                html = f"""<html><head><meta charset="utf-8"><title>Audit Log</title>
                <style>
                body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; }}
                h1 {{ font-size: 18px; }} h2 {{ font-size: 14px; color: #444; font-weight: normal; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
                th, td {{ border: 1px solid #ccc; padding: 6px 10px; font-size: 12px; text-align: left; }}
                th {{ background: #1a2332; color: white; }}
                tr:nth-child(even) {{ background: #f4f6f9; }}
                </style></head><body>
                <h1>{APP_TITLE}</h1>
                <h2>Audit Log - {selected_date.get()} &middot; Generated {datetime.now():%Y-%m-%d %H:%M} by {self.current_user}</h2>
                <table><tr>{html_head}</tr>{html_rows}</table>
                </body></html>"""
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html)
                api_log("Audit Log Export", "Success", f"HTML (PDF fallback): {filename}")
                webbrowser.open(f"file://{html_path}")
                messagebox.showinfo(
                    "PDF library not installed",
                    "The 'reportlab' package isn't installed, so a print-ready HTML "
                    "version was opened in your browser instead.\n\n"
                    "In the browser: press Ctrl+P -> 'Save as PDF' to get a real PDF.\n\n"
                    "To enable direct one-click PDF export next time, run this once:\n"
                    "   pip install reportlab")

        def delete_history():
            """Safe history deletion - only deletes COMPLETED records."""
            dlg = tk.Toplevel(self)
            dlg.title("Delete Completed History")
            dlg.geometry("480x450")
            dlg.resizable(False, False)
            
            tk.Label(dlg, text="Delete Completed History (Safe Deletion)", font=("Segoe UI", 11, "bold")).pack(pady=10)
            tk.Label(dlg, text="Deletes ONLY finished records from today back to:", font=FONT_BODY).pack(pady=6)
            
            period_var = tk.StringVar(value="30")
            
            periods = [
                ("Today only", "1"),
                ("Last 7 days", "7"),
                ("Last 30 days", "30"),
                ("Last 90 days", "90"),
            ]
            
            for label, days in periods:
                ttk.Radiobutton(dlg, text=label, variable=period_var, value=days).pack(anchor="w", padx=30, pady=5)
            
            # Info box
            info_frame = tk.Frame(dlg, bg="#f5f5f5", relief="solid", borderwidth=1)
            info_frame.pack(fill="x", padx=20, pady=12)
            
            tk.Label(info_frame, text="SAFE DELETION - Will Delete:", bg="#f5f5f5", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(8, 4))
            tk.Label(info_frame, text="✓ Visitors who HAVE checked out\n✓ Completed visit requests\n✓ Associated badges\n✓ Old audit logs",
                     font=FONT_SMALL, justify="left", bg="#f5f5f5").pack(anchor="w", padx=20, pady=(0, 8))
            
            tk.Label(info_frame, text="WILL NOT Delete:", bg="#f5f5f5", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(4, 4))
            tk.Label(info_frame, text="✗ Active visitors (still checked in)\n✗ Active badges (still assigned)\n✗ Pending/incomplete requests\n✗ In-progress visits",
                     font=FONT_SMALL, justify="left", bg="#f5f5f5").pack(anchor="w", padx=20, pady=(0, 8))
            
            def confirm():
                days = int(period_var.get())
                day_labels = {"1": "today", "7": "last 7 days", "30": "last 30 days", "90": "last 90 days"}
                period_label = day_labels[str(days)]
                
                if not messagebox.askyesno("Confirm Safe Deletion",
                        f"Delete COMPLETED history from {period_label}?\n\n"
                        f"Only FINISHED records will be deleted:\n"
                        f"• Checked-out visitors\n"
                        f"• Completed requests\n"
                        f"• Returned badges\n"
                        f"• Audit logs\n\n"
                        f"Active records will be KEPT safe.\n\n"
                        "This action CANNOT be undone."):
                    return
                
                ok, msg = api_call("POST", f"/api/delete_history", {"days": days})
                if ok:
                    detail = msg.get("detail", f"Completed history deleted for period from {period_label}.")
                    messagebox.showinfo("Deletion Complete", detail)
                    filter_by_date()
                    dlg.destroy()
                else:
                    messagebox.showerror("Error", msg)
            
            ttk.Button(dlg, text="Proceed with Safe Deletion", command=confirm).pack(pady=14)

        # ---- Buttons ----
        btns = tk.Frame(card, bg=COLOR_CARD)
        btns.pack(fill="x", padx=14, pady=(0, 14))
        
        # Left side: View/Export
        ttk.Button(btns, text="Refresh", command=filter_by_date).pack(side="left")
        ttk.Button(btns, text="Export CSV", command=export_csv).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Export PDF", style="Accent.TButton", command=export_pdf).pack(
            side="left", padx=(8, 0))
        
        # Right side: Admin Delete (only if System Admin)
        if self.current_role == "admin":
            sep = tk.Label(btns, text=" | ", bg=COLOR_CARD).pack(side="left", padx=8)
            ttk.Button(btns, text="🗑 Delete History", command=delete_history).pack(side="left")
        
        tk.Label(wrap, text=f"Exports are saved to: {REPORTS_DIR}", font=FONT_SMALL,
                  bg=COLOR_BG, fg=COLOR_MUTED).pack(anchor="w", pady=(8, 0))

    # -------- NOTIFICATIONS --------
    def page_notifications(self):
        wrap = tk.Frame(self.content, bg=COLOR_BG)
        wrap.pack(fill="both", expand=True, padx=28, pady=22)
        
        section_title(wrap, "Notifications", "Stay updated on visitor requests, approvals, and check-ins").pack(
            anchor="w", pady=(0, 16))
        
        ok, result = api_get_notifications()
        if not ok:
            tk.Label(wrap, text=f"⚠ Could not load notifications:\n{result}",
                      font=FONT_BODY, bg=COLOR_BG, fg=COLOR_DANGER, wraplength=800, justify="left").pack(
                anchor="w", pady=20)
            return
        
        notifications = result.get("notifications", [])
        unread_count = result.get("unread_count", 0)
        
        # Header with status and action buttons
        header_frame = tk.Frame(wrap, bg=COLOR_BG)
        header_frame.pack(fill="x", pady=(0, 12))
        
        tk.Label(header_frame, text=f"{unread_count} unread • {len(notifications)} total", 
                 font=FONT_SMALL, bg=COLOR_BG, fg=COLOR_MUTED).pack(side="left")
        
        # Action buttons at top right
        def mark_all_read():
            if notifications:
                ok, result = api_mark_all_read()
                if ok:
                    self.show_page("Notifications")
        
        def delete_all():
            if not notifications:
                messagebox.showinfo("No notifications", "Nothing to delete")
                return
            if messagebox.askyesno("Delete All", "Delete all notifications?"):
                ok, result = api_delete_all_notifications()
                if ok:
                    self.show_page("Notifications")
        
        if notifications:
            ttk.Button(header_frame, text="Mark All as Read", command=mark_all_read).pack(side="right", padx=(8, 0))
            ttk.Button(header_frame, text="Delete All", command=delete_all).pack(side="right")
        
        # Notification card
        card = tk.Frame(wrap, bg=COLOR_CARD, highlightbackground="#e2e6ec", highlightthickness=1)
        card.pack(fill="both", expand=True)
        
        if not notifications:
            tk.Label(card, text="No notifications. You're all caught up!",
                      font=FONT_BODY, bg=COLOR_CARD, fg=COLOR_MUTED).pack(anchor="w", padx=18, pady=20)
        else:
            # Scrollable notification list
            inner_frame = tk.Frame(card, bg=COLOR_CARD)
            inner_frame.pack(fill="both", expand=True)
            
            scrollbar = ttk.Scrollbar(inner_frame)
            scrollbar.pack(side="right", fill="y")
            
            canvas = tk.Canvas(inner_frame, bg=COLOR_CARD, highlightthickness=0, yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.config(command=canvas.yview)
            
            scrollable_frame = tk.Frame(canvas, bg=COLOR_CARD)
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            
            def on_frame_configure(e):
                canvas.configure(scrollregion=canvas.bbox("all"))
            
            scrollable_frame.bind("<Configure>", on_frame_configure)
            
            # Create clickable notifications
            for notif in notifications:
                notif_id = notif["id"]
                notif_type = notif["type"]
                title = notif["title"]
                message = notif["message"]
                status = notif["status"]
                created_at = notif["created_at"]
                related_type = notif.get("related_type")
                related_id = notif.get("related_id")
                
                icon, color = get_notification_type_icon(notif_type)
                
                # Parse timestamp
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(created_at)
                    time_str = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    time_str = created_at[:16]
                
                # Button will be added below with new handler
                
                item_frame = tk.Frame(scrollable_frame, bg=COLOR_CARD, relief="solid", borderwidth=1)
                item_frame.pack(fill="x", padx=0, pady=0)
                
                # Content on left
                content_frame = tk.Frame(item_frame, bg=COLOR_CARD)
                content_frame.pack(fill="both", expand=True, padx=14, pady=12, side="left")
                
                # Header: icon + title
                header_frame_notif = tk.Frame(content_frame, bg=COLOR_CARD)
                header_frame_notif.pack(fill="x", anchor="w")
                
                tk.Label(header_frame_notif, text=f"{icon} {title}", font=("Segoe UI", 10, "bold"),
                         bg=COLOR_CARD, fg=COLOR_TEXT).pack(side="left")
                
                tk.Label(header_frame_notif, text=time_str, font=FONT_SMALL,
                         bg=COLOR_CARD, fg=COLOR_MUTED).pack(side="right")
                
                # Message
                if message:
                    tk.Label(content_frame, text=message, font=FONT_SMALL,
                            bg=COLOR_CARD, fg=COLOR_TEXT, wraplength=500, justify="left").pack(anchor="w", pady=(4, 0))
                
                # Simple handler function
                def handle_notification_click(app, notif_id, rel_type, rel_id, role):
                    try:
                        api_mark_notification_read(notif_id)
                        if rel_type == "visit_request":
                            if role == "approver":
                                app.show_page("Approve Requests")
                            elif role == "officer":
                                # Officer role - has Check-In page
                                app.show_page("Check-In")
                            elif role == "guard":
                                # Security Guard/Gate role - has Gate Approvals
                                app.show_page("Gate Approvals")
                            elif role == "security_manager":
                                if notif_type in ("hsa_review", "hsa_change_request", "hsa_decision", "hsa_change_decision"):
                                    app.show_page("HSA & Schedule Requests")
                                else:
                                    app.show_page("Security Review")
                            else:
                                # Host/Employee
                                app.show_page("My Requests")
                        elif rel_type == "visitor_change_request":
                            if role == "security_manager" or role == "admin":
                                app.show_page("HSA & Schedule Requests")
                            elif role == "host":
                                app.show_page("My Requests")
                            else:
                                app.show_page("Notifications")
                        elif rel_type == "visitor":
                            if role == "officer":
                                # Officer role - has Check-In page
                                app.show_page("Check-In")
                            elif role == "guard":
                                # Security Guard/Gate role - has Gate Approvals
                                app.show_page("Gate Approvals")
                            elif role == "host":
                                # Host sees check-in/out in My Overview
                                app.show_page("My Overview")
                            else:
                                app.show_page("My Requests")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to open: {str(e)}")
                
                btn_frame = tk.Frame(item_frame, bg=COLOR_CARD)
                btn_frame.pack(side="right", padx=14, pady=12)
                
                ttk.Button(btn_frame, text="Open →", 
                          command=partial(handle_notification_click, self, notif_id, related_type, related_id, self.current_role)).pack()
                
                # Separator
                separator = tk.Frame(scrollable_frame, bg="#e0e0e0", height=1)
                separator.pack(fill="x")


if __name__ == "__main__":
    app = VMSApp()
    app.mainloop()

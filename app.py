"""
app.py
======
Main Flask application for the ACC (Academic Credential) Portal System.

Features:
    - User registration & login (session-based auth, hashed passwords)
    - Student profile registration with file uploads (valid ID, credentials)
    - Scholarship application submission and status viewing
    - CSRF protection on every form
    - Authenticated, ownership-checked file retrieval

Run:
    python app.py
(See README.md for full setup instructions.)
"""

# =============================================================================
# Imports
# =============================================================================
import os
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_db, close_db, init_db
from file_utils import validate_upload, save_upload

# =============================================================================
# App configuration
# =============================================================================
app = Flask(__name__)

# SECURITY: SECRET_KEY signs the session cookie. If this key is weak or
# leaked, an attacker can forge session cookies and impersonate any user.
# In production, load this from an environment variable — never hard-code
# a real secret in source control. The fallback here is only for local
# development.
app.config["SECRET_KEY"] = os.environ.get("ACC_PORTAL_SECRET_KEY", "dev-only-change-me")

# SECURITY: Caps the maximum size of any incoming request body (including
# file uploads) at the Flask/Werkzeug level. This is a second layer of
# defense in addition to the per-file check in file_utils.py — it stops
# an oversized request from even being fully read into memory, which
# protects against memory-exhaustion denial-of-service attempts.
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB per request

# SECURITY: Session cookies expire after 30 minutes of inactivity. This
# limits the window an attacker has to reuse a stolen/leaked session
# cookie (session fixation / hijacking mitigation).
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# SECURITY: Restrict cookies so JavaScript can't read them (mitigates
# cookie theft via XSS) and so they aren't sent on cross-site requests
# (mitigates CSRF alongside the CSRFProtect extension below).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# In production behind HTTPS, also set: app.config["SESSION_COOKIE_SECURE"] = True

# SECURITY: Enables CSRF tokens on every form rendered with
# {{ csrf_token() }} / Flask-WTF's hidden_tag(), and rejects any POST
# request that doesn't include a valid token. This prevents Cross-Site
# Request Forgery — where a malicious site tricks a logged-in user's
# browser into submitting a request to this app without their knowledge.
csrf = CSRFProtect(app)

# Register the DB connection cleanup to run after every request.
app.teardown_appcontext(close_db)


# =============================================================================
# Helper: login-required decorator
# =============================================================================
def login_required(view_func):
    """
    Decorator that protects a route so it can only be accessed by a
    logged-in user. Redirects anonymous visitors to the login page.

    Args:
        view_func (callable): the Flask view function to wrap.

    Returns:
        callable: the wrapped view function.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


def admin_required(view_func):
    """
    Decorator that protects a route so it can only be accessed by a
    logged-in user whose account has is_admin = 1. Must be combined with
    (or used instead of, since it also checks login) login_required
    logic — here it performs both checks itself so every admin route
    only needs this one decorator.

    SECURITY: The admin flag is read from `session["is_admin"]`, which
    was set at login time directly from the trusted `users.is_admin`
    database column (never from any client-supplied input), so a user
    cannot elevate their own privileges by tampering with form data or
    request parameters. The session cookie itself is cryptographically
    signed with SECRET_KEY, so a user also cannot hand-edit the cookie
    to flip this flag to True without invalidating the signature.

    Args:
        view_func (callable): the Flask view function to wrap.

    Returns:
        callable: the wrapped view function.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        if not session.get("is_admin"):
            # Return 404 rather than 403 so the existence of admin
            # routes isn't confirmed to non-admin users probing URLs.
            abort(404)
        return view_func(*args, **kwargs)
    return wrapped


# =============================================================================
# Routes: Authentication
# =============================================================================
@app.route("/", methods=["GET"])
def index():
    """
    Landing page. Redirects to the dashboard if already logged in,
    otherwise shows the login page.

    Returns:
        Response: rendered template or redirect.
    """
    if "user_id" in session:
        if session.get("is_admin"):
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Handle new user account creation (username, email, password only —
    profile details are collected separately in /register/profile).

    GET: show the registration form.
    POST: validate input, hash the password, and insert a new user row.

    Security:
        - Password is hashed with werkzeug's generate_password_hash
          (PBKDF2 with a random salt by default). We NEVER store or log
          the plaintext password. Hashing + salting means that even if
          the database is leaked, attackers cannot directly read
          passwords, and cannot use precomputed "rainbow table" lookups
          because each password gets a unique salt.
        - Username/email uniqueness is enforced at the DB level (UNIQUE
          constraint) as well as checked here, preventing duplicate
          account / account-squatting issues.
        - All queries use parameterized "?" placeholders to prevent SQL
          Injection.

    Returns:
        Response: rendered template on GET or validation failure,
        redirect to login on success.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- Server-side validation (never trust client-side JS alone) ---
        errors = []
        if len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if "@" not in email or "." not in email:
            errors.append("Please enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html")

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()
        if existing:
            flash("That username or email is already registered.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        db.commit()

        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handle user login. Verifies credentials and starts a session.

    Security:
        - Uses check_password_hash to verify the submitted password
          against the stored hash (constant-time comparison internally,
          which helps resist timing attacks).
        - Uses a single generic error message ("Invalid username or
          password") for both "user not found" and "wrong password"
          cases, so an attacker cannot use the error message to enumerate
          which usernames/emails exist in the system (username
          enumeration prevention).

    Returns:
        Response: rendered template on GET/failure, redirect to
        dashboard on success.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # Start the session. Flask signs this cookie using SECRET_KEY, so
        # the client cannot tamper with the contents (e.g. change user_id)
        # without invalidating the signature.
        session.clear()  # avoid session fixation: start with a clean session
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["is_admin"] = bool(user["is_admin"])
        session.permanent = True  # apply PERMANENT_SESSION_LIFETIME timeout

        flash(f"Welcome back, {user['username']}!", "success")
        if session["is_admin"]:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """
    Log the current user out by clearing the session.

    Returns:
        Response: redirect to the login page.
    """
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =============================================================================
# Routes: Dashboard
# =============================================================================
@app.route("/dashboard")
@login_required
def dashboard():
    """
    Show the logged-in student's dashboard: profile status, uploaded
    documents, and scholarship application history.

    Returns:
        Response: rendered dashboard template.
    """
    db = get_db()
    user_id = session["user_id"]

    student = db.execute(
        "SELECT * FROM students WHERE user_id = ?", (user_id,)
    ).fetchone()

    uploads = db.execute(
        "SELECT * FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC",
        (user_id,)
    ).fetchall()

    applications = db.execute(
        "SELECT * FROM scholarship_applications WHERE user_id = ? ORDER BY submitted_at DESC",
        (user_id,)
    ).fetchall()

    return render_template(
        "dashboard.html",
        student=student,
        uploads=uploads,
        applications=applications
    )


# =============================================================================
# Routes: Student profile registration + document upload
# =============================================================================
@app.route("/register/profile", methods=["GET", "POST"])
@login_required
def register_profile():
    """
    Collect student profile details and required document uploads
    (valid ID, credentials). Creates/updates the `students` row and
    inserts rows into `uploads` for each accepted file.

    Security:
        - Every uploaded file passes through validate_upload() BEFORE
          anything is written to disk: extension whitelist, magic-byte
          signature check, and size limit (see file_utils.py for details
          on why each check matters).
        - Files are saved with save_upload(), which generates a random
          filename and stores it under a per-user folder — the original
          user-supplied filename is never used as a path.

    Returns:
        Response: rendered form template, or redirect to dashboard on
        success.
    """
    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        address = request.form.get("address", "").strip()
        contact_number = request.form.get("contact_number", "").strip()
        birthdate = request.form.get("birthdate", "").strip()

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        if not address:
            errors.append("Address is required.")
        if not contact_number:
            errors.append("Contact number is required.")
        if not birthdate:
            errors.append("Birthdate is required.")

        valid_id_file = request.files.get("valid_id")
        credential_file = request.files.get("credential")

        # Validate the uploaded files (extension + signature + size).
        id_ok, id_error = validate_upload(valid_id_file, "valid_id")
        if not id_ok:
            errors.append(f"Valid ID: {id_error}")

        cred_ok, cred_error = validate_upload(credential_file, "credential")
        if not cred_ok:
            errors.append(f"Credential: {cred_error}")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_profile.html")

        # --- Save profile (insert or update if it already exists) ---
        existing_student = db.execute(
            "SELECT id FROM students WHERE user_id = ?", (user_id,)
        ).fetchone()

        if existing_student:
            db.execute(
                """UPDATE students
                   SET full_name = ?, address = ?, contact_number = ?, birthdate = ?
                   WHERE user_id = ?""",
                (full_name, address, contact_number, birthdate, user_id)
            )
        else:
            db.execute(
                """INSERT INTO students (user_id, full_name, address, contact_number, birthdate)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, full_name, address, contact_number, birthdate)
            )

        # --- Save each validated file to disk, then record its metadata ---
        for file_storage, category in ((valid_id_file, "valid_id"), (credential_file, "credential")):
            meta = save_upload(file_storage, user_id, category)
            db.execute(
                """INSERT INTO uploads
                   (user_id, file_category, original_filename, stored_filename,
                    file_path, mime_type, file_size_bytes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, category, meta["original_filename"], meta["stored_filename"],
                 meta["file_path"], meta["mime_type"], meta["file_size_bytes"])
            )

        db.commit()
        flash("Profile and documents submitted successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register_profile.html")


# =============================================================================
# Routes: Scholarship application
# =============================================================================
@app.route("/scholarship/apply", methods=["GET", "POST"])
@login_required
def scholarship_apply():
    """
    Let a logged-in student submit a scholarship application. Optionally
    accepts a supporting document upload.

    Returns:
        Response: rendered form template, or redirect to dashboard on
        success.
    """
    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        scholarship_type = request.form.get("scholarship_type", "").strip()
        reason = request.form.get("reason", "").strip()

        errors = []
        if not scholarship_type:
            errors.append("Please select a scholarship type.")
        if len(reason) < 20:
            errors.append("Please provide a more detailed reason (at least 20 characters).")

        supporting_doc = request.files.get("supporting_doc")
        if supporting_doc and supporting_doc.filename != "":
            doc_ok, doc_error = validate_upload(supporting_doc, "scholarship_doc")
            if not doc_ok:
                errors.append(f"Supporting document: {doc_error}")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("scholarship_apply.html")

        db.execute(
            """INSERT INTO scholarship_applications (user_id, scholarship_type, reason, status)
               VALUES (?, ?, ?, 'Pending')""",
            (user_id, scholarship_type, reason)
        )

        if supporting_doc and supporting_doc.filename != "":
            meta = save_upload(supporting_doc, user_id, "scholarship_doc")
            db.execute(
                """INSERT INTO uploads
                   (user_id, file_category, original_filename, stored_filename,
                    file_path, mime_type, file_size_bytes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, "scholarship_doc", meta["original_filename"], meta["stored_filename"],
                 meta["file_path"], meta["mime_type"], meta["file_size_bytes"])
            )

        db.commit()
        flash("Scholarship application submitted successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("scholarship_apply.html")


# =============================================================================
# Routes: Authenticated, ownership-checked file access
# =============================================================================
@app.route("/uploads/<int:upload_id>")
@login_required
def view_upload(upload_id):
    """
    Serve an uploaded file, but ONLY if it belongs to the currently
    logged-in user. This prevents any user from viewing another user's
    ID photo or documents just by guessing/incrementing an upload ID
    (an "Insecure Direct Object Reference" / IDOR vulnerability), which
    is why files are never placed under Flask's public `static/` folder.

    Args:
        upload_id (int): the primary key of the `uploads` row to serve.

    Returns:
        Response: the file content, or 404 if not found / not owned by
        the current user.
    """
    db = get_db()
    user_id = session["user_id"]

    # Admins may view any student's file (needed for document review);
    # regular users may only view their own (ownership check retained).
    if session.get("is_admin"):
        upload_row = db.execute(
            "SELECT * FROM uploads WHERE id = ?", (upload_id,)
        ).fetchone()
    else:
        upload_row = db.execute(
            "SELECT * FROM uploads WHERE id = ? AND user_id = ?",
            (upload_id, user_id)
        ).fetchone()

    if upload_row is None:
        abort(404)

    directory = os.path.dirname(upload_row["file_path"])
    filename = os.path.basename(upload_row["file_path"])
    return send_from_directory(directory, filename)


# =============================================================================
# Routes: Admin
# =============================================================================
@app.route("/admin")
@admin_required
def admin_dashboard():
    """
    Admin landing page: quick stats overview (total students, pending
    applications, etc.) plus links into the student list and application
    review screens.

    Returns:
        Response: rendered admin dashboard template.
    """
    db = get_db()

    total_students = db.execute(
        "SELECT COUNT(*) AS c FROM users WHERE is_admin = 0"
    ).fetchone()["c"]

    total_applications = db.execute(
        "SELECT COUNT(*) AS c FROM scholarship_applications"
    ).fetchone()["c"]

    pending_count = db.execute(
        "SELECT COUNT(*) AS c FROM scholarship_applications WHERE status = 'Pending'"
    ).fetchone()["c"]

    approved_count = db.execute(
        "SELECT COUNT(*) AS c FROM scholarship_applications WHERE status = 'Approved'"
    ).fetchone()["c"]

    rejected_count = db.execute(
        "SELECT COUNT(*) AS c FROM scholarship_applications WHERE status = 'Rejected'"
    ).fetchone()["c"]

    profiles_completed = db.execute(
        "SELECT COUNT(*) AS c FROM students"
    ).fetchone()["c"]

    stats = {
        "total_students": total_students,
        "profiles_completed": profiles_completed,
        "total_applications": total_applications,
        "pending_count": pending_count,
        "approved_count": approved_count,
        "rejected_count": rejected_count,
    }

    recent_applications = db.execute(
        """SELECT sa.*, u.username FROM scholarship_applications sa
           JOIN users u ON u.id = sa.user_id
           ORDER BY sa.submitted_at DESC LIMIT 5"""
    ).fetchall()

    return render_template(
        "admin_dashboard.html", stats=stats, recent_applications=recent_applications
    )


@app.route("/admin/students")
@admin_required
def admin_students():
    """
    List all registered students, with optional search by name, username,
    or email, so an admin can quickly find a specific student.

    Query params:
        q (str, optional): search term.

    Returns:
        Response: rendered student list template.
    """
    db = get_db()
    query = request.args.get("q", "").strip()

    if query:
        # Parameterized LIKE query -- the "%" wildcards are placed around
        # the bound parameter value, never concatenated into the SQL
        # string itself, so this remains injection-safe.
        like_term = f"%{query}%"
        rows = db.execute(
            """SELECT u.id AS user_id, u.username, u.email, u.created_at,
                      s.full_name, s.contact_number
               FROM users u
               LEFT JOIN students s ON s.user_id = u.id
               WHERE u.is_admin = 0
                 AND (u.username LIKE ? OR u.email LIKE ? OR s.full_name LIKE ?)
               ORDER BY u.created_at DESC""",
            (like_term, like_term, like_term)
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT u.id AS user_id, u.username, u.email, u.created_at,
                      s.full_name, s.contact_number
               FROM users u
               LEFT JOIN students s ON s.user_id = u.id
               WHERE u.is_admin = 0
               ORDER BY u.created_at DESC"""
        ).fetchall()

    return render_template("admin_students.html", students=rows, query=query)


@app.route("/admin/students/<int:student_user_id>")
@admin_required
def admin_student_detail(student_user_id):
    """
    Show one student's full profile, uploaded documents, and scholarship
    application history, for admin review.

    Args:
        student_user_id (int): the `users.id` of the student to view.

    Returns:
        Response: rendered detail template, or 404 if no such student.
    """
    db = get_db()

    user_row = db.execute(
        "SELECT * FROM users WHERE id = ? AND is_admin = 0", (student_user_id,)
    ).fetchone()
    if user_row is None:
        abort(404)

    student = db.execute(
        "SELECT * FROM students WHERE user_id = ?", (student_user_id,)
    ).fetchone()

    uploads = db.execute(
        "SELECT * FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC",
        (student_user_id,)
    ).fetchall()

    applications = db.execute(
        "SELECT * FROM scholarship_applications WHERE user_id = ? ORDER BY submitted_at DESC",
        (student_user_id,)
    ).fetchall()

    return render_template(
        "admin_student_detail.html", user=user_row, student=student,
        uploads=uploads, applications=applications
    )


@app.route("/admin/applications")
@admin_required
def admin_applications():
    """
    List all scholarship applications across all students, with optional
    filtering by status, for admin review.

    Query params:
        status (str, optional): "Pending", "Approved", or "Rejected".

    Returns:
        Response: rendered applications list template.
    """
    db = get_db()
    status_filter = request.args.get("status", "").strip()

    valid_statuses = {"Pending", "Approved", "Rejected"}
    if status_filter in valid_statuses:
        applications = db.execute(
            """SELECT sa.*, u.username, u.email FROM scholarship_applications sa
               JOIN users u ON u.id = sa.user_id
               WHERE sa.status = ?
               ORDER BY sa.submitted_at DESC""",
            (status_filter,)
        ).fetchall()
    else:
        applications = db.execute(
            """SELECT sa.*, u.username, u.email FROM scholarship_applications sa
               JOIN users u ON u.id = sa.user_id
               ORDER BY sa.submitted_at DESC"""
        ).fetchall()

    return render_template(
        "admin_applications.html", applications=applications, status_filter=status_filter
    )


@app.route("/admin/applications/<int:application_id>/decide", methods=["POST"])
@admin_required
def admin_decide_application(application_id):
    """
    Approve or reject a scholarship application. Records which admin made
    the decision and when, for an audit trail.

    Form fields:
        decision (str): "Approved" or "Rejected".

    Security:
        - Protected by @admin_required, so only admin accounts can reach
          this route.
        - Protected by CSRF (Flask-WTF), so the decision can't be forged
          by a request from another site.
        - The decision value is checked against a whitelist before being
          written to the database, rather than trusting the submitted
          string directly.

    Args:
        application_id (int): the `scholarship_applications.id` to update.

    Returns:
        Response: redirect back to the applications list.
    """
    decision = request.form.get("decision", "")
    if decision not in ("Approved", "Rejected"):
        flash("Invalid decision.", "error")
        return redirect(url_for("admin_applications"))

    db = get_db()
    application = db.execute(
        "SELECT id FROM scholarship_applications WHERE id = ?", (application_id,)
    ).fetchone()
    if application is None:
        abort(404)

    db.execute(
        """UPDATE scholarship_applications
           SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
           WHERE id = ?""",
        (decision, session["user_id"], application_id)
    )
    db.commit()

    flash(f"Application #{application_id} marked as {decision}.", "success")
    return redirect(url_for("admin_applications"))


# =============================================================================
# Entry point
# =============================================================================
if __name__ == "__main__":
    # Initialize the database (creates tables if they don't exist yet)
    # every time the app starts, so first-run setup is automatic.
    init_db()
    # debug=True is for LOCAL DEVELOPMENT ONLY — it enables the interactive
    # debugger and auto-reload, both of which are security risks in
    # production (the debugger can allow remote code execution if exposed).
    # Set debug=False and use a production WSGI server (e.g. gunicorn)
    # for deployment.
    app.run(debug=True)

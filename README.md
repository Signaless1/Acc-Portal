<<<<<<< HEAD
# ACC Portal System

A student academic credential portal built with **Flask**, **Python**, **HTML (Jinja2)**, and **SQLite**.

## Features
- Account registration & login (hashed passwords, session-based auth)
- Student profile registration with file uploads (valid ID: JPEG/PNG; credentials: JPEG/PNG/PDF)
- Scholarship application submission with status tracking (Pending / Approved / Rejected)
- Admin portal: stats overview, student directory with search, document review, and application approve/reject

## Project Structure
```
acc_portal/
├── app.py                        # Main Flask application (routes)
├── db.py                         # Database connection helper
├── file_utils.py                 # File upload validation & safe storage
├── create_admin.py               # CLI script to create admin accounts
├── schema.sql                    # SQLite table definitions
├── requirements.txt              # Python dependencies
├── static/
│   └── css/style.css             # Shared styling
├── templates/
│   ├── base.html                 # Shared layout + navbar + flash messages
│   ├── register.html             # Account creation form
│   ├── login.html                # Login form
│   ├── register_profile.html     # Student profile + document upload form
│   ├── scholarship_apply.html    # Scholarship application form
│   ├── dashboard.html            # Student: profile / uploads / applications overview
│   ├── admin_dashboard.html      # Admin: stats overview
│   ├── admin_students.html       # Admin: searchable student list
│   ├── admin_student_detail.html # Admin: one student's full profile + documents
│   └── admin_applications.html   # Admin: review + approve/reject applications
└── uploads/                      # Uploaded files (NOT publicly served directly)
```

## Setup & Run

1. **Create a virtual environment (recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set a real secret key (recommended for anything beyond local testing):**
   ```bash
   export ACC_PORTAL_SECRET_KEY="a-long-random-string"   # Windows: set ACC_PORTAL_SECRET_KEY=...
   ```

4. **Run the app** (this also auto-creates `acc_portal.db` from `schema.sql` on first run):
   ```bash
   python app.py
   ```

5. Open **http://127.0.0.1:5000** in your browser.

## Usage Flow

### Student
1. Register an account (`/register`) → username, email, password.
2. Log in (`/login`).
3. Complete your student profile and upload your Valid ID + Credential (`/register/profile`).
4. Apply for a scholarship (`/scholarship/apply`).
5. View everything, including your application status, on your dashboard (`/dashboard`).

### Admin
Admin accounts **cannot** be created through the public `/register` form — this is intentional (see Security Summary below). Create one from the command line instead:

```bash
python create_admin.py
```

Follow the interactive prompts for username, email, and password. Then log in at `/login` with those credentials — admins are automatically redirected to the **Admin Dashboard** (`/admin`) instead of the student dashboard.

From there, an admin can:
- View overview stats (`/admin`) — total students, profiles completed, pending/approved/rejected applications.
- Search and browse all registered students (`/admin/students`).
- Open a student's full profile, uploaded documents (Valid ID, Credentials), and application history (`/admin/students/<id>`).
- Review and **Approve** or **Reject** scholarship applications (`/admin/applications`), filterable by status. Each decision records which admin made it and when.


---

## Security Summary

| Measure | Implemented Via | Risk It Prevents |
|---|---|---|
| Password hashing | `werkzeug.security.generate_password_hash` / `check_password_hash` | Stops plaintext passwords from being exposed in a data breach; salting defeats rainbow-table attacks |
| Parameterized SQL queries | `?` placeholders in every `db.execute()` call | **SQL Injection** — user input can never alter the structure of a SQL command |
| CSRF protection | `Flask-WTF`'s `CSRFProtect` + `{{ csrf_token() }}` in every form | **Cross-Site Request Forgery** — blocks forged form submissions from other sites |
| File extension whitelist | `file_utils.is_extension_allowed()` | Blocks obviously disallowed file types at the door |
| Magic-byte signature check | `file_utils.detect_signature()` | Catches files that are **renamed** to look like an image/PDF but aren't (polyglot/disguised-payload attacks) |
| File size limits | Per-file check + Flask's `MAX_CONTENT_LENGTH` | Denial-of-service via disk/memory exhaustion |
| `secure_filename()` + random stored filenames | `file_utils.save_upload()` | **Path traversal** and filename-collision/overwrite attacks |
| Per-user upload folders outside `static/` | `uploads/<user_id>/` + authenticated `/uploads/<id>` route | **Insecure Direct Object Reference (IDOR)** — stops one user from viewing another user's ID/documents by guessing a URL |
| Session cookie flags (`HttpOnly`, `SameSite=Lax`) | Flask config | Cookie theft via XSS; cross-site cookie leakage |
| Session timeout (30 min) | `PERMANENT_SESSION_LIFETIME` | Limits damage window if a session cookie is stolen |
| Generic login error message | `login()` route | Prevents username/email enumeration |
| `session.clear()` on login | `login()` route | Prevents session fixation attacks |
| Admin accounts only creatable via server-side CLI script (`create_admin.py`) | `/register` always inserts `is_admin = 0`; `create_admin.py` is a separate script run at the terminal | **Privilege escalation** — no web-reachable code path can ever turn a signup into an admin account |
| Admin role read only from the signed session, never from request input | `admin_required` decorator checks `session["is_admin"]`, set at login from the trusted DB column | A user cannot self-promote to admin by tampering with form fields, cookies, or request params (the signed cookie can't be edited without invalidating it) |
| Admin routes return 404 (not 403) to non-admins | `admin_required` decorator | Avoids confirming to a probing user that admin routes even exist |
| Whitelisted decision values on approve/reject | `admin_decide_application()` checks `decision` against `("Approved", "Rejected")` | Stops arbitrary/unexpected values from being written to the `status` column |
| Audit trail on scholarship decisions | `reviewed_by` / `reviewed_at` columns | Accountability — every approve/reject is traceable to an admin and a timestamp |

**Before deploying to production**, additionally:
- Set `app.config["SESSION_COOKIE_SECURE"] = True` (requires HTTPS).
- Set `debug=False` and run behind a production WSGI server (e.g. `gunicorn`), not `app.run()`.
- Load `SECRET_KEY` from a secrets manager / environment variable — never commit it.
- Consider rate-limiting login attempts (e.g. `Flask-Limiter`) to slow brute-force attacks.
=======
# Acc-Portal
A portal made for scholarship application and management for ACC using AI
>>>>>>> 0e39d77f5350414e03454ba161de0409d2c72bdc

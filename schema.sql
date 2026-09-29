-- =============================================================================
-- schema.sql
-- Database schema for the ACC (Academic Credential) Portal System.
--
-- Design notes:
--   - `users` holds ONLY authentication data (username, email, hashed password).
--     Keeping auth data separate from profile data is a common security/
--     design pattern: it limits what's exposed if the `students` table is
--     ever joined into a less-trusted report or export.
--   - `students` holds personal/profile info and is linked to `users` via a
--     foreign key (one-to-one).
--   - `uploads` stores FILE METADATA ONLY (path, type, original name) — never
--     the raw file bytes. Actual files live on disk under /uploads/<user_id>/.
--     This keeps the database small and fast, and is the standard approach
--     for handling file uploads in a relational database.
--   - `scholarship_applications` stores one row per application, linked to
--     the student who submitted it, with a status column for admin review.
--   - All foreign keys use ON DELETE CASCADE so that deleting a user cleanly
--     removes their dependent records instead of leaving orphaned rows
--     (which could otherwise be exploited or cause inconsistent data).
-- =============================================================================

PRAGMA foreign_keys = ON;  -- SQLite disables FK enforcement by default; turn it on.

-- -----------------------------------------------------------------------------
-- Table: users
-- Stores login credentials only. Passwords are stored as salted hashes
-- (via werkzeug.security), NEVER as plaintext.
-- `is_admin` distinguishes staff/admin accounts from regular student
-- accounts. It defaults to 0 (not admin) so the public /register route
-- can NEVER create an admin account by itself — admin accounts are only
-- ever created via the separate create_admin.py script (see README).
-- This separation is a security measure: it removes any code path where
-- a normal user-facing form could be tricked into granting admin rights.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- Table: students
-- Personal/profile information, one row per user.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS students (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL UNIQUE,
    full_name       TEXT NOT NULL,
    address         TEXT NOT NULL,
    contact_number  TEXT NOT NULL,
    birthdate       DATE NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- Table: uploads
-- Metadata for uploaded files (valid ID, credentials, scholarship docs).
-- `file_category` distinguishes what kind of document this is.
-- `stored_filename` is the sanitized/randomized name saved on disk;
-- `original_filename` is what the user uploaded (kept for display only,
-- never used to build a filesystem path).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS uploads (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL,
    file_category       TEXT NOT NULL CHECK (file_category IN ('valid_id', 'credential', 'scholarship_doc')),
    original_filename   TEXT NOT NULL,
    stored_filename     TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    mime_type           TEXT NOT NULL,
    file_size_bytes     INTEGER NOT NULL,
    uploaded_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- Table: scholarship_applications
-- One row per scholarship application submitted by a student.
-- `reviewed_by` / `reviewed_at` provide a lightweight audit trail so it's
-- clear which admin made the approve/reject decision and when.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scholarship_applications (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL,
    scholarship_type    TEXT NOT NULL,
    reason              TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected')),
    submitted_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_by         INTEGER,
    reviewed_at         TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users (id) ON DELETE SET NULL
);

-- Helpful indexes for the columns we'll query on most often.
CREATE INDEX IF NOT EXISTS idx_uploads_user_id ON uploads (user_id);
CREATE INDEX IF NOT EXISTS idx_scholarship_user_id ON scholarship_applications (user_id);

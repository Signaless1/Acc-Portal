"""
create_admin.py
================
Command-line script to create an admin account.

SECURITY: Admin accounts are intentionally NEVER creatable through the
public /register route or any web form — that route always inserts rows
with is_admin = 0. The only way to create an admin account is by running
this script directly on the server, which requires filesystem/terminal
access. This prevents a web-based privilege-escalation path (e.g. a bug
or tampered request turning a normal signup into an admin account).

Usage:
    python create_admin.py
    (then follow the interactive prompts)
"""

import getpass
import sqlite3
from werkzeug.security import generate_password_hash

from db import DATABASE_PATH, init_db


def create_admin():
    """
    Interactively prompt for admin credentials and insert an admin user
    row (is_admin = 1) into the database.

    Returns:
        None
    """
    init_db()  # make sure tables exist before we try to insert

    print("=== Create ACC Portal Admin Account ===")
    username = input("Admin username: ").strip()
    email = input("Admin email: ").strip().lower()
    password = getpass.getpass("Admin password (min 8 chars): ")
    confirm = getpass.getpass("Confirm password: ")

    if len(username) < 3:
        print("Error: username must be at least 3 characters.")
        return
    if "@" not in email or "." not in email:
        print("Error: please enter a valid email address.")
        return
    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        return
    if password != confirm:
        print("Error: passwords do not match.")
        return

    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")

    existing = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (username, email)
    ).fetchone()
    if existing:
        print("Error: that username or email is already registered.")
        conn.close()
        return

    password_hash = generate_password_hash(password)
    conn.execute(
        "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
        (username, email, password_hash)
    )
    conn.commit()
    conn.close()

    print(f"Admin account '{username}' created successfully.")


if __name__ == "__main__":
    create_admin()

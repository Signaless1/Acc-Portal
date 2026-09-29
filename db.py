"""
db.py
=====
Database connection helper for the ACC Portal System.

We use RAW sqlite3 (instead of an ORM like Flask-SQLAlchemy) for this
project because:
    1. The schema is small and stable (4 tables), so the overhead of an
       ORM isn't necessary.
    2. It makes the SQL fully visible and easy to audit for security
       (parameterized queries are easy to spot-check).
    3. SQLite + raw sqlite3 has zero extra setup, which keeps the project
       easy to run for learning/demo purposes.

SECURITY NOTE: Every query in this project uses "?" placeholders and
passes values as a separate parameter tuple (e.g.
`cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`).
This is what prevents SQL Injection — the database driver treats the
placeholder values strictly as DATA, never as part of the SQL command
itself, so an attacker cannot break out of the query by injecting
characters like `' OR '1'='1`. We NEVER use Python string formatting
(f-strings, %, .format(), string concatenation) to build SQL with
user input.
"""

import sqlite3
from flask import g

DATABASE_PATH = "acc_portal.db"


def get_db():
    """
    Return a SQLite connection for the current request context.

    Flask's `g` object is a per-request storage container. We store the
    connection on `g` so that if multiple parts of the same request need
    the database, they reuse the same connection instead of opening a
    new one each time.

    Returns:
        sqlite3.Connection: an open connection with row_factory set to
        sqlite3.Row, which lets us access columns by name (row["email"])
        instead of only by numeric index — this makes template code much
        more readable.

    Raises:
        sqlite3.Error: if the connection cannot be established.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
        # Enforce foreign key constraints (SQLite ignores them by default).
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    """
    Close the database connection at the end of the request, if one was
    opened. Registered as a Flask `teardown_appcontext` handler in app.py.

    Args:
        exception: any unhandled exception from the request (Flask passes
            this automatically); unused here but required by the hook
            signature.

    Returns:
        None
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """
    Initialize the database by executing schema.sql. Safe to run multiple
    times because every CREATE TABLE statement uses "IF NOT EXISTS".

    Returns:
        None
    """
    conn = sqlite3.connect(DATABASE_PATH)
    with open("schema.sql", "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

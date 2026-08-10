"""SQLite access: one connection per request, closed on teardown.

Every query in this project goes through here, and every query that touches user
input binds its values as parameters (the ``?`` placeholders) instead of pasting
them into the SQL text. That single habit is what makes SQL injection impossible:
the driver ships the statement and the values over separate channels, so a value
can never be re-read as syntax no matter what characters it contains.
"""
import sqlite3

from flask import Flask, current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Uniqueness is enforced by the database, not by a SELECT-then-INSERT check in
-- Python. Two requests racing to claim the same address cannot both win here;
-- with an application-level check they can, because both can read "free"
-- before either writes.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE TABLE IF NOT EXISTS sessions (
    -- The primary key is the HASH of the session token, never the token. A
    -- read-only leak of this table therefore hands an attacker nothing they can
    -- put in a cookie: they would have to invert SHA-256 to get the real value.
    token_hash   TEXT    PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    csrf_token   TEXT    NOT NULL,
    created_at   TEXT    NOT NULL,
    last_seen_at TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Supports "log this user out everywhere", which needs to find every session
-- belonging to one user without scanning the table.
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS accounts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Ownership is a column, which is what lets every read filter on it. An
    -- ownership rule that lives only in Python has to be remembered at every
    -- call site; one that lives in the schema can be put in the WHERE clause.
    user_id    INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    kind       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts (user_id);

CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   INTEGER NOT NULL,
    -- Money is stored as an INTEGER number of cents, never a float. Binary
    -- floating point cannot represent 0.1 exactly, so 0.1 + 0.2 != 0.3 and a
    -- ledger built on floats drifts. Integers are exact; the decimal point is
    -- a display concern.
    amount_cents INTEGER NOT NULL,
    description  TEXT    NOT NULL,
    occurred_on  TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_transactions_account ON transactions (account_id);
"""


def get_db() -> sqlite3.Connection:
    """Return this request's connection, opening it on first use.

    ``g`` is Flask's per-request scratch space, so every handler in one request
    shares a connection (and therefore a transaction) while two concurrent
    requests stay fully isolated from each other.
    """
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        # Rows come back as mapping-like objects, so callers say row["email"]
        # rather than row[1] — one less thing to break when a column moves.
        g.db.row_factory = sqlite3.Row
        # SQLite ships with foreign keys OFF for backwards compatibility, and
        # the setting is per-connection, so it has to be re-armed every time.
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exception: BaseException | None = None) -> None:
    """Close the request's connection. Registered as a teardown handler.

    Teardown runs even when the view raised, which is the point: a handler that
    dies mid-request must not leak its connection or leave a transaction open.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create the schema. Safe to run repeatedly — every statement is IF NOT EXISTS."""
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()


def init_app(app: Flask) -> None:
    """Attach database lifecycle to the app."""
    app.teardown_appcontext(close_db)

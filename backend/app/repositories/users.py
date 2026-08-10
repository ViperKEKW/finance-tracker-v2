"""User persistence.

Every statement in this file binds its values. None of them build SQL with
f-strings, ``%``, or ``+`` — not even the ones whose input "obviously" comes
from somewhere trusted, because trust boundaries move as a codebase grows and
the parameterized version costs nothing.
"""
import sqlite3

from app.db import get_db
from app.security.passwords import hash_password


def normalize_email(email: str) -> str:
    """Fold an address into the single form used for both storage and lookup.

    Doing this in one shared function is what keeps registration and login
    agreeing with each other. If login lowercased and registration did not,
    "Milton@example.com" would create an account that could never be logged
    into — a real bug that looks like a password problem when it is reported.
    """
    return email.strip().lower()


def create_user(email: str, password: str) -> int | None:
    """Insert a user and return the new id, or None when the email is taken.

    The duplicate is caught from the database's UNIQUE index rather than
    pre-checked with a SELECT. A pre-check is a time-of-check/time-of-use race:
    two simultaneous signups can both read "available" before either writes.
    """
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (normalize_email(email), hash_password(password)),
        )
    except sqlite3.IntegrityError:
        db.rollback()
        # Callers must turn this into the same generic response as success.
        # Saying "that email is already registered" hands an attacker a free
        # account-enumeration oracle straight out of the signup form.
        return None
    db.commit()
    return cursor.lastrowid


def get_user_by_email(email: str) -> sqlite3.Row | None:
    """Look up a user for login. Returns the hash, so keep it off any response."""
    db = get_db()
    return db.execute(
        "SELECT id, email, password_hash FROM users WHERE email = ?",
        (normalize_email(email),),
    ).fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    """Look up a user for display. Deliberately does not select password_hash."""
    db = get_db()
    return db.execute(
        "SELECT id, email, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def update_password_hash(user_id: int, new_hash: str) -> None:
    """Replace a stored hash — used by the rehash-on-login upgrade path."""
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (new_hash, user_id),
    )
    db.commit()

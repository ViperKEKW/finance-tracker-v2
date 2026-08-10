"""Server-side session storage.

Flask ships with a client-side session: the data lives in a signed cookie in the
browser. It is tamper-proof but not secret (it is base64, not encryption) and,
more importantly, it cannot be revoked. Once issued, that cookie is valid until
it expires no matter what happens afterwards, because the server keeps no record
of it. "Log out everywhere" and "kill this session, the laptop was stolen" are
both impossible.

This module keeps sessions on the server instead. The browser holds an opaque
random token that means nothing on its own; all the state, and all the authority
to revoke it, lives in the database.
"""
import sqlite3
from datetime import datetime, timedelta, timezone

from app.db import get_db
from app.security.tokens import hash_token, new_token

# Two clocks, because they answer different questions. IDLE_TIMEOUT bounds how
# long an unattended session stays usable; ABSOLUTE_LIFETIME bounds how long a
# stolen token is useful no matter how actively the thief keeps it warm. Idle
# timeout alone can be refreshed forever.
IDLE_TIMEOUT = timedelta(hours=2)
ABSOLUTE_LIFETIME = timedelta(hours=12)


def _now() -> datetime:
    """One clock for the whole module, and it is UTC.

    Storing local time is how you get an hour of sessions that expire in the
    past every autumn.
    """
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def create_session(user_id: int) -> tuple[str, str]:
    """Open a session. Returns (session_token, csrf_token) for the caller to set.

    The raw session token is returned here and never stored — only its hash goes
    into the database. This function is the one and only moment the real value
    exists on the server, which is why it has to be handed straight to the
    response rather than kept anywhere.
    """
    token = new_token()
    csrf = new_token()
    now = _now()
    get_db().execute(
        "INSERT INTO sessions"
        " (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            hash_token(token),
            user_id,
            csrf,
            _iso(now),
            _iso(now),
            _iso(now + ABSOLUTE_LIFETIME),
        ),
    )
    get_db().commit()
    return token, csrf


def get_valid_session(token: str | None) -> sqlite3.Row | None:
    """Resolve a token to a live session, or None.

    Expired rows are deleted rather than merely ignored. Ignoring them works
    until the table is enormous and someone notices that "sessions" is the
    biggest thing in the database; deleting on read keeps it self-cleaning
    without a scheduled job.
    """
    if not token:
        return None
    row = get_db().execute(
        "SELECT token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at"
        " FROM sessions WHERE token_hash = ?",
        (hash_token(token),),
    ).fetchone()
    if row is None:
        return None

    now = _now()
    expires_at = datetime.fromisoformat(row["expires_at"])
    last_seen_at = datetime.fromisoformat(row["last_seen_at"])
    if now >= expires_at or now >= last_seen_at + IDLE_TIMEOUT:
        _delete_by_hash(row["token_hash"])
        return None

    # Touch the idle clock. The absolute expiry is deliberately NOT extended —
    # that is the whole difference between the two limits.
    get_db().execute(
        "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
        (_iso(now), row["token_hash"]),
    )
    get_db().commit()
    return row


def delete_session(token: str | None) -> None:
    """End one session. Used by logout."""
    if token:
        _delete_by_hash(hash_token(token))


def delete_all_for_user(user_id: int) -> None:
    """End every session for a user.

    This is what a password change must call. Changing a password while old
    sessions stay live is a real and common bug: the user changes it precisely
    because they think someone else is in the account, and the attacker's cookie
    keeps working.
    """
    get_db().execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    get_db().commit()


def _delete_by_hash(token_hash: str) -> None:
    get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    get_db().commit()


def count_for_user(user_id: int) -> int:
    """How many live sessions a user has. Used by tests and, later, a UI."""
    return get_db().execute(
        "SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?", (user_id,)
    ).fetchone()["n"]

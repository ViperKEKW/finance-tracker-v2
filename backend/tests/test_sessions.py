from datetime import datetime, timedelta, timezone

from conftest import login, register

from app.db import get_db
from app.repositories.sessions import (
    ABSOLUTE_LIFETIME,
    IDLE_TIMEOUT,
    count_for_user,
    create_session,
    delete_all_for_user,
    delete_session,
    get_valid_session,
)
from app.repositories.users import create_user
from app.security.auth import SESSION_COOKIE
from app.security.tokens import hash_token, new_token, tokens_match


def _age_session(token, *, last_seen=None, expires=None):
    """Rewrite a session's clocks to simulate the passage of time.

    Written as two fixed statements rather than one assembled from a list of
    column names. The first draft built "UPDATE sessions SET " + ", ".join(...)
    and ruff's S608 flagged it — correctly. The values were bound, so it was not
    exploitable, but the shape is the one that becomes an injection the moment
    somebody passes a column name in from outside. Cheaper to not write it.
    """
    token_hash = hash_token(token)
    if last_seen is not None:
        get_db().execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
            (last_seen.isoformat(), token_hash),
        )
    if expires is not None:
        get_db().execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (expires.isoformat(), token_hash),
        )
    get_db().commit()


# --- tokens ---


def test_new_tokens_are_unique():
    assert len({new_token() for _ in range(500)}) == 500


def test_tokens_match_is_correct_both_ways():
    token = new_token()
    assert tokens_match(token, token) is True
    assert tokens_match(token, new_token()) is False


def test_hash_token_is_deterministic():
    # Lookup by hash only works because the same token always digests the same.
    token = new_token()
    assert hash_token(token) == hash_token(token)


# --- lifecycle ---


def test_a_fresh_session_resolves(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    token, _ = create_session(user_id)
    assert get_valid_session(token)["user_id"] == user_id


def test_an_unknown_token_resolves_to_nothing(app_ctx):
    assert get_valid_session(new_token()) is None


def test_a_missing_token_resolves_to_nothing(app_ctx):
    assert get_valid_session(None) is None
    assert get_valid_session("") is None


def test_create_session_returns_distinct_session_and_csrf_tokens(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    token, csrf = create_session(user_id)
    # If these were the same value, the CSRF cookie would be a copy of the
    # session credential sitting in JavaScript-readable storage.
    assert token != csrf


# --- expiry ---


def test_an_idle_session_expires(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    token, _ = create_session(user_id)
    _age_session(token, last_seen=datetime.now(timezone.utc) - IDLE_TIMEOUT - timedelta(minutes=1))
    assert get_valid_session(token) is None


def test_activity_pushes_the_idle_clock_forward(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    token, _ = create_session(user_id)
    _age_session(token, last_seen=datetime.now(timezone.utc) - IDLE_TIMEOUT + timedelta(minutes=5))
    assert get_valid_session(token) is not None   # still inside the window, and touches it
    _age_session(token, last_seen=datetime.now(timezone.utc) - timedelta(minutes=1))
    assert get_valid_session(token) is not None


def test_the_absolute_lifetime_cannot_be_refreshed(app_ctx):
    """The distinction between the two clocks, made concrete.

    This session is being actively used — its idle clock was touched a second
    ago — and it still dies, because it was opened too long ago. That is what
    bounds how long a stolen token stays useful to a thief who keeps it warm.
    """
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    token, _ = create_session(user_id)
    _age_session(
        token,
        last_seen=datetime.now(timezone.utc),
        expires=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    assert get_valid_session(token) is None


def test_expired_sessions_are_deleted_not_merely_ignored(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    token, _ = create_session(user_id)
    _age_session(token, expires=datetime.now(timezone.utc) - timedelta(seconds=1))
    get_valid_session(token)
    assert count_for_user(user_id) == 0


def test_absolute_lifetime_is_longer_than_idle_timeout():
    # A configuration sanity check: reversed, the absolute limit would make the
    # idle timeout unreachable and the two-clock design would be decorative.
    assert ABSOLUTE_LIFETIME > IDLE_TIMEOUT


# --- revocation ---


def test_delete_session_revokes_exactly_one(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    keep, _ = create_session(user_id)
    drop, _ = create_session(user_id)
    delete_session(drop)
    assert get_valid_session(drop) is None
    assert get_valid_session(keep) is not None


def test_delete_all_for_user_revokes_every_device(app_ctx):
    user_id = create_user("milton@example.com", "hunter2-hunter2")
    tokens = [create_session(user_id)[0] for _ in range(3)]
    delete_all_for_user(user_id)
    assert all(get_valid_session(t) is None for t in tokens)


def test_delete_all_for_user_leaves_other_users_alone(app_ctx):
    milton = create_user("milton@example.com", "hunter2-hunter2")
    other = create_user("other@example.com", "hunter2-hunter2")
    mine, _ = create_session(milton)
    theirs, _ = create_session(other)
    delete_all_for_user(milton)
    assert get_valid_session(mine) is None
    assert get_valid_session(theirs) is not None


def test_a_second_login_does_not_kill_an_unrelated_device(client, app):
    """Rotation must drop the token the caller PRESENTED, not every session.

    Logging in on a phone should not sign you out on a laptop; only the fixation
    case (arriving already holding a token) is what rotation targets.
    """
    register(client)
    login(client)
    laptop_token = client.get_cookie(SESSION_COOKIE).value

    phone = app.test_client()
    login(phone)

    # Explicit context: this test issues client requests, so the fixture cannot
    # hold one open without making g leak between them.
    with app.app_context():
        assert get_valid_session(laptop_token) is not None

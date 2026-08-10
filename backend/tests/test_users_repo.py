from app.db import get_db
from app.repositories.users import (
    create_user,
    get_user_by_email,
    get_user_by_id,
    normalize_email,
    update_password_hash,
)
from app.security.passwords import hash_password, verify_password


def test_create_user_returns_an_id(app):
    assert create_user("milton@example.com", "hunter2") is not None


def test_password_is_never_stored_in_plaintext(app):
    create_user("milton@example.com", "hunter2")
    row = get_db().execute("SELECT password_hash FROM users").fetchone()
    assert row["password_hash"] != "hunter2"
    assert verify_password(row["password_hash"], "hunter2") is True


def test_duplicate_email_returns_none_instead_of_raising(app):
    create_user("milton@example.com", "hunter2")
    assert create_user("milton@example.com", "different") is None


def test_duplicate_is_caught_case_and_whitespace_insensitively(app):
    create_user("milton@example.com", "hunter2")
    # Normalizing before the uniqueness check is what stops two accounts that
    # differ only in capitalization from both existing.
    assert create_user("  MILTON@Example.COM  ", "hunter2") is None


def test_lookup_matches_regardless_of_how_the_email_was_typed(app):
    create_user("Milton@Example.com", "hunter2")
    assert get_user_by_email("milton@example.com") is not None
    assert get_user_by_email("  MILTON@EXAMPLE.COM ") is not None


def test_normalize_email_trims_and_lowercases():
    assert normalize_email("  Milton@Example.COM  ") == "milton@example.com"


def test_get_user_by_id_does_not_expose_the_hash(app):
    user_id = create_user("milton@example.com", "hunter2")
    row = get_user_by_id(user_id)
    assert "password_hash" not in row.keys()


def test_update_password_hash_replaces_the_credential(app):
    user_id = create_user("milton@example.com", "old-password")
    update_password_hash(user_id, hash_password("new-password"))
    row = get_user_by_email("milton@example.com")
    assert verify_password(row["password_hash"], "new-password") is True
    assert verify_password(row["password_hash"], "old-password") is False


# --- injection: the parameterized-query control, proven rather than asserted ---


def test_classic_or_true_payload_does_not_return_a_user(app):
    create_user("milton@example.com", "hunter2")
    # Concatenated into the SQL text, this closes the quote and makes the WHERE
    # clause always true, returning the first user. Bound as a parameter it is
    # just a very strange email address that matches nothing.
    assert get_user_by_email("' OR '1'='1") is None


def test_comment_terminated_payload_does_not_return_a_user(app):
    create_user("milton@example.com", "hunter2")
    assert get_user_by_email("milton@example.com' --") is None


def test_stacked_drop_table_payload_leaves_the_table_intact(app):
    create_user("milton@example.com", "hunter2")
    get_user_by_email("x'; DROP TABLE users; --")
    # The real assertion is that the table survived: the payload was stored and
    # compared as data, never executed as a second statement.
    assert get_user_by_email("milton@example.com") is not None


def test_payload_can_be_registered_as_a_literal_email(app):
    # The flip side of the same control. A parameterized query is not filtering
    # or escaping these characters, it is refusing to interpret them at all, so
    # the payload round-trips byte for byte.
    payload = "' OR '1'='1"
    create_user(payload, "hunter2")
    row = get_user_by_email(payload)
    # Normalization still lowercases it — that is our own rule, applied to the
    # value. What matters is that every quote, space, and equals sign survived
    # untouched, because nothing ever tried to escape or strip them.
    assert row["email"] == normalize_email(payload)
    assert "'" in row["email"]

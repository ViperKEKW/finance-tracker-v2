from argon2 import PasswordHasher
from conftest import GOOD_PASSWORD, csrf_headers, login, register

from app.db import get_db
from app.repositories.sessions import count_for_user
from app.repositories.users import get_user_by_email
from app.security.auth import SESSION_COOKIE
from app.security.passwords import needs_rehash, verify_password
from app.security.tokens import hash_token

# The app fixture deliberately does NOT hold an app context — see conftest for
# why — so any test that queries the database directly opens its own.

# --- registration ---


def test_register_creates_an_account(client, app):
    assert register(client).status_code == 201
    with app.app_context():
        assert get_user_by_email("milton@example.com") is not None


def test_register_requires_both_fields(client):
    assert client.post("/api/auth/register", json={"email": "a@b.com"}).status_code == 400
    assert client.post("/api/auth/register", json={}).status_code == 400


def test_register_survives_a_missing_body(client):
    # get_json(silent=True) means a bodyless POST is a 400, not a 500.
    assert client.post("/api/auth/register").status_code == 400


def test_register_enforces_password_length(client, app):
    assert register(client, password="short").status_code == 400
    with app.app_context():
        assert get_user_by_email("milton@example.com") is None


def test_duplicate_registration_is_indistinguishable_from_a_new_one(client):
    first = register(client)
    second = register(client, password="a-completely-different-one")
    # Same status and same body: the form is not an account-enumeration oracle.
    assert first.status_code == second.status_code == 201
    assert first.get_json() == second.get_json()


def test_duplicate_registration_does_not_overwrite_the_password(client, app):
    register(client)
    register(client, password="attacker-chosen-password")
    with app.app_context():
        row = get_user_by_email("milton@example.com")
    # A second signup on a taken address must not be a password reset.
    assert verify_password(row["password_hash"], GOOD_PASSWORD) is True
    assert verify_password(row["password_hash"], "attacker-chosen-password") is False


# --- login ---


def test_login_succeeds_and_returns_the_user(client):
    register(client)
    resp = login(client)
    assert resp.status_code == 200
    assert resp.get_json()["email"] == "milton@example.com"


def test_login_sets_both_cookies(client):
    register(client)
    login(client)
    assert client.get_cookie(SESSION_COOKIE) is not None
    assert client.get_cookie("ft_csrf") is not None


def test_wrong_password_is_rejected_with_a_generic_message(client):
    register(client)
    resp = login(client, password="not-the-right-password")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid email or password"


def test_unknown_email_gives_the_identical_response(client):
    register(client)
    wrong_password = login(client, password="not-the-right-password")
    no_such_user = login(client, email="nobody@example.com")
    # Byte-identical: status and body reveal nothing about which one existed.
    assert wrong_password.status_code == no_such_user.status_code == 401
    assert wrong_password.get_json() == no_such_user.get_json()


def test_failed_login_creates_no_session(client, app):
    register(client)
    login(client, password="wrong-password-entirely")
    with app.app_context():
        user = get_user_by_email("milton@example.com")
        assert count_for_user(user["id"]) == 0


# --- session fixation ---


def test_login_issues_a_different_token_than_the_caller_arrived_with(client):
    register(client)
    login(client)
    first = client.get_cookie(SESSION_COOKIE).value

    login(client)  # log in again while already holding a session
    second = client.get_cookie(SESSION_COOKIE).value

    assert first != second


def test_the_pre_login_session_is_destroyed_not_just_replaced(client, app):
    register(client)
    login(client)
    stolen = client.get_cookie(SESSION_COOKIE).value

    login(client)  # rotation happens here

    # An attacker holding the old token must not still be inside. Use a fresh
    # client so only the old cookie is presented.
    attacker = app.test_client()
    attacker.set_cookie(SESSION_COOKIE, stolen)
    assert attacker.get("/api/auth/me").status_code == 401


# --- identity and logout ---


def test_me_requires_a_session(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_logged_in_user(auth_client):
    body = auth_client.get("/api/auth/me").get_json()
    assert body["email"] == "milton@example.com"


def test_me_never_leaks_the_password_hash(auth_client):
    assert "password_hash" not in auth_client.get("/api/auth/me").get_json()


def test_logout_revokes_the_session_server_side(auth_client, app):
    token = auth_client.get_cookie(SESSION_COOKIE).value
    resp = auth_client.post("/api/auth/logout", headers=csrf_headers(auth_client))
    assert resp.status_code == 200

    # The real assertion: the token is dead even for someone who kept a copy,
    # because logout deleted the row rather than only clearing the cookie.
    replay = app.test_client()
    replay.set_cookie(SESSION_COOKIE, token)
    assert replay.get("/api/auth/me").status_code == 401


def test_logout_clears_the_cookies(auth_client):
    auth_client.post("/api/auth/logout", headers=csrf_headers(auth_client))
    cookie = auth_client.get_cookie(SESSION_COOKIE)
    assert cookie is None or cookie.value == ""


def test_logout_requires_authentication(client):
    assert client.post("/api/auth/logout").status_code == 401


# --- storage ---


def test_the_raw_session_token_is_never_stored(auth_client, app):
    token = auth_client.get_cookie(SESSION_COOKIE).value
    with app.app_context():
        stored = [r["token_hash"] for r in get_db().execute("SELECT token_hash FROM sessions")]

    # A read-only leak of this table yields digests, not usable cookies.
    assert token not in stored
    assert hash_token(token) in stored


# --- rehash on login ---


def test_a_failed_login_does_not_rewrite_the_stored_hash(client, app):
    """The rehash-on-login upgrade must be gated behind a SUCCESSFUL check.

    If needs_rehash ran before verification, anyone could overwrite any account's
    credential by submitting a guess — the upgrade path would become the attack.
    """
    register(client)
    stale = "$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQAAAAA$" + "a" * 43
    with app.app_context():
        get_db().execute("UPDATE users SET password_hash = ?", (stale,))
        get_db().commit()

    assert login(client).status_code == 401
    with app.app_context():
        assert get_user_by_email("milton@example.com")["password_hash"] == stale


def test_a_successful_login_upgrades_a_stale_hash(client, app):
    """The other half: a correct password does trigger the silent upgrade."""
    register(client)
    # The real password, re-hashed under deliberately weak parameters — the
    # shape of a credential written years ago under the settings of the day.
    weak = PasswordHasher(memory_cost=8, time_cost=1, parallelism=1).hash(GOOD_PASSWORD)
    with app.app_context():
        get_db().execute("UPDATE users SET password_hash = ?", (weak,))
        get_db().commit()
        assert needs_rehash(weak) is True

    assert login(client).status_code == 200

    with app.app_context():
        upgraded = get_user_by_email("milton@example.com")["password_hash"]
    # Rewritten, and now at current parameters — with no reset email involved.
    assert upgraded != weak
    assert needs_rehash(upgraded) is False
    assert verify_password(upgraded, GOOD_PASSWORD) is True

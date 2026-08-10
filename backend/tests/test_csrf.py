"""CSRF is enforced by a before_request hook, so these tests hit whatever routes
exist rather than a route that opted in. That is the property worth protecting:
a new endpoint is covered the day it is written."""
from conftest import csrf_headers, csrf_of, login, register

from app.security.auth import CSRF_HEADER, SESSION_COOKIE


def test_state_change_without_the_header_is_rejected(auth_client):
    resp = auth_client.post("/api/auth/logout")
    assert resp.status_code == 403
    assert "CSRF" in resp.get_json()["error"]


def test_state_change_with_the_wrong_token_is_rejected(auth_client):
    resp = auth_client.post("/api/auth/logout", headers={CSRF_HEADER: "not-the-token"})
    assert resp.status_code == 403


def test_state_change_with_the_right_token_is_allowed(auth_client):
    resp = auth_client.post("/api/auth/logout", headers=csrf_headers(auth_client))
    assert resp.status_code == 200


def test_the_cookie_alone_is_not_enough(auth_client):
    """The whole point, stated as a test.

    This client holds both cookies and sends them automatically — exactly the
    position an attacker's cross-site page puts the browser in. It still fails,
    because the token has to be READ and echoed in a header, and the same-origin
    policy is what stops another site from reading it.
    """
    assert auth_client.get_cookie("ft_csrf") is not None
    assert auth_client.post("/api/auth/logout").status_code == 403


def test_safe_methods_need_no_token(auth_client):
    assert auth_client.get("/api/auth/me").status_code == 200
    assert auth_client.get("/api/health").status_code == 200


def test_login_and_register_are_exempt(client):
    # No session exists yet, so there is no server-side token to compare. Both
    # must still work without a header or nobody could ever authenticate.
    assert register(client).status_code == 201
    assert login(client).status_code == 200


def test_unauthenticated_state_change_answers_401_not_403(client):
    # Answering 403 here would confirm the CSRF token was wrong, which tells an
    # unauthenticated caller something about a session they do not have.
    assert client.post("/api/auth/logout").status_code == 401


def test_a_stale_token_from_a_previous_session_does_not_work(client):
    register(client)
    login(client)
    old_csrf = csrf_of(client)

    login(client)  # rotation mints a new session AND a new CSRF token

    resp = client.post("/api/auth/logout", headers={CSRF_HEADER: old_csrf})
    assert resp.status_code == 403


def test_another_users_csrf_token_does_not_work(client, app):
    register(client, email="milton@example.com")
    login(client, email="milton@example.com")
    victim_session = client.get_cookie(SESSION_COOKIE).value

    attacker = app.test_client()
    register(attacker, email="attacker@example.com")
    login(attacker, email="attacker@example.com")
    attacker_csrf = csrf_of(attacker)

    # Victim's session cookie plus the attacker's own CSRF token: the token is
    # compared against the row the SESSION points at, so it does not match.
    forged = app.test_client()
    forged.set_cookie(SESSION_COOKIE, victim_session)
    assert forged.post("/api/auth/logout", headers={CSRF_HEADER: attacker_csrf}).status_code == 403

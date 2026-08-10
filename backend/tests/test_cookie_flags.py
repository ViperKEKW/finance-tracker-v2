"""The cookie attributes are the control, so they get asserted directly.

These read the raw Set-Cookie header rather than the client's cookie jar,
because the jar throws the attributes away once it has parsed them — and the
attributes are the entire point of this file.
"""
from conftest import GOOD_PASSWORD, register

from app import create_app
from app.db import init_db
from app.security.auth import CSRF_COOKIE, SESSION_COOKIE


def _set_cookie_headers(response):
    return response.headers.getlist("Set-Cookie")


def _header_for(response, name):
    return next(h for h in _set_cookie_headers(response) if h.startswith(name + "="))


def _login_response(client):
    register(client)
    return client.post(
        "/api/auth/login",
        json={"email": "milton@example.com", "password": GOOD_PASSWORD},
    )


def test_session_cookie_is_httponly(client):
    header = _header_for(_login_response(client), SESSION_COOKIE)
    # Without this, any XSS anywhere on the origin reads document.cookie and
    # exfiltrates a working session.
    assert "HttpOnly" in header


def test_session_cookie_is_samesite_lax(client):
    assert "SameSite=Lax" in _header_for(_login_response(client), SESSION_COOKIE)


def test_session_cookie_is_scoped_to_the_whole_site(client):
    assert "Path=/" in _header_for(_login_response(client), SESSION_COOKIE)


def test_session_cookie_expires(client):
    # A session cookie with no Max-Age lives until the browser closes, which on
    # a phone is approximately never.
    assert "Max-Age=" in _header_for(_login_response(client), SESSION_COOKIE)


def test_csrf_cookie_is_deliberately_readable(client):
    header = _header_for(_login_response(client), CSRF_COOKIE)
    # The one cookie that must NOT be HttpOnly: the frontend has to read it to
    # echo it back in a header. Safe because it grants nothing on its own.
    assert "HttpOnly" not in header


def test_csrf_cookie_still_gets_the_other_protections(client):
    header = _header_for(_login_response(client), CSRF_COOKIE)
    assert "SameSite=Lax" in header


def test_secure_is_the_default_when_nothing_overrides_it(tmp_path):
    """The production default, asserted without the test client's HTTP problem.

    The rest of the suite runs with COOKIE_SECURE off so the client will store
    cookies over plain HTTP. This test builds an app WITHOUT that override to
    prove the shipped default is the safe one.
    """
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "secure.sqlite3")})
    with app.app_context():
        init_db()
    client = app.test_client()
    client.post(
        "/api/auth/register",
        json={"email": "milton@example.com", "password": GOOD_PASSWORD},
    )
    resp = client.post(
        "/api/auth/login",
        json={"email": "milton@example.com", "password": GOOD_PASSWORD},
    )
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        assert "Secure" in _header_for(resp, name)


def test_logout_expires_both_cookies(client):
    from conftest import csrf_headers

    _login_response(client)
    resp = client.post("/api/auth/logout", headers=csrf_headers(client))
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        header = _header_for(resp, name)
        assert "Max-Age=0" in header or "Expires=Thu, 01 Jan 1970" in header

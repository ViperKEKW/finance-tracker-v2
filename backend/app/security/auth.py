"""Cookie policy, request-scoped identity, and the login_required gate."""
import functools
from collections.abc import Callable

from flask import Response, current_app, g, jsonify, request

from app.repositories.sessions import ABSOLUTE_LIFETIME, get_valid_session
from app.repositories.users import get_user_by_id

# The session cookie is the credential. The CSRF cookie is deliberately NOT a
# credential — it is a value the browser is allowed to read and echo back, and
# it is worthless to anyone who cannot also send the session cookie.
SESSION_COOKIE = "ft_session"
CSRF_COOKIE = "ft_csrf"
CSRF_HEADER = "X-CSRF-Token"


def _cookie_secure() -> bool:
    """Secure defaults to on; only a test or local run should turn it off.

    Written as "not False" rather than a truthy check so that a missing config
    key fails closed. Getting this backwards ships a cookie that a network
    attacker can read off plain HTTP.
    """
    return current_app.config.get("COOKIE_SECURE", True) is not False


def set_session_cookies(response: Response, token: str, csrf_token: str) -> Response:
    """Attach both cookies with the flags that make them safe to hold.

    The three flags on the session cookie each stop a different attack:

      httponly  JavaScript cannot read it. An XSS bug is still a serious
                problem, but it no longer hands the attacker a token they can
                exfiltrate and replay from their own machine at leisure.
      secure    The browser refuses to send it over plain HTTP, so it cannot be
                sniffed on a hostile network or leaked by a downgrade.
      samesite  The browser will not attach it to cross-site POSTs, which
                removes the easy shape of CSRF (see csrf.py for why this is a
                layer and not the whole answer).

    The CSRF cookie is the one place httponly is deliberately OFF, because the
    frontend has to read it in order to echo it back in a header. That is the
    entire mechanism, and it is safe precisely because the value grants nothing
    on its own.
    """
    secure = _cookie_secure()
    max_age = int(ABSOLUTE_LIFETIME.total_seconds())
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, secure=secure, samesite="Lax", max_age=max_age, path="/",
    )
    response.set_cookie(
        CSRF_COOKIE, csrf_token,
        httponly=False, secure=secure, samesite="Lax", max_age=max_age, path="/",
    )
    return response


def clear_session_cookies(response: Response) -> Response:
    """Expire both cookies. Attributes must match what was set or some browsers keep them."""
    secure = _cookie_secure()
    for name, httponly in ((SESSION_COOKIE, True), (CSRF_COOKIE, False)):
        response.set_cookie(
            name, "", httponly=httponly, secure=secure, samesite="Lax",
            max_age=0, expires=0, path="/",
        )
    return response


def current_session():
    """The live session row for this request, or None. Resolved at most once."""
    if "session_row" not in g:
        g.session_row = get_valid_session(request.cookies.get(SESSION_COOKIE))
    return g.session_row


def current_user():
    """The authenticated user for this request, or None.

    Identity comes from the session token alone. Nothing here reads a user id
    out of the request body, a query string, or a header — those are all
    attacker-controlled, and trusting any of them is how an authentication
    system becomes decorative.
    """
    if "user" not in g:
        session_row = current_session()
        g.user = get_user_by_id(session_row["user_id"]) if session_row else None
    return g.user


def login_required(view: Callable) -> Callable:
    """Reject unauthenticated requests with 401 before the view body runs."""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "authentication required"}), 401
        return view(*args, **kwargs)

    return wrapped

"""CSRF protection, wired as a before_request so it cannot be forgotten.

The attack, concretely. You are logged in here. You visit some other site, which
contains a form that POSTs to our /api/accounts endpoint. The browser attaches
your session cookie to that request, because cookies are attached by
destination, not by who asked. Our server sees a perfectly authenticated request
and does what it says. You never clicked anything that looked like us.

The defense: require something on the request that a cross-site page cannot
produce. The session cookie does not qualify, because the browser sends it
automatically. A value the page has to READ and then explicitly attach does
qualify, because the same-origin policy stops another site from reading our
cookie or our responses.

So the flow is: at login we mint a CSRF token, store it on the server session,
and hand a copy to the browser in a readable cookie. Our frontend reads it and
echoes it in the X-CSRF-Token header. An attacker's page can cause the cookie to
be SENT, but cannot READ it, so it cannot populate the header.

Why not rely on SameSite=Lax alone, which is already set? It is a real layer and
it kills the classic cross-site form POST. It is not sufficient on its own:

  - "Site" means registrable domain, so a compromised or sloppy subdomain is
    same-site with us and Lax does nothing about it.
  - Lax still sends the cookie on top-level GET navigation, so any state change
    that ever leaks onto a GET is unprotected.
  - Enforcement varies across browsers and versions, and support depends on
    whoever is visiting, not on us.

Defense in depth: the token is the control, SameSite is the safety net.
"""
from flask import g, jsonify, request

from app.security.auth import CSRF_HEADER, current_session
from app.security.tokens import tokens_match

# GET/HEAD/OPTIONS must not change state, so they need no token. That is a
# constraint on us as much as a rule: the moment a GET route mutates something,
# it has silently opted out of CSRF protection.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Endpoints reachable before a session exists, so there is no server-side token
# to compare against yet. Login CSRF (an attacker forcing you to log into THEIR
# account, so your activity lands in their history) is the residual risk here;
# the standard fix is a pre-session token, which is worth adding when there is
# anything sensitive to record. Noted rather than silently accepted.
EXEMPT_ENDPOINTS = {"auth.register", "auth.login"}


def csrf_protect():
    """Reject unsafe requests that do not echo the session's CSRF token.

    Registered with before_request rather than offered as a decorator, and that
    is a deliberate security-design choice: a decorator is opt-in, so protection
    depends on every future route author remembering it, and the one they forget
    is the one that gets exploited. A before_request hook is opt-out, so a new
    route is protected the moment it exists and skipping it takes a visible edit
    to the exempt list.
    """
    if request.method in SAFE_METHODS:
        return None
    if request.endpoint in EXEMPT_ENDPOINTS:
        return None

    session_row = current_session()
    if session_row is None:
        # No session means login_required will reject it anyway; answering the
        # same way here avoids telling an unauthenticated caller whether their
        # CSRF token happened to be right.
        return jsonify({"error": "authentication required"}), 401

    provided = request.headers.get(CSRF_HEADER, "")
    if not tokens_match(session_row["csrf_token"], provided):
        return jsonify({"error": "invalid or missing CSRF token"}), 403

    g.csrf_ok = True
    return None

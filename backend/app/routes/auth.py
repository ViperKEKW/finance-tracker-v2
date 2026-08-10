"""Registration, login, logout, and identity."""
from flask import Blueprint, jsonify, request

from app.repositories.sessions import create_session, delete_session
from app.repositories.users import (
    create_user,
    get_user_by_email,
    update_password_hash,
)
from app.security.auth import (
    SESSION_COOKIE,
    clear_session_cookies,
    current_user,
    login_required,
    set_session_cookies,
)
from app.security.passwords import hash_password, needs_rehash, verify_password

bp = Blueprint("auth", __name__)

# Long enough to matter, short enough not to push people toward reuse. Length is
# the only password rule here on purpose: forced symbol-and-digit rules push
# users to Password1! and their variants, which is why NIST dropped them.
MIN_PASSWORD_LENGTH = 12

# One string for every failed login. Which half was wrong is exactly the thing
# an attacker wants to learn, and it is of no use to a legitimate user who can
# simply try again.
INVALID_CREDENTIALS = "invalid email or password"


def _credentials():
    """Pull email and password out of the JSON body, tolerating a missing body."""
    payload = request.get_json(silent=True) or {}
    email = payload.get("email")
    password = payload.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        return None, None
    return email, password


@bp.post("/register")
def register():
    """Create an account.

    The response is identical whether or not the address was already taken.
    That is the same anti-enumeration stance as the login timing defense: a
    signup form that says "already registered" is a free membership oracle for
    anyone with a list of email addresses. A production build sends the real
    outcome to the inbox, where only its owner can read it.
    """
    email, password = _credentials()
    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify(
            {"error": f"password must be at least {MIN_PASSWORD_LENGTH} characters"}
        ), 400

    create_user(email, password)  # None means taken; deliberately not surfaced
    return jsonify({"status": "if that address is available, the account was created"}), 201


@bp.post("/login")
def login():
    """Exchange credentials for a session."""
    email, password = _credentials()
    if not email or not password:
        return jsonify({"error": INVALID_CREDENTIALS}), 401

    user = get_user_by_email(email)
    stored_hash = user["password_hash"] if user else None

    # Runs a full verification even when user is None — see verify_password.
    if not verify_password(stored_hash, password):
        return jsonify({"error": INVALID_CREDENTIALS}), 401

    # The one moment the plaintext is legitimately in hand, so the one moment a
    # stored hash can be upgraded to current parameters without a reset email.
    if needs_rehash(stored_hash):
        update_password_hash(user["id"], hash_password(password))

    # Session fixation defense. If the caller arrived holding a session token,
    # it dies here and a freshly minted one takes its place. Without this, an
    # attacker who can plant a known token in the victim's browser BEFORE login
    # still holds a valid token AFTER it, and the victim has authenticated the
    # attacker's session for them.
    delete_session(request.cookies.get(SESSION_COOKIE))

    token, csrf_token = create_session(user["id"])
    response = jsonify({"id": user["id"], "email": user["email"]})
    return set_session_cookies(response, token, csrf_token), 200


@bp.post("/logout")
@login_required
def logout():
    """End the current session on the server, then clear the cookies.

    Order matters. Clearing the cookie alone would leave a live row that any
    copy of the token still opens; deleting server-side is what actually revokes
    it. The cookie clearing is tidiness, not the control.
    """
    delete_session(request.cookies.get(SESSION_COOKIE))
    response = jsonify({"status": "logged out"})
    return clear_session_cookies(response), 200


@bp.get("/me")
@login_required
def me():
    """Who the session belongs to. Never includes the password hash."""
    user = current_user()
    return jsonify(
        {"id": user["id"], "email": user["email"], "created_at": user["created_at"]}
    ), 200

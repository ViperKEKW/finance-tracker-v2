import pytest

from app import create_app
from app.db import init_db
from app.security.auth import CSRF_COOKIE, CSRF_HEADER

GOOD_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def app(tmp_path):
    """An app wired to a throwaway database file. No app context is held.

    That last part is load-bearing. Flask reuses an already-pushed app context
    rather than nesting a new one, so a fixture that holds one open makes ``g``
    persist across every request in the test — and ``g`` is where current_user()
    caches the resolved session. An earlier version of this fixture did hold one,
    and it hid a revocation failure: a request after logout kept reading the
    cached session and looked authenticated.

    Production pushes a fresh app context per request. So does this now. Tests
    that need direct database access take app_ctx instead.

    tmp_path is per-test, so no test can see another test's data.

    COOKIE_SECURE is off because the test client speaks plain HTTP and would
    otherwise refuse to store the cookies. test_cookie_flags.py asserts the
    production default separately, by reading the header instead of the jar.
    """
    application = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "COOKIE_SECURE": False,
        }
    )
    with application.app_context():
        init_db()
    return application


@pytest.fixture
def app_ctx(app):
    """The app with a context held, for tests that call repositories directly.

    Safe here because these tests do not also issue client requests. When a test
    needs both, use the client for the requests and open ``with
    app.app_context():`` around the direct queries.
    """
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


def csrf_of(client) -> str:
    """Read the CSRF token the way the real frontend does — out of the cookie."""
    cookie = client.get_cookie(CSRF_COOKIE)
    return cookie.value if cookie else ""


def csrf_headers(client) -> dict:
    """Headers a legitimate same-origin caller would send on a state change."""
    return {CSRF_HEADER: csrf_of(client)}


def register(client, email="milton@example.com", password=GOOD_PASSWORD):
    return client.post("/api/auth/register", json={"email": email, "password": password})


def login(client, email="milton@example.com", password=GOOD_PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "password": password})


@pytest.fixture
def auth_client(client):
    """A client that has registered and logged in. Cookies are in its jar."""
    register(client)
    login(client)
    return client


# --- helpers for state-changing calls, which all need the CSRF header ---


def api_post(client, url, json=None):
    return client.post(url, json=json, headers=csrf_headers(client))


def api_patch(client, url, json=None):
    return client.patch(url, json=json, headers=csrf_headers(client))


def api_delete(client, url):
    return client.delete(url, headers=csrf_headers(client))


def signed_in(app, email):
    """A fresh, logged-in client for a distinct user. Used by the IDOR suite."""
    c = app.test_client()
    register(c, email=email)
    login(c, email=email)
    return c


def make_account(client, name="Checking", kind="checking") -> int:
    resp = api_post(client, "/api/accounts", {"name": name, "kind": kind})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


def make_transaction(client, account_id, amount_cents=-1250,
                     description="Coffee", occurred_on="2026-08-10") -> int:
    resp = api_post(
        client,
        f"/api/accounts/{account_id}/transactions",
        {
            "amount_cents": amount_cents,
            "description": description,
            "occurred_on": occurred_on,
        },
    )
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["id"]


@pytest.fixture
def victim(app):
    """Milton, with one account holding one transaction."""
    c = signed_in(app, "milton@example.com")
    account_id = make_account(c, "Milton Checking")
    transaction_id = make_transaction(c, account_id, -4200, "Groceries")
    return {"client": c, "account_id": account_id, "transaction_id": transaction_id}


@pytest.fixture
def attacker(app):
    """A second, unrelated, fully legitimate user. Authenticated — just not you.

    This is the realistic threat model for broken access control. The attacker
    does not need a stolen session or an injection; they sign up normally and
    then change a number in a URL.
    """
    c = signed_in(app, "attacker@example.com")
    make_account(c, "Attacker Checking")
    return c

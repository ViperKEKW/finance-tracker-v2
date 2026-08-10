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

import pytest

from app import create_app
from app.db import init_db


@pytest.fixture
def app(tmp_path):
    """An app wired to a throwaway database file, inside a live app context.

    tmp_path is per-test, so no test can see another test's users — the suite
    stays order-independent. The app context is held open for the body of the
    test so repository functions can call get_db() directly.
    """
    application = create_app(
        {"TESTING": True, "DATABASE": str(tmp_path / "test.sqlite3")}
    )
    with application.app_context():
        init_db()
        yield application


@pytest.fixture
def client(app):
    return app.test_client()

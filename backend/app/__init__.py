"""Finance Tracker v2 backend — Flask application factory."""
import os

from flask import Flask

from app import db
from app.security.csrf import csrf_protect


def create_app(config: dict | None = None) -> Flask:
    """Build the Flask app. Config is injected so tests can override it."""
    app = Flask(__name__)
    app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "finance_tracker.sqlite3")
    # Cookies are Secure unless something explicitly says otherwise. Tests and
    # local HTTP runs opt out; nothing else should.
    app.config["COOKIE_SECURE"] = True
    if config:
        app.config.update(config)

    db.init_app(app)

    # Opt-out rather than opt-in: every state-changing request is CSRF-checked
    # the moment its route exists, and skipping that takes a visible edit to the
    # exempt list in csrf.py rather than a forgotten decorator.
    app.before_request(csrf_protect)

    from app.routes.auth import bp as auth_bp
    from app.routes.health import bp as health_bp

    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    return app

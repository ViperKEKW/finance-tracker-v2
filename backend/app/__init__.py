"""Finance Tracker v2 backend — Flask application factory."""
import os

from flask import Flask

from app import db


def create_app(config: dict | None = None) -> Flask:
    """Build the Flask app. Config is injected so tests can override it."""
    app = Flask(__name__)
    app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "finance_tracker.sqlite3")
    if config:
        app.config.update(config)

    db.init_app(app)

    from app.routes.health import bp as health_bp

    app.register_blueprint(health_bp, url_prefix="/api")
    return app

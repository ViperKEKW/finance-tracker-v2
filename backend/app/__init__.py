"""Finance Tracker v2 backend — Flask application factory."""
from flask import Flask


def create_app(config: dict | None = None) -> Flask:
    """Build the Flask app. Config is injected so tests can override it."""
    app = Flask(__name__)
    if config:
        app.config.update(config)

    from app.routes.health import bp as health_bp

    app.register_blueprint(health_bp, url_prefix="/api")
    return app

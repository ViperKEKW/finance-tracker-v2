"""Liveness endpoint — deliberately the only unauthenticated route in the API."""
from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)


@bp.get("/health")
def health():
    return jsonify({"status": "ok"})

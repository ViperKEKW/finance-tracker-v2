"""Account and transaction endpoints.

Two rules run through every handler here.

The owner always comes from current_user(), never from the request. Any id in
the URL or the body is attacker-controlled and is only ever used as a filter,
never as an identity.

A resource that is not yours answers 404, not 403. 403 means "this exists and
you may not have it", which confirms the id is real and lets someone enumerate
their way to a map of other people's data. 404 tells them nothing.
"""
from datetime import date

from flask import Blueprint, jsonify, request

from app.repositories.accounts import (
    VALID_KINDS,
    account_balance_cents,
    create_account,
    delete_account,
    get_account,
    list_accounts,
    rename_account,
)
from app.repositories.transactions import (
    create_transaction,
    delete_transaction,
    get_transaction,
    list_transactions,
)
from app.security.auth import current_user, login_required

bp = Blueprint("accounts", __name__)

NOT_FOUND = ({"error": "not found"}, 404)
MAX_NAME_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 500


def _uid() -> int:
    return current_user()["id"]


def _body() -> dict:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}


def _clean_name(raw, field="name"):
    """Validate a short free-text field. Returns (value, error)."""
    if not isinstance(raw, str) or not raw.strip():
        return None, f"{field} is required"
    value = raw.strip()
    if len(value) > MAX_NAME_LENGTH:
        return None, f"{field} must be at most {MAX_NAME_LENGTH} characters"
    return value, None


def _account_json(row, balance=None):
    body = {
        "id": row["id"],
        "name": row["name"],
        "kind": row["kind"],
        "created_at": row["created_at"],
    }
    if balance is not None:
        body["balance_cents"] = balance
    return body


def _transaction_json(row):
    return {
        "id": row["id"],
        "account_id": row["account_id"],
        "amount_cents": row["amount_cents"],
        "description": row["description"],
        "occurred_on": row["occurred_on"],
    }


# --- accounts ---


@bp.get("/accounts")
@login_required
def index():
    return jsonify([_account_json(r) for r in list_accounts(_uid())]), 200


@bp.post("/accounts")
@login_required
def create():
    body = _body()
    name, error = _clean_name(body.get("name"))
    if error:
        return jsonify({"error": error}), 400
    kind = body.get("kind")
    if kind not in VALID_KINDS:
        return jsonify({"error": f"kind must be one of {', '.join(VALID_KINDS)}"}), 400

    account_id = create_account(_uid(), name, kind)
    return jsonify(_account_json(get_account(_uid(), account_id))), 201


@bp.get("/accounts/<int:account_id>")
@login_required
def show(account_id):
    account = get_account(_uid(), account_id)
    if account is None:
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify(_account_json(account, account_balance_cents(_uid(), account_id))), 200


@bp.patch("/accounts/<int:account_id>")
@login_required
def rename(account_id):
    name, error = _clean_name(_body().get("name"))
    if error:
        return jsonify({"error": error}), 400
    if not rename_account(_uid(), account_id, name):
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify(_account_json(get_account(_uid(), account_id))), 200


@bp.delete("/accounts/<int:account_id>")
@login_required
def destroy(account_id):
    if not delete_account(_uid(), account_id):
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify({"status": "deleted"}), 200


# --- transactions, nested under their account ---


@bp.get("/accounts/<int:account_id>/transactions")
@login_required
def transactions_index(account_id):
    rows = list_transactions(_uid(), account_id)
    if rows is None:
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify([_transaction_json(r) for r in rows]), 200


@bp.post("/accounts/<int:account_id>/transactions")
@login_required
def transactions_create(account_id):
    body = _body()

    amount = body.get("amount_cents")
    # bool is a subclass of int in Python, so True would sail through a bare
    # isinstance check and land in the ledger as 1 cent.
    if isinstance(amount, bool) or not isinstance(amount, int):
        return jsonify({"error": "amount_cents must be an integer number of cents"}), 400

    description, error = _clean_name(body.get("description"), "description")
    if error:
        return jsonify({"error": error}), 400
    if len(description) > MAX_DESCRIPTION_LENGTH:
        return jsonify(
            {"error": f"description must be at most {MAX_DESCRIPTION_LENGTH} characters"}
        ), 400

    occurred_on = body.get("occurred_on")
    if not isinstance(occurred_on, str):
        return jsonify({"error": "occurred_on must be a YYYY-MM-DD date"}), 400
    try:
        date.fromisoformat(occurred_on)
    except ValueError:
        return jsonify({"error": "occurred_on must be a YYYY-MM-DD date"}), 400

    transaction_id = create_transaction(
        _uid(), account_id, amount, description, occurred_on
    )
    # None here means the account is not this user's — same answer as missing.
    if transaction_id is None:
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify(_transaction_json(get_transaction(_uid(), transaction_id))), 201


# --- transactions, addressed directly ---


@bp.get("/transactions/<int:transaction_id>")
@login_required
def transaction_show(transaction_id):
    row = get_transaction(_uid(), transaction_id)
    if row is None:
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify(_transaction_json(row)), 200


@bp.delete("/transactions/<int:transaction_id>")
@login_required
def transaction_destroy(transaction_id):
    if not delete_transaction(_uid(), transaction_id):
        return jsonify(NOT_FOUND[0]), NOT_FOUND[1]
    return jsonify({"status": "deleted"}), 200

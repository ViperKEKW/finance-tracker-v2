"""Broken access control, tested from the attacker's chair.

Every test here uses a fully legitimate second account. Nothing is stolen, no
session is forged, no payload is injected. The attacker signs up, logs in, and
changes a number in a URL — which is the entire technique, and why this
category sits at number one on the OWASP Top 10.

v1 of this project shipped this bug. These tests exist so v2 cannot.
"""
from conftest import api_delete, api_patch, api_post, make_account, make_transaction

# --- reading someone else's data ---


def test_cannot_read_another_users_account(attacker, victim):
    resp = attacker.get(f"/api/accounts/{victim['account_id']}")
    # 404, not 403. A 403 would confirm the id is real.
    assert resp.status_code == 404


def test_cannot_read_another_users_transaction_list(attacker, victim):
    assert attacker.get(
        f"/api/accounts/{victim['account_id']}/transactions"
    ).status_code == 404


def test_cannot_read_another_users_transaction_directly(attacker, victim):
    """The endpoint shape that leaks in real applications.

    A transaction has no user_id column, so the ownership hop runs through its
    account. Skip the join and this returns somebody else's money.
    """
    assert attacker.get(
        f"/api/transactions/{victim['transaction_id']}"
    ).status_code == 404


def test_listing_accounts_shows_only_your_own(attacker, victim):
    body = attacker.get("/api/accounts").get_json()
    assert [a["name"] for a in body] == ["Attacker Checking"]
    assert victim["account_id"] not in [a["id"] for a in body]


# --- writing to someone else's data ---


def test_cannot_rename_another_users_account(attacker, victim):
    resp = api_patch(
        attacker, f"/api/accounts/{victim['account_id']}", {"name": "Pwned"}
    )
    assert resp.status_code == 404
    # And the victim's account is untouched — the write did not partially land.
    owner_view = victim["client"].get(f"/api/accounts/{victim['account_id']}").get_json()
    assert owner_view["name"] == "Milton Checking"


def test_cannot_delete_another_users_account(attacker, victim):
    resp = api_delete(attacker, f"/api/accounts/{victim['account_id']}")
    assert resp.status_code == 404
    assert victim["client"].get(f"/api/accounts/{victim['account_id']}").status_code == 200


def test_cannot_write_a_transaction_into_another_users_account(attacker, victim):
    resp = api_post(
        attacker,
        f"/api/accounts/{victim['account_id']}/transactions",
        {"amount_cents": 999999, "description": "gift", "occurred_on": "2026-08-10"},
    )
    assert resp.status_code == 404

    # The victim's ledger is unchanged. An unscoped INSERT would have let an
    # attacker write into a stranger's books.
    theirs = victim["client"].get(
        f"/api/accounts/{victim['account_id']}/transactions"
    ).get_json()
    assert len(theirs) == 1
    assert theirs[0]["description"] == "Groceries"


def test_cannot_delete_another_users_transaction(attacker, victim):
    resp = api_delete(attacker, f"/api/transactions/{victim['transaction_id']}")
    assert resp.status_code == 404
    assert victim["client"].get(
        f"/api/transactions/{victim['transaction_id']}"
    ).status_code == 200


# --- the balance must not aggregate across owners ---


def test_balance_counts_only_the_owners_transactions(app, victim):
    other = make_account(victim["client"], "Savings", "savings")
    make_transaction(victim["client"], other, 100_000, "Paycheck")

    shown = victim["client"].get(f"/api/accounts/{victim['account_id']}").get_json()
    # -4200 from Groceries only; the other account's 100000 must not bleed in.
    assert shown["balance_cents"] == -4200


# --- ids that do not exist answer the same way as ids you may not have ---


def test_a_nonexistent_id_is_indistinguishable_from_someone_elses(attacker, victim):
    theirs = attacker.get(f"/api/accounts/{victim['account_id']}")
    nothing = attacker.get("/api/accounts/999999")
    assert theirs.status_code == nothing.status_code == 404
    assert theirs.get_json() == nothing.get_json()


# --- authentication is still required before authorization matters ---


def test_every_endpoint_rejects_an_anonymous_caller(client, victim):
    account_id = victim["account_id"]
    assert client.get("/api/accounts").status_code == 401
    assert client.get(f"/api/accounts/{account_id}").status_code == 401
    assert client.get(f"/api/accounts/{account_id}/transactions").status_code == 401
    assert client.get(f"/api/transactions/{victim['transaction_id']}").status_code == 401
    # State changes answer 401 rather than 403 so an anonymous caller learns
    # nothing about whether their CSRF token would have been accepted.
    assert client.post("/api/accounts", json={"name": "x", "kind": "cash"}).status_code == 401
    assert client.delete(f"/api/accounts/{account_id}").status_code == 401


def test_state_changes_still_require_the_csrf_token(attacker):
    # No header: rejected before any ownership logic runs.
    assert attacker.post(
        "/api/accounts", json={"name": "x", "kind": "cash"}
    ).status_code == 403

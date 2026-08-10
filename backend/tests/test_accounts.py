from conftest import (
    api_delete,
    api_patch,
    api_post,
    make_account,
    make_transaction,
)

# --- accounts ---


def test_create_and_read_back(auth_client):
    account_id = make_account(auth_client, "Everyday", "checking")
    body = auth_client.get(f"/api/accounts/{account_id}").get_json()
    assert body["name"] == "Everyday"
    assert body["kind"] == "checking"


def test_new_account_starts_at_zero(auth_client):
    account_id = make_account(auth_client)
    assert auth_client.get(f"/api/accounts/{account_id}").get_json()["balance_cents"] == 0


def test_list_is_empty_before_anything_exists(auth_client):
    assert auth_client.get("/api/accounts").get_json() == []


def test_rename(auth_client):
    account_id = make_account(auth_client, "Old Name")
    resp = api_patch(auth_client, f"/api/accounts/{account_id}", {"name": "New Name"})
    assert resp.status_code == 200
    assert auth_client.get(f"/api/accounts/{account_id}").get_json()["name"] == "New Name"


def test_delete(auth_client):
    account_id = make_account(auth_client)
    assert api_delete(auth_client, f"/api/accounts/{account_id}").status_code == 200
    assert auth_client.get(f"/api/accounts/{account_id}").status_code == 404


def test_deleting_an_account_takes_its_transactions_with_it(auth_client):
    account_id = make_account(auth_client)
    transaction_id = make_transaction(auth_client, account_id)
    api_delete(auth_client, f"/api/accounts/{account_id}")
    # ON DELETE CASCADE, which only fires because db.py re-arms the foreign_keys
    # pragma on every connection.
    assert auth_client.get(f"/api/transactions/{transaction_id}").status_code == 404


def test_rejects_an_unknown_kind(auth_client):
    resp = api_post(auth_client, "/api/accounts", {"name": "x", "kind": "crypto-yolo"})
    assert resp.status_code == 400


def test_rejects_a_blank_name(auth_client):
    resp = api_post(auth_client, "/api/accounts", {"name": "   ", "kind": "cash"})
    assert resp.status_code == 400


def test_rejects_an_overlong_name(auth_client):
    resp = api_post(auth_client, "/api/accounts", {"name": "x" * 101, "kind": "cash"})
    assert resp.status_code == 400


def test_name_is_trimmed(auth_client):
    account_id = make_account(auth_client, "  Spaced  ")
    assert auth_client.get(f"/api/accounts/{account_id}").get_json()["name"] == "Spaced"


def test_survives_a_missing_body(auth_client):
    from conftest import csrf_headers

    resp = auth_client.post("/api/accounts", headers=csrf_headers(auth_client))
    assert resp.status_code == 400


# --- transactions ---


def test_create_and_list_transactions(auth_client):
    account_id = make_account(auth_client)
    make_transaction(auth_client, account_id, -1250, "Coffee")
    rows = auth_client.get(f"/api/accounts/{account_id}/transactions").get_json()
    assert len(rows) == 1
    assert rows[0]["amount_cents"] == -1250


def test_balance_sums_debits_and_credits(auth_client):
    account_id = make_account(auth_client)
    make_transaction(auth_client, account_id, 250_000, "Paycheck", "2026-08-01")
    make_transaction(auth_client, account_id, -4200, "Groceries", "2026-08-02")
    make_transaction(auth_client, account_id, -1250, "Coffee", "2026-08-03")
    balance = auth_client.get(f"/api/accounts/{account_id}").get_json()["balance_cents"]
    # Integer cents, so this is exact. The same sum in floats drifts.
    assert balance == 244_550


def test_an_empty_account_lists_no_transactions(auth_client):
    account_id = make_account(auth_client)
    resp = auth_client.get(f"/api/accounts/{account_id}/transactions")
    # 200 with [], distinct from the 404 an account you do not own returns.
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_rejects_a_float_amount(auth_client):
    account_id = make_account(auth_client)
    resp = api_post(
        auth_client,
        f"/api/accounts/{account_id}/transactions",
        {"amount_cents": 12.50, "description": "x", "occurred_on": "2026-08-10"},
    )
    # Cents are integers. Accepting 12.50 here is how a ledger starts drifting.
    assert resp.status_code == 400


def test_rejects_a_string_amount(auth_client):
    account_id = make_account(auth_client)
    resp = api_post(
        auth_client,
        f"/api/accounts/{account_id}/transactions",
        {"amount_cents": "1250", "description": "x", "occurred_on": "2026-08-10"},
    )
    assert resp.status_code == 400


def test_rejects_a_boolean_amount(auth_client):
    account_id = make_account(auth_client)
    resp = api_post(
        auth_client,
        f"/api/accounts/{account_id}/transactions",
        {"amount_cents": True, "description": "x", "occurred_on": "2026-08-10"},
    )
    # bool subclasses int in Python, so a bare isinstance(x, int) lets True
    # through and books it as one cent.
    assert resp.status_code == 400


def test_rejects_a_malformed_date(auth_client):
    account_id = make_account(auth_client)
    for bad in ("10/08/2026", "2026-13-01", "yesterday", ""):
        resp = api_post(
            auth_client,
            f"/api/accounts/{account_id}/transactions",
            {"amount_cents": 100, "description": "x", "occurred_on": bad},
        )
        assert resp.status_code == 400, bad


def test_rejects_a_blank_description(auth_client):
    account_id = make_account(auth_client)
    resp = api_post(
        auth_client,
        f"/api/accounts/{account_id}/transactions",
        {"amount_cents": 100, "description": "  ", "occurred_on": "2026-08-10"},
    )
    assert resp.status_code == 400


def test_transactions_come_back_newest_first(auth_client):
    account_id = make_account(auth_client)
    make_transaction(auth_client, account_id, 1, "oldest", "2026-08-01")
    make_transaction(auth_client, account_id, 2, "newest", "2026-08-09")
    make_transaction(auth_client, account_id, 3, "middle", "2026-08-05")
    order = [r["description"] for r in
             auth_client.get(f"/api/accounts/{account_id}/transactions").get_json()]
    assert order == ["newest", "middle", "oldest"]


def test_delete_a_transaction(auth_client):
    account_id = make_account(auth_client)
    transaction_id = make_transaction(auth_client, account_id)
    assert api_delete(auth_client, f"/api/transactions/{transaction_id}").status_code == 200
    assert auth_client.get(f"/api/transactions/{transaction_id}").status_code == 404


def test_transaction_text_is_stored_verbatim(auth_client):
    """Storage does not mangle input; escaping is the renderer's job.

    Sanitizing on the way in destroys data and still does not make output safe,
    because the same value may be rendered into HTML, a CSV, and a JSON body,
    each of which needs different escaping. Store what was sent, escape at the
    boundary where it is used.
    """
    account_id = make_account(auth_client)
    payload = "<script>alert('xss')</script> O'Brien & Sons"
    transaction_id = make_transaction(auth_client, account_id, -100, payload)
    stored = auth_client.get(f"/api/transactions/{transaction_id}").get_json()
    assert stored["description"] == payload

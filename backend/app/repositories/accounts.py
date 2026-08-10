"""Account persistence, with ownership enforced in the query itself.

This is the file where v1's worst bug lived. v1 had, in effect:

    account = get_account(account_id)          # whatever id the URL said
    return jsonify(account)                    # no ownership check at all

Change the number in the URL, read somebody else's finances. That is an
Insecure Direct Object Reference — OWASP calls the category Broken Access
Control, and it has been the number one item on the Top 10 since 2021, because
it is trivially easy to write and invisible to every automated scanner that does
not know who is supposed to own what.

The fix people usually reach for first is a guard after the fetch:

    account = get_account(account_id)
    if account["user_id"] != current_user_id:   # better, still fragile
        abort(403)

That works exactly as long as every present and future caller remembers to write
it. The one endpoint that forgets is the breach.

So ownership is not a check here. It is a parameter. Every function below takes
user_id and puts it in the WHERE clause, which means a query for someone else's
row does not return a row to check — it returns nothing at all. There is no
"forgot the check" state available to a caller, because there is no version of
these functions that can be called without an owner.
"""
import sqlite3

from app.db import get_db

VALID_KINDS = ("checking", "savings", "credit", "cash")


def create_account(user_id: int, name: str, kind: str) -> int:
    """Create an account owned by user_id.

    The owner comes from the session, never from the request body. If callers
    could send user_id, this would be an authorization bypass with extra steps.
    """
    cursor = get_db().execute(
        "INSERT INTO accounts (user_id, name, kind) VALUES (?, ?, ?)",
        (user_id, name, kind),
    )
    get_db().commit()
    return cursor.lastrowid


def list_accounts(user_id: int) -> list[sqlite3.Row]:
    """Every account this user owns, and only those."""
    return get_db().execute(
        "SELECT id, name, kind, created_at FROM accounts"
        " WHERE user_id = ? ORDER BY id",
        (user_id,),
    ).fetchall()


def get_account(user_id: int, account_id: int) -> sqlite3.Row | None:
    """One account, scoped to its owner.

    Note there is no get_account(account_id) overload. Not offering one is the
    control: a function that cannot be called without an owner cannot be called
    without an authorization check.
    """
    return get_db().execute(
        "SELECT id, name, kind, created_at FROM accounts"
        " WHERE id = ? AND user_id = ?",
        (account_id, user_id),
    ).fetchone()


def rename_account(user_id: int, account_id: int, name: str) -> bool:
    """Rename an account. False when it does not exist OR is not theirs.

    The two cases are deliberately indistinguishable to the caller, which is
    what lets the route answer 404 for both and avoid confirming that somebody
    else's account id is real.
    """
    cursor = get_db().execute(
        "UPDATE accounts SET name = ? WHERE id = ? AND user_id = ?",
        (name, account_id, user_id),
    )
    get_db().commit()
    return cursor.rowcount > 0


def delete_account(user_id: int, account_id: int) -> bool:
    """Delete an account and, by ON DELETE CASCADE, its transactions.

    Writes need the ownership clause every bit as much as reads. An unscoped
    DELETE is worse than an unscoped SELECT: the first leaks data, the second
    destroys it.
    """
    cursor = get_db().execute(
        "DELETE FROM accounts WHERE id = ? AND user_id = ?",
        (account_id, user_id),
    )
    get_db().commit()
    return cursor.rowcount > 0


def account_balance_cents(user_id: int, account_id: int) -> int | None:
    """Sum of the account's transactions, in cents. None if not theirs."""
    if get_account(user_id, account_id) is None:
        return None
    row = get_db().execute(
        "SELECT COALESCE(SUM(amount_cents), 0) AS total FROM transactions"
        " WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    return row["total"]

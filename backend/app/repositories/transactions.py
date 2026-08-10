"""Transaction persistence.

Transactions are the interesting authorization case, because a transaction does
not carry a user_id. It belongs to an account, and the account belongs to a
user, so ownership is one hop away.

That hop is exactly where access control tends to fall apart. The accounts table
gets its ownership clause because the column is right there and it is obvious;
the child table gets forgotten, because "it is only reachable through an account
anyway" — which is true right up until someone adds an endpoint that takes a
transaction id directly.

So every query here joins to accounts and filters on a.user_id. The join is the
authorization. A transaction whose account belongs to someone else does not fail
a check, it fails to match.
"""
import sqlite3

from app.db import get_db


def create_transaction(
    user_id: int, account_id: int, amount_cents: int, description: str, occurred_on: str
) -> int | None:
    """Add a transaction. None when the account is not this user's.

    The ownership test is a SELECT scoped to the user rather than a plain
    existence check, so writing into somebody else's account is not merely
    forbidden — it is unreachable.
    """
    owns = get_db().execute(
        "SELECT 1 FROM accounts WHERE id = ? AND user_id = ?",
        (account_id, user_id),
    ).fetchone()
    if owns is None:
        return None

    cursor = get_db().execute(
        "INSERT INTO transactions (account_id, amount_cents, description, occurred_on)"
        " VALUES (?, ?, ?, ?)",
        (account_id, amount_cents, description, occurred_on),
    )
    get_db().commit()
    return cursor.lastrowid


def list_transactions(user_id: int, account_id: int) -> list[sqlite3.Row] | None:
    """Transactions for one account, or None when it is not this user's.

    None and [] mean different things and the route depends on the difference:
    None is "no such account of yours" (404), [] is "your account, no
    transactions yet" (200 with an empty list).
    """
    owns = get_db().execute(
        "SELECT 1 FROM accounts WHERE id = ? AND user_id = ?",
        (account_id, user_id),
    ).fetchone()
    if owns is None:
        return None

    return get_db().execute(
        "SELECT id, account_id, amount_cents, description, occurred_on, created_at"
        " FROM transactions WHERE account_id = ?"
        " ORDER BY occurred_on DESC, id DESC",
        (account_id,),
    ).fetchall()


def get_transaction(user_id: int, transaction_id: int) -> sqlite3.Row | None:
    """One transaction, reached directly by id, still scoped to its owner.

    This is the endpoint shape that leaks in real applications: the id is in the
    URL, the transaction has no user_id column, and the ownership hop is easy to
    skip. The JOIN is what makes it safe.
    """
    return get_db().execute(
        "SELECT t.id, t.account_id, t.amount_cents, t.description,"
        "       t.occurred_on, t.created_at"
        " FROM transactions t"
        " JOIN accounts a ON a.id = t.account_id"
        " WHERE t.id = ? AND a.user_id = ?",
        (transaction_id, user_id),
    ).fetchone()


def delete_transaction(user_id: int, transaction_id: int) -> bool:
    """Delete one transaction. False when it is not this user's.

    SQLite does not accept a JOIN inside DELETE, so ownership is expressed as a
    subquery instead. Same control, different syntax — worth knowing, because
    "I could not write the join so I dropped the clause" is how this gets lost.
    """
    cursor = get_db().execute(
        "DELETE FROM transactions"
        " WHERE id = ?"
        "   AND account_id IN (SELECT id FROM accounts WHERE user_id = ?)",
        (transaction_id, user_id),
    )
    get_db().commit()
    return cursor.rowcount > 0

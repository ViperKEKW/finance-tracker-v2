"""Session and CSRF token generation, hashing, and comparison.

The obvious question when you read this next to passwords.py: why is a session
token hashed with plain SHA-256 when a password gets the full Argon2id
treatment? Are we not being sloppy in one of the two places?

No, and the reason is entropy. Argon2 is deliberately slow because a password is
whatever a human chose, which in practice is drawn from a small, guessable set,
so the only defense is to make each guess expensive. A session token is 32 bytes
straight from the OS CSPRNG. There is no dictionary to run and no pattern to
exploit; an attacker's only option is brute force over 2^256, which no amount of
slowness would matter against. Making token verification slow would buy nothing
and cost real latency, because it happens on every single authenticated request
rather than once per login.

The hashing still earns its place. It means the sessions table stores no usable
credential: an attacker with read access to the database (a SQL injection
elsewhere, a leaked backup, an over-permissioned analytics job) gets a column of
digests, not a set of cookies they can paste into a browser and become you.
That is the same reasoning as never storing plaintext passwords, applied to the
other thing that grants access.
"""
import hashlib
import hmac
import secrets

# 32 bytes = 256 bits. token_urlsafe returns base64url text, so the printable
# string is longer than 32 characters; the entropy is what matters.
TOKEN_BYTES = 32


def new_token() -> str:
    """Mint a fresh, unguessable token.

    secrets, not random. The random module is a Mersenne Twister seeded for
    reproducibility, and observing a few outputs is enough to predict the rest —
    a fine property for simulations and a catastrophic one for session tokens.
    secrets draws from the operating system's CSPRNG.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Hash a token for storage or lookup.

    Deterministic and unsalted on purpose: we need to look a session up BY its
    hash, so the same token must always produce the same digest. A per-row salt
    would make that lookup impossible without scanning every row. The property
    salt provides for passwords (defeating precomputation) is irrelevant here,
    because there is nothing to precompute against 256 bits of randomness.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(expected: str, provided: str) -> bool:
    """Compare two tokens without leaking how much of the guess was right.

    ``==`` on strings short-circuits at the first differing byte, so a wrong
    guess that shares a longer prefix takes measurably longer to reject. Given
    enough samples that turns into a byte-at-a-time reconstruction of the real
    token. compare_digest runs in time that depends only on length.

    This is the same class of bug as the early return in verify_password, just
    at the level of a single comparison instead of a whole code path.
    """
    return hmac.compare_digest(expected, provided)

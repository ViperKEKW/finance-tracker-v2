"""Password hashing.

v1 of this project used bcrypt at cost 10. This is the deliberate upgrade to
Argon2id, the algorithm OWASP lists first in its Password Storage guidance.

The reason is memory-hardness. bcrypt is expensive in CPU time but cheap in
memory, so an attacker can pack thousands of parallel bcrypt cores onto one GPU
and crack in bulk. Argon2id forces every single guess to allocate a large block
of RAM, and RAM is the one resource a GPU cannot cheaply multiply. Same wall
clock cost for one honest login, far worse economics for an offline cracker.
"""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# The library's defaults track current OWASP parameter guidance. Keeping one
# shared instance means a future tuning pass is a single edit here, and existing
# users migrate to the new parameters on their next login via needs_rehash().
_hasher = PasswordHasher()

# A real Argon2 hash of a value nobody can log in with. Its only job is to give
# verify_password() something genuine to burn CPU and RAM on when the account
# does not exist — see the comment in verify_password.
_DUMMY_HASH = _hasher.hash("no-account-holds-this-password")


def hash_password(password: str) -> str:
    """Hash a password for storage.

    The returned string is self-describing: it carries the algorithm, version,
    and cost parameters alongside a per-password random salt. That is why there
    is no separate salt column — and why the salt does not need to be secret.
    Its job is to make every stored hash unique so one rainbow table cannot
    cover two users who chose the same password.
    """
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Check a password against a stored hash. ``None`` means no such user.

    The None branch still runs a full Argon2 verification against a dummy hash
    instead of returning early. Returning early would make a missing account
    answer in microseconds while a real account takes the full hashing time, and
    that timing gap is a free username-enumeration oracle: an attacker learns
    which addresses are registered without ever guessing a password correctly.
    Doing the same work in both cases closes it.
    """
    target = stored_hash if stored_hash is not None else _DUMMY_HASH
    try:
        _hasher.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    # Belt and braces: a caller holding no hash must never receive True, even in
    # the astronomically unlikely event that the dummy password was guessed.
    return stored_hash is not None


def needs_rehash(stored_hash: str) -> bool:
    """True when a hash was made with weaker parameters than we now use.

    Call this right after a successful login — the one moment the plaintext is
    legitimately in hand — and re-hash if it returns True. That is how a stored
    credential gets upgraded without ever asking the user to reset anything.
    """
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        # Unparseable means it is not one of ours (a bcrypt row from v1, or
        # corruption). Either way it should be replaced.
        return True

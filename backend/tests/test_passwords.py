from app.security.passwords import hash_password, needs_rehash, verify_password


def test_hash_is_not_the_plaintext():
    hashed = hash_password("hunter2")
    assert "hunter2" not in hashed


def test_hash_is_self_describing_argon2id():
    # The stored string carries algorithm, version, and cost parameters, which
    # is what makes needs_rehash() possible years later.
    assert hash_password("hunter2").startswith("$argon2id$")


def test_same_password_hashes_differently_each_time():
    # Different random salt per call. Identical passwords across two accounts
    # must not produce identical rows, or one cracked hash cracks both.
    assert hash_password("hunter2") != hash_password("hunter2")


def test_correct_password_verifies():
    assert verify_password(hash_password("hunter2"), "hunter2") is True


def test_wrong_password_is_rejected():
    assert verify_password(hash_password("hunter2"), "hunter3") is False


def test_missing_user_is_rejected_without_crashing():
    # The None path still runs a real verification against the dummy hash; the
    # contract callers rely on is only that it returns False rather than raising.
    assert verify_password(None, "anything") is False


def test_garbage_hash_is_rejected_not_raised():
    assert verify_password("not-a-hash", "hunter2") is False


def test_current_hash_does_not_need_rehash():
    assert needs_rehash(hash_password("hunter2")) is False


def test_unparseable_hash_is_flagged_for_rehash():
    # A leftover bcrypt row from v1 lands here and gets replaced on next login.
    assert needs_rehash("$2b$10$abcdefghijklmnopqrstuv") is True

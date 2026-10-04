import bcrypt

from app.hashing import DUMMY_HASH, check_password


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("utf-8")


def test_check_password_accepts_correct_password():
    assert check_password("secret123", _hash("secret123")) is True


def test_check_password_rejects_wrong_password():
    assert check_password("wrong", _hash("secret123")) is False


def test_password_longer_than_72_bytes_is_rejected_not_raised():
    # bcrypt < 5 silently truncates to 72 bytes (so this would match), bcrypt >= 5 raises ValueError.
    assert check_password("a" * 73, _hash("a" * 72)) is False


def test_dummy_hash_is_a_full_cost_bcrypt_hash():
    assert DUMMY_HASH.startswith("$2b$12$")
    assert check_password("secret123", DUMMY_HASH) is False

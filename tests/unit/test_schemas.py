import pytest
from pydantic import ValidationError

from app.schemas.user_schemas import LoginRequest, UserRegister, UserUpdate


def _error_fields(exc_info):
    return {".".join(str(p) for p in e["loc"]) for e in exc_info.value.errors()}


def test_register_accepts_valid_payload():
    user = UserRegister(username="alice", password="secret123", email="alice@example.com")
    assert user.email == "alice@example.com"


def test_register_email_is_optional():
    assert UserRegister(username="alice", password="secret123").email is None


def test_register_accepts_password_of_exactly_72_bytes():
    user = UserRegister(username="alice", password="я" * 36)  # 36 Cyrillic chars = 72 bytes
    assert user.password == "я" * 36


@pytest.mark.parametrize("payload, field", [
    ({"username": "al", "password": "secret123"}, "username"),
    ({"username": "a" * 51, "password": "secret123"}, "username"),
    ({"username": 123, "password": "secret123"}, "username"),
    ({"password": "secret123"}, "username"),
    ({"username": "alice"}, "password"),
    ({"username": "alice", "password": "12345"}, "password"),
    ({"username": "alice", "password": "я" * 37}, "password"),  # 74 bytes
    ({"username": "alice", "password": "secret123", "email": "not-an-email"}, "email"),
])
def test_register_rejects_invalid_payload(payload, field):
    with pytest.raises(ValidationError) as exc_info:
        UserRegister.model_validate(payload)
    assert field in _error_fields(exc_info)


def test_update_accepts_email_only():
    assert UserUpdate(email="new@example.com").password is None


def test_update_accepts_password_only():
    assert UserUpdate(password="newsecret1").email is None


def test_update_requires_at_least_one_field():
    with pytest.raises(ValidationError, match="At least one"):
        UserUpdate.model_validate({})


def test_update_rejects_all_null_fields():
    with pytest.raises(ValidationError, match="At least one"):
        UserUpdate.model_validate({"email": None, "password": None})


@pytest.mark.parametrize("payload", [{"password": "12345"}, {"password": "я" * 37}, {"email": "nope"}])
def test_update_rejects_invalid_fields(payload):
    with pytest.raises(ValidationError):
        UserUpdate.model_validate(payload)


@pytest.mark.parametrize("payload", [
    {},
    {"username": "alice"},
    {"username": "alice", "password": None},
    {"username": "", "password": "secret123"},
    {"username": "alice", "password": ""},
])
def test_login_requires_non_empty_strings(payload):
    with pytest.raises(ValidationError):
        LoginRequest.model_validate(payload)


def test_register_and_login_reject_nul_in_username():
    with pytest.raises(ValidationError) as exc_info:
        UserRegister(username="a\x00bc", password="secret123")
    assert "username" in _error_fields(exc_info)
    with pytest.raises(ValidationError) as exc_info:
        LoginRequest(username="a\x00bc", password="x")
    assert "username" in _error_fields(exc_info)


def _email(length):
    return "a" * (length - len("@example.com")) + "@example.com"


def test_email_of_exactly_100_chars_is_accepted():
    assert UserRegister(username="alice", password="secret123", email=_email(100)).email == _email(100)
    assert UserUpdate(email=_email(100)).email == _email(100)


def test_email_over_100_chars_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        UserRegister(username="alice", password="secret123", email=_email(101))
    assert "email" in _error_fields(exc_info)
    with pytest.raises(ValidationError) as exc_info:
        UserUpdate(email=_email(101))
    assert "email" in _error_fields(exc_info)

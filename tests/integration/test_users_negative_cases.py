import pytest
import requests

from config import BASE_URL, HEADERS


def _error_fields(resp):
    return [error["field"] for error in resp.json()["errors"]]


# ================== REGISTRATION ==================

@pytest.mark.parametrize("payload, field", [
    ({"password": "StrongPass123!"}, "username"),
    ({"username": "testuser"}, "password"),
    ({"username": "ab", "password": "StrongPass123!"}, "username"),
    ({"username": "validuser", "password": "123"}, "password"),
    ({"username": "bademailuser", "password": "StrongPass123!", "email": "not-an-email"}, "email"),
], ids=["no-username", "no-password", "short-username", "short-password", "bad-email"])
def test_register_rejects_invalid_payload(payload, field):
    resp = requests.post(f"{BASE_URL}/users/register", json=payload, headers=HEADERS)

    assert resp.status_code == 400
    assert field in _error_fields(resp)


def test_register_rejects_non_object_body():
    resp = requests.post(f"{BASE_URL}/users/register", json=["user", "pass"], headers=HEADERS)
    assert resp.status_code == 400


def test_register_duplicate_username(test_user):
    """Повторная регистрация занятого username"""
    resp = requests.post(
        f"{BASE_URL}/users/register",
        json={"username": test_user["username"], "password": "StrongPass123!"},
        headers=HEADERS,
    )

    assert resp.status_code == 409
    assert resp.json() == {"message": "Username already taken"}


# ================== AUTHORIZATION ==================

@pytest.mark.parametrize("method, path", [
    ("get", "/users/me"),
    ("get", "/users/users"),
    ("get", "/users/users/1"),
    ("put", "/users/users/1"),
    ("delete", "/users/users/1"),
])
def test_endpoints_require_token(method, path):
    resp = requests.request(method, f"{BASE_URL}{path}", json={"email": "x@example.com"}, headers=HEADERS)
    assert resp.status_code == 401


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_foreign_user_is_forbidden(user_factory, method):
    attacker, victim = user_factory(), user_factory()

    resp = requests.request(
        method,
        f"{BASE_URL}/users/users/{victim['id']}",
        json={"password": "Hacked123!"},
        headers=attacker["headers"],
    )

    assert resp.status_code == 403
    # The victim must still exist and be reachable with its own token
    own = requests.get(f"{BASE_URL}/users/users/{victim['id']}", headers=victim["headers"])
    assert own.status_code == 200


def test_foreign_password_change_does_not_take_effect(user_factory, login):
    attacker, victim = user_factory(), user_factory()

    resp = requests.put(
        f"{BASE_URL}/users/users/{victim['id']}",
        json={"password": "Hacked123!"},
        headers=attacker["headers"],
    )
    assert resp.status_code == 403

    hacked = requests.post(
        f"{BASE_URL}/auth/login",
        json={"username": victim["username"], "password": "Hacked123!"},
        headers=HEADERS,
    )
    assert hacked.status_code == 401
    assert login(victim["username"], victim["password"])


def test_nonexistent_foreign_id_is_forbidden(test_user):
    """Чужой несуществующий id не раскрывает, существует ли пользователь"""
    resp = requests.get(f"{BASE_URL}/users/users/9999999", headers=test_user["headers"])
    assert resp.status_code == 403


def test_update_with_empty_body(test_user):
    resp = requests.put(f"{BASE_URL}/users/users/{test_user['id']}", json={}, headers=test_user["headers"])
    assert resp.status_code == 400

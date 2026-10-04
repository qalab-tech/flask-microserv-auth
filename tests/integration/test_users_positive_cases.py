import time

import requests

from config import BASE_URL, HEADERS


def test_register_user(unique_username, login):
    """Успешная регистрация"""
    payload = {"username": unique_username, "password": "StrongPass123!", "email": f"{unique_username}@example.com"}

    resp = requests.post(f"{BASE_URL}/users/register", json=payload, headers=HEADERS)

    assert resp.status_code == 201
    user_id = resp.json()["user_id"]
    token = login(unique_username, payload["password"])
    cleanup = requests.delete(
        f"{BASE_URL}/users/users/{user_id}", headers={**HEADERS, "Authorization": f"Bearer {token}"}
    )
    assert cleanup.status_code == 200


def test_get_me(test_user):
    resp = requests.get(f"{BASE_URL}/users/me", headers=test_user["headers"])

    assert resp.status_code == 200
    assert resp.json()["id"] == test_user["id"]
    assert resp.json()["username"] == test_user["username"]


def test_get_all_users(test_user):
    """Получение списка пользователей"""
    resp = requests.get(f"{BASE_URL}/users/users", headers=test_user["headers"])

    assert resp.status_code == 200
    assert isinstance(resp.json()["users"], list)


def test_get_user_by_id(test_user):
    """Получение пользователя по ID"""
    resp = requests.get(f"{BASE_URL}/users/users/{test_user['id']}", headers=test_user["headers"])

    assert resp.status_code == 200
    assert resp.json()["id"] == test_user["id"]


def test_update_email_keeps_token_valid(test_user):
    """Обновление email не отзывает токен"""
    resp = requests.put(
        f"{BASE_URL}/users/users/{test_user['id']}",
        json={"email": "updated_test@example.com"},
        headers=test_user["headers"],
    )

    assert resp.status_code == 200
    assert resp.json()["email"] == "updated_test@example.com"
    assert requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"]).status_code == 200


def test_change_password_revokes_old_token(test_user, login):
    """Смена пароля отзывает старые токены"""
    time.sleep(1)  # revocation works in whole seconds: a token issued in the same second survives
    new_password = "NewStrongPass456!"

    resp = requests.put(
        f"{BASE_URL}/users/users/{test_user['id']}",
        json={"password": new_password},
        headers=test_user["headers"],
    )
    assert resp.status_code == 200

    old = requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"])
    assert old.status_code == 401
    assert old.json()["status"] == "revoked"

    token = login(test_user["username"], new_password)
    test_user["headers"] = {**HEADERS, "Authorization": f"Bearer {token}"}
    assert requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"]).status_code == 200


def test_delete_user(test_user):
    """Удаление пользователя отзывает его токены"""
    time.sleep(1)  # see test_change_password_revokes_old_token

    resp = requests.delete(f"{BASE_URL}/users/users/{test_user['id']}", headers=test_user["headers"])
    assert resp.status_code == 200

    validate = requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"])
    assert validate.status_code == 401
    assert validate.json()["status"] == "revoked"

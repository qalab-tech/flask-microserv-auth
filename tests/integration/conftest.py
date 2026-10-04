import uuid

import pytest
import requests

from config import BASE_URL, HEADERS


@pytest.fixture
def unique_username():
    """Генерирует уникальное имя пользователя"""
    return f"testuser_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def login():
    """Log in and return the access token."""
    def _login(username: str, password: str) -> str:
        resp = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": password},
            headers=HEADERS,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["token"]
    return _login


@pytest.fixture
def user_factory(login):
    """Create users with tokens; deletes them after the test with their current headers."""
    created = []

    def _create() -> dict:
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        password = "StrongPass123!"
        resp = requests.post(
            f"{BASE_URL}/users/register",
            json={"username": username, "password": password, "email": f"{username}@example.com"},
            headers=HEADERS,
        )
        assert resp.status_code == 201, f"Failed to create test user: {resp.text}"
        token = login(username, password)
        user = {
            "id": resp.json()["user_id"],
            "username": username,
            "password": password,
            "token": token,
            "headers": {**HEADERS, "Authorization": f"Bearer {token}"},
        }
        created.append(user)
        return user

    yield _create

    # Cleanup: tests that change the password or log out must update user["headers"].
    for user in created:
        requests.delete(f"{BASE_URL}/users/users/{user['id']}", headers=user["headers"])


@pytest.fixture
def test_user(user_factory):
    """Создаёт тестового пользователя и возвращает его данные"""
    return user_factory()

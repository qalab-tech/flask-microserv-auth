import pytest
import requests

from config import BASE_URL, HEADERS


def test_register_user(unique_username):
    """Успешная регистрация"""
    user_data = {
        "username": unique_username,
        "password": "StrongPass123!",
        "email": f"{unique_username}@example.com"
    }

    response = requests.post(
        f"{BASE_URL}/users/register",
        json=user_data,
        headers=HEADERS
    )

    assert response.status_code == 201
    assert "user_id" in response.json()


def test_get_all_users():
    """Получение списка пользователей"""
    response = requests.get(f"{BASE_URL}/users/users")
    assert response.status_code == 200
    data = response.json()
    assert "users" in data
    assert isinstance(data["users"], list)


def test_get_user_by_id(test_user):
    """Получение пользователя по ID"""
    response = requests.get(f"{BASE_URL}/users/users/{test_user['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == test_user["id"]


def test_update_user(test_user):
    """Обновление пользователя"""
    update_data = {"email": "updated_test@example.com"}

    response = requests.put(
        f"{BASE_URL}/users/users/{test_user['id']}",
        json=update_data,
        headers=HEADERS
    )
    assert response.status_code == 200


def test_delete_user(test_user):
    """Удаление пользователя"""
    response = requests.delete(f"{BASE_URL}/users/users/{test_user['id']}")
    assert response.status_code == 200
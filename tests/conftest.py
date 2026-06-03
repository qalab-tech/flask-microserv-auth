import sys
import os
import pytest
import requests

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import BASE_URL, HEADERS


# ================== FIXTURES ==================

@pytest.fixture(scope="function")
def unique_username():
    """Генерирует уникальное имя пользователя"""
    import uuid
    return f"testuser_{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="function")
def test_user(unique_username):
    """Создаёт тестового пользователя и возвращает его данные"""
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

    assert response.status_code == 201, f"Failed to create test user: {response.text}"

    user_id = response.json()["user_id"]

    yield {**user_data, "id": user_id}

    # Cleanup
    requests.delete(f"{BASE_URL}/users/users/{user_id}")
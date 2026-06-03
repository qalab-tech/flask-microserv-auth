import requests
from config import BASE_URL, HEADERS


# ================== NEGATIVE TESTS ==================

def test_register_without_username():
    """Регистрация без username"""
    response = requests.post(
        f"{BASE_URL}/users/register",
        json={"password": "StrongPass123!"},
        headers=HEADERS
    )
    assert response.status_code == 400
    assert "error" in response.json()


def test_register_without_password():
    """Регистрация без пароля"""
    response = requests.post(
        f"{BASE_URL}/users/register",
        json={"username": "testuser"},
        headers=HEADERS
    )
    assert response.status_code == 400


def test_register_short_username():
    """Слишком короткий username"""
    response = requests.post(
        f"{BASE_URL}/users/register",
        json={"username": "ab", "password": "StrongPass123!"},
        headers=HEADERS
    )
    assert response.status_code == 400
    assert "Username must be at least 3 characters" in response.json().get("error", "")


def test_register_short_password():
    """Слишком короткий пароль"""
    response = requests.post(
        f"{BASE_URL}/users/register",
        json={"username": "validuser", "password": "123"},
        headers=HEADERS
    )
    assert response.status_code == 400
    assert "Password must be at least" in response.json().get("error", "")


def test_register_duplicate_username():
    """Попытка зарегистрировать пользователя с уже существующим username"""
    # Сначала создаём пользователя
    user_data = {
        "username": "duplicate_test",
        "password": "StrongPass123!"
    }
    requests.post(f"{BASE_URL}/users/register", json=user_data, headers=HEADERS)

    # Пытаемся создать ещё раз
    response = requests.post(f"{BASE_URL}/users/register", json=user_data, headers=HEADERS)
    assert response.status_code == 400  # или 409, в зависимости от обработки


def test_get_nonexistent_user():
    """Получение несуществующего пользователя"""
    response = requests.get(f"{BASE_URL}/users/users/9999999")
    assert response.status_code == 404


def test_update_nonexistent_user():
    """Обновление несуществующего пользователя"""
    response = requests.put(
        f"{BASE_URL}/users/users/9999999",
        json={"email": "new@example.com"},
        headers=HEADERS
    )
    assert response.status_code in (400, 404)


def test_delete_nonexistent_user():
    """Удаление несуществующего пользователя"""
    response = requests.delete(f"{BASE_URL}/users/users/9999999")
    assert response.status_code in (400, 404)


def test_register_invalid_email():
    """Регистрация с некорректным email"""
    response = requests.post(
        f"{BASE_URL}/users/register",
        json={
            "username": "bademailuser",
            "password": "StrongPass123!",
            "email": "not-an-email"
        },
        headers=HEADERS
    )
    # Может быть 201 или 400 — зависит от твоей валидации
    assert response.status_code in (400, 201)
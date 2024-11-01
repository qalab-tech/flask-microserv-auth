# tests/test_auth_service.py

import pytest
from app import create_app


@pytest.fixture
def client():
    # Инициализируем приложение с тестовой конфигурацией
    app = create_app()
    app.config['TESTING'] = True

    return app.test_client()


def test_login(client):
    # Отправка запроса с JSON-данными и правильным заголовком Content-Type
    response = client.post('/auth/login', json={'username': 'test', 'password': 'test'},
                           headers={"Content-Type": "application/json"})

    # Проверка на статус ответа и наличие токена в случае успеха
    assert response.status_code in (200, 401)  # Успешный или неуспешный вход

    if response.status_code == 200:
        assert 'token' in response.json  # Проверка, что в ответе есть токен
    else:
        assert response.json.get('message') == 'Invalid credentials'


@pytest.mark.parametrize("username, password, expected_status", [
    ("valid_user", "correct_pass", 200),
    ("invalid_user", "wrong_pass", 401),
])
def test_login_parametrized(client, username, password, expected_status):
    response = client.post('/auth/login', json={'username': username, 'password': password})
    assert response.status_code == expected_status

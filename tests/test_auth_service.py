# tests/test_auth_service.py

import pytest
from app import create_app

@pytest.fixture
def client():
    # Инициализируем приложение с тестовой конфигурацией
    app = create_app()
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'hudTTPZbw6WV4yxEUnVdT5CooIT1TepeD0-Nwlw_-D4'  # Установка тестового секретного ключа

    return app.test_client()

def test_login(client):
    # Отправка запроса с JSON-данными и правильным заголовком Content-Type
    response = client.post('/auth/login', json={'username': 'test', 'password': 'test'}, headers={"Content-Type": "application/json"})

    # Проверка на статус ответа и наличие токена в случае успеха
    assert response.status_code in (200, 401)  # Успешный или неуспешный вход

    if response.status_code == 200:
        assert 'token' in response.json  # Проверка, что в ответе есть токен
    else:
        assert response.json.get('message') == 'Invalid credentials'

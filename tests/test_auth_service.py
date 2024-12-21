# tests/test_auth_service.py

import pytest
from app import create_app


@pytest.fixture
def client():
    # Init test configuration for the Flask application
    app = create_app()
    app.config['TESTING'] = True

    return app.test_client()


def test_login(client):
    # Send request with credentials and proper  Content-Type header
    response = client.post('/auth/login', json={'username': 'test', 'password': 'test'},
                           headers={"Content-Type": "application/json"})

    # Check response status code and presence of token
    assert response.status_code in (200, 401)

    if response.status_code == 200:
        assert 'token' in response.json  # Checking if the response contains a token
    else:
        assert response.json.get('message') == 'Invalid credentials'


@pytest.mark.parametrize("username, password, expected_status", [
    ("valid_user", "correct_pass", 200),
    ("invalid_user", "wrong_pass", 401),
])
def test_login_parametrized(client, username, password, expected_status):
    response = client.post('/auth/login', json={'username': username, 'password': password})
    assert response.status_code == expected_status

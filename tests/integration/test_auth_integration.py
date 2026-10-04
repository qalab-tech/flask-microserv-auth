import pytest
import requests

from config import BASE_URL, HEADERS


@pytest.mark.parametrize("username, password", [("test", "test"), ("valid_user", "correct_pass")])
def test_seeded_users_can_log_in(username, password):
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "password": password}, headers=HEADERS)

    assert resp.status_code == 200
    assert "token" in resp.json()


@pytest.mark.parametrize("username, password", [("test", "wrong-password"), ("no_such_user_xyz", "whatever")])
def test_login_rejects_invalid_credentials(username, password):
    resp = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "password": password}, headers=HEADERS)

    assert resp.status_code == 401
    assert resp.json()["message"] == "Invalid credentials"


def test_login_rejects_non_json_body():
    resp = requests.post(f"{BASE_URL}/auth/login", data="not json", headers={"Content-Type": "text/plain"})
    assert resp.status_code == 400


def test_validate_returns_user_info(test_user):
    resp = requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"])

    assert resp.status_code == 200
    assert resp.json() == {"status": "valid", "user": test_user["username"], "user_id": test_user["id"]}


def test_validate_without_header_reports_missing():
    resp = requests.get(f"{BASE_URL}/auth/validate")

    assert resp.status_code == 401
    assert resp.json()["status"] == "missing"


def test_validate_with_malformed_header_reports_invalid():
    resp = requests.get(f"{BASE_URL}/auth/validate", headers={"Authorization": "Bearer"})

    assert resp.status_code == 401
    assert resp.json()["status"] == "invalid"


def test_logout_revokes_token(test_user, login):
    resp = requests.post(f"{BASE_URL}/auth/logout", headers=test_user["headers"])
    assert resp.status_code == 204

    validate = requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"])
    assert validate.status_code == 401
    assert validate.json()["status"] == "revoked"

    # Fresh token so that the fixture can delete the user
    token = login(test_user["username"], test_user["password"])
    test_user["headers"] = {**HEADERS, "Authorization": f"Bearer {token}"}

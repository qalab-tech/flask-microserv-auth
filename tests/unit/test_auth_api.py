import jwt
import pytest

import config
from app.controllers import auth_controller
from app.hashing import DUMMY_HASH

OTHER_KEY = "another-secret-key-that-is-long-enough-42"


def _validate(client, token=None, header=None):
    headers = {}
    if header is not None:
        headers["Authorization"] = header
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return client.get("/auth/validate", headers=headers)


# ---------- login ----------

def test_login_returns_token_with_expected_claims(client, make_user):
    user = make_user()
    resp = client.post("/auth/login", json={"username": "alice", "password": "secret123"})

    assert resp.status_code == 200
    claims = jwt.decode(resp.json["token"], config.SECRET_KEY, algorithms=["HS256"])
    assert claims["sub"] == str(user["id"])
    assert claims["username"] == "alice"
    assert {"iat", "exp", "jti"} <= claims.keys()


@pytest.mark.parametrize("username, password", [("alice", "wrong-password"), ("bob", "secret123")])
def test_login_rejects_invalid_credentials(client, make_user, username, password):
    make_user()
    resp = client.post("/auth/login", json={"username": username, "password": password})

    assert resp.status_code == 401
    assert resp.json == {"message": "Invalid credentials"}


def test_login_for_unknown_user_still_runs_bcrypt(client, monkeypatch):
    checked_hashes = []

    def spy(password, hashed_password):
        checked_hashes.append(hashed_password)
        return False

    monkeypatch.setattr(auth_controller, "check_password", spy)
    resp = client.post("/auth/login", json={"username": "ghost", "password": "secret123"})

    assert resp.status_code == 401
    assert checked_hashes == [DUMMY_HASH]


def test_login_with_password_over_72_bytes_returns_401(client, make_user):
    make_user()
    resp = client.post("/auth/login", json={"username": "alice", "password": "я" * 40})
    assert resp.status_code == 401


@pytest.mark.parametrize("kwargs", [
    {"data": "username=alice", "content_type": "application/x-www-form-urlencoded"},
    {"json": ["alice", "secret123"]},
    {"json": {"username": "alice"}},
    {"json": {"username": "alice", "password": None}},
], ids=["form", "array", "no-password", "null-password"])
def test_login_rejects_malformed_body(client, kwargs):
    resp = client.post("/auth/login", **kwargs)

    assert resp.status_code == 400
    assert resp.json["message"] == "Validation failed"
    assert resp.json["errors"]


# ---------- validate ----------

def test_validate_accepts_valid_token(client, make_user):
    user = make_user()
    resp = _validate(client, user["token"])

    assert resp.status_code == 200
    assert resp.json == {"status": "valid", "user": "alice", "user_id": user["id"]}


def test_validate_accepts_lowercase_bearer_scheme(client, make_user):
    user = make_user()
    assert _validate(client, header=f"bearer {user['token']}").status_code == 200


def test_validate_without_header_reports_missing(client):
    resp = _validate(client)

    assert resp.status_code == 401
    assert resp.json["status"] == "missing"


@pytest.mark.parametrize("header", [
    "", "Bearer", "Bearer ", "Basic YWxpY2U6c2VjcmV0", "Bearer a b", "Token abc", "Bearer not-a-jwt",
])
def test_validate_rejects_malformed_header(client, header):
    resp = _validate(client, header=header)

    assert resp.status_code == 401
    assert resp.json["status"] == "invalid"


@pytest.mark.parametrize("overrides", [
    {"key": OTHER_KEY}, {"jti": None}, {"sub": "abc"},
], ids=["foreign-signature", "no-jti", "non-numeric-sub"])
def test_validate_rejects_forged_tokens(client, forge_token, overrides):
    resp = _validate(client, forge_token(**overrides))

    assert resp.status_code == 401
    assert resp.json["status"] == "invalid"


def test_validate_reports_expired_token(client, make_user, clock):
    clock.now -= config.JWT_ACCESS_TOKEN_EXPIRES + 10
    user = make_user()  # logged in long ago, so the token is already expired

    resp = _validate(client, user["token"])

    assert resp.status_code == 401
    assert resp.json["status"] == "expired"


def test_validate_returns_503_when_redis_is_down(client, make_user, break_redis):
    user = make_user()
    break_redis()

    resp = _validate(client, user["token"])

    assert resp.status_code == 503
    assert resp.json == {"message": "Service temporarily unavailable"}


# ---------- logout ----------

def test_logout_revokes_only_the_current_token(client, make_user):
    user = make_user()
    other_token = client.post("/auth/login", json={"username": "alice", "password": "secret123"}).json["token"]

    resp = client.post("/auth/logout", headers=user["headers"])

    assert resp.status_code == 204
    assert _validate(client, user["token"]).json["status"] == "revoked"
    assert _validate(client, other_token).status_code == 200


def test_logout_requires_token(client):
    resp = client.post("/auth/logout")

    assert resp.status_code == 401
    assert resp.json["status"] == "missing"


# ---------- swagger ----------

def test_swagger_marks_only_protected_endpoints_with_bearer(client):
    resp = client.get("/swagger.json")
    assert resp.status_code == 200
    paths = resp.json["paths"]

    assert {"Bearer": []} in paths["/auth/validate"]["get"]["security"]
    assert {"Bearer": []} in paths["/auth/logout"]["post"]["security"]
    assert "security" not in paths["/auth/login"]["post"]

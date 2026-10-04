import pytest

from app.services import user_service


def _login(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password})


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- registration ----------

def test_register_creates_user(client):
    resp = client.post("/users/register", json={
        "username": "alice", "password": "secret123", "email": "alice@example.com",
    })

    assert resp.status_code == 201
    assert resp.json["message"] == "User registered successfully"
    assert isinstance(resp.json["user_id"], int)


def test_register_duplicate_returns_409_without_db_details(client, make_user):
    make_user()
    resp = client.post("/users/register", json={"username": "alice", "password": "secret123"})

    assert resp.status_code == 409
    assert resp.json == {"message": "Username already taken"}


@pytest.mark.parametrize("payload, field", [
    ({"username": "al", "password": "secret123"}, "username"),
    ({"password": "secret123"}, "username"),
    ({"username": "alice", "password": "12345"}, "password"),
    ({"username": "alice", "password": "я" * 37}, "password"),
    ({"username": "alice", "password": "secret123", "email": "not-an-email"}, "email"),
])
def test_register_rejects_invalid_payload(client, payload, field):
    resp = client.post("/users/register", json=payload)

    assert resp.status_code == 400
    assert field in [error["field"] for error in resp.json["errors"]]


def test_register_rejects_non_object_body(client):
    resp = client.post("/users/register", json=["alice", "secret123"])

    assert resp.status_code == 400
    assert resp.json["errors"] == [{"field": "body", "msg": "Request body must be a JSON object"}]


# ---------- authentication required ----------

@pytest.mark.parametrize("method, path", [
    ("get", "/users/me"),
    ("get", "/users/users"),
    ("get", "/users/users/1"),
    ("put", "/users/users/1"),
    ("delete", "/users/users/1"),
])
def test_endpoints_require_token(client, make_user, method, path):
    make_user()
    json = {"email": "x@example.com"} if method == "put" else None
    resp = getattr(client, method)(path, json=json)

    assert resp.status_code == 401
    assert resp.json["status"] == "missing"


# ---------- own profile ----------

def test_me_returns_own_profile(client, make_user):
    user = make_user(email="alice@example.com")
    resp = client.get("/users/me", headers=user["headers"])

    assert resp.status_code == 200
    assert resp.json == {
        "id": user["id"],
        "username": "alice",
        "email": "alice@example.com",
        "created_at": "2026-01-01T12:00:00",
    }


def test_list_users_for_authenticated_user(client, make_user):
    alice = make_user()
    make_user(username="bob")

    resp = client.get("/users/users", headers=alice["headers"])

    assert resp.status_code == 200
    assert resp.json["total"] == 2
    assert [u["username"] for u in resp.json["users"]] == ["alice", "bob"]
    assert "hashed_password" not in resp.json["users"][0]


def test_get_own_user(client, make_user):
    user = make_user()
    resp = client.get(f"/users/users/{user['id']}", headers=user["headers"])

    assert resp.status_code == 200
    assert resp.json["id"] == user["id"]


@pytest.mark.parametrize("method, path, json", [
    ("get", "/users/me", None),
    ("get", "/users/users/{id}", None),
    ("put", "/users/users/{id}", {"email": "new@example.com"}),
    ("delete", "/users/users/{id}", None),
], ids=["me", "get", "put", "delete"])
def test_own_user_missing_from_db_returns_404(client, make_user, repo, method, path, json):
    user = make_user()
    repo.users.pop(user["id"])

    resp = getattr(client, method)(path.format(id=user["id"]), headers=user["headers"], json=json)

    assert resp.status_code == 404
    assert resp.json == {"message": "User not found"}


# ---------- ownership ----------

@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_foreign_user_is_forbidden(client, make_user, method):
    alice = make_user()
    bob = make_user(username="bob")
    json = {"password": "hacked123"} if method == "put" else None

    resp = getattr(client, method)(f"/users/users/{bob['id']}", headers=alice["headers"], json=json)

    assert resp.status_code == 403
    assert resp.json == {"message": "Forbidden"}


def test_foreign_password_change_leaves_victim_untouched(client, make_user):
    alice = make_user()
    bob = make_user(username="bob", password="bobsecret1")

    client.put(f"/users/users/{bob['id']}", headers=alice["headers"], json={"password": "hacked123"})

    assert _login(client, "bob", "bobsecret1").status_code == 200
    assert _login(client, "bob", "hacked123").status_code == 401


def test_nonexistent_foreign_id_is_forbidden_not_404(client, make_user):
    alice = make_user()
    resp = client.get("/users/users/9999", headers=alice["headers"])
    assert resp.status_code == 403


# ---------- update ----------

def test_update_email_keeps_token_valid(client, make_user, clock):
    user = make_user()
    clock.advance(5)

    resp = client.put(f"/users/users/{user['id']}", headers=user["headers"], json={"email": "new@example.com"})

    assert resp.status_code == 200
    assert resp.json["email"] == "new@example.com"
    assert client.get("/auth/validate", headers=user["headers"]).status_code == 200


def test_password_change_revokes_old_tokens(client, make_user, clock):
    user = make_user()
    clock.advance(5)

    resp = client.put(f"/users/users/{user['id']}", headers=user["headers"], json={"password": "newsecret1"})

    assert resp.status_code == 200
    old = client.get("/auth/validate", headers=user["headers"])
    assert old.status_code == 401
    assert old.json["status"] == "revoked"
    assert _login(client, "alice", "secret123").status_code == 401
    new_token = _login(client, "alice", "newsecret1").json["token"]
    assert client.get("/auth/validate", headers=_bearer(new_token)).status_code == 200


@pytest.mark.parametrize("payload", [
    {}, {"email": None, "password": None}, {"password": "12345"}, {"email": "not-an-email"},
], ids=["empty", "all-null", "short-password", "bad-email"])
def test_update_rejects_invalid_payload(client, make_user, payload):
    user = make_user()
    resp = client.put(f"/users/users/{user['id']}", headers=user["headers"], json=payload)

    assert resp.status_code == 400
    assert resp.json["message"] == "Validation failed"


def test_password_change_with_redis_down_returns_503(client, make_user, clock, break_redis):
    user = make_user()
    clock.advance(5)
    break_redis(writes_only=True)

    resp = client.put(f"/users/users/{user['id']}", headers=user["headers"], json={"password": "newsecret1"})

    assert resp.status_code == 503
    # The password is already changed in the DB; retrying the request completes the revocation.
    assert _login(client, "alice", "newsecret1").status_code == 200


# ---------- delete ----------

def test_delete_own_user_revokes_tokens(client, make_user, clock, repo):
    user = make_user()
    clock.advance(5)

    resp = client.delete(f"/users/users/{user['id']}", headers=user["headers"])

    assert resp.status_code == 200
    assert resp.json == {"message": "User deleted successfully"}
    assert user["id"] not in repo.users
    old = client.get("/auth/validate", headers=user["headers"])
    assert old.status_code == 401
    assert old.json["status"] == "revoked"


def test_delete_with_redis_down_keeps_user(client, make_user, clock, repo, break_redis):
    user = make_user()
    clock.advance(5)
    break_redis(writes_only=True)

    resp = client.delete(f"/users/users/{user['id']}", headers=user["headers"])

    assert resp.status_code == 503
    assert user["id"] in repo.users


# ---------- unexpected errors ----------

def test_unexpected_error_returns_generic_500(client, make_user, monkeypatch):
    user = make_user()

    def boom(**kwargs):
        raise RuntimeError("could not connect to server at 10.0.0.5")

    monkeypatch.setattr(user_service, "get_all_users", boom)
    resp = client.get("/users/users", headers=user["headers"])

    assert resp.status_code == 500
    assert resp.json == {"message": "Internal server error"}


# ---------- extra guarantees ----------

def test_foreign_put_with_invalid_body_is_forbidden_not_400(client, make_user):
    alice = make_user()
    bob = make_user(username="bob")

    resp = client.put(f"/users/users/{bob['id']}", headers=alice["headers"], json={"password": "1"})

    assert resp.status_code == 403


# ---------- swagger ----------

def test_swagger_marks_user_endpoints_with_bearer(client):
    resp = client.get("/swagger.json")
    assert resp.status_code == 200
    paths = resp.json["paths"]

    for path, method in [
        ("/users/me", "get"),
        ("/users/users", "get"),
        ("/users/users/{user_id}", "get"),
        ("/users/users/{user_id}", "put"),
        ("/users/users/{user_id}", "delete"),
    ]:
        assert {"Bearer": []} in paths[path][method]["security"], (path, method)
    assert "security" not in paths["/users/register"]["post"]

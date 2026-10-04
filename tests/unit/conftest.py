import datetime
import time

import bcrypt
import fakeredis
import jwt
import pytest
import redis

import config
from app import app as flask_app
from app import tokens
from app.controllers import auth_controller
from app.errors import UserAlreadyExists
from app.services import user_service


class BrokenRedis:
    """Redis stand-in whose every command fails like a dropped connection."""

    def __getattr__(self, name):
        def fail(*args, **kwargs):
            raise redis.exceptions.ConnectionError("Redis is down")
        return fail


class ReadOnlyRedis(fakeredis.FakeRedis):
    """Reads work, writes fail: Redis went down between checking a token and revoking it."""

    def set(self, *args, **kwargs):
        raise redis.exceptions.ConnectionError("Redis is down")


class Clock:
    """Drives tokens._now(). Starts a minute in the past so issued tokens are valid for PyJWT's real clock."""

    def __init__(self):
        self.now = int(time.time()) - 60

    def advance(self, seconds: int) -> None:
        self.now += seconds


@pytest.fixture
def redis_server():
    return fakeredis.FakeServer()


@pytest.fixture
def fake_redis(monkeypatch, redis_server):
    client = fakeredis.FakeRedis(server=redis_server, decode_responses=True)
    monkeypatch.setattr(tokens, "redis_client", client)
    return client


@pytest.fixture
def break_redis(monkeypatch, redis_server):
    """Call break_redis() to fail every Redis command, break_redis(writes_only=True) to fail only writes."""
    def _break(writes_only: bool = False) -> None:
        client = ReadOnlyRedis(server=redis_server, decode_responses=True) if writes_only else BrokenRedis()
        monkeypatch.setattr(tokens, "redis_client", client)
    return _break


@pytest.fixture
def clock(monkeypatch):
    test_clock = Clock()
    monkeypatch.setattr(tokens, "_now", lambda: test_clock.now)
    return test_clock


@pytest.fixture
def forge_token(clock):
    """Sign arbitrary claims; pass a claim as None to drop it."""
    def _forge(key: str | None = None, **overrides) -> str:
        claims = {"sub": "1", "username": "alice", "iat": clock.now, "exp": clock.now + 600, "jti": "f" * 32}
        claims.update(overrides)
        claims = {name: value for name, value in claims.items() if value is not None}
        return jwt.encode(claims, key or config.SECRET_KEY, algorithm="HS256")
    return _forge


class FakeUserRepo:
    """In-memory stand-in for app.repositories.users_repository."""

    def __init__(self):
        self.users: dict[int, dict] = {}
        self.next_id = 1

    @staticmethod
    def _public(user: dict) -> dict:
        return {key: user[key] for key in ("id", "username", "email", "created_at")}

    def create_user(self, username, hashed_password, email=None):
        if any(u["username"] == username for u in self.users.values()):
            raise UserAlreadyExists()
        user = {
            "id": self.next_id,
            "username": username,
            "email": email,
            "hashed_password": hashed_password,
            "created_at": datetime.datetime(2026, 1, 1, 12, 0, 0),
        }
        self.users[self.next_id] = user
        self.next_id += 1
        return self._public(user)

    def get_user_by_id(self, user_id):
        user = self.users.get(user_id)
        return self._public(user) if user else None

    def get_all_users(self, limit=50, offset=0):
        users = [self._public(u) for u in sorted(self.users.values(), key=lambda u: u["id"])]
        return {"users": users[offset:offset + limit], "total": len(users)}

    def update_user(self, user_id, email=None, hashed_password=None):
        user = self.users.get(user_id)
        if user is None:
            return None
        if email is not None:
            user["email"] = email
        if hashed_password is not None:
            user["hashed_password"] = hashed_password
        return self._public(user)

    def delete_user(self, user_id):
        return self.users.pop(user_id, None) is not None

    def get_user_credentials(self, username):
        for user in self.users.values():
            if user["username"] == username:
                return {key: user[key] for key in ("id", "username", "hashed_password")}
        return None


def _fast_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("utf-8")


@pytest.fixture
def repo(monkeypatch):
    fake = FakeUserRepo()
    for name in ("create_user", "get_user_by_id", "get_all_users", "update_user", "delete_user"):
        monkeypatch.setattr(user_service, name, getattr(fake, name))
    monkeypatch.setattr(auth_controller, "get_user_credentials", fake.get_user_credentials)
    monkeypatch.setattr(user_service, "hash_password", _fast_hash)
    return fake


@pytest.fixture
def client(repo, fake_redis, clock):
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


@pytest.fixture
def make_user(client):
    """Register a user through the API, log in and return its id, credentials and auth headers."""
    def _make(username: str = "alice", password: str = "secret123", email: str | None = None) -> dict:
        resp = client.post("/users/register", json={"username": username, "password": password, "email": email})
        assert resp.status_code == 201, resp.json
        login = client.post("/auth/login", json={"username": username, "password": password})
        assert login.status_code == 200, login.json
        token = login.json["token"]
        return {
            "id": resp.json["user_id"],
            "username": username,
            "password": password,
            "token": token,
            "headers": {"Authorization": f"Bearer {token}"},
        }
    return _make

import time

import fakeredis
import jwt
import pytest
import redis

import config
from app import tokens


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

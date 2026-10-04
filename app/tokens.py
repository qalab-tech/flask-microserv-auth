"""JWT access tokens: issuing, verification and revocation (revocation state lives in Redis)."""
import time
import uuid

import jwt
import redis

from app.errors import ServiceUnavailable, TokenExpired, TokenInvalid, TokenRevoked
from config import JWT_ACCESS_TOKEN_EXPIRES, REDIS_HOST, REDIS_PORT, SECRET_KEY

ALGORITHM = "HS256"
REQUIRED_CLAIMS = ["sub", "username", "iat", "exp", "jti"]

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True,
    socket_timeout=2,
    socket_connect_timeout=2,
)


def _now() -> int:
    return int(time.time())


def issue_token(user_id: int, username: str) -> str:
    now = _now()
    payload = {
        "sub": str(user_id),  # PyJWT >= 2.10 requires a string subject
        "username": username,
        "iat": now,
        "exp": now + JWT_ACCESS_TOKEN_EXPIRES,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"require": REQUIRED_CLAIMS})
        user_id = int(claims["sub"])
    except jwt.ExpiredSignatureError as e:
        raise TokenExpired() from e
    except (jwt.InvalidTokenError, ValueError) as e:
        raise TokenInvalid() from e

    try:
        revoked, valid_after = redis_client.mget(f"revoked:{claims['jti']}", f"valid_after:{user_id}")
    except redis.RedisError as e:
        raise ServiceUnavailable() from e

    # iat and valid_after are whole seconds. A token issued in the same second as
    # revoke_all_for_user() stays valid, so logging in right after a password change works.
    if revoked is not None or (valid_after is not None and claims["iat"] < int(valid_after)):
        raise TokenRevoked()
    return claims


def revoke_token(claims: dict) -> None:
    """Revoke a single token (logout) until it would have expired anyway."""
    ttl = max(1, int(claims["exp"]) - _now())
    try:
        redis_client.set(f"revoked:{claims['jti']}", 1, ex=ttl)
    except redis.RedisError as e:
        raise ServiceUnavailable() from e


def revoke_all_for_user(user_id: int) -> None:
    """Revoke every token of the user issued before now (password change, deletion)."""
    try:
        redis_client.set(f"valid_after:{user_id}", _now(), ex=JWT_ACCESS_TOKEN_EXPIRES)
    except redis.RedisError as e:
        raise ServiceUnavailable() from e

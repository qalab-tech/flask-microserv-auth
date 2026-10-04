from functools import wraps

from flask import g, request

from app.errors import Forbidden, TokenInvalid, TokenMissing
from app.tokens import decode_token


def require_auth(func):
    """Require `Authorization: Bearer <token>`; exposes g.current_user and g.token_claims."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization")
        if header is None:
            raise TokenMissing()
        parts = header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise TokenInvalid()
        claims = decode_token(parts[1])
        g.token_claims = claims
        g.current_user = {"id": int(claims["sub"]), "username": claims["username"]}
        return func(*args, **kwargs)
    return wrapper


def ensure_owner(user_id: int) -> None:
    """Allow access only to the token owner's own resources."""
    if user_id != g.current_user["id"]:
        raise Forbidden()

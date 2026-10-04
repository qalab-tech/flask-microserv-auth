import os
from collections.abc import Mapping

MIN_SECRET_KEY_LENGTH = 32


def load_secret_key(env: Mapping[str, str] = os.environ) -> str:
    """Fail fast at startup instead of on the first login."""
    secret_key = env.get("SECRET_KEY")
    if not secret_key or len(secret_key) < MIN_SECRET_KEY_LENGTH:
        raise RuntimeError(
            f"SECRET_KEY must be set and be at least {MIN_SECRET_KEY_LENGTH} characters long"
        )
    return secret_key


def parse_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


SECRET_KEY = load_secret_key()
AUTH_DATABASE_URL = os.getenv("AUTH_DATABASE_URL")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))
SEED_TEST_USERS = parse_bool(os.getenv("SEED_TEST_USERS"))

BASE_URL = "http://localhost:5001"
HEADERS = {"Content-Type": "application/json"}

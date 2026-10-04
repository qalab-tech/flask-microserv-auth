# Безопасность и авторизация auth-service — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Закрыть дыры безопасности из аудита: доступ к `/users/*` только у владельца, отзыв JWT через Redis, валидация входа без 500, единый формат ошибок, тестовые пользователи только под флагом.

**Architecture:** Новые модули `app/tokens.py` (выпуск, проверка и отзыв JWT), `app/auth_guard.py` (декоратор `@require_auth` + `ensure_owner`), `app/errors.py` (доменные исключения и единый обработчик на flask-restx `Api`), `app/validation.py` (`parse_body` на pydantic). Контроллеры только разбирают запрос и бросают исключения, а HTTP-ответы формирует один обработчик. Unit-тесты используют Flask `test_client`, `fakeredis` и in-memory подмену репозитория.

**Tech Stack:** Python 3.13 (Docker) / 3.14 (локальный `.venv`), Flask 3.1, flask-restx 1.3, pydantic 2, PyJWT 2.13, redis-py 8, psycopg2, bcrypt, pytest, fakeredis.

**Spec:** `docs/superpowers/specs/2026-10-03-auth-security-design.md`

## Global Constraints

- Payload токена ровно: `sub` (str id), `username`, `iat`, `exp`, `jti`; алгоритм `HS256`.
- Ключи Redis: `revoked:<jti>` (TTL `max(1, exp − now)`) и `valid_after:<user_id>` (TTL `JWT_ACCESS_TOKEN_EXPIRES`).
- Отзыв по `valid_after`: строго `iat < valid_after`, целые секунды.
- Redis недоступен → 503 `{"message":"Service temporarily unavailable"}` (fail-closed).
- `SECRET_KEY` обязателен, длина ≥ 32 символов, иначе `RuntimeError` при импорте `config`.
- `JWT_ACCESS_TOKEN_EXPIRES` — `int`, по умолчанию 3600.
- Пароль: минимум 6 символов, максимум 72 байта в UTF-8. Username 3–50 символов.
- Любое тело ошибки содержит ключ `message`. Ошибки 400 дополнительно содержат `errors: [{"field","msg"}]`, ошибки авторизации (401) — `status`.
- Проверка владельца (`ensure_owner`) выполняется до обращения к БД и до разбора тела запроса.
- Пути `/users/users/...` не менять. albums-тесты (`tests/tests_albums_api/`) не трогать.
- **В индексе git лежат чужие staged-файлы** (`tests/tests_albums_api/*`). Коммитить только перечисленные в задаче пути: `git add <paths> && git commit -m "..." -- <paths>`. Никогда не `git add -A` / `git commit -a` / `git commit` без путей.
- Каждое сообщение коммита заканчивается строкой `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Unit-тесты запускаются так: `.venv/bin/python -m pytest tests/unit -q` из корня репозитория.

## Review Focus

1. Логин с паролем длиннее 72 байт: bcrypt ≥ 5 бросает `ValueError`, ожидается 401, а не 500 → Task 4 (`test_password_longer_than_72_bytes_is_rejected_not_raised`, `test_login_with_password_over_72_bytes_returns_401`).
2. Подписанный токен с нечисловым `sub` (`"abc"`): ожидается 401 `invalid`, а не 500 из-за `int()` → Task 3 (`test_invalid_tokens_are_rejected[non-numeric-sub]`) и Task 4 (`test_validate_rejects_forged_tokens`).
3. Схема `bearer` в нижнем регистре: по RFC схема регистронезависима, токен должен приниматься → Task 4 (`test_validate_accepts_lowercase_bearer_scheme`).
4. Тело — валидный JSON, но не объект (`[]`, `"str"`): ожидается 400, а не 500 на `.get` → Task 2 (`test_parse_body_rejects_non_object_body`), Task 4, Task 5.
5. `PUT` с `{"email": null, "password": null}`: ожидается 400, а не 404 «User not found» → Task 2 (`test_update_rejects_all_null_fields`), Task 5 (`test_update_rejects_invalid_payload`).

## Отклонения от спецификации (согласованы 2026-10-04, внесены в спеку, раздел 8)

- flask-restx всегда добавляет `message` в тело ошибки (`default_data.get("message", str(e))`). Поэтому 401 на `/auth/validate` и `/auth/logout` — `{"message":"Unauthorized","status":"..."}`, а не только `{"status":"..."}`. Форма совместима: поле `status` на месте. Строки таблицы ошибок для `AuthError` объединяются в одну.
- Минимальная длина пароля — 6 **символов** (в спецификации «6–72 байта»), максимальная — 72 **байта**. Иначе пароль из трёх кириллических букв (6 байт) проходил бы проверку.
- Вместо `AuthError(status)` — подклассы `TokenMissing`, `TokenInvalid`, `TokenExpired`, `TokenRevoked` с атрибутом класса `status`.
- Неиспользуемые `UserResponse`/`UserListResponse` (в pydantic v2 дают deprecation-предупреждения) удаляются из `user_schemas.py` при переписывании файла.
- В Swagger добавляется схема `Bearer` (кнопка Authorize), иначе защищённые эндпоинты нельзя вызвать из UI.
- `REDIS_HOST`/`REDIS_PORT` получают значения по умолчанию `localhost`/`6379` вместо исключения при импорте.
- `Makefile`: пути тестов обновляются после переезда, добавляется `make test-unit`.

## Файловая структура

| Файл | Действие | Ответственность |
|---|---|---|
| `requirements.txt` | modify | + `redis`, `pydantic`, `email-validator`, `requests`, `fakeredis` |
| `config.py` | modify | проверка конфигурации при старте, типизированные настройки |
| `app/db.py` | modify | ленивый пул соединений |
| `app/errors.py` | create | доменные исключения + `register_error_handlers(api)` |
| `app/validation.py` | create | `parse_body(model)` |
| `app/schemas/user_schemas.py` | rewrite | `UserRegister`, `UserUpdate`, `LoginRequest` |
| `app/hashing.py` | modify | `BCRYPT_MAX_BYTES`, `DUMMY_HASH`, защита от паролей > 72 байт |
| `app/tokens.py` | create | выпуск, проверка и отзыв JWT |
| `app/auth_guard.py` | create | `@require_auth`, `ensure_owner` |
| `app/controllers/auth_controller.py` | rewrite | login / validate / logout |
| `app/controllers/users_controller.py` | rewrite | `/users/*` с авторизацией, `/users/me` |
| `app/services/user_service.py` | rewrite | бизнес-логика + отзыв токенов |
| `app/repositories/users_repository.py` | modify | `UniqueViolation` → `UserAlreadyExists`, `get_user_credentials` |
| `app/redis_cache.py`, `app/repositories/auth_repository.py` | delete | заменены |
| `init_db.py` | rewrite | создание схемы, тестовые пользователи под флагом, код выхода |
| `docker-compose.yml`, `Makefile` | modify | `SEED_TEST_USERS`, пути тестов |
| `tests/conftest.py` | modify | `sys.path` + значения env по умолчанию |
| `tests/unit/conftest.py` | create | fakeredis, часы, подмена репозитория, `client`, `make_user` |
| `tests/unit/test_*.py` | create | unit- и API-тесты |
| `tests/integration/*` | move + rewrite | HTTP-тесты против живого сервиса |

---

### Task 1: Зависимости, проверка конфигурации, ленивый пул БД

**Files:**
- Modify: `requirements.txt`
- Modify: `config.py` (весь файл)
- Modify: `app/db.py` (весь файл)
- Modify: `tests/conftest.py:1-9`
- Test: `tests/unit/test_config.py`, `tests/unit/test_db.py`

**Interfaces:**
- Produces: `config.load_secret_key(env: Mapping[str, str]) -> str`, `config.parse_bool(value: str | None) -> bool`, `config.MIN_SECRET_KEY_LENGTH = 32`, `config.SECRET_KEY: str`, `config.JWT_ACCESS_TOKEN_EXPIRES: int`, `config.REDIS_HOST: str`, `config.REDIS_PORT: int`, `config.SEED_TEST_USERS: bool`; `app.db._connection_pool` (модульная переменная, `None` до первого вызова), `app.db.get_db_connection()`, `app.db.release_db_connection(conn)`.

- [x] **Step 1: Обновить зависимости и установить**

`requirements.txt` целиком. Строка `allure-pytest` уже есть в рабочей копии пользователя, она сохраняется:
```
allure-pytest
bcrypt
email-validator
fakeredis
flask
flask_restx
gunicorn
prometheus-flask-exporter
psycopg2-binary
pydantic
pyjwt
pytest
python-dotenv
redis
requests
```
Run: `.venv/bin/python -m pip install -r requirements.txt`
Expected: `Successfully installed ... fakeredis-...` (остальное уже стоит).

- [x] **Step 2: Значения env по умолчанию для тестов**

В `tests/conftest.py` заменить строки 1–9 (импорты и `sys.path`) на код ниже. Фикстуры ниже по файлу пока не трогать:
```python
import os
import sys

import pytest
import requests

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Defaults for running tests outside Docker; real environment variables take precedence.
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-0123")
os.environ.setdefault("AUTH_DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/authdb")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")

from config import BASE_URL, HEADERS  # noqa: E402
```

- [x] **Step 3: Написать падающие тесты**

`tests/unit/test_config.py`:
```python
import pytest

import config
from config import MIN_SECRET_KEY_LENGTH, load_secret_key, parse_bool


def test_missing_secret_key_fails_fast():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_secret_key({})


def test_short_secret_key_fails_fast():
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_secret_key({"SECRET_KEY": "x" * (MIN_SECRET_KEY_LENGTH - 1)})


def test_long_enough_secret_key_is_accepted():
    key = "x" * MIN_SECRET_KEY_LENGTH
    assert load_secret_key({"SECRET_KEY": key}) == key


@pytest.mark.parametrize("raw, expected", [
    (None, False), ("", False), ("false", False), ("0", False), ("no", False),
    ("true", True), ("TRUE", True), (" yes ", True), ("1", True), ("on", True),
])
def test_parse_bool(raw, expected):
    assert parse_bool(raw) is expected


def test_numeric_settings_are_ints():
    assert isinstance(config.JWT_ACCESS_TOKEN_EXPIRES, int)
    assert isinstance(config.REDIS_PORT, int)
```

`tests/unit/test_db.py`:
```python
import pytest

import app.db as db


class FakePool:
    created = 0

    def __init__(self, minconn, maxconn, dsn):
        FakePool.created += 1
        self.dsn = dsn

    def getconn(self):
        return "connection"

    def putconn(self, connection):
        pass

    def closeall(self):
        pass


@pytest.fixture
def fake_pool(monkeypatch):
    FakePool.created = 0
    monkeypatch.setattr(db, "_connection_pool", None)
    monkeypatch.setattr(db.psycopg2.pool, "SimpleConnectionPool", FakePool)
    return FakePool


def test_pool_is_created_lazily_and_only_once(fake_pool, monkeypatch):
    monkeypatch.setenv("AUTH_DATABASE_URL", "postgresql://u:p@db/authdb")
    assert fake_pool.created == 0

    assert db.get_db_connection() == "connection"
    assert db.get_db_connection() == "connection"

    assert fake_pool.created == 1


def test_missing_database_url_fails_on_first_use(fake_pool, monkeypatch):
    monkeypatch.delenv("AUTH_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="AUTH_DATABASE_URL"):
        db.get_db_connection()
```

- [x] **Step 4: Убедиться, что тесты падают**

Run: `.venv/bin/python -m pytest tests/unit/test_config.py tests/unit/test_db.py -q`
Expected: FAIL / ERROR — `ImportError: cannot import name 'MIN_SECRET_KEY_LENGTH'`, а импорт `app.db` падает на создании пула (нет БД).

- [x] **Step 5: Реализовать `config.py`**

```python
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
```

- [x] **Step 6: Реализовать ленивый пул в `app/db.py`**

```python
import os

import psycopg2
from psycopg2 import pool  # noqa: F401  (makes psycopg2.pool available)

from app.logger_config import setup_logger

logger = setup_logger("db_connection")

# Created on first use, so importing the app (e.g. in unit tests) needs no database.
_connection_pool = None


def _get_pool():
    global _connection_pool
    if _connection_pool is None:
        database_url = os.getenv("AUTH_DATABASE_URL")
        if database_url is None:
            logger.error("AUTH_DATABASE_URL is not set in the environment variables")
            raise ValueError("AUTH_DATABASE_URL is not set in the environment variables.")
        try:
            _connection_pool = psycopg2.pool.SimpleConnectionPool(1, 20, database_url)
            logger.info("Connection pool created successfully")
        except Exception as e:
            logger.error(f"Error creating connection pool: {str(e)}")
            raise
    return _connection_pool


def get_db_connection():
    """Get connection from pool"""
    try:
        connection = _get_pool().getconn()
        logger.info("Successfully connected to the database")
        return connection
    except Exception as e:
        logger.error(f"Error getting connection from pool: {str(e)}")
        raise


def release_db_connection(connection):
    """Return connection to pool"""
    try:
        if connection:
            _get_pool().putconn(connection)
            logger.info("Connection returned to pool")
    except Exception as e:
        logger.error(f"Error releasing connection: {str(e)}")


def close_all_connections():
    """Close all connections from pool"""
    try:
        if _connection_pool:
            _connection_pool.closeall()
            logger.info("All connections in the pool closed")
    except Exception as e:
        logger.error(f"Error closing all connections: {str(e)}")
```

- [x] **Step 7: Убедиться, что тесты проходят**

Run: `.venv/bin/python -m pytest tests/unit/test_config.py tests/unit/test_db.py -q`
Expected: PASS (14 passed).

Run: `.venv/bin/python -c "import sys; sys.path.insert(0,'.'); import os; os.environ.setdefault('SECRET_KEY','x'*32); from app import app; print('ok')"`
Expected: `ok` — приложение импортируется без БД.

- [x] **Step 8: Commit**

```bash
git add requirements.txt config.py app/db.py tests/conftest.py tests/unit/test_config.py tests/unit/test_db.py
git commit -m "fix: validate config at startup and create DB pool lazily

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- requirements.txt config.py app/db.py tests/conftest.py tests/unit/test_config.py tests/unit/test_db.py
```

---

### Task 2: Ошибки, валидация тела запроса, схемы

**Files:**
- Create: `app/errors.py`, `app/validation.py`
- Rewrite: `app/schemas/user_schemas.py`
- Modify: `app/hashing.py` (добавить константу)
- Test: `tests/unit/test_schemas.py`, `tests/unit/test_validation.py`, `tests/unit/test_error_handlers.py`

**Interfaces:**
- Consumes: ничего из предыдущих задач.
- Produces:
  - `app.errors`: `RequestValidationError(details: list[dict])` с атрибутом `.details`; `AuthError` (атрибут `status: str`) и подклассы `TokenMissing` (`"missing"`), `TokenInvalid` (`"invalid"`), `TokenExpired` (`"expired"`), `TokenRevoked` (`"revoked"`); `InvalidCredentials`, `Forbidden`, `UserNotFound`, `UserAlreadyExists`, `ServiceUnavailable`; `register_error_handlers(api) -> None`.
  - `app.validation.parse_body(model: type[ModelT]) -> ModelT`.
  - `app.schemas.user_schemas`: `UserRegister(username, email, password)`, `UserUpdate(email, password)`, `LoginRequest(username, password)`.
  - `app.hashing.BCRYPT_MAX_BYTES = 72`.

- [x] **Step 1: Написать падающие тесты схем**

`tests/unit/test_schemas.py`:
```python
import pytest
from pydantic import ValidationError

from app.schemas.user_schemas import LoginRequest, UserRegister, UserUpdate


def _error_fields(exc_info):
    return {".".join(str(p) for p in e["loc"]) for e in exc_info.value.errors()}


def test_register_accepts_valid_payload():
    user = UserRegister(username="alice", password="secret123", email="alice@example.com")
    assert user.email == "alice@example.com"


def test_register_email_is_optional():
    assert UserRegister(username="alice", password="secret123").email is None


def test_register_accepts_password_of_exactly_72_bytes():
    UserRegister(username="alice", password="я" * 36)  # 36 Cyrillic chars = 72 bytes


@pytest.mark.parametrize("payload, field", [
    ({"username": "al", "password": "secret123"}, "username"),
    ({"username": "a" * 51, "password": "secret123"}, "username"),
    ({"username": 123, "password": "secret123"}, "username"),
    ({"password": "secret123"}, "username"),
    ({"username": "alice"}, "password"),
    ({"username": "alice", "password": "12345"}, "password"),
    ({"username": "alice", "password": "я" * 37}, "password"),  # 74 bytes
    ({"username": "alice", "password": "secret123", "email": "not-an-email"}, "email"),
])
def test_register_rejects_invalid_payload(payload, field):
    with pytest.raises(ValidationError) as exc_info:
        UserRegister.model_validate(payload)
    assert field in _error_fields(exc_info)


def test_update_accepts_email_only():
    assert UserUpdate(email="new@example.com").password is None


def test_update_accepts_password_only():
    assert UserUpdate(password="newsecret1").email is None


def test_update_requires_at_least_one_field():
    with pytest.raises(ValidationError, match="At least one"):
        UserUpdate.model_validate({})


def test_update_rejects_all_null_fields():
    with pytest.raises(ValidationError, match="At least one"):
        UserUpdate.model_validate({"email": None, "password": None})


@pytest.mark.parametrize("payload", [{"password": "12345"}, {"password": "я" * 37}, {"email": "nope"}])
def test_update_rejects_invalid_fields(payload):
    with pytest.raises(ValidationError):
        UserUpdate.model_validate(payload)


@pytest.mark.parametrize("payload", [
    {},
    {"username": "alice"},
    {"username": "alice", "password": None},
    {"username": "", "password": "secret123"},
    {"username": "alice", "password": ""},
])
def test_login_requires_non_empty_strings(payload):
    with pytest.raises(ValidationError):
        LoginRequest.model_validate(payload)
```

- [x] **Step 2: Написать падающие тесты `parse_body`**

`tests/unit/test_validation.py`:
```python
import pytest
from flask import Flask

from app.errors import RequestValidationError
from app.schemas.user_schemas import LoginRequest, UserUpdate
from app.validation import parse_body

app = Flask(__name__)

NOT_AN_OBJECT = [{"field": "body", "msg": "Request body must be a JSON object"}]


def test_parse_body_returns_model():
    with app.test_request_context(method="POST", json={"username": "alice", "password": "pw"}):
        body = parse_body(LoginRequest)
    assert body.username == "alice"
    assert body.password == "pw"


@pytest.mark.parametrize("kwargs", [
    {"data": "username=alice", "content_type": "application/x-www-form-urlencoded"},
    {"data": "{broken", "content_type": "application/json"},
    {"json": ["alice", "pw"]},
    {"json": "alice"},
    {},
], ids=["form", "broken-json", "array", "string", "empty"])
def test_parse_body_rejects_non_object_body(kwargs):
    with app.test_request_context(method="POST", **kwargs):
        with pytest.raises(RequestValidationError) as exc_info:
            parse_body(LoginRequest)
    assert exc_info.value.details == NOT_AN_OBJECT


def test_parse_body_reports_field_errors():
    with app.test_request_context(method="POST", json={"username": "alice"}):
        with pytest.raises(RequestValidationError) as exc_info:
            parse_body(LoginRequest)
    assert exc_info.value.details == [{"field": "password", "msg": "Field required"}]


def test_parse_body_reports_model_level_errors_as_body():
    with app.test_request_context(method="POST", json={}):
        with pytest.raises(RequestValidationError) as exc_info:
            parse_body(UserUpdate)
    assert [d["field"] for d in exc_info.value.details] == ["body"]
```

- [x] **Step 3: Написать падающие тесты обработчика ошибок**

`tests/unit/test_error_handlers.py`:
```python
import pytest
from flask import Flask
from flask_restx import Api, Resource
from werkzeug.exceptions import NotFound

from app.errors import (
    Forbidden, InvalidCredentials, RequestValidationError, ServiceUnavailable,
    TokenExpired, TokenInvalid, TokenMissing, TokenRevoked, UserAlreadyExists,
    UserNotFound, register_error_handlers,
)


def _client_raising(exc):
    app = Flask(__name__)
    app.config["TESTING"] = True
    api = Api(app)
    register_error_handlers(api)

    @api.route("/boom")
    class Boom(Resource):
        def get(self):
            raise exc

    return app.test_client()


@pytest.mark.parametrize("exc, status, body", [
    (RequestValidationError([{"field": "x", "msg": "bad"}]), 400,
     {"message": "Validation failed", "errors": [{"field": "x", "msg": "bad"}]}),
    (TokenMissing(), 401, {"message": "Unauthorized", "status": "missing"}),
    (TokenInvalid(), 401, {"message": "Unauthorized", "status": "invalid"}),
    (TokenExpired(), 401, {"message": "Unauthorized", "status": "expired"}),
    (TokenRevoked(), 401, {"message": "Unauthorized", "status": "revoked"}),
    (InvalidCredentials(), 401, {"message": "Invalid credentials"}),
    (Forbidden(), 403, {"message": "Forbidden"}),
    (UserNotFound(), 404, {"message": "User not found"}),
    (UserAlreadyExists(), 409, {"message": "Username already taken"}),
    (ServiceUnavailable(), 503, {"message": "Service temporarily unavailable"}),
    (RuntimeError("db password is hunter2"), 500, {"message": "Internal server error"}),
], ids=lambda v: type(v).__name__ if isinstance(v, Exception) else None)
def test_exception_maps_to_response(exc, status, body):
    resp = _client_raising(exc).get("/boom")
    assert resp.status_code == status
    assert resp.json == body


def test_http_exceptions_keep_their_status():
    resp = _client_raising(NotFound()).get("/boom")
    assert resp.status_code == 404
```

- [x] **Step 4: Убедиться, что тесты падают**

Run: `.venv/bin/python -m pytest tests/unit/test_schemas.py tests/unit/test_validation.py tests/unit/test_error_handlers.py -q`
Expected: ERROR при коллекции — `ModuleNotFoundError: No module named 'app.errors'` / `ImportError: cannot import name 'LoginRequest'`.

- [x] **Step 5: Добавить константу в `app/hashing.py`**

После строки `from app.performance_monitor import log_duration, async_log_duration` вставить:
```python

# bcrypt only looks at the first 72 bytes of a password; bcrypt >= 5 raises on longer input.
BCRYPT_MAX_BYTES = 72
```

- [x] **Step 6: Создать `app/errors.py`**

```python
"""Domain exceptions and the single place that turns them into HTTP responses."""
from werkzeug.exceptions import HTTPException


class RequestValidationError(Exception):
    """Request body is not a JSON object or does not match the schema."""

    def __init__(self, details: list[dict]):
        super().__init__("Validation failed")
        self.details = details


class AuthError(Exception):
    """Bearer token is missing or unusable; `status` goes to the response body."""
    status = "invalid"


class TokenMissing(AuthError):
    status = "missing"


class TokenInvalid(AuthError):
    status = "invalid"


class TokenExpired(AuthError):
    status = "expired"


class TokenRevoked(AuthError):
    status = "revoked"


class InvalidCredentials(Exception):
    """Wrong username or password."""


class Forbidden(Exception):
    """Authenticated, but not allowed to touch this resource."""


class UserNotFound(Exception):
    pass


class UserAlreadyExists(Exception):
    pass


class ServiceUnavailable(Exception):
    """A dependency (Redis) is unreachable; the client may retry."""


def register_error_handlers(api) -> None:
    """Register handlers on a flask-restx Api. The first matching handler wins, so Exception goes last."""

    @api.errorhandler(RequestValidationError)
    def handle_validation_error(e):
        return {"message": "Validation failed", "errors": e.details}, 400

    @api.errorhandler(AuthError)
    def handle_auth_error(e):
        return {"message": "Unauthorized", "status": e.status}, 401

    @api.errorhandler(InvalidCredentials)
    def handle_invalid_credentials(e):
        return {"message": "Invalid credentials"}, 401

    @api.errorhandler(Forbidden)
    def handle_forbidden(e):
        return {"message": "Forbidden"}, 403

    @api.errorhandler(UserNotFound)
    def handle_user_not_found(e):
        return {"message": "User not found"}, 404

    @api.errorhandler(UserAlreadyExists)
    def handle_user_already_exists(e):
        return {"message": "Username already taken"}, 409

    @api.errorhandler(ServiceUnavailable)
    def handle_service_unavailable(e):
        return {"message": "Service temporarily unavailable"}, 503

    @api.errorhandler(Exception)
    def handle_unexpected_error(e):
        if isinstance(e, HTTPException):
            return {"message": e.description}, e.code
        # flask-restx logs the traceback for 5xx responses; the client gets no details.
        return {"message": "Internal server error"}, 500
```

- [x] **Step 7: Создать `app/validation.py`**

```python
from typing import TypeVar

from flask import request
from pydantic import BaseModel, ValidationError

from app.errors import RequestValidationError

ModelT = TypeVar("ModelT", bound=BaseModel)


def parse_body(model: type[ModelT]) -> ModelT:
    """Validate the JSON request body against a pydantic model."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise RequestValidationError([{"field": "body", "msg": "Request body must be a JSON object"}])
    try:
        return model.model_validate(data)
    except ValidationError as e:
        details = [
            {"field": ".".join(str(part) for part in err["loc"]) or "body", "msg": err["msg"]}
            for err in e.errors()
        ]
        raise RequestValidationError(details) from e
```

- [x] **Step 8: Переписать `app/schemas/user_schemas.py`**

```python
from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, model_validator

from app.hashing import BCRYPT_MAX_BYTES


def _check_password_bytes(password: str) -> str:
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError(f"Password must be at most {BCRYPT_MAX_BYTES} bytes in UTF-8")
    return password


# At least 6 characters; at most 72 bytes because bcrypt ignores everything after that.
Password = Annotated[str, Field(min_length=6), AfterValidator(_check_password_bytes)]


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr | None = None
    password: Password


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    password: Password | None = None

    @model_validator(mode="after")
    def check_not_empty(self):
        if self.email is None and self.password is None:
            raise ValueError("At least one of 'email' or 'password' must be provided")
        return self


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
```

- [x] **Step 9: Убедиться, что тесты проходят**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: PASS, все тесты Task 1 и Task 2 зелёные.

- [x] **Step 10: Commit**

```bash
git add app/errors.py app/validation.py app/schemas/user_schemas.py app/hashing.py tests/unit/test_schemas.py tests/unit/test_validation.py tests/unit/test_error_handlers.py
git commit -m "feat: add domain errors, request validation and unified error handler

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- app/errors.py app/validation.py app/schemas/user_schemas.py app/hashing.py tests/unit/test_schemas.py tests/unit/test_validation.py tests/unit/test_error_handlers.py
```

---

### Task 3: Модуль токенов с отзывом через Redis

**Files:**
- Create: `app/tokens.py`
- Create: `tests/unit/conftest.py`
- Test: `tests/unit/test_tokens.py`

`app/redis_cache.py` в этой задаче **не** удаляется: им ещё пользуется старый `auth_controller` (удаление — в Task 4).

**Interfaces:**
- Consumes: `config.SECRET_KEY`, `config.JWT_ACCESS_TOKEN_EXPIRES`, `config.REDIS_HOST`, `config.REDIS_PORT` (Task 1); `TokenExpired`, `TokenInvalid`, `TokenRevoked`, `ServiceUnavailable` (Task 2).
- Produces:
  - `app.tokens.redis_client` — модульная переменная (тесты её подменяют);
  - `app.tokens._now() -> int` — текущее время в секундах (тесты подменяют);
  - `app.tokens.issue_token(user_id: int, username: str) -> str`;
  - `app.tokens.decode_token(token: str) -> dict` — claims (`sub` — строка); бросает `TokenExpired | TokenInvalid | TokenRevoked | ServiceUnavailable`;
  - `app.tokens.revoke_token(claims: dict) -> None`; `app.tokens.revoke_all_for_user(user_id: int) -> None` — оба бросают `ServiceUnavailable`.
  - Фикстуры в `tests/unit/conftest.py`: `redis_server`, `fake_redis`, `break_redis` (вызов `break_redis()` или `break_redis(writes_only=True)`), `clock` (`.now: int`, `.advance(seconds)`), `forge_token(key=None, **overrides) -> str`.

- [x] **Step 1: Создать `tests/unit/conftest.py` с фикстурами**

```python
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
```

- [x] **Step 2: Написать падающие тесты**

`tests/unit/test_tokens.py`:
```python
import pytest

import config
from app import tokens
from app.errors import ServiceUnavailable, TokenExpired, TokenInvalid, TokenRevoked

OTHER_KEY = "another-secret-key-that-is-long-enough-42"


def test_issued_token_round_trips(fake_redis, clock):
    claims = tokens.decode_token(tokens.issue_token(42, "alice"))

    assert claims["sub"] == "42"
    assert claims["username"] == "alice"
    assert claims["iat"] == clock.now
    assert claims["exp"] == clock.now + config.JWT_ACCESS_TOKEN_EXPIRES
    assert len(claims["jti"]) == 32


def test_each_token_gets_its_own_jti(fake_redis, clock):
    first = tokens.decode_token(tokens.issue_token(1, "alice"))
    second = tokens.decode_token(tokens.issue_token(1, "alice"))
    assert first["jti"] != second["jti"]


def test_expired_token_is_rejected(fake_redis, clock):
    clock.now -= config.JWT_ACCESS_TOKEN_EXPIRES + 10
    token = tokens.issue_token(1, "alice")

    with pytest.raises(TokenExpired):
        tokens.decode_token(token)


@pytest.mark.parametrize("overrides", [
    {"key": OTHER_KEY},
    {"jti": None},
    {"username": None},
    {"sub": None},
    {"sub": "abc"},
], ids=["foreign-signature", "no-jti", "no-username", "no-sub", "non-numeric-sub"])
def test_invalid_tokens_are_rejected(fake_redis, forge_token, overrides):
    with pytest.raises(TokenInvalid):
        tokens.decode_token(forge_token(**overrides))


def test_garbage_is_rejected(fake_redis):
    with pytest.raises(TokenInvalid):
        tokens.decode_token("not-a-jwt")


def test_revoked_token_is_rejected(fake_redis, clock):
    token = tokens.issue_token(1, "alice")
    tokens.revoke_token(tokens.decode_token(token))

    with pytest.raises(TokenRevoked):
        tokens.decode_token(token)


def test_revoking_one_token_keeps_the_others(fake_redis, clock):
    first = tokens.issue_token(1, "alice")
    second = tokens.issue_token(1, "alice")
    tokens.revoke_token(tokens.decode_token(first))

    assert tokens.decode_token(second)["sub"] == "1"


def test_revocation_key_lives_only_as_long_as_the_token(fake_redis, clock):
    claims = tokens.decode_token(tokens.issue_token(1, "alice"))
    clock.advance(100)
    tokens.revoke_token(claims)

    ttl = fake_redis.ttl(f"revoked:{claims['jti']}")
    assert 0 < ttl <= config.JWT_ACCESS_TOKEN_EXPIRES - 100


def test_revoke_all_rejects_tokens_issued_earlier(fake_redis, clock):
    old = tokens.issue_token(1, "alice")
    clock.advance(5)
    tokens.revoke_all_for_user(1)

    with pytest.raises(TokenRevoked):
        tokens.decode_token(old)


def test_revoke_all_keeps_tokens_issued_in_the_same_second(fake_redis, clock):
    tokens.revoke_all_for_user(1)
    fresh = tokens.issue_token(1, "alice")

    assert tokens.decode_token(fresh)["sub"] == "1"


def test_revoke_all_affects_only_that_user(fake_redis, clock):
    bob = tokens.issue_token(2, "bob")
    clock.advance(5)
    tokens.revoke_all_for_user(1)

    assert tokens.decode_token(bob)["sub"] == "2"


def test_revoke_all_key_lives_as_long_as_a_token(fake_redis, clock):
    tokens.revoke_all_for_user(1)
    assert 0 < fake_redis.ttl("valid_after:1") <= config.JWT_ACCESS_TOKEN_EXPIRES


def test_decode_fails_closed_when_redis_is_down(clock, break_redis):
    token = tokens.issue_token(1, "alice")
    break_redis()

    with pytest.raises(ServiceUnavailable):
        tokens.decode_token(token)


def test_revocations_report_redis_outage(clock, break_redis):
    break_redis()
    with pytest.raises(ServiceUnavailable):
        tokens.revoke_token({"jti": "f" * 32, "exp": clock.now + 600})
    with pytest.raises(ServiceUnavailable):
        tokens.revoke_all_for_user(1)
```

- [x] **Step 3: Убедиться, что тесты падают**

Run: `.venv/bin/python -m pytest tests/unit/test_tokens.py -q`
Expected: ERROR — `ImportError: cannot import name 'tokens' from 'app'`.

- [x] **Step 4: Реализовать `app/tokens.py`**

```python
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
```

- [x] **Step 5: Убедиться, что тесты проходят**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: PASS, все тесты зелёные.

- [x] **Step 6: Commit**

```bash
git add app/tokens.py tests/unit/conftest.py tests/unit/test_tokens.py
git commit -m "feat: add JWT tokens module with Redis-backed revocation

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- app/tokens.py tests/unit/conftest.py tests/unit/test_tokens.py
```

---

### Task 4: Эндпоинты авторизации (login / validate / logout)

**Files:**
- Create: `app/auth_guard.py`
- Rewrite: `app/controllers/auth_controller.py`
- Modify: `app/hashing.py` (`DUMMY_HASH`, `check_password`)
- Modify: `app/repositories/users_repository.py` (добавить `get_user_credentials`)
- Delete: `app/redis_cache.py`, `app/repositories/auth_repository.py`
- Modify: `tests/unit/conftest.py` (добавить репозиторий, `client`, `make_user`)
- Test: `tests/unit/test_hashing.py`, `tests/unit/test_auth_api.py`

**Interfaces:**
- Consumes: `decode_token`, `issue_token`, `revoke_token` (Task 3); `parse_body`, `LoginRequest`, `InvalidCredentials`, `TokenMissing`, `TokenInvalid`, `Forbidden`, `register_error_handlers` (Task 2); фикстуры `fake_redis`, `clock`, `forge_token`, `break_redis` (Task 3).
- Produces:
  - `app.auth_guard.require_auth` (декоратор; ставит `g.current_user = {"id": int, "username": str}` и `g.token_claims: dict`), `app.auth_guard.ensure_owner(user_id: int) -> None` (бросает `Forbidden`);
  - `app.hashing.DUMMY_HASH: str`, `app.hashing.check_password(password: str, hashed_password: str) -> bool` (не бросает на паролях длиннее 72 байт);
  - `app.repositories.users_repository.get_user_credentials(username: str) -> dict | None` (`{id, username, hashed_password}`);
  - `app.controllers.auth_controller.auth_api` (с зарегистрированными обработчиками ошибок);
  - фикстуры: `repo` (экземпляр `FakeUserRepo`, атрибут `.users: dict[int, dict]`), `client`, `make_user(username="alice", password="secret123", email=None) -> {"id","username","password","token","headers"}`.

- [ ] **Step 1: Дописать фикстуры в `tests/unit/conftest.py`**

Добавить к импортам в начале файла:
```python
import datetime

import bcrypt

from app import app as flask_app
from app.controllers import auth_controller
from app.errors import UserAlreadyExists
from app.services import user_service
```
Добавить в конец файла:
```python
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
```

- [ ] **Step 2: Написать падающие тесты хэширования**

`tests/unit/test_hashing.py`:
```python
import bcrypt

from app.hashing import DUMMY_HASH, check_password


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("utf-8")


def test_check_password_accepts_correct_password():
    assert check_password("secret123", _hash("secret123")) is True


def test_check_password_rejects_wrong_password():
    assert check_password("wrong", _hash("secret123")) is False


def test_password_longer_than_72_bytes_is_rejected_not_raised():
    # bcrypt < 5 silently truncates to 72 bytes (so this would match), bcrypt >= 5 raises ValueError.
    assert check_password("a" * 73, _hash("a" * 72)) is False


def test_dummy_hash_is_a_full_cost_bcrypt_hash():
    assert DUMMY_HASH.startswith("$2b$12$")
    assert check_password("secret123", DUMMY_HASH) is False
```

- [ ] **Step 3: Написать падающие API-тесты авторизации**

`tests/unit/test_auth_api.py`:
```python
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
```

- [ ] **Step 4: Убедиться, что тесты падают**

Run: `.venv/bin/python -m pytest tests/unit/test_hashing.py tests/unit/test_auth_api.py -q`
Expected: FAIL / ERROR — `ImportError: cannot import name 'DUMMY_HASH'`; после его появления — падения API-тестов (`AttributeError: module ... has no attribute 'get_user_credentials'` в фикстуре `repo`, 403 вместо 401, 500 на кривом теле и т. п.).

- [ ] **Step 5: Обновить `app/hashing.py`**

Заменить функцию `check_password` и добавить `DUMMY_HASH` в конец файла:
```python
@log_duration
def check_password(password: str, hashed_password: str) -> bool:
    """Compare password with a hashed value"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > BCRYPT_MAX_BYTES:
        # Registration never accepts such passwords, and bcrypt >= 5 would raise ValueError.
        return False
    return bcrypt.checkpw(password_bytes, hashed_password.encode('utf-8'))


# Hash of a throwaway password: logins for unknown usernames are checked against it,
# so they take as long as logins for existing ones.
DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing-equalization", bcrypt.gensalt()).decode('utf-8')
```

- [ ] **Step 6: Добавить `get_user_credentials` в `app/repositories/users_repository.py`**

Вставить после `get_user_by_id`:
```python
@log_duration
def get_user_credentials(username: str):
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cursor.execute("SELECT id, username, hashed_password FROM users WHERE username = %s", (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        release_db_connection(connection)
```

- [ ] **Step 7: Создать `app/auth_guard.py`**

```python
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
```

- [ ] **Step 8: Переписать `app/controllers/auth_controller.py`**

```python
# app/auth_controller.py
from flask import Blueprint, g
from flask_restx import Api, Namespace, Resource, fields

from app.auth_guard import require_auth
from app.errors import InvalidCredentials, register_error_handlers
from app.hashing import DUMMY_HASH, check_password
from app.logger_config import setup_logger
from app.repositories.users_repository import get_user_credentials
from app.schemas.user_schemas import LoginRequest
from app.tokens import issue_token, revoke_token
from app.validation import parse_body

logger = setup_logger("auth_controller")

# Create auth Blueprint

auth_bp = Blueprint('auth_bp', __name__)
authorizations = {
    "Bearer": {"type": "apiKey", "in": "header", "name": "Authorization", "description": "Bearer <token>"}
}
auth_api = Api(
    auth_bp,
    title='Auth API',
    description='API for authentication',
    authorizations=authorizations,
    security="Bearer",
)
register_error_handlers(auth_api)

# Create namespace

auth_ns = Namespace('auth', description="Operations related to authentication")
auth_api.add_namespace(auth_ns)

# Define models for Swagger Documentation
login_model = auth_api.model('Login', {
    'username': fields.String(required=True, description='Username of the user'),
    'password': fields.String(required=True, description='Password of the user')
})


# /login route description
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Success')
    @auth_ns.response(400, 'Invalid request body')
    @auth_ns.response(401, 'Invalid credentials')
    def post(self):
        """Log in and get an access token"""
        body = parse_body(LoginRequest)
        user = get_user_credentials(body.username)
        # Unknown usernames are checked against a dummy hash so that the response
        # time does not reveal whether the username exists.
        hashed_password = user["hashed_password"] if user else DUMMY_HASH
        password_ok = check_password(body.password, hashed_password)
        if user is None or not password_ok:
            logger.warning(f"Invalid credentials for username '{body.username}'")
            raise InvalidCredentials()
        return {"token": issue_token(user["id"], user["username"])}, 200


# /validate route description
@auth_ns.route('/validate')
class Validate(Resource):
    @auth_ns.response(200, 'Token is valid')
    @auth_ns.response(401, 'Token is missing, invalid, expired or revoked')
    @auth_ns.response(503, 'Token store is unavailable')
    @require_auth
    def get(self):
        """Token validation endpoint"""
        return {
            "status": "valid",
            "user": g.current_user["username"],
            "user_id": g.current_user["id"],
        }, 200


# /logout route description
@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.response(204, 'Token revoked')
    @auth_ns.response(401, 'Token is missing, invalid, expired or revoked')
    @auth_ns.response(503, 'Token store is unavailable')
    @require_auth
    def post(self):
        """Revoke the current token"""
        revoke_token(g.token_claims)
        return "", 204
```

- [ ] **Step 9: Удалить заменённые модули**

Run: `git rm -q app/redis_cache.py app/repositories/auth_repository.py && grep -rn "redis_cache\|auth_repository" app tests init_db.py`
Expected: grep ничего не находит (exit code 1).

- [ ] **Step 10: Убедиться, что тесты проходят**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: PASS, все тесты зелёные.

- [ ] **Step 11: Commit**

```bash
git add app/auth_guard.py app/controllers/auth_controller.py app/hashing.py app/repositories/users_repository.py tests/unit/conftest.py tests/unit/test_hashing.py tests/unit/test_auth_api.py
git commit -m "feat: token-based login, validate and logout with revocation

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- app/auth_guard.py app/controllers/auth_controller.py app/hashing.py app/repositories/users_repository.py app/redis_cache.py app/repositories/auth_repository.py tests/unit/conftest.py tests/unit/test_hashing.py tests/unit/test_auth_api.py
```

---

### Task 5: Эндпоинты пользователей с проверкой владельца

**Files:**
- Modify: `app/repositories/users_repository.py` (`create_user`: `UniqueViolation` → `UserAlreadyExists`)
- Rewrite: `app/services/user_service.py`, `app/controllers/users_controller.py`
- Test: `tests/unit/test_users_repository.py`, `tests/unit/test_users_api.py`

**Interfaces:**
- Consumes: `require_auth`, `ensure_owner` (Task 4); `revoke_all_for_user` (Task 3); `parse_body`, `UserRegister`, `UserUpdate`, `UserNotFound`, `UserAlreadyExists` (Task 2); фикстуры `client`, `make_user`, `repo`, `clock`, `break_redis` (Tasks 3–4).
- Produces: `user_service.register_user(data: UserRegister) -> dict`, `get_user_profile(user_id: int) -> dict`, `get_users_list(limit=50, offset=0) -> dict`, `update_user_profile(user_id: int, data: UserUpdate) -> dict`, `remove_user(user_id: int) -> None`; эндпоинт `GET /users/me`.

- [ ] **Step 1: Написать падающий тест репозитория**

`tests/unit/test_users_repository.py`:
```python
import psycopg2.errors
import pytest

from app.errors import UserAlreadyExists
from app.repositories import users_repository


class FailingCursor:
    def __init__(self, error):
        self.error = error

    def execute(self, sql, params=None):
        raise self.error

    def close(self):
        pass


class FakeConnection:
    def __init__(self, error):
        self.error = error
        self.rolled_back = False

    def cursor(self, cursor_factory=None):
        return FailingCursor(self.error)

    def rollback(self):
        self.rolled_back = True

    def commit(self):
        raise AssertionError("must not commit after a failed INSERT")


@pytest.fixture
def connection_failing_with(monkeypatch):
    def _make(error):
        connection = FakeConnection(error)
        monkeypatch.setattr(users_repository, "get_db_connection", lambda: connection)
        monkeypatch.setattr(users_repository, "release_db_connection", lambda c: None)
        return connection
    return _make


def test_duplicate_username_raises_domain_error(connection_failing_with):
    connection = connection_failing_with(psycopg2.errors.UniqueViolation("duplicate key value"))

    with pytest.raises(UserAlreadyExists):
        users_repository.create_user("alice", "hash")
    assert connection.rolled_back


def test_other_database_errors_propagate_unchanged(connection_failing_with):
    connection_failing_with(RuntimeError("connection lost"))

    with pytest.raises(RuntimeError, match="connection lost"):
        users_repository.create_user("alice", "hash")
```

- [ ] **Step 2: Написать падающие API-тесты пользователей**

`tests/unit/test_users_api.py`:
```python
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


def test_own_user_missing_from_db_returns_404(client, make_user, repo):
    user = make_user()
    repo.users.pop(user["id"])

    resp = client.get("/users/me", headers=user["headers"])

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
```

- [ ] **Step 3: Убедиться, что тесты падают**

Run: `.venv/bin/python -m pytest tests/unit/test_users_repository.py tests/unit/test_users_api.py -q`
Expected: FAIL — `UniqueViolation` вместо `UserAlreadyExists`; 200 вместо 401/403 на чужих и неавторизованных запросах; 404 на `/users/me`; 400 вместо 409.

- [ ] **Step 4: Обработать `UniqueViolation` в `create_user`**

В `app/repositories/users_repository.py` добавить импорты:
```python
from psycopg2 import errors as pg_errors

from app.errors import UserAlreadyExists
```
В `create_user` вставить перед `except Exception as e:`:
```python
    except pg_errors.UniqueViolation as e:
        connection.rollback()
        logger.warning(f"Username already taken: {username}")
        raise UserAlreadyExists() from e
```

- [ ] **Step 5: Переписать `app/services/user_service.py`**

```python
from app.errors import UserNotFound
from app.hashing import hash_password
from app.logger_config import setup_logger
from app.repositories.users_repository import (
    create_user, get_user_by_id, get_all_users,
    update_user, delete_user
)
from app.schemas.user_schemas import UserRegister, UserUpdate
from app.tokens import revoke_all_for_user

logger = setup_logger("user_service")


def register_user(data: UserRegister) -> dict:
    """Регистрация нового пользователя"""
    user = create_user(
        username=data.username,
        hashed_password=hash_password(data.password),
        email=data.email
    )
    logger.info(f"User registered successfully: {data.username}")
    return user


def get_user_profile(user_id: int) -> dict:
    """Получить профиль пользователя"""
    user = get_user_by_id(user_id)
    if not user:
        raise UserNotFound()
    return user


def get_users_list(limit: int = 50, offset: int = 0) -> dict:
    """Получить список пользователей"""
    return get_all_users(limit=limit, offset=offset)


def update_user_profile(user_id: int, data: UserUpdate) -> dict:
    """Обновление профиля; смена пароля отзывает все токены пользователя"""
    hashed_password = hash_password(data.password) if data.password is not None else None
    user = update_user(user_id=user_id, email=data.email, hashed_password=hashed_password)
    if not user:
        raise UserNotFound()
    if hashed_password is not None:
        # After the DB write: if Redis is down the client gets 503 and can safely retry.
        revoke_all_for_user(user_id)
    return user


def remove_user(user_id: int) -> None:
    """Удаление пользователя; токены отзываются до удаления"""
    # Revoke first: if Redis is down, the user is not deleted and no live tokens are left behind.
    revoke_all_for_user(user_id)
    if not delete_user(user_id):
        raise UserNotFound()
```

- [ ] **Step 6: Переписать `app/controllers/users_controller.py`**

```python
from flask import Blueprint, g
from flask_restx import Resource, fields, Namespace

from app.auth_guard import ensure_owner, require_auth
from app.controllers.auth_controller import auth_api
from app.logger_config import setup_logger
from app.schemas.user_schemas import UserRegister, UserUpdate
from app.services.user_service import (
    register_user, get_user_profile, get_users_list,
    update_user_profile, remove_user
)
from app.validation import parse_body

logger = setup_logger("users_controller")

# ================== Blueprint ==================
users_bp = Blueprint('users_bp', __name__)

# Используем тот же Api, что и в auth_controller
users_api = auth_api

users_ns = Namespace('users', description="Operations with users")
users_api.add_namespace(users_ns)

# ================== Swagger Models ==================
register_model = users_api.model('UserRegister', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password'),
    'email': fields.String(required=False, description='Email')
})

update_model = users_api.model('UserUpdate', {
    'email': fields.String(required=False, description='New email'),
    'password': fields.String(required=False, description='New password')
})


def _serialize(user: dict) -> dict:
    """Make a user row JSON-friendly (created_at → ISO 8601)."""
    data = dict(user)
    if data.get('created_at') is not None:
        data['created_at'] = data['created_at'].isoformat()
    return data


# ================== Routes ==================

@users_ns.route('/register')
class Register(Resource):
    @users_ns.expect(register_model)
    def post(self):
        """Register new user"""
        user = register_user(parse_body(UserRegister))
        return {"message": "User registered successfully", "user_id": user['id']}, 201


@users_ns.route('/me')
class Me(Resource):
    @require_auth
    def get(self):
        """Get the profile of the token owner"""
        return _serialize(get_user_profile(g.current_user['id'])), 200


@users_ns.route('/users')
class UsersList(Resource):
    @require_auth
    def get(self):
        """Get all users"""
        result = get_users_list(limit=50)
        return {"users": [_serialize(user) for user in result['users']], "total": result['total']}, 200


@users_ns.route('/users/<int:user_id>')
class UserDetail(Resource):
    @require_auth
    def get(self, user_id):
        """Get own user by ID"""
        ensure_owner(user_id)
        return _serialize(get_user_profile(user_id)), 200

    @users_ns.expect(update_model)
    @require_auth
    def put(self, user_id):
        """Update own user; a password change revokes all tokens"""
        ensure_owner(user_id)
        return _serialize(update_user_profile(user_id, parse_body(UserUpdate))), 200

    @require_auth
    def delete(self, user_id):
        """Delete own user and revoke all tokens"""
        ensure_owner(user_id)
        remove_user(user_id)
        return {"message": "User deleted successfully"}, 200
```

- [ ] **Step 7: Убедиться, что тесты проходят**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: PASS, все тесты зелёные.

Run: `grep -n "str(e)" app/controllers/*.py`
Expected: ничего (exit code 1).

- [ ] **Step 8: Commit**

```bash
git add app/repositories/users_repository.py app/services/user_service.py app/controllers/users_controller.py tests/unit/test_users_repository.py tests/unit/test_users_api.py
git commit -m "fix: require token owner for user endpoints, add /users/me

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- app/repositories/users_repository.py app/services/user_service.py app/controllers/users_controller.py tests/unit/test_users_repository.py tests/unit/test_users_api.py
```

---

### Task 6: Тестовые пользователи под флагом, сбой инициализации останавливает старт

**Files:**
- Rewrite: `init_db.py`
- Modify: `docker-compose.yml` (секция `auth-service.environment`)
- Test: `tests/unit/test_init_db.py`

**Interfaces:**
- Consumes: `config.SEED_TEST_USERS` (Task 1), `app.db.get_db_connection` / `release_db_connection`.
- Produces: `init_db.initialize_database(seed_test_users: bool) -> None`, `init_db.main() -> int` (0 — успех, 1 — ошибка).

- [ ] **Step 1: Написать падающие тесты**

`tests/unit/test_init_db.py`:
```python
import pytest

import init_db


class FakeCursor:
    def __init__(self, fail: bool):
        self.fail = fail
        self.executed: list[str] = []

    def execute(self, sql, params=None):
        if self.fail:
            raise RuntimeError("permission denied for schema public")
        self.executed.append(" ".join(sql.split()))

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeConnection:
    def __init__(self, fail: bool):
        self.cursor_obj = FakeCursor(fail)
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


@pytest.fixture
def connection(monkeypatch):
    def _make(fail: bool = False) -> FakeConnection:
        conn = FakeConnection(fail)
        monkeypatch.setattr(init_db, "get_db_connection", lambda: conn)
        monkeypatch.setattr(init_db, "release_db_connection", lambda c: None)
        return conn
    return _make


def _inserts(conn):
    return [sql for sql in conn.cursor_obj.executed if sql.startswith("INSERT")]


def test_without_seed_flag_only_creates_schema(connection):
    conn = connection()
    init_db.initialize_database(seed_test_users=False)

    assert conn.cursor_obj.executed[0].startswith("CREATE TABLE IF NOT EXISTS users")
    assert _inserts(conn) == []
    assert conn.committed


def test_with_seed_flag_creates_both_test_users(connection):
    conn = connection()
    init_db.initialize_database(seed_test_users=True)

    assert len(_inserts(conn)) == 2
    assert conn.committed


def test_main_reads_seed_flag_from_config(connection, monkeypatch):
    conn = connection()
    monkeypatch.setattr(init_db, "SEED_TEST_USERS", False)

    assert init_db.main() == 0
    assert _inserts(conn) == []


def test_main_returns_error_code_when_schema_creation_fails(connection):
    conn = connection(fail=True)

    assert init_db.main() == 1
    assert conn.rolled_back
    assert not conn.committed
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `.venv/bin/python -m pytest tests/unit/test_init_db.py -q`
Expected: FAIL — `AttributeError: module 'init_db' has no attribute 'initialize_database'`.

- [ ] **Step 3: Переписать `init_db.py`**

```python
import sys

import bcrypt

from app.db import get_db_connection, release_db_connection
from app.logger_config import setup_logger
from config import SEED_TEST_USERS

logger = setup_logger("init_db")

CREATE_USERS_TABLE = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        email VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

# Well-known credentials for local development and autotests only (SEED_TEST_USERS=true).
TEST_USERS = [
    ("test", "test", "test@example.com"),
    ("valid_user", "correct_pass", "valid_user@example.com"),
]


def _seed_test_users(cursor) -> None:
    for username, password, email in TEST_USERS:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        cursor.execute(
            "INSERT INTO users (username, hashed_password, email) VALUES (%s, %s, %s)",
            (username, hashed, email),
        )
        logger.info(f"✅ Test user '{username}' created")


def initialize_database(seed_test_users: bool) -> None:
    """Create the schema and, only when asked, the test users."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(CREATE_USERS_TABLE)
            if seed_test_users:
                _seed_test_users(cursor)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        release_db_connection(connection)


def main() -> int:
    try:
        initialize_database(SEED_TEST_USERS)
    except Exception:
        logger.exception("❌ Database initialization failed")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Включить тестовых пользователей в compose для dev**

В `docker-compose.yml`, секция `auth-service.environment`, после строки `ENV: docker` добавить:
```yaml
      SEED_TEST_USERS: "true"
```

- [ ] **Step 5: Убедиться, что тесты проходят**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: PASS, все тесты зелёные.

- [ ] **Step 6: Commit**

```bash
git add init_db.py docker-compose.yml tests/unit/test_init_db.py
git commit -m "fix: seed test users only behind SEED_TEST_USERS, fail start on DB init error

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- init_db.py docker-compose.yml tests/unit/test_init_db.py
```

---

### Task 7: Интеграционные тесты под новый контракт

**Files:**
- Move: `tests/test_users_positive_cases.py` → `tests/integration/test_users_positive_cases.py` (rewrite)
- Move: `tests/test_users_negative_cases.py` → `tests/integration/test_users_negative_cases.py` (rewrite)
- Move: `tests/test_auth_service.py` → `tests/integration/test_auth_integration.py` (rewrite)
- Create: `tests/integration/conftest.py`
- Modify: `tests/conftest.py` (убрать фикстуры, переехавшие в integration)
- Modify: `Makefile` (пути тестов, `test-unit`)

**Interfaces:**
- Consumes: живой сервис на `config.BASE_URL` с `SEED_TEST_USERS=true` (Task 6) и весь контракт из Tasks 4–5.
- Produces: фикстуры `unique_username`, `login(username, password) -> str`, `user_factory() -> {"id","username","password","token","headers"}` (с автоочисткой), `test_user`.

Имена файлов не должны совпадать с unit-тестами (`test_auth_api.py`, `test_users_api.py`): в каталогах нет `__init__.py`, и одинаковые имена модулей ломают коллекцию pytest.

- [ ] **Step 1: Перенести файлы**

```bash
mkdir -p tests/integration
git mv tests/test_users_positive_cases.py tests/integration/test_users_positive_cases.py
git mv tests/test_users_negative_cases.py tests/integration/test_users_negative_cases.py
git mv tests/test_auth_service.py tests/integration/test_auth_integration.py
```

- [ ] **Step 2: Оставить в `tests/conftest.py` только bootstrap**

Файл целиком:
```python
import os
import sys

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Defaults for running tests outside Docker; real environment variables take precedence.
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-long-enough-0123")
os.environ.setdefault("AUTH_DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/authdb")
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("REDIS_PORT", "6379")
```

- [ ] **Step 3: Создать `tests/integration/conftest.py`**

```python
import uuid

import pytest
import requests

from config import BASE_URL, HEADERS


@pytest.fixture
def unique_username():
    """Генерирует уникальное имя пользователя"""
    return f"testuser_{uuid.uuid4().hex[:8]}"


@pytest.fixture
def login():
    """Log in and return the access token."""
    def _login(username: str, password: str) -> str:
        resp = requests.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": password},
            headers=HEADERS,
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["token"]
    return _login


@pytest.fixture
def user_factory(login):
    """Create users with tokens; deletes them after the test with their current headers."""
    created = []

    def _create() -> dict:
        username = f"testuser_{uuid.uuid4().hex[:8]}"
        password = "StrongPass123!"
        resp = requests.post(
            f"{BASE_URL}/users/register",
            json={"username": username, "password": password, "email": f"{username}@example.com"},
            headers=HEADERS,
        )
        assert resp.status_code == 201, f"Failed to create test user: {resp.text}"
        token = login(username, password)
        user = {
            "id": resp.json()["user_id"],
            "username": username,
            "password": password,
            "token": token,
            "headers": {**HEADERS, "Authorization": f"Bearer {token}"},
        }
        created.append(user)
        return user

    yield _create

    # Cleanup: tests that change the password or log out must update user["headers"].
    for user in created:
        requests.delete(f"{BASE_URL}/users/users/{user['id']}", headers=user["headers"])


@pytest.fixture
def test_user(user_factory):
    """Создаёт тестового пользователя и возвращает его данные"""
    return user_factory()
```

- [ ] **Step 4: Переписать `tests/integration/test_auth_integration.py`**

```python
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
```

- [ ] **Step 5: Переписать `tests/integration/test_users_positive_cases.py`**

```python
import time

import requests

from config import BASE_URL, HEADERS


def test_register_user(unique_username, login):
    """Успешная регистрация"""
    payload = {"username": unique_username, "password": "StrongPass123!", "email": f"{unique_username}@example.com"}

    resp = requests.post(f"{BASE_URL}/users/register", json=payload, headers=HEADERS)

    assert resp.status_code == 201
    user_id = resp.json()["user_id"]
    token = login(unique_username, payload["password"])
    requests.delete(f"{BASE_URL}/users/users/{user_id}", headers={**HEADERS, "Authorization": f"Bearer {token}"})


def test_get_me(test_user):
    resp = requests.get(f"{BASE_URL}/users/me", headers=test_user["headers"])

    assert resp.status_code == 200
    assert resp.json()["id"] == test_user["id"]
    assert resp.json()["username"] == test_user["username"]


def test_get_all_users(test_user):
    """Получение списка пользователей"""
    resp = requests.get(f"{BASE_URL}/users/users", headers=test_user["headers"])

    assert resp.status_code == 200
    assert isinstance(resp.json()["users"], list)


def test_get_user_by_id(test_user):
    """Получение пользователя по ID"""
    resp = requests.get(f"{BASE_URL}/users/users/{test_user['id']}", headers=test_user["headers"])

    assert resp.status_code == 200
    assert resp.json()["id"] == test_user["id"]


def test_update_email_keeps_token_valid(test_user):
    """Обновление email не отзывает токен"""
    resp = requests.put(
        f"{BASE_URL}/users/users/{test_user['id']}",
        json={"email": "updated_test@example.com"},
        headers=test_user["headers"],
    )

    assert resp.status_code == 200
    assert resp.json()["email"] == "updated_test@example.com"
    assert requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"]).status_code == 200


def test_change_password_revokes_old_token(test_user, login):
    """Смена пароля отзывает старые токены"""
    time.sleep(1)  # revocation works in whole seconds: a token issued in the same second survives
    new_password = "NewStrongPass456!"

    resp = requests.put(
        f"{BASE_URL}/users/users/{test_user['id']}",
        json={"password": new_password},
        headers=test_user["headers"],
    )
    assert resp.status_code == 200

    old = requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"])
    assert old.status_code == 401
    assert old.json()["status"] == "revoked"

    token = login(test_user["username"], new_password)
    test_user["headers"] = {**HEADERS, "Authorization": f"Bearer {token}"}
    assert requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"]).status_code == 200


def test_delete_user(test_user):
    """Удаление пользователя отзывает его токены"""
    time.sleep(1)  # see test_change_password_revokes_old_token

    resp = requests.delete(f"{BASE_URL}/users/users/{test_user['id']}", headers=test_user["headers"])
    assert resp.status_code == 200

    validate = requests.get(f"{BASE_URL}/auth/validate", headers=test_user["headers"])
    assert validate.status_code == 401
    assert validate.json()["status"] == "revoked"
```

- [ ] **Step 6: Переписать `tests/integration/test_users_negative_cases.py`**

```python
import pytest
import requests

from config import BASE_URL, HEADERS


def _error_fields(resp):
    return [error["field"] for error in resp.json()["errors"]]


# ================== REGISTRATION ==================

@pytest.mark.parametrize("payload, field", [
    ({"password": "StrongPass123!"}, "username"),
    ({"username": "testuser"}, "password"),
    ({"username": "ab", "password": "StrongPass123!"}, "username"),
    ({"username": "validuser", "password": "123"}, "password"),
    ({"username": "bademailuser", "password": "StrongPass123!", "email": "not-an-email"}, "email"),
], ids=["no-username", "no-password", "short-username", "short-password", "bad-email"])
def test_register_rejects_invalid_payload(payload, field):
    resp = requests.post(f"{BASE_URL}/users/register", json=payload, headers=HEADERS)

    assert resp.status_code == 400
    assert field in _error_fields(resp)


def test_register_rejects_non_object_body():
    resp = requests.post(f"{BASE_URL}/users/register", json=["user", "pass"], headers=HEADERS)
    assert resp.status_code == 400


def test_register_duplicate_username(test_user):
    """Повторная регистрация занятого username"""
    resp = requests.post(
        f"{BASE_URL}/users/register",
        json={"username": test_user["username"], "password": "StrongPass123!"},
        headers=HEADERS,
    )

    assert resp.status_code == 409
    assert resp.json() == {"message": "Username already taken"}


# ================== AUTHORIZATION ==================

@pytest.mark.parametrize("method, path", [
    ("get", "/users/me"),
    ("get", "/users/users"),
    ("get", "/users/users/1"),
    ("put", "/users/users/1"),
    ("delete", "/users/users/1"),
])
def test_endpoints_require_token(method, path):
    resp = requests.request(method, f"{BASE_URL}{path}", json={"email": "x@example.com"}, headers=HEADERS)
    assert resp.status_code == 401


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_foreign_user_is_forbidden(user_factory, method):
    attacker, victim = user_factory(), user_factory()

    resp = requests.request(
        method,
        f"{BASE_URL}/users/users/{victim['id']}",
        json={"password": "Hacked123!"},
        headers=attacker["headers"],
    )

    assert resp.status_code == 403


def test_foreign_password_change_does_not_take_effect(user_factory, login):
    attacker, victim = user_factory(), user_factory()

    requests.put(
        f"{BASE_URL}/users/users/{victim['id']}",
        json={"password": "Hacked123!"},
        headers=attacker["headers"],
    )

    assert login(victim["username"], victim["password"])


def test_nonexistent_foreign_id_is_forbidden(test_user):
    """Чужой несуществующий id не раскрывает, существует ли пользователь"""
    resp = requests.get(f"{BASE_URL}/users/users/9999999", headers=test_user["headers"])
    assert resp.status_code == 403


def test_update_with_empty_body(test_user):
    resp = requests.put(f"{BASE_URL}/users/users/{test_user['id']}", json={}, headers=test_user["headers"])
    assert resp.status_code == 400
```

- [ ] **Step 7: Обновить `Makefile`**

Заменить секцию «Тесты» на:
```makefile
test:
	docker-compose exec auth-service pytest tests/unit tests/integration -v --tb=short

test-unit:
	pytest tests/unit -v --tb=short

test-positive:
	docker-compose exec auth-service pytest tests/integration/test_users_positive_cases.py -v --tb=short

test-negative:
	docker-compose exec auth-service pytest tests/integration/test_users_negative_cases.py -v --tb=short
```
В первой строке файла добавить `test-unit` в `.PHONY`. В `help` после строки `make test` добавить:
```makefile
	@echo "  make test-unit       - Unit-тесты локально, без Docker"
```

- [ ] **Step 8: Проверить коллекцию и unit-тесты**

Run: `.venv/bin/python -m pytest tests/unit tests/integration --collect-only -q | tail -3`
Expected: `N tests collected` без ошибок коллекции.

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: PASS.

- [ ] **Step 9: Прогнать интеграционные тесты на живом сервисе**

Run: `make fresh && sleep 20 && make test`
Expected: все тесты PASS.

Если `docker`/`docker-compose` недоступен в окружении исполнителя, шаг не пропускать молча: в отчёте явно написать «интеграционные тесты не запускались, нужен прогон `make fresh && make test` у пользователя».

- [ ] **Step 10: Commit**

```bash
git add tests/conftest.py tests/integration Makefile
git commit -m "test: move HTTP tests to tests/integration and cover the new auth contract

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- tests/conftest.py tests/integration tests/test_users_positive_cases.py tests/test_users_negative_cases.py tests/test_auth_service.py Makefile
```

---

### Task 8: Финальная проверка

**Files:** без изменений кода.

- [ ] **Step 1: Полный прогон unit-тестов**

Run: `.venv/bin/python -m pytest tests/unit -q`
Expected: все PASS, 0 failed, 0 errors.

- [ ] **Step 2: Проверка, что не осталось ссылок на удалённые модули и утечек текста исключений**

Run: `grep -rn "redis_cache\|auth_repository\|generate_token\|verify_token\|str(e)}, " app init_db.py tests`
Expected: ничего (exit code 1).

- [ ] **Step 3: Проверка, что чужие staged-файлы не попали в коммиты**

Run: `git status --short && git log --stat --oneline -8 | grep -c tests_albums_api`
Expected: `tests/tests_albums_api/*` по-прежнему в статусе `A`/`AM`; счётчик `0`.

- [ ] **Step 4: Сверка с разделом 7.2 спецификации**

Пройти по списку «Обязательные сценарии» в `docs/superpowers/specs/2026-10-03-auth-security-design.md` и для каждого назвать тест, который его покрывает. Непокрытые сценарии — вернуть в соответствующую задачу.

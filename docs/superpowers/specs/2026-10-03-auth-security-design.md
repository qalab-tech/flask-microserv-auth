# Безопасность и авторизация auth-service — дизайн

- **Дата:** 2026-10-03
- **Статус:** утверждён; отклонения из плана согласованы 2026-10-04 (раздел 8)
- **Кусок:** 1 из 4 по итогам аудита (безопасность и авторизация)

## 1. Контекст и цель

Аудит проекта выявил 23 проблемы. Они разбиты на четыре независимых куска:

1. **Безопасность и авторизация** — этот документ (пункты аудита 1, 3–10, частично 20–23).
2. Сборка и инфраструктура (зависимости, compose, Dockerfile).
3. Качество кода (логирование, пул соединений, health, структура blueprints, пути).
4. Тесты (остаток после кусков 1–3).

**Назначение проекта:** портфолио. Нужны правильные практики и чистый код без «энтерпрайза»:
без ролей, refresh-токенов и миграций схемы.

**Критерии готовности:**
- изменять, удалять и читать профиль можно только с валидным токеном владельца;
- после logout, смены пароля и удаления пользователя ранее выданные токены отклоняются;
- на некорректный ввод сервис не отвечает 500, а внутренние ошибки не попадают в ответ клиенту;
- тестовые пользователи с известными паролями не создаются, если это явно не включено;
- unit-тесты запускаются без Docker, Postgres и Redis; все сценарии из раздела 7 покрыты тестами.

**Ограничения:**
- стек не меняется: Flask + flask-restx, Postgres (psycopg2), Redis, gunicorn;
- контракт с albums-сервисом меняется только совместимо (раздел 4.3);
- пути `/users/users/...` пока не меняются (это кусок 3).

## 2. Принятые решения

| Вопрос | Решение |
|---|---|
| Модель доступа к `/users/*` | Регистрация публичная, всё остальное требует JWT. `GET/PUT/DELETE /users/users/<id>` разрешены только владельцу (иначе 403). Список доступен любому авторизованному. Добавляется `GET /users/me`. Ролей нет. |
| Payload токена | `sub` (числовой id строкой), `username`, `iat`, `exp`, `jti`. Ответ `/auth/validate` расширяется полем `user_id`, поле `user` (username) сохраняется. |
| Роль Redis | Кэш токенов удаляется. Redis хранит только отзывы: `revoked:<jti>` и `valid_after:<user_id>`. |
| Redis недоступен | Fail-closed: 503. |
| Тестовые пользователи | Создаются только при `SEED_TEST_USERS=true`. |

## 3. Компоненты

### 3.1 Новые модули

**`app/tokens.py`** (заменяет `app/redis_cache.py`, старый модуль удаляется)
- `issue_token(user_id: int, username: str) -> str`
- `decode_token(token: str) -> dict` возвращает claims или бросает `TokenExpired`, `TokenInvalid`, `TokenRevoked`, `ServiceUnavailable`.
- `revoke_token(claims: dict) -> None` записывает `revoked:<jti>`.
- `revoke_all_for_user(user_id: int) -> None` записывает `valid_after:<user_id>`.
- Зависимости: Redis-клиент, `SECRET_KEY`, `JWT_ACCESS_TOKEN_EXPIRES`. Redis-клиент создаётся с `socket_timeout=2`, `socket_connect_timeout=2` и подменяется в тестах.

**`app/auth_guard.py`**
- Декоратор `@require_auth` разбирает заголовок строго в формате `Authorization: Bearer <token>`: ровно две части, схема `Bearer` без учёта регистра. Вызывает `decode_token` и кладёт `g.current_user = {"id": int, "username": str}`, а `g.token_claims` — сырые claims для logout.
- `ensure_owner(user_id: int)` бросает `Forbidden`, если `user_id != g.current_user["id"]`.

**`app/errors.py`**
- Доменные исключения: `UserNotFound`, `UserAlreadyExists`, `Forbidden`, `AuthError` с подклассами `TokenMissing`, `TokenInvalid`, `TokenExpired`, `TokenRevoked` (у каждого атрибут класса `status` ∈ `missing`, `invalid`, `expired`, `revoked`), `ServiceUnavailable`.
- Функция `register_error_handlers(api)` регистрирует обработчики на общем `Api` flask-restx (раздел 5).

### 3.2 Изменения существующих модулей

- **`config.py`** — проверка при импорте: нет `SECRET_KEY` или он короче 32 символов → `RuntimeError`. `JWT_ACCESS_TOKEN_EXPIRES` приводится к `int`, по умолчанию 3600. Новый флаг `SEED_TEST_USERS` (bool, по умолчанию `false`). Неиспользуемый `JWT_REFRESH_TOKEN_EXPIRES` удаляется. `REDIS_HOST`/`REDIS_PORT` по умолчанию `localhost`/`6379`.
- **`app/schemas/user_schemas.py`** — схемы начинают использоваться для валидации тел запросов:
  - `UserRegister`: username 3–50, email `EmailStr | None`, password от 6 **символов** до 72 **байт** в UTF-8;
  - `UserUpdate`: email и password опциональны с теми же правилами; хотя бы одно поле обязательно;
  - `LoginRequest` (новая): username и password — непустые строки;
  - неиспользуемые `UserResponse`/`UserListResponse` удаляются.
- **`app/services/user_service.py`** — ручная валидация удаляется (её заменяет pydantic). Вместо `ValueError` бросаются `UserNotFound`. При смене пароля и удалении сервис вызывает отзыв токенов (раздел 4.2).
- **`app/repositories/users_repository.py`** — `psycopg2.errors.UniqueViolation` превращается в `UserAlreadyExists`. Добавляется `get_user_credentials(username)` → `{id, username, hashed_password} | None` для логина; `app/repositories/auth_repository.py` удаляется.
- **`app/controllers/auth_controller.py`** — второй экземпляр `Flask(__name__)` удаляется. Логин использует `hashing.check_password`; если пользователь не найден, проверка выполняется с фиктивным bcrypt-хэшем (защита от определения логинов по времени ответа). Добавляется `POST /auth/logout`.
- **`app/controllers/users_controller.py`** — `@require_auth` и `ensure_owner` на всех эндпоинтах, кроме регистрации. Добавляется `GET /users/me`. Блоки `try/except Exception` с `str(e)` удаляются, ошибки обрабатывает единый обработчик.
- **`app/db.py`** — пул создаётся лениво при первом вызове `get_db_connection()` (нужно, чтобы приложение импортировалось в unit-тестах).
- **`init_db.py`** — пользователи `test/test` и `valid_user/correct_pass` создаются только при `SEED_TEST_USERS=true`. Если создать таблицу не удалось — `sys.exit(1)`, и gunicorn не стартует.
- **`docker-compose.yml`** — для dev добавляется `SEED_TEST_USERS: "true"`. Остальные изменения compose — кусок 2.
- **`requirements.txt`** — добавляются `redis`, `pydantic`, `email-validator`, `requests`, `fakeredis`. Версии закрепляются в куске 2.

## 4. API-контракт

### 4.1 Эндпоинты

| Метод и путь | Доступ | Успех | Ошибки |
|---|---|---|---|
| `POST /auth/login` | публично | 200 `{"token"}` | 400 тело невалидно; 401 `{"message":"Invalid credentials"}` |
| `GET /auth/validate` | Bearer | 200 `{"status":"valid","user":"<username>","user_id":<id>}` | 401 `{"message":"Unauthorized","status":"missing"\|"invalid"\|"expired"\|"revoked"}`; 503 |
| `POST /auth/logout` *(новый)* | Bearer | 204 | 401 как у `/validate`; 503 |
| `POST /users/register` | публично | 201 `{"message","user_id"}` | 400 валидация; 409 логин занят |
| `GET /users/me` *(новый)* | Bearer | 200 профиль | 401; 503 |
| `GET /users/users` | Bearer | 200 `{"users","total"}` | 401; 503 |
| `GET /users/users/<id>` | Bearer, владелец | 200 профиль | 401; 403; 404; 503 |
| `PUT /users/users/<id>` | Bearer, владелец | 200 профиль | 400; 401; 403; 404; 503 |
| `DELETE /users/users/<id>` | Bearer, владелец | 200 `{"message"}` | 401; 403; 404; 503 |

Профиль: `{"id", "username", "email", "created_at"}`, где `created_at` в ISO 8601.

Проверка владельца выполняется **до** обращения к БД: если чужой id не существует, ответ всё равно 403. Так нельзя перебором выяснить, какие id существуют.

### 4.2 Токен и отзыв

Токен подписан HS256:
```json
{"sub": "42", "username": "test", "iat": 1759480000, "exp": 1759483600, "jti": "<uuid4 hex>"}
```
`sub` — строка (PyJWT ≥ 2.10 требует строковый `sub`). При декодировании все пять claims обязательны.

| Ключ Redis | Значение | TTL | Кто пишет |
|---|---|---|---|
| `revoked:<jti>` | `1` | `max(1, exp − now)` | `/auth/logout` |
| `valid_after:<user_id>` | unix-время в секундах (int) | `JWT_ACCESS_TOKEN_EXPIRES` | смена пароля, удаление |

Шаги `decode_token`:
1. `jwt.decode(..., algorithms=["HS256"], options={"require": ["sub","username","iat","exp","jti"]})`. `ExpiredSignatureError` → `TokenExpired`, любая другая ошибка `InvalidTokenError` → `TokenInvalid`. `sub`, который не приводится к `int`, → `TokenInvalid`.
2. Одним `MGET` читаются `revoked:<jti>` и `valid_after:<sub>`.
3. Есть `revoked`, **или** `iat < valid_after` → `TokenRevoked`.
4. `redis.exceptions.RedisError` → `ServiceUnavailable`.

Сравнение `iat < valid_after` строгое, в целых секундах. Токен, выпущенный в ту же секунду, что и отзыв, остаётся валидным: это допустимая цена за то, что новый логин сразу после смены пароля работает. В коде будет комментарий.

Порядок операций:
- **Смена пароля** (`PUT` с `password`): валидация → hash → `revoke_all_for_user` → `UPDATE` в БД → 200. Если Redis упал, пароль не меняется, ответ 503. Если упала БД после отзыва, токены уже отозваны, а старый пароль работает — пользователь просто логинится заново (порядок изменён 2026-10-04, раздел 8).
- **Смена только email** токены не отзывает.
- **Удаление:** `revoke_all_for_user` → `DELETE` → 200. Если Redis упал, удаление не выполняется (503).

### 4.3 Изменения, которые затрагивают вызывающих

1. Если заголовка `Authorization` нет, `/auth/validate` отвечает 401 `{"message":"Unauthorized","status":"missing"}` вместо 403.
2. `/users/*` (кроме регистрации) требует Bearer-токен.
3. После смены пароля или удаления все токены пользователя, включая текущий, недействительны.
4. Для несуществующего пользователя (своего id) `PUT` и `DELETE` отвечают 404, а не 400.
5. Повторная регистрация → 409 вместо 400.
6. Токены, выпущенные до деплоя, отклоняются (401 `invalid`): у них нет `sub` и `jti`.

Ответ `/auth/login` и поле `user` в `/auth/validate` не меняются.

## 5. Обработка ошибок

Единый формат тела ошибки:
```json
{"message": "Validation failed", "errors": [{"field": "password", "msg": "..."}]}
```
Поле `errors` есть только у 400.

| Исключение | Статус | Тело |
|---|---|---|
| `pydantic.ValidationError`, тело не JSON или не объект | 400 | `{"message":"Validation failed","errors":[...]}` |
| `AuthError` (любой эндпоинт) | 401 | `{"message":"Unauthorized","status":"<status>"}` |
| неверные логин или пароль | 401 | `{"message":"Invalid credentials"}` |
| `Forbidden` | 403 | `{"message":"Forbidden"}` |
| `UserNotFound` | 404 | `{"message":"User not found"}` |
| `UserAlreadyExists` | 409 | `{"message":"Username already taken"}` |
| `ServiceUnavailable` | 503 | `{"message":"Service temporarily unavailable"}` |
| любое другое исключение | 500 | `{"message":"Internal server error"}`; подробности только в логе (`logger.exception`) |

`HTTPException` Flask (404 на неизвестный маршрут, 405) обрабатывается штатно.

## 6. Вне рамок этого куска

- секреты в compose и `.env`, закрытые порты Postgres и Redis, относительный `build`, закреплённые версии, разделение prod и dev зависимостей — кусок 2;
- дубли логов, пул соединений (кроме ленивой инициализации), health с проверкой БД и Redis, структура blueprints, пути `/users/users` — кусок 3;
- роли, refresh-токены, миграции, rate limiting — не делаем;
- albums-тесты (`tests/tests_albums_api/`) не трогаем.

## 7. Тестирование

### 7.1 Структура

| Уровень | Каталог | Подмены | Запуск |
|---|---|---|---|
| Unit и API | `tests/unit/` | `fakeredis` вместо Redis; репозитории через `monkeypatch`; `time.time` через `monkeypatch`; Flask `test_client` | `pytest tests/unit` локально, без Docker |
| Интеграционные | `tests/integration/` (сюда переезжают `test_users_*_cases.py` и `test_auth_service.py`) | нет, живой сервис по HTTP | `make test` в контейнере |

Фикстура `test_user` в интеграционных тестах логинится и отдаёт `auth_headers`. Удаление пользователя после теста выполняется с его же токеном.

### 7.2 Обязательные сценарии

Каждый сценарий пишется по TDD: сначала падающий тест, потом исправление.

Авторизация на `/users/*`:
- без токена `GET/PUT/DELETE /users/users/<id>`, `GET /users/users`, `GET /users/me` → 401;
- с чужим токеном `PUT` с паролем → 403, пароль не меняется;
- чужой несуществующий id → 403;
- свой id → 200; `GET /users/me` возвращает свой профиль.

Токены:
- истёкший → 401 `expired`;
- `Bearer` без токена, схема `Basic`, мусор, токен с другой подписью, токен без `jti` → 401 `invalid`, не 500
  (правило: заголовок есть, но некорректен → `invalid`);
- нет заголовка `Authorization` → 401 `missing`;
- после logout → 401 `revoked`;
- после смены пароля старый токен → `revoked`, новый логин работает; после смены только email старый токен валиден;
- после удаления старый токен → `revoked`;
- Redis недоступен → `/auth/validate` 503; `DELETE` → 503, и удаление не выполняется.

Ввод и ошибки:
- логин с телом не-JSON, без пароля, с паролем `null` → 400;
- регистрация с паролем длиннее 72 байт, коротким паролем, невалидным email → 400 с `errors`;
- `PUT` с пустым телом → 400;
- повторная регистрация → 409, в теле нет текста psycopg2;
- непредвиденное исключение в репозитории → 500 `Internal server error`, текст исключения в ответ не попадает.

Прочее:
- логин несуществующего пользователя вызывает `check_password` с фиктивным хэшем;
- нет `SECRET_KEY` или он короче 32 символов → `RuntimeError` при загрузке конфига;
- `init_db` без `SEED_TEST_USERS` не создаёт тестовых пользователей; при ошибке создания таблицы завершается с кодом 1.

### 7.3 Исправление тестов, которые не могут упасть

- `test_login` (принимает и 200, и 401) переписывается на два точных кейса;
- `test_register_invalid_email` ждёт строго 400;
- `test_register_duplicate_username` использует уникальное имя, ждёт 409 и удаляет пользователя после теста.

## 8. Согласованные отклонения (2026-10-04)

- Тело 401 всегда содержит `message` (flask-restx добавляет его сам): `{"message":"Unauthorized","status":"..."}`. Поле `status` сохраняется, контракт с albums совместим.
- Пароль: минимум 6 символов, максимум 72 байта в UTF-8.
- `AuthError(status)` заменён подклассами `TokenMissing`/`TokenInvalid`/`TokenExpired`/`TokenRevoked`.
- Неиспользуемые `UserResponse`/`UserListResponse` удаляются.
- В Swagger добавляется схема `Bearer` (кнопка Authorize).
- `REDIS_HOST`/`REDIS_PORT` по умолчанию `localhost`/`6379`. Забытая переменная в проде проявится как 503 (fail-closed), а не как падение при старте — осознанный компромисс ради запуска unit-тестов без Docker.
- `Makefile`: пути тестов обновляются, добавляется `make test-unit`.

### Дополнения по итогам финального ревью (2026-10-04)

- Удаление пользователя пишет `valid_after = now + 1` (TTL `JWT_ACCESS_TOKEN_EXPIRES + 1`): токен, выпущенный в ту же секунду, что и удаление, тоже отклоняется. Для смены пароля остаётся `valid_after = now`, чтобы новый логин сразу после смены работал.
- `username` с NUL-символом (`\x00`) отклоняется с 400 (psycopg2 не принимает такие строки). Email ограничен 100 символами — по ширине колонки `VARCHAR(100)`.
- Пользовательский `username` в логах выводится через `%r`, чтобы перевод строки в нём не подделывал записи лога.
- Смена пароля переведена на порядок «сначала отзыв, потом `UPDATE`», как у удаления: при недоступном Redis пароль не меняется, и украденный токен не переживает смену пароля.
